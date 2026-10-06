use crate::config::{
    UserAuthState, load_user_auth_state, now_unix, persist_user_auth_state, resolve_api_base,
};
use aegis_dto::{
    HostAlias, HostId, path,
    protocol::{
        AegisAliasResponse, AegisCredentialKind, AegisDirectClientCertRequest,
        AegisDirectClientCertResponse, AegisDirectGateway, AegisDirectGatewayInventory,
        AegisDirectGatewayPublishRequest, AegisDirectTargetListResponse, AegisDnsSyncRequest,
        AegisDnsSyncResponse, AegisEgressEnableRequest, AegisEgressIdentityRequest,
        AegisEgressInventory, AegisEgressResult, AegisEgressStatus, AegisEnrollment,
        AegisEnrollmentActivateResponse, AegisEnrollmentCreateRequest,
        AegisEnrollmentCredentialResponse, AegisEnrollmentHeartbeatRequest,
        AegisEnrollmentListResponse, AegisEnrollmentPrepareRequest, AegisEnrollmentPrepareResponse,
        AegisHost, AegisHostClientCertRequest, AegisHostListResponse, AegisHostReportRequest,
        AegisHostReportResponse, AegisNetworkListResponse, AegisNetworkMemberListResponse,
        AegisNetworkMemberResponse, AegisPutNetworkMemberRequest, AegisSatelliteCreateRequest,
        AegisSatelliteDetailsResponse, AegisSatelliteListResponse, AegisSatelliteProvisionResponse,
        AegisTlsSyncRequest, AegisTlsSyncResponse, AgentTokenIssueResponse, AgentTokenRequest,
        AgentTokenResponse, AgentTokenRevokeRequest, ErrorResponse, SshCaPublicKeyResponse,
        SshIssueCertResponse,
    },
};
use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, Client as OAuthClient, ClientId, CsrfToken,
    EndpointNotSet, ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse,
    TokenResponse, TokenUrl,
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenType},
};
use phylax_core::{AccessClaims, dangerous::decode_unverified_claims, oauth};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    dns::{Addrs, Name, Resolve, Resolving},
    header::{CACHE_CONTROL, CONTENT_LENGTH, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use url::Url;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
struct AegisOAuthTokenExtraFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_expires_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
}

impl ExtraTokenFields for AegisOAuthTokenExtraFields {}

type AegisTokenResponse = StandardTokenResponse<AegisOAuthTokenExtraFields, BasicTokenType>;
type AegisOauthClient<HasAuthUrl = EndpointNotSet, HasTokenUrl = EndpointNotSet> = OAuthClient<
    BasicErrorResponse,
    AegisTokenResponse,
    StandardTokenIntrospectionResponse<AegisOAuthTokenExtraFields, BasicTokenType>,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    HasTokenUrl,
>;
const ACCESS_TOKEN_REFRESH_SKEW_SECONDS: i64 = 30;
const AEGIS_TOOL_CLIENT_ID: &str = "aegis-tool";
#[cfg(test)]
const AEGIS_ADMIN_SCOPE: &str = "aegis:admin";
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct AgentAccessState {
    pub access_token: String,
    pub host_id: HostId,
    pub credential_kind: AegisCredentialKind,
    pub refresh_token: String,
    pub access_expires_at_unix: i64,
}

impl AgentAccessState {
    pub fn access_needs_refresh(&self, now_unix: i64, skew_seconds: i64) -> bool {
        now_unix.saturating_add(skew_seconds) >= self.access_expires_at_unix
    }
}

#[derive(Debug)]
pub enum ApiClientError {
    Transport(anyhow::Error),
    Status { status: StatusCode, message: String },
}

impl ApiClientError {
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            Self::Status {
                status: StatusCode::UNAUTHORIZED,
                ..
            }
        )
    }
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::Status { status, message } if message.is_empty() => {
                write!(f, "api request failed with {status}")
            }
            Self::Status { status, message } => {
                write!(f, "api request failed with {status}: {message}")
            }
        }
    }
}

impl std::error::Error for ApiClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error.as_ref()),
            Self::Status { .. } => None,
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiClientError>;

#[derive(Clone, Debug)]
pub struct BrowserLoginStart {
    pub authorization_url: Url,
    pub state: String,
    pub pkce_verifier: String,
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    http: Client,
    request_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ApiDnsMode {
    #[default]
    System,
    AgentControl,
}

#[derive(Clone, Copy, Debug)]
struct ApiClientOptions {
    dns: ApiDnsMode,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl Default for ApiClientOptions {
    fn default() -> Self {
        Self {
            dns: ApiDnsMode::System,
            connect_timeout: API_CONNECT_TIMEOUT,
            request_timeout: API_REQUEST_TIMEOUT,
        }
    }
}

#[derive(Clone)]
struct AgentControlDnsResolver {
    resolver: TokioResolver,
}

impl AgentControlDnsResolver {
    fn new() -> Self {
        let name_servers = [
            IpAddr::from([1, 1, 1, 1]),
            IpAddr::from([1, 0, 0, 1]),
            IpAddr::from([8, 8, 8, 8]),
            IpAddr::from([8, 8, 4, 4]),
            "2606:4700:4700::1111".parse().expect("valid address"),
            "2606:4700:4700::1001".parse().expect("valid address"),
            "2001:4860:4860::8888".parse().expect("valid address"),
            "2001:4860:4860::8844".parse().expect("valid address"),
        ]
        .into_iter()
        .map(NameServerConfig::udp_and_tcp)
        .collect();
        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let mut options = ResolverOpts::default();
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .expect("valid DNS resolver configuration");
        Self { resolver }
    }
}

impl Resolve for AgentControlDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addresses = lookup
                .iter()
                .map(|address| SocketAddr::new(address, 0))
                .collect::<Vec<_>>();
            let addresses: Addrs = Box::new(addresses.into_iter());
            Ok(addresses)
        })
    }
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_options(base_url, ApiClientOptions::default())
    }

    pub(crate) fn new_agent_control(base_url: impl Into<String>) -> Result<Self> {
        Self::with_options(
            base_url,
            ApiClientOptions {
                dns: ApiDnsMode::AgentControl,
                ..ApiClientOptions::default()
            },
        )
    }

    fn with_options(base_url: impl Into<String>, options: ApiClientOptions) -> Result<Self> {
        let base_url = aegis_dto::namespace::ApiEndpoint::parse(&base_url.into())
            .map_err(anyhow::Error::msg)?;
        base_url.require_namespace().map_err(anyhow::Error::msg)?;
        let base_url = base_url.base_url();
        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        );
        let mut builder = Client::builder()
            .user_agent(format!("aegis-tool/{}", env!("CARGO_PKG_VERSION")))
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .default_headers(default_headers);
        if options.dns == ApiDnsMode::AgentControl {
            builder = builder.dns_resolver(std::sync::Arc::new(AgentControlDnsResolver::new()));
        }
        let http = builder.build()?;
        Ok(Self {
            base_url,
            http,
            request_timeout: options.request_timeout,
        })
    }

    fn operation_request_timeout(&self) -> ApiResult<Duration> {
        crate::tunnel_operation::request_timeout(self.request_timeout)
            .map_err(ApiClientError::Transport)
    }

    pub fn get_namespace_context(
        &self,
        token: &str,
    ) -> ApiResult<aegis_dto::namespace::NamespaceContext> {
        let response = self
            .http
            .get(
                self.url("/aegis/context")
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to fetch namespace membership"))?;
        parse_json_response(response)
    }

    pub fn get_hosts(&self, token: &str) -> ApiResult<AegisHostListResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_HOSTS)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to fetch host inventory"))?;
        parse_json_response(response)
    }

    pub fn create_enrollment(
        &self,
        token: &str,
        request: &AegisEnrollmentCreateRequest,
    ) -> ApiResult<AegisEnrollment> {
        let response = self
            .http
            .post(
                self.url(path::AEGIS_ENROLLMENTS)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| transport_error(error, "failed to create Aegis enrollment"))?;
        parse_json_response(response)
    }

    pub fn get_enrollments(&self, token: &str) -> ApiResult<AegisEnrollmentListResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_ENROLLMENTS)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to list Aegis enrollments"))?;
        parse_json_response(response)
    }

    pub fn get_enrollment(&self, token: &str, host_id: &HostId) -> ApiResult<AegisEnrollment> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_enrollment(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to fetch Aegis enrollment {host_id}"))
            })?;
        parse_json_response(response)
    }

    pub fn issue_enrollment_credential(
        &self,
        token: &str,
        host_id: &HostId,
    ) -> ApiResult<AegisEnrollmentCredentialResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_enrollment_credential(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to issue credential for Aegis enrollment {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn delete_enrollment(&self, token: &str, host_id: &HostId) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_enrollment(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to cancel Aegis enrollment {host_id}"),
                )
            })?;
        parse_empty_response(response)
    }

    pub fn prepare_enrollment(
        &self,
        token: &str,
        host_id: &HostId,
        request: &AegisEnrollmentPrepareRequest,
    ) -> ApiResult<AegisEnrollmentPrepareResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_enrollment_prepare(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to prepare Aegis enrollment {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn heartbeat_enrollment(
        &self,
        token: &str,
        host_id: &HostId,
        request: &AegisEnrollmentHeartbeatRequest,
    ) -> ApiResult<AegisEnrollment> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_enrollment_heartbeat(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to update Aegis enrollment {host_id} progress"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn activate_enrollment(
        &self,
        token: &str,
        host_id: &HostId,
    ) -> ApiResult<AegisEnrollmentActivateResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_enrollment_activate(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to activate Aegis enrollment {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn get_alias(&self, token: &str, alias: &HostAlias) -> ApiResult<AegisAliasResponse> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_alias(alias))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to resolve host alias {alias}"))
            })?;
        parse_json_response(response)
    }

    pub fn add_host_alias(
        &self,
        token: &str,
        host_id: &HostId,
        alias: &HostAlias,
    ) -> ApiResult<AegisHost> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_host_alias(host_id, alias))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to add alias {alias} to host {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn promote_host_alias(
        &self,
        token: &str,
        host_id: &HostId,
        alias: &HostAlias,
    ) -> ApiResult<AegisHost> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_host_alias_promote(host_id, alias))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to promote alias {alias} on host {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn remove_host_alias(
        &self,
        token: &str,
        host_id: &HostId,
        alias: &HostAlias,
    ) -> ApiResult<AegisHost> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_host_alias(host_id, alias))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to remove alias {alias} from host {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn get_networks(&self, token: &str) -> ApiResult<AegisNetworkListResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_NETWORKS)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to fetch aegis networks"))?;
        parse_json_response(response)
    }

    pub fn get_network_members(
        &self,
        token: &str,
        network: &str,
    ) -> ApiResult<AegisNetworkMemberListResponse> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_network_members(network))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to fetch `{network}` network inventory"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn report_host(
        &self,
        token: &str,
        host_id: &HostId,
        request: &AegisHostReportRequest,
    ) -> ApiResult<AegisHostReportResponse> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_host_report(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| transport_error(error, "failed to publish host report"))?;
        parse_json_response(response)
    }

    pub fn sync_dns(
        &self,
        token: &str,
        request: &AegisDnsSyncRequest,
    ) -> ApiResult<AegisDnsSyncResponse> {
        let response = self
            .http
            .post(
                self.url(path::AEGIS_DNS_SYNC)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| transport_error(error, "failed to synchronize Aegis DNS"))?;
        parse_json_response(response)
    }

    pub fn sync_tls(
        &self,
        token: &str,
        request: &AegisTlsSyncRequest,
    ) -> ApiResult<AegisTlsSyncResponse> {
        let response = self
            .http
            .post(
                self.url(path::AEGIS_TLS_SYNC)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(error, "failed to synchronize Aegis TLS configuration")
            })?;
        parse_json_response(response)
    }

    pub fn request_network_member_client_cert(
        &self,
        token: &str,
        network: &str,
        host_id: &HostId,
        ed25519_public_key: &str,
    ) -> ApiResult<SshIssueCertResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_network_member_client_cert(network, host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(&AegisHostClientCertRequest {
                ed25519_public_key: ed25519_public_key.to_string(),
            })
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to request client certificate for {network}/{host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn get_direct_gateway_inventory(
        &self,
        token: &str,
        host_id: &HostId,
    ) -> ApiResult<AegisDirectGatewayInventory> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_direct_gateway_inventory(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to fetch direct-gateway inventory for {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn put_direct_gateway(
        &self,
        token: &str,
        host_id: &HostId,
        request: &AegisDirectGatewayPublishRequest,
    ) -> ApiResult<AegisDirectGateway> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_direct_gateway(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to publish direct gateway {host_id}"))
            })?;
        parse_json_response(response)
    }

    pub fn delete_direct_gateway(&self, token: &str, host_id: &HostId) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_direct_gateway(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to remove direct gateway {host_id}"))
            })?;
        parse_empty_response(response)
    }

    pub fn get_egress_status(
        &self,
        token: &str,
        source_host_id: &HostId,
    ) -> ApiResult<AegisEgressStatus> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_egress(source_host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to fetch egress status for {source_host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn put_egress(
        &self,
        token: &str,
        source_host_id: &HostId,
        request: &AegisEgressEnableRequest,
    ) -> ApiResult<AegisEgressStatus> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_egress(source_host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to enable egress on {source_host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn delete_egress(&self, token: &str, source_host_id: &HostId) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_egress(source_host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to disable egress on {source_host_id}"),
                )
            })?;
        parse_empty_response(response)
    }

    pub fn put_egress_identity(
        &self,
        token: &str,
        host_id: &HostId,
        request: &AegisEgressIdentityRequest,
    ) -> ApiResult<()> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_host_egress(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to publish egress identity for {host_id}"),
                )
            })?;
        parse_empty_response(response)
    }

    pub fn get_egress_inventory(&self, token: &str) -> ApiResult<AegisEgressInventory> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_EGRESS_INVENTORY)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| transport_error(error, "failed to fetch egress inventory"))?;
        parse_json_response(response)
    }

    pub fn post_egress_result(
        &self,
        token: &str,
        source_host_id: &HostId,
        result: &AegisEgressResult,
    ) -> ApiResult<AegisEgressStatus> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_egress_result(source_host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(result)
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to publish egress result for {source_host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn put_satellite(
        &self,
        token: &str,
        slug: &str,
        request: &AegisSatelliteCreateRequest,
    ) -> ApiResult<AegisSatelliteProvisionResponse> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_satellite(slug))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to create satellite {slug}"))
            })?;
        parse_json_response(response)
    }

    pub fn get_satellites(&self, token: &str) -> ApiResult<AegisSatelliteListResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_SATELLITES)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to fetch satellites"))?;
        parse_json_response(response)
    }

    pub fn get_satellite(
        &self,
        token: &str,
        slug: &str,
    ) -> ApiResult<AegisSatelliteDetailsResponse> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_satellite(slug))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, format!("failed to fetch satellite {slug}")))?;
        parse_json_response(response)
    }

    pub fn get_satellite_targets(
        &self,
        token: &str,
        slug: &str,
    ) -> ApiResult<AegisDirectTargetListResponse> {
        let response = self
            .http
            .get(
                self.url(&path::aegis_satellite_targets(slug))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to fetch targets for satellite {slug}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn request_satellite_client_cert(
        &self,
        token: &str,
        slug: &str,
        request: &AegisDirectClientCertRequest,
    ) -> ApiResult<AegisDirectClientCertResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_satellite_client_cert(slug))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to request a client certificate for satellite {slug}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn delete_satellite(&self, token: &str, slug: &str) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_satellite(slug))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to delete satellite {slug}"))
            })?;
        parse_empty_response(response)
    }

    pub fn get_client_ca_public_key(&self) -> ApiResult<SshCaPublicKeyResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_USER_SSH_CA)
                    .map_err(ApiClientError::Transport)?,
            )
            .send()
            .map_err(|error| transport_error(error, "failed to fetch client CA public key"))?;
        parse_json_response(response)
    }

    pub(crate) fn issue_tls_certificate(
        &self,
        token: &str,
        label: &str,
        public_key: &str,
    ) -> ApiResult<String> {
        if label.is_empty()
            || label.len() > 128
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(ApiClientError::Transport(anyhow::anyhow!(
                "invalid TLS certificate label"
            )));
        }
        let response = self
            .http
            .put(
                self.url(&path::aegis_tls_cert_public_key(label))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .body(public_key.to_owned())
            .send()
            .map_err(|error| transport_error(error, "failed to publish TLS public key"))?;
        parse_empty_response(response)?;
        let response = self
            .http
            .get(
                self.url(&path::aegis_tls_cert(label))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, "failed to retrieve TLS certificate"))?;
        let status = response.status();
        let text = response
            .text()
            .map_err(|error| transport_error(error, "failed to read TLS certificate"))?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(status_error(status, text))
        }
    }

    pub fn get_server_ca_public_key(&self) -> ApiResult<SshCaPublicKeyResponse> {
        let response = self
            .http
            .get(
                self.url(path::AEGIS_HOST_SSH_CA)
                    .map_err(ApiClientError::Transport)?,
            )
            .send()
            .map_err(|error| transport_error(error, "failed to fetch server CA public key"))?;
        parse_json_response(response)
    }

    pub fn request_network_member_server_cert(
        &self,
        token: &str,
        network: &str,
        host_id: &HostId,
    ) -> ApiResult<SshIssueCertResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_network_member_server_cert(network, host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to request server certificate for {network}/{host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn put_network_member(
        &self,
        token: &str,
        network: &str,
        host_id: &HostId,
        request: &AegisPutNetworkMemberRequest,
    ) -> ApiResult<AegisNetworkMemberResponse> {
        let response = self
            .http
            .put(
                self.url(&path::aegis_network_member(network, host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| {
                transport_error(
                    error,
                    format!("failed to store `{network}` network member {host_id}"),
                )
            })?;
        parse_json_response(response)
    }

    pub fn delete_host(&self, token: &str, host_id: &HostId) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(&path::aegis_host(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .send()
            .map_err(|error| transport_error(error, format!("failed to delete host {host_id}")))?;
        parse_empty_response(response)
    }

    pub fn issue_agent_token(
        &self,
        token: &str,
        host_id: &HostId,
    ) -> ApiResult<AgentTokenIssueResponse> {
        let response = self
            .http
            .post(
                self.url(&path::aegis_host_agent_token(host_id))
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .header(CONTENT_LENGTH, "0")
            .body(Vec::new())
            .send()
            .map_err(|error| {
                transport_error(error, format!("failed to issue agent token for {host_id}"))
            })?;
        parse_json_response(response)
    }

    pub fn revoke_agent_token(
        &self,
        token: &str,
        request: &AgentTokenRevokeRequest,
    ) -> ApiResult<()> {
        let response = self
            .http
            .delete(
                self.url(path::AEGIS_AGENT_TOKEN)
                    .map_err(ApiClientError::Transport)?,
            )
            .bearer_auth(token)
            .json(request)
            .send()
            .map_err(|error| transport_error(error, "failed to revoke agent token"))?;
        parse_empty_response(response)
    }

    pub fn exchange_agent_refresh_token(
        &self,
        refresh_token: &str,
        now: i64,
    ) -> ApiResult<AgentAccessState> {
        let response = self
            .http
            .post(
                self.url(path::AEGIS_AGENT_TOKEN)
                    .map_err(ApiClientError::Transport)?,
            )
            .json(&AgentTokenRequest {
                grant_type: oauth::GRANT_TYPE_REFRESH_TOKEN.to_string(),
                refresh_token: refresh_token.to_string(),
            })
            .timeout(self.operation_request_timeout()?)
            .send()
            .map_err(|error| transport_error(error, "failed to exchange agent refresh token"))?;
        let response: AgentTokenResponse = parse_json_response(response)?;
        Ok(AgentAccessState {
            access_token: response.access_token,
            host_id: response.host_id,
            credential_kind: response.credential_kind,
            refresh_token: response.refresh_token,
            access_expires_at_unix: now.saturating_add(response.expires_in as i64),
        })
    }

    fn url(&self, path: &str) -> Result<String> {
        let joined = format!("{}{}", self.base_url, path);
        Url::parse(&joined)
            .with_context(|| format!("invalid api url constructed from {joined}"))?;
        Ok(joined)
    }
}

pub struct AuthenticatedApiClient {
    api: ApiClient,
    access_token: String,
    claims: AccessClaims,
    stored_auth_state: Option<Box<UserAuthState>>,
}

pub struct HostAgentApiClient {
    api: ApiClient,
    access_token: String,
    access_expires_at_unix: i64,
    refresh_token: String,
    host_id: HostId,
    credential_kind: AegisCredentialKind,
}

impl AuthenticatedApiClient {
    pub fn load(api_base_override: Option<&str>) -> Result<Self> {
        let _auth_lock = crate::locks::user_auth_lock()?;
        let installed_agent_api_base = installed_agent_api_base()?;
        let api_base = crate::config::namespace_endpoint(&resolve_api_base(
            api_base_override,
            installed_agent_api_base.as_deref(),
        )?)?
        .base_url();
        let mut auth_state = load_user_auth_state()?.ok_or_else(|| {
            anyhow!(
                "aegis user auth is missing; run `aegis manage login` with an authorized user principal"
            )
        })?;
        validate_auth_endpoint(&api_base, &auth_state)?;
        let now = now_unix();
        if auth_state.access_needs_refresh(now, ACCESS_TOKEN_REFRESH_SKEW_SECONDS) {
            auth_state = refresh_auth_state(&api_base, &auth_state, now)?;
            persist_user_auth_state(&auth_state)?;
        }
        Self::from_stored_auth_state(api_base, auth_state)
    }

    pub fn from_access_token(api_base: impl Into<String>, access_token: String) -> Result<Self> {
        let api = ApiClient::new(api_base)?;
        let claims = decode_unverified_claims::<AccessClaims>(&access_token)
            .context("failed to inspect access token")?;
        Ok(Self {
            api,
            access_token,
            claims,
            stored_auth_state: None,
        })
    }

    fn from_stored_auth_state(
        api_base: impl Into<String>,
        auth_state: UserAuthState,
    ) -> Result<Self> {
        validate_user_auth_state(&auth_state)?;
        let mut client = Self::from_access_token(api_base, auth_state.access_token.clone())?;
        client.stored_auth_state = Some(Box::new(auth_state));
        Ok(client)
    }

    pub fn claims(&mut self) -> Result<AccessClaims> {
        Ok(self.claims.clone())
    }

    pub fn issue_agent_token(&mut self, host_id: &HostId) -> Result<String> {
        Ok(self.issue_agent_token_response(host_id)?.refresh_token)
    }

    pub fn issue_agent_token_response(
        &mut self,
        host_id: &HostId,
    ) -> Result<AgentTokenIssueResponse> {
        self.call_authenticated(|api, token| api.issue_agent_token(token, host_id))
    }

    pub fn revoke_agent_token(&mut self, refresh_token: &str) -> Result<()> {
        self.call_authenticated(|api, token| {
            api.revoke_agent_token(
                token,
                &AgentTokenRevokeRequest {
                    refresh_token: refresh_token.to_string(),
                },
            )
        })
    }

    pub fn require_user_admin(&mut self, context: &str) -> Result<()> {
        let membership = self.call_authenticated(ApiClient::get_namespace_context)?;
        if membership.role != aegis_dto::NamespaceRole::Admin {
            bail!("namespace administrator required for `{context}`");
        }
        Ok(())
    }

    pub fn namespace_context(&mut self) -> Result<aegis_dto::namespace::NamespaceContext> {
        self.call_authenticated(ApiClient::get_namespace_context)
    }

    pub fn api_base(&self) -> &str {
        &self.api.base_url
    }

    pub(crate) fn user_access_token(&mut self, force_refresh: bool) -> Result<String> {
        self.refresh_stored_access(force_refresh)?;
        Ok(self.access_token.clone())
    }

    pub fn get_hosts(&mut self) -> Result<AegisHostListResponse> {
        self.call_authenticated(|api, token| api.get_hosts(token))
    }

    pub fn create_enrollment(
        &mut self,
        request: &AegisEnrollmentCreateRequest,
    ) -> Result<AegisEnrollment> {
        self.call_authenticated(|api, token| api.create_enrollment(token, request))
    }

    pub fn get_enrollments(&mut self) -> Result<AegisEnrollmentListResponse> {
        self.call_authenticated(ApiClient::get_enrollments)
    }

    pub fn get_enrollment(&mut self, host_id: &HostId) -> Result<AegisEnrollment> {
        self.call_authenticated(|api, token| api.get_enrollment(token, host_id))
    }

    pub fn issue_enrollment_credential(
        &mut self,
        host_id: &HostId,
    ) -> Result<AegisEnrollmentCredentialResponse> {
        self.call_authenticated(|api, token| api.issue_enrollment_credential(token, host_id))
    }

    pub fn delete_enrollment(&mut self, host_id: &HostId) -> Result<()> {
        self.call_authenticated(|api, token| api.delete_enrollment(token, host_id))
    }

    pub fn get_alias(&mut self, alias: &HostAlias) -> Result<AegisAliasResponse> {
        self.call_authenticated(|api, token| api.get_alias(token, alias))
    }

    pub fn resolve_host_id(&mut self, host: &str) -> Result<HostId> {
        if let Ok(host_id) = host.parse::<HostId>() {
            return Ok(host_id);
        }
        let alias = HostAlias::parse(host.to_string())?;
        Ok(self.get_alias(&alias)?.host_id)
    }

    pub fn add_host_alias(&mut self, host_id: &HostId, alias: &HostAlias) -> Result<AegisHost> {
        self.call_authenticated(|api, token| api.add_host_alias(token, host_id, alias))
    }

    pub fn promote_host_alias(&mut self, host_id: &HostId, alias: &HostAlias) -> Result<AegisHost> {
        self.call_authenticated(|api, token| api.promote_host_alias(token, host_id, alias))
    }

    pub fn remove_host_alias(&mut self, host_id: &HostId, alias: &HostAlias) -> Result<AegisHost> {
        self.call_authenticated(|api, token| api.remove_host_alias(token, host_id, alias))
    }

    pub fn get_networks(&mut self) -> Result<AegisNetworkListResponse> {
        self.call_authenticated(|api, token| api.get_networks(token))
    }

    pub fn get_network_members(&mut self, network: &str) -> Result<AegisNetworkMemberListResponse> {
        self.call_authenticated(|api, token| api.get_network_members(token, network))
    }

    pub fn sync_dns(&mut self, request: &AegisDnsSyncRequest) -> Result<AegisDnsSyncResponse> {
        self.call_authenticated(|api, token| api.sync_dns(token, request))
    }

    pub fn sync_tls(&mut self, request: &AegisTlsSyncRequest) -> Result<AegisTlsSyncResponse> {
        self.call_authenticated(|api, token| api.sync_tls(token, request))
    }

    pub fn request_network_member_client_cert(
        &mut self,
        network: &str,
        host_id: &HostId,
        ed25519_public_key: &str,
    ) -> Result<SshIssueCertResponse> {
        self.call_authenticated(|api, token| {
            api.request_network_member_client_cert(token, network, host_id, ed25519_public_key)
        })
    }

    pub fn put_satellite(
        &mut self,
        slug: &str,
        request: &AegisSatelliteCreateRequest,
    ) -> Result<AegisSatelliteProvisionResponse> {
        self.call_authenticated(|api, token| api.put_satellite(token, slug, request))
    }

    pub fn get_satellites(&mut self) -> Result<AegisSatelliteListResponse> {
        self.call_authenticated(ApiClient::get_satellites)
    }

    pub fn get_satellite(&mut self, slug: &str) -> Result<AegisSatelliteDetailsResponse> {
        self.call_authenticated(|api, token| api.get_satellite(token, slug))
    }

    pub fn delete_satellite(&mut self, slug: &str) -> Result<()> {
        self.call_authenticated(|api, token| api.delete_satellite(token, slug))
    }

    pub fn request_network_member_server_cert(
        &mut self,
        network: &str,
        host_id: &HostId,
    ) -> Result<SshIssueCertResponse> {
        self.call_authenticated(|api, token| {
            api.request_network_member_server_cert(token, network, host_id)
        })
    }

    pub fn delete_host(&mut self, host_id: &HostId) -> Result<()> {
        self.call_authenticated(|api, token| api.delete_host(token, host_id))
    }

    pub fn get_server_ca_public_key(&self) -> Result<SshCaPublicKeyResponse> {
        self.api.get_server_ca_public_key().map_err(Into::into)
    }

    pub fn get_client_ca_public_key(&self) -> Result<SshCaPublicKeyResponse> {
        self.api.get_client_ca_public_key().map_err(Into::into)
    }

    fn call_authenticated<T, F>(&mut self, operation: F) -> Result<T>
    where
        F: Fn(&ApiClient, &str) -> ApiResult<T>,
    {
        self.refresh_stored_access(false)?;
        match operation(&self.api, &self.access_token) {
            Err(error) if error.is_unauthorized() => {
                if !self.refresh_stored_access(true)? {
                    return Err(error.into());
                }
                operation(&self.api, &self.access_token).map_err(Into::into)
            }
            result => result.map_err(Into::into),
        }
    }

    fn refresh_stored_access(&mut self, force: bool) -> Result<bool> {
        let Some(current) = self.stored_auth_state.as_ref() else {
            return Ok(false);
        };
        let now = now_unix();
        if !force && !current.access_needs_refresh(now, ACCESS_TOKEN_REFRESH_SKEW_SECONDS) {
            return Ok(false);
        }

        let current_access_token = current.access_token.clone();
        let _auth_lock = crate::locks::user_auth_lock()?;
        let disk_state = load_user_auth_state()?.ok_or_else(|| {
            anyhow!(
                "aegis user auth disappeared while this command was running; run `aegis manage login` again"
            )
        })?;
        let (next_state, persist) =
            self.resolve_stored_access(&current_access_token, disk_state, now)?;
        if persist {
            persist_user_auth_state(&next_state)?;
        }
        self.install_stored_access(next_state)?;
        Ok(true)
    }

    fn resolve_stored_access(
        &self,
        current_access_token: &str,
        disk_state: UserAuthState,
        now: i64,
    ) -> Result<(UserAuthState, bool)> {
        if disk_state.access_token != current_access_token
            && !disk_state.access_needs_refresh(now, ACCESS_TOKEN_REFRESH_SKEW_SECONDS)
        {
            return Ok((disk_state, false));
        }
        let refreshed = refresh_auth_state(&self.api.base_url, &disk_state, now)
            .context("failed to renew Aegis OAuth access while this command was running")?;
        Ok((refreshed, true))
    }

    fn install_stored_access(&mut self, next_state: UserAuthState) -> Result<()> {
        validate_user_auth_state(&next_state)?;
        let claims = decode_unverified_claims::<AccessClaims>(&next_state.access_token)
            .context("failed to inspect renewed access token")?;
        self.access_token = next_state.access_token.clone();
        self.claims = claims;
        self.stored_auth_state = Some(Box::new(next_state));
        Ok(())
    }
}

impl HostAgentApiClient {
    pub fn from_refresh_token(api_base: impl Into<String>, refresh_token: &str) -> Result<Self> {
        let api = ApiClient::new(api_base)?;
        let access = api.exchange_agent_refresh_token(refresh_token, now_unix())?;
        Ok(Self {
            api,
            access_token: access.access_token,
            access_expires_at_unix: access.access_expires_at_unix,
            refresh_token: access.refresh_token,
            host_id: access.host_id,
            credential_kind: access.credential_kind,
        })
    }

    pub fn host_id(&self) -> HostId {
        self.host_id
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub fn credential_kind(&self) -> AegisCredentialKind {
        self.credential_kind
    }

    pub fn get_enrollment(&mut self) -> Result<AegisEnrollment> {
        self.require_enrollment_credential("load enrollment intent")?;
        let host_id = self.host_id;
        self.call_authenticated(|api, token| api.get_enrollment(token, &host_id))
    }

    pub fn prepare_enrollment(
        &mut self,
        request: &AegisEnrollmentPrepareRequest,
    ) -> Result<AegisEnrollmentPrepareResponse> {
        self.require_enrollment_credential("prepare a host")?;
        let host_id = self.host_id;
        self.call_authenticated(|api, token| api.prepare_enrollment(token, &host_id, request))
    }

    pub fn heartbeat_enrollment(
        &mut self,
        request: &AegisEnrollmentHeartbeatRequest,
    ) -> Result<AegisEnrollment> {
        self.require_enrollment_credential("update enrollment progress")?;
        let host_id = self.host_id;
        self.call_authenticated(|api, token| api.heartbeat_enrollment(token, &host_id, request))
    }

    pub fn activate_enrollment(&mut self) -> Result<AegisEnrollmentActivateResponse> {
        self.require_enrollment_credential("activate a host")?;
        let host_id = self.host_id;
        let response =
            self.call_authenticated(|api, token| api.activate_enrollment(token, &host_id))?;
        self.credential_kind = AegisCredentialKind::Agent;
        Ok(response)
    }

    fn require_enrollment_credential(&mut self, operation: &str) -> Result<()> {
        self.refresh_access_if_needed(false)?;
        if self.credential_kind != AegisCredentialKind::Enrollment {
            bail!("an enrollment credential is required to {operation}");
        }
        Ok(())
    }

    fn call_authenticated<T, F>(&mut self, operation: F) -> Result<T>
    where
        F: Fn(&ApiClient, &str) -> ApiResult<T>,
    {
        self.refresh_access_if_needed(false)?;
        match operation(&self.api, &self.access_token) {
            Err(ApiClientError::Status {
                status: StatusCode::UNAUTHORIZED,
                ..
            }) => {
                self.refresh_access_if_needed(true)?;
                operation(&self.api, &self.access_token).map_err(Into::into)
            }
            outcome => outcome.map_err(Into::into),
        }
    }

    fn refresh_access_if_needed(&mut self, force: bool) -> Result<()> {
        let now = now_unix();
        if !force
            && now.saturating_add(ACCESS_TOKEN_REFRESH_SKEW_SECONDS) < self.access_expires_at_unix
        {
            return Ok(());
        }
        let access = self
            .api
            .exchange_agent_refresh_token(&self.refresh_token, now)
            .context("failed to renew Aegis machine access while enrollment was running")?;
        if access.host_id != self.host_id {
            bail!(
                "renewed machine credential changed host identity from `{}` to `{}`",
                self.host_id,
                access.host_id
            );
        }
        self.access_token = access.access_token;
        self.access_expires_at_unix = access.access_expires_at_unix;
        self.refresh_token = access.refresh_token;
        self.credential_kind = access.credential_kind;
        Ok(())
    }
}

pub(crate) fn installed_agent_api_base() -> Result<Option<String>> {
    Ok(crate::config::AgentContext::load()?.map(|context| context.api_base))
}

pub(crate) fn uses_local_agent(api_base_override: Option<&str>) -> Result<bool> {
    let Some(installed) = installed_agent_api_base()? else {
        return Ok(false);
    };
    let selected = aegis_dto::namespace::ApiEndpoint::parse(&resolve_api_base(
        api_base_override,
        Some(&installed),
    )?)
    .map_err(anyhow::Error::msg)?;
    selected.require_namespace().map_err(anyhow::Error::msg)?;
    let installed =
        aegis_dto::namespace::ApiEndpoint::parse(&installed).map_err(anyhow::Error::msg)?;
    Ok(selected == installed)
}

pub fn start_browser_login(api_base: &str, redirect_uri: &Url) -> Result<BrowserLoginStart> {
    let auth_url = AuthUrl::new(format!(
        "{}{}",
        aegis_dto::namespace::ApiEndpoint::parse(api_base)
            .map_err(anyhow::Error::msg)?
            .service_url(),
        oauth::path::OAUTH_AUTHORIZE
    ))
    .context("invalid oauth authorization endpoint")?;
    let token_url = TokenUrl::new(format!(
        "{}{}",
        aegis_dto::namespace::ApiEndpoint::parse(api_base)
            .map_err(anyhow::Error::msg)?
            .service_url(),
        oauth::path::OAUTH_TOKEN
    ))
    .context("invalid oauth token endpoint")?;
    let oauth = AegisOauthClient::new(ClientId::new(AEGIS_TOOL_CLIENT_ID.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string()).context("invalid oauth redirect_uri")?,
        )
        .set_auth_type(AuthType::RequestBody);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let authorization_request = oauth
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);
    let (authorization_url, csrf_state) = authorization_request.url();

    Ok(BrowserLoginStart {
        authorization_url,
        state: csrf_state.secret().to_string(),
        pkce_verifier: pkce_verifier.secret().to_string(),
    })
}

pub fn finish_browser_login(
    api_base: &str,
    redirect_uri: &Url,
    code: &str,
    pkce_verifier: &str,
    now: i64,
) -> Result<UserAuthState> {
    let auth_url = AuthUrl::new(format!(
        "{}{}",
        aegis_dto::namespace::ApiEndpoint::parse(api_base)
            .map_err(anyhow::Error::msg)?
            .service_url(),
        oauth::path::OAUTH_AUTHORIZE
    ))
    .context("invalid oauth authorization endpoint")?;
    let token_url = TokenUrl::new(format!(
        "{}{}",
        aegis_dto::namespace::ApiEndpoint::parse(api_base)
            .map_err(anyhow::Error::msg)?
            .service_url(),
        oauth::path::OAUTH_TOKEN
    ))
    .context("invalid oauth token endpoint")?;
    let oauth = AegisOauthClient::new(ClientId::new(AEGIS_TOOL_CLIENT_ID.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string()).context("invalid oauth redirect_uri")?,
        )
        .set_auth_type(AuthType::RequestBody);

    let http = oauth_http_client()?;
    let response = oauth
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
        .request(&http)
        .context("failed to exchange oauth authorization code")?;
    auth_state_from_token_response(response, now)
}

fn auth_state_from_token_response(response: AegisTokenResponse, now: i64) -> Result<UserAuthState> {
    let access_expires_in = response
        .expires_in()
        .ok_or_else(|| anyhow!("oauth token response missing expires_in"))?;
    let refresh_token = response
        .refresh_token()
        .ok_or_else(|| anyhow!("oauth token response missing refresh_token"))?;
    let extra = response.extra_fields();
    let refresh_expires_in = extra
        .refresh_expires_in
        .ok_or_else(|| anyhow!("oauth token response missing refresh_expires_in"))?;
    let principal = extra
        .principal
        .as_deref()
        .ok_or_else(|| anyhow!("oauth token response missing principal"))?;
    let principal = crate::principal_grants::validate_user_id(principal)
        .context("oauth token response principal is not a stable aegis user ID")?;
    decode_unverified_claims::<AccessClaims>(response.access_token().secret())
        .context("failed to inspect oauth access token")?;

    Ok(UserAuthState {
        access_token: response.access_token().secret().to_string(),
        refresh_token: refresh_token.secret().to_string(),
        principal,
        access_expires_at_unix: now.saturating_add(access_expires_in.as_secs() as i64),
        refresh_expires_at_unix: now.saturating_add(refresh_expires_in as i64),
    })
}

fn validate_user_auth_state(auth_state: &UserAuthState) -> Result<()> {
    crate::principal_grants::validate_user_id(&auth_state.principal)
        .context("stored user principal is not a stable aegis user ID")?;
    Ok(())
}

pub(crate) fn exchange_refresh_token(
    api_base: &str,
    refresh_token: &str,
    now: i64,
) -> Result<UserAuthState> {
    let endpoint =
        aegis_dto::namespace::ApiEndpoint::parse(api_base).map_err(anyhow::Error::msg)?;
    let response = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!(
            "{}{}",
            endpoint.service_url(),
            aegis_dto::identity::USER_TOKEN_PATH
        ))
        .json(&serde_json::json!({"grant_type":"refresh_token", "refresh_token":refresh_token}))
        .send()
        .context("failed to exchange user credential")?
        .error_for_status()
        .context("user credential expired, revoked, or already imported")?
        .json()
        .context("invalid user token response")?;
    auth_state_from_token_response(response, now)
}

fn validate_auth_endpoint(api_base: &str, state: &UserAuthState) -> Result<()> {
    let endpoint =
        aegis_dto::namespace::ApiEndpoint::parse(api_base).map_err(anyhow::Error::msg)?;
    let claims = decode_unverified_claims::<AccessClaims>(&state.access_token)?;
    anyhow::ensure!(
        claims.iss == endpoint.service_url()
            && claims.sub.strip_kind("user") == Some(&state.principal),
        "Saved user session belongs to another deployment or account; sign in to the selected deployment first"
    );
    Ok(())
}

pub(crate) fn refresh_auth_state(
    api_base: &str,
    current: &UserAuthState,
    now: i64,
) -> Result<UserAuthState> {
    validate_auth_endpoint(api_base, current)?;
    if current.refresh_is_expired(now) {
        bail!("User session expired; run `aegis manage login` again");
    }
    exchange_refresh_token(api_base, &current.refresh_token, now)
}

fn oauth_http_client() -> Result<oauth2::reqwest::blocking::Client> {
    oauth2::reqwest::blocking::Client::builder()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .connect_timeout(OAUTH_CONNECT_TIMEOUT)
        .timeout(OAUTH_REQUEST_TIMEOUT)
        .build()
        .context("failed to build oauth http client")
}

fn transport_error(error: impl Into<anyhow::Error>, message: impl Into<String>) -> ApiClientError {
    ApiClientError::Transport(error.into().context(message.into()))
}

fn parse_json_response<T>(response: Response) -> ApiResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    if status.is_success() {
        return response
            .json::<T>()
            .map_err(|error| ApiClientError::Transport(error.into()));
    }

    Err(response_status_error(response))
}

fn parse_empty_response(response: Response) -> ApiResult<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    Err(response_status_error(response))
}

fn response_status_error(response: Response) -> ApiClientError {
    status_error(response.status(), response.text().unwrap_or_default())
}

fn status_error(status: StatusCode, text: String) -> ApiClientError {
    let message = serde_json::from_str::<ErrorResponse>(&text)
        .map(|payload| payload.error)
        .unwrap_or_else(|_| text.trim().to_string());
    ApiClientError::Status { status, message }
}

#[cfg(test)]
mod tests {
    use super::{
        AEGIS_ADMIN_SCOPE, AEGIS_TOOL_CLIENT_ID, AegisOAuthTokenExtraFields, ApiClient,
        AuthenticatedApiClient, auth_state_from_token_response, start_browser_login,
    };
    use crate::config::UserAuthState;
    use aegis_dto::{
        HostId, path,
        protocol::{
            AegisAgentHealth, AegisAgentStatus, AegisDirectGatewayReport, AegisHostReportRequest,
            AegisPrincipalGrant,
        },
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use oauth2::{StandardTokenResponse, basic::BasicTokenType};
    use phylax_core::{AccessClaims, ScopeSet, Subject};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use url::Url;

    type TestTokenResponse = StandardTokenResponse<AegisOAuthTokenExtraFields, BasicTokenType>;

    #[test]
    fn api_client_requires_a_namespace_before_connecting() {
        let error = ApiClient::new("https://api.example.test/v2")
            .err()
            .expect("an unscoped API client must fail");
        assert!(error.to_string().contains("select an Aegis namespace"));
        assert!(ApiClient::new("https://api.example.test/v2/namespaces/test").is_ok());
    }

    #[test]
    fn tls_issuance_keeps_auth_on_the_namespace_endpoint() {
        let (base, recorded, thread) = spawn_mock_server(2, |index, request| {
            assert_eq!(request.authorization.as_deref(), Some("Bearer host-token"));
            if index == 0 {
                assert_eq!(request.method, "PUT");
                assert_eq!(
                    request.path,
                    "/namespaces/test/aegis/tls/certs/web/public-key.pem"
                );
                assert_eq!(request.body, "public-key");
                MockResponse::empty(204)
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(
                    request.path,
                    "/namespaces/test/aegis/tls/certs/web/cert.pem"
                );
                MockResponse {
                    status: 200,
                    content_type: "application/x-pem-file",
                    body: "certificate".into(),
                }
            }
        });
        let api = ApiClient::new(base).unwrap();
        assert!(
            api.issue_tls_certificate("host-token", "../other", "public-key")
                .is_err()
        );
        assert_eq!(
            api.issue_tls_certificate("host-token", "web", "public-key")
                .unwrap(),
            "certificate"
        );
        thread.join().unwrap();
        assert_eq!(recorded.lock().unwrap().len(), 2);
    }

    #[test]
    fn administration_uses_current_namespace_membership() {
        for (token_admin, role, allowed) in [(true, "member", false), (false, "admin", true)] {
            let (base_url, recorded, handle) = spawn_mock_server(1, move |_, request| {
                assert_eq!("GET", request.method);
                assert_eq!("/namespaces/test/aegis/context", request.path);
                MockResponse::json(serde_json::json!({"namespace": "test", "role": role}))
            });
            let mut client = AuthenticatedApiClient::from_access_token(
                base_url,
                unsigned_user_access_token(token_admin),
            )
            .expect("user client should build");
            assert_eq!(allowed, client.require_user_admin("test operation").is_ok());
            handle.join().expect("mock server should complete");
            assert_eq!(1, recorded.lock().unwrap().len());
        }
    }

    fn unsigned_user_access_token(admin: bool) -> String {
        unsigned_user_access_token_with("test-jti", 2, admin)
    }

    fn unsigned_user_access_token_with(jti: &str, exp: i64, admin: bool) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"at+jwt"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&serde_json::json!({
                "iss": "https://api.example",
                "sub": "user:OpaqueUserID",
                "aud": ["api.example"],
                "exp": exp,
                "iat": 1,
                "jti": jti,
                "client_id": AEGIS_TOOL_CLIENT_ID,
                "scope": if admin {
                    "aegis:admin aegis:read aegis:user"
                } else {
                    "aegis:read aegis:user"
                },
            }))
            .expect("claims should serialize"),
        );
        format!("{header}.{claims}.sig")
    }

    fn user_access_claims(admin: bool) -> AccessClaims {
        AccessClaims {
            iss: "issuer".to_string(),
            sub: Subject::new("user:OpaqueUserID").expect("subject should build"),
            aud: vec!["api.example".to_string()],
            exp: i64::MAX,
            iat: 0,
            jti: "test-jti".to_string(),
            client_id: AEGIS_TOOL_CLIENT_ID.to_string(),
            scope: ScopeSet::new(
                ["aegis:read", "aegis:user"]
                    .into_iter()
                    .chain(admin.then_some(AEGIS_ADMIN_SCOPE)),
            )
            .expect("scopes should build"),
            sid: Some("test-session".to_string()),
            authorized_party: Some(AEGIS_TOOL_CLIENT_ID.to_string()),
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        cache_control: Option<String>,
        body: String,
    }

    #[derive(Clone, Debug)]
    struct MockResponse {
        status: u16,
        content_type: &'static str,
        body: String,
    }

    impl MockResponse {
        fn json(body: serde_json::Value) -> Self {
            Self {
                status: 200,
                content_type: "application/json",
                body: body.to_string(),
            }
        }

        fn empty(status: u16) -> Self {
            Self {
                status,
                content_type: "application/octet-stream",
                body: String::new(),
            }
        }
    }

    fn spawn_mock_server<F>(
        expected_requests: usize,
        responder: F,
    ) -> (
        String,
        Arc<Mutex<Vec<RecordedRequest>>>,
        thread::JoinHandle<()>,
    )
    where
        F: Fn(usize, &RecordedRequest) -> MockResponse + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let base_url = format!(
            "http://{}/namespaces/test",
            listener.local_addr().expect("local addr")
        );
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_thread = Arc::clone(&recorded);
        let handle = thread::spawn(move || {
            for index in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let request = read_request(&mut stream);
                recorded_for_thread
                    .lock()
                    .expect("requests lock")
                    .push(request.clone());
                let response = responder(index, &request);
                write_response(&mut stream, response);
            }
        });
        (base_url, recorded, handle)
    }

    fn read_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut buffer = Vec::new();
        let mut tmp = [0u8; 1024];
        let mut header_end = None;
        let mut content_length = 0usize;

        loop {
            let bytes_read = stream.read(&mut tmp).expect("request should read");
            if bytes_read == 0 {
                break;
            }
            buffer.extend_from_slice(&tmp[..bytes_read]);
            if header_end.is_none()
                && let Some(position) = find_subsequence(&buffer, b"\r\n\r\n")
            {
                header_end = Some(position + 4);
                let headers = String::from_utf8_lossy(&buffer[..position + 4]);
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(0);
            }
            if let Some(end) = header_end
                && buffer.len() >= end + content_length
            {
                break;
            }
        }

        let header_end = header_end.expect("request should contain headers");
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let body = String::from_utf8(buffer[header_end..].to_vec()).expect("UTF-8 request body");
        let mut lines = headers.lines();
        let request_line = lines.next().expect("request line should exist");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or_default().to_string();
        let path = request_parts.next().unwrap_or_default().to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim(), value.trim()))
            .collect::<Vec<_>>();
        let header = |expected: &str| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(expected))
                .map(|(_, value)| (*value).to_string())
        };

        RecordedRequest {
            method,
            path,
            authorization: header("authorization"),
            cache_control: header("cache-control"),
            body,
        }
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn write_response(stream: &mut TcpStream, response: MockResponse) {
        let reason = match response.status {
            200 => "OK",
            204 => "No Content",
            401 => "Unauthorized",
            other => panic!("unexpected mock status {other}"),
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status,
            reason,
            response.content_type,
            response.body.len(),
            response.body
        )
        .expect("response should write");
        stream.flush().expect("response should flush");
    }

    #[test]
    fn machine_token_exchange_allows_cloud_startup_latency() {
        let id: HostId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let (base, _, server) = spawn_mock_server(1, move |_, request| {
            assert_eq!(request.method, "POST");
            assert!(request.path.ends_with(path::AEGIS_AGENT_TOKEN));
            thread::sleep(Duration::from_secs(6));
            MockResponse::json(serde_json::json!({
                "access_token": "access",
                "refresh_token": "rotated",
                "token_type": "Bearer",
                "host_id": id,
                "credential_kind": "enrollment",
                "expires_in": 300,
                "refresh_expires_in": 3600,
            }))
        });
        let access = ApiClient::new(base)
            .unwrap()
            .exchange_agent_refresh_token("initial", 1000)
            .unwrap();
        server.join().unwrap();
        assert_eq!(access.host_id, id);
        assert_eq!(access.access_expires_at_unix, 1300);
        assert_eq!(access.refresh_token, "rotated");
    }

    #[test]
    fn auth_state_from_token_response_tracks_both_expiries() {
        let access_token = unsigned_user_access_token(false);
        let response: TestTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 300,
            "refresh_token": "refresh",
            "refresh_expires_in": 3600,
            "principal": "OpaqueUserID"
        }))
        .expect("token response should deserialize");
        let state =
            auth_state_from_token_response(response, 1_000).expect("auth state should build");

        assert_eq!(1_300, state.access_expires_at_unix);
        assert_eq!(4_600, state.refresh_expires_at_unix);
        assert_eq!("OpaqueUserID", state.principal);
    }

    #[test]
    fn auth_state_from_token_response_requires_refresh_metadata() {
        let response: TestTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "access",
            "token_type": "bearer",
            "expires_in": 300,
            "refresh_token": "refresh",
            "principal": "OpaqueUserID"
        }))
        .expect("token response should deserialize");

        let error = auth_state_from_token_response(response, 1_000)
            .expect_err("missing refresh metadata should fail");
        assert!(
            error.to_string().contains("refresh_expires_in"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn user_auth_rejects_email_principals() {
        let response: TestTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": unsigned_user_access_token(false),
            "token_type": "bearer",
            "expires_in": 300,
            "refresh_token": "refresh",
            "refresh_expires_in": 3_600,
            "principal": "user@example.com"
        }))
        .expect("token response should deserialize");
        auth_state_from_token_response(response, 1_000)
            .expect_err("email token principal must be rejected");

        assert!(
            AuthenticatedApiClient::from_stored_auth_state(
                "https://api.example.test/v2/namespaces/test",
                UserAuthState {
                    access_token: "unused".to_string(),
                    refresh_token: "refresh".to_string(),
                    principal: "user@example.com".to_string(),
                    access_expires_at_unix: 1_300,
                    refresh_expires_at_unix: 4_600,
                },
            )
            .is_err(),
            "stored email principal must be rejected"
        );
    }

    #[test]
    fn start_browser_login_builds_standard_authorize_url() {
        let redirect_uri = Url::parse("http://127.0.0.1:4567/callback").expect("url");
        let login = start_browser_login("https://api.example/v2", &redirect_uri)
            .expect("browser login should start");

        assert_eq!(
            format!(
                "https://api.example/v2{}",
                phylax_core::oauth::path::OAUTH_AUTHORIZE
            ),
            format!(
                "{}://{}{}",
                login.authorization_url.scheme(),
                login.authorization_url.host_str().expect("host"),
                login.authorization_url.path()
            )
        );
        let query = login
            .authorization_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(Some("code"), query.get("response_type").map(String::as_str));
        assert_eq!(
            Some(AEGIS_TOOL_CLIENT_ID),
            query.get("client_id").map(String::as_str)
        );
        assert_eq!(
            Some("http://127.0.0.1:4567/callback"),
            query.get("redirect_uri").map(String::as_str)
        );
        assert_eq!(
            Some("S256"),
            query.get("code_challenge_method").map(String::as_str)
        );
        assert!(!login.state.is_empty());
        assert!(!login.pkce_verifier.is_empty());
    }

    #[test]
    fn authenticated_static_client_sends_bearer_token() {
        let (base_url, recorded, handle) =
            spawn_mock_server(1, move |index, request| match index {
                0 => {
                    assert_eq!("GET", request.method);
                    assert_eq!(
                        format!("/namespaces/test{}", path::AEGIS_HOSTS),
                        request.path
                    );
                    assert_eq!(
                        Some("Bearer static-access"),
                        request.authorization.as_deref()
                    );
                    assert_eq!(Some("no-cache, no-store"), request.cache_control.as_deref());
                    MockResponse::json(serde_json::json!({
                        "hosts": {}
                    }))
                }
                _ => unreachable!("unexpected request"),
            });
        let mut client = AuthenticatedApiClient {
            api: ApiClient::new(base_url.clone()).expect("api client should build"),
            access_token: "static-access".to_string(),
            claims: user_access_claims(false),
            stored_auth_state: None,
        };

        let response = client.get_hosts().expect("hosts request should succeed");
        assert!(response.hosts.is_empty());
        handle.join().expect("server thread should finish");
        assert_eq!(1, recorded.lock().expect("requests lock").len());
    }

    #[test]
    fn host_reports_require_the_canonical_response() {
        let host_id: HostId = "00000000-0000-4000-8000-000000000001"
            .parse()
            .expect("host id should parse");
        let expected_path = format!("/namespaces/test{}", path::aegis_host_report(&host_id));
        let (base_url, recorded, handle) =
            spawn_mock_server(2, move |index, request| match index {
                0 => {
                    assert_eq!("PUT", request.method);
                    assert_eq!(expected_path, request.path);
                    MockResponse::empty(204)
                }
                1 => MockResponse::json(serde_json::json!({
                    "principal_grants": [{
                        "login_principal": "ubuntu",
                        "user_id": "OpaqueUserID"
                    }]
                })),
                _ => unreachable!("unexpected request"),
            });
        let api = ApiClient::new(base_url).expect("api client should build");
        let request = AegisHostReportRequest {
            messages: Vec::new(),
            agent: AegisAgentStatus {
                version: "1.2.3".to_string(),
                health: AegisAgentHealth {
                    boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
                    reconciled_since_boot: true,
                    applied_aliases: None,
                    last_reconcile_unix: None,
                    last_reconcile_warning: None,
                    last_reconcile_error: None,
                },
                reported_unix: 1,
            },
            principal_grants: Vec::new(),
            ssh_lockdown_enabled: true,
            direct_gateway: AegisDirectGatewayReport {
                observed_unix: 1,
                peers: Vec::new(),
            },
        };

        assert!(api.report_host("agent-token", &host_id, &request).is_err());
        assert_eq!(
            vec![AegisPrincipalGrant {
                login_principal: "ubuntu".to_string(),
                user_id: "OpaqueUserID".to_string(),
            }],
            api.report_host("agent-token", &host_id, &request)
                .expect("canonical response should succeed")
                .principal_grants
        );
        handle.join().expect("server thread should finish");
        assert_eq!(2, recorded.lock().expect("requests lock").len());
    }

    #[test]
    fn stored_access_renewal_exchanges_an_expiring_token() {
        let renewed_access = unsigned_user_access_token_with("renewed-jti", 1_300, false);
        let renewed_access_for_server = renewed_access.clone();
        let (base_url, recorded, handle) =
            spawn_mock_server(1, move |index, request| match index {
                0 => {
                    assert_eq!("POST", request.method);
                    assert_eq!(aegis_dto::identity::USER_TOKEN_PATH, request.path);
                    assert_eq!(None, request.authorization);
                    MockResponse::json(serde_json::json!({
                        "access_token": renewed_access_for_server,
                        "token_type": "bearer",
                        "expires_in": 300,
                        "refresh_token": "rotated-refresh",
                        "refresh_expires_in": 3_600,
                        "principal": "OpaqueUserID"
                    }))
                }
                _ => unreachable!("unexpected request"),
            });
        let expired_access = unsigned_user_access_token_with("expired-jti", 999, false);
        let mut claims =
            phylax_core::dangerous::decode_unverified_claims::<AccessClaims>(&expired_access)
                .unwrap();
        claims.iss = aegis_dto::namespace::ApiEndpoint::parse(&base_url)
            .unwrap()
            .service_url()
            .to_owned();
        let expired_access = format!(
            "{}.{}.sig",
            expired_access.split('.').next().unwrap(),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let expired_state = UserAuthState {
            access_token: expired_access.clone(),
            refresh_token: "initial-refresh".to_string(),
            principal: "OpaqueUserID".to_string(),
            access_expires_at_unix: 999,
            refresh_expires_at_unix: 10_000,
        };
        let mut client =
            AuthenticatedApiClient::from_stored_auth_state(base_url, expired_state.clone())
                .expect("stored client should build");

        let (next_state, persist) = client
            .resolve_stored_access(&expired_access, expired_state, 1_000)
            .expect("expiring access should renew");
        assert!(persist);
        assert_eq!(renewed_access, next_state.access_token);
        assert_eq!("rotated-refresh", next_state.refresh_token);
        assert_eq!(1_300, next_state.access_expires_at_unix);
        client
            .install_stored_access(next_state)
            .expect("renewed access should install");
        assert_eq!(renewed_access, client.access_token);

        handle.join().expect("server thread should finish");
        assert_eq!(1, recorded.lock().expect("requests lock").len());
    }
}
