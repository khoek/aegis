use crate::{
    aegis_store::{
        AegisAliasWriteError, AegisDirectGatewayRecord, AegisDirectWireGuardRecord,
        AegisDirectWriteError, AegisEgressWriteError, AegisEnrollmentPreparation,
        AegisEnrollmentPrepared, AegisEnrollmentRecord, AegisEnrollmentWriteError,
        AegisHostDeleteError, AegisHostRecord, AegisHostRecordSsh, AegisHostReportUpdate,
        AegisHostWriteError, AegisNetworkMemberRecord, AegisSatelliteBrokerUseRecord,
        AegisSatelliteRecord, AegisStore, AegisUserIdentity,
    },
    config::{AegisConfig, ClientCaConfig, DirectClientCaConfig, ServerCaConfig, TlsConfig},
    firestore::{AegisDb, fetch_tls_cert_config, put_tls_cert_public_key, sync_tls_cert_configs},
};
use aegis_dto::protocol::{
    AegisAgentReport, AegisAgentStatus, AegisAliasResponse, AegisDirectClientCertRequest,
    AegisDirectClientCertResponse, AegisDirectGateway, AegisDirectGatewayConfig,
    AegisDirectGatewayInventory, AegisDirectGatewayPublishRequest, AegisDirectGatewayReport,
    AegisDirectPeerObservation, AegisDirectSatellite, AegisDirectTarget,
    AegisDirectTargetListResponse, AegisDirectWireGuard, AegisDnsSyncRequest, AegisDnsSyncResponse,
    AegisEgressEnableRequest, AegisEgressHost, AegisEgressIdentityRequest, AegisEgressInventory,
    AegisEgressOutcome, AegisEgressPolicy, AegisEgressResult, AegisEgressStatus, AegisEnrollment,
    AegisEnrollmentActivateResponse, AegisEnrollmentCreateRequest,
    AegisEnrollmentCredentialResponse, AegisEnrollmentHeartbeatRequest,
    AegisEnrollmentListResponse, AegisEnrollmentPhase, AegisEnrollmentPrepareRequest,
    AegisEnrollmentPrepareResponse, AegisHost, AegisHostClientCertRequest, AegisHostEgress,
    AegisHostListResponse, AegisHostMessage, AegisHostReportResponse, AegisHostSsh,
    AegisNetworkConfig, AegisNetworkListResponse, AegisNetworkMember,
    AegisNetworkMemberListResponse, AegisNetworkMemberResponse, AegisNetworkMemberWireGuard,
    AegisNetworkResponse, AegisPrincipalGrant, AegisPutHostRequest, AegisPutNetworkMemberRequest,
    AegisSatellite, AegisSatelliteBrokerUse, AegisSatelliteCreateRequest,
    AegisSatelliteDetailsResponse, AegisSatelliteGatewayStatus, AegisSatelliteListResponse,
    AegisSatelliteProvisionResponse, AegisSatelliteStatus, AegisTlsSyncRequest,
    AegisTlsSyncResponse,
};
use aegis_dto::{
    AegisHostMode, DEFAULT_AEGIS_ENROLLMENT_TTL_SECONDS, HostAlias, HostAliases, HostId,
    normalize_wireguard_ipv4, normalize_wireguard_ipv6, normalize_wireguard_key,
    protocol::{
        AegisCredentialKind, AegisHostReportRequest, AgentTokenIssueResponse,
        AgentTokenRevokeRequest, SshCaPublicKeyResponse, SshIssueCertResponse,
        aegis_direct_account, aegis_direct_cert_principal, aegis_user_cert_principal,
    },
    wireguard_host_identity_from_addresses,
};
use anyhow::Context;
use arche_web::error::ApiError;
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use phylax_core::{
    AccessClaims, AccessTokenGrant, JsonRefreshTokenExchange, JsonRefreshTokenGrant,
    JsonRefreshTokenGrantRequest, JwtIssuer, RefreshTokenValidation, ScopeSet, Subject,
    random_urlsafe_string,
};
use phylax_gcp::{
    FirestoreAuthStore, RefreshSessionSubjectTransition, RefreshTokenGrantRequest,
    RefreshTokenIssueRequest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssh_key::{PublicKey, certificate, private::PrivateKey, rand_core::OsRng};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};
use time::{Duration, OffsetDateTime};

const USER_CERT_EXTENSIONS: &[(&str, &str)] = &[
    ("permit-X11-forwarding", ""),
    ("permit-agent-forwarding", ""),
    ("permit-port-forwarding", ""),
    ("permit-pty", ""),
    ("permit-user-rc", ""),
];
const SSH_CERT_VALID_AFTER_BACKDATE_SECONDS: i64 = 60;
const PRINCIPAL_CLIENT_CERT_TTL_SECONDS: i64 = 60;
const HOST_REPORT_MAX_SKEW_SECONDS: i64 = 300;
const MAX_AEGIS_ENROLLMENT_TTL_SECONDS: u64 = 12 * DEFAULT_AEGIS_ENROLLMENT_TTL_SECONDS;
const AGENT_CLIENT_ID: &str = "aegis-agent";
pub(crate) const AEGIS_TOOL_CLIENT_ID: &str = "aegis-tool";
pub(crate) const AEGIS_READ_SCOPE: &str = "aegis:read";
pub(crate) const AEGIS_USER_SCOPE: &str = "aegis:user";
#[cfg(test)]
pub(crate) const AEGIS_ADMIN_SCOPE: &str = "aegis:admin";
const AEGIS_HOST_SELF_SCOPE: &str = "aegis:host:self";
const AEGIS_ENROLL_SCOPE: &str = "aegis:enroll";
#[derive(Clone)]
pub struct AegisState<S = AegisDb> {
    pub store: S,
    pub(crate) auth: Arc<dyn CredentialSessionStore>,
    pub issuer: Arc<JwtIssuer>,
    pub client_ca: ClientCaConfig,
    pub client_ca_key: Arc<PrivateKey>,
    pub direct_client_ca_key: Arc<PrivateKey>,
    pub server_ca: ServerCaConfig,
    pub server_ca_key: Arc<PrivateKey>,
    pub tls: TlsConfig,
    pub api_issuer: String,
    pub api_audience: String,
    pub user_api_audience: String,
    pub namespace: aegis_dto::NamespaceId,
    pub cfg: AegisConfig,
}

pub fn router(state: AegisState, agent_token_grant: AegisAgentTokenGrant) -> axum::Router {
    use crate::path;
    use axum::{
        Router,
        routing::{delete, get, post, put},
    };
    Router::new()
        .route("/aegis/context", get(get_namespace_context))
        .route(path::AEGIS_NETWORKS, get(get_networks))
        .route(path::AEGIS_NETWORK, get(get_network))
        .route(path::AEGIS_NETWORK_MEMBERS, get(get_network_members))
        .route(
            path::AEGIS_NETWORK_MEMBER,
            get(get_network_member).put(put_network_member),
        )
        .route(
            path::AEGIS_NETWORK_MEMBER_CLIENT_CERT,
            post(post_network_member_client_cert),
        )
        .route(
            path::AEGIS_NETWORK_MEMBER_SERVER_CERT,
            post(post_network_member_server_cert),
        )
        .route(
            path::AEGIS_DIRECT_GATEWAY,
            put(put_direct_gateway).delete(delete_direct_gateway),
        )
        .route(
            path::AEGIS_DIRECT_GATEWAY_INVENTORY,
            get(get_direct_gateway_inventory),
        )
        .route(
            path::AEGIS_EGRESS,
            get(get_egress).put(put_egress).delete(delete_egress),
        )
        .route(path::AEGIS_EGRESS_INVENTORY, get(get_egress_inventory))
        .route(path::AEGIS_EGRESS_RESULT, post(post_egress_result))
        .route(path::AEGIS_SATELLITES, get(get_satellites))
        .route(
            path::AEGIS_SATELLITE,
            get(get_satellite)
                .put(put_satellite)
                .delete(delete_satellite),
        )
        .route(path::AEGIS_SATELLITE_TARGETS, get(get_satellite_targets))
        .route(
            path::AEGIS_SATELLITE_CLIENT_CERT,
            post(post_satellite_client_cert),
        )
        .route(path::AEGIS_HOST_REPORT, put(put_host_report))
        .route(path::AEGIS_DNS_SYNC, post(post_dns_sync))
        .route(path::AEGIS_HOSTS, get(get_hosts))
        .route(
            path::AEGIS_ENROLLMENTS,
            get(get_enrollments).post(post_enrollment),
        )
        .route(
            path::AEGIS_ENROLLMENT,
            get(get_enrollment).delete(delete_enrollment),
        )
        .route(
            path::AEGIS_ENROLLMENT_CREDENTIAL,
            post(post_enrollment_credential),
        )
        .route(
            path::AEGIS_ENROLLMENT_PREPARE,
            post(post_enrollment_prepare),
        )
        .route(
            path::AEGIS_ENROLLMENT_HEARTBEAT,
            post(post_enrollment_heartbeat),
        )
        .route(
            path::AEGIS_ENROLLMENT_ACTIVATE,
            post(post_enrollment_activate),
        )
        .route(
            path::AEGIS_HOST,
            get(get_host).put(put_host).delete(delete_host),
        )
        .route(
            path::AEGIS_HOST_ALIAS,
            put(put_host_alias).delete(delete_host_alias),
        )
        .route(
            path::AEGIS_HOST_ALIAS_PROMOTE,
            post(post_host_alias_promote),
        )
        .route(path::AEGIS_ALIAS, get(get_alias))
        .route(path::AEGIS_HOST_EGRESS, put(put_egress_identity))
        .route(path::AEGIS_HOST_AGENT_TOKEN, post(post_host_agent_token))
        .route(path::AEGIS_AGENT_TOKEN, delete(delete_agent_token))
        .route(path::AEGIS_USER_SSH_CA, get(get_client_ca_public_key))
        .route(path::AEGIS_HOST_SSH_CA, get(get_server_ca_public_key))
        .route(path::AEGIS_TLS_ROOT_CA, get(get_tls_root_ca_certificate))
        .route(path::AEGIS_TLS_SYNC, post(post_tls_sync))
        .route(
            path::AEGIS_TLS_ISSUING_CA,
            get(get_tls_issuing_ca_certificate),
        )
        .route(path::AEGIS_TLS_ISSUING_CRL, get(get_tls_issuing_crl))
        .route(path::AEGIS_TLS_CERT, get(get_tls_certificate))
        .route(
            path::AEGIS_TLS_CERT_PUBLIC_KEY,
            put(put_tls_certificate_public_key),
        )
        .with_state(state)
        .merge(phylax_core::json_refresh_token_router(
            path::AEGIS_AGENT_TOKEN,
            agent_token_grant,
        ))
}

pub(crate) struct AegisStateParts<'a, S> {
    pub store: S,
    pub auth: Arc<dyn CredentialSessionStore>,
    pub issuer: Arc<JwtIssuer>,
    pub client_ca: &'a ClientCaConfig,
    pub direct_client_ca: &'a DirectClientCaConfig,
    pub server_ca: &'a ServerCaConfig,
    pub tls: &'a TlsConfig,
    pub api_issuer: &'a str,
    pub api_audience: &'a str,
    pub user_api_audience: &'a str,
    pub namespace: aegis_dto::NamespaceId,
    pub cfg: &'a AegisConfig,
}

#[derive(Clone)]
pub struct AegisAgentTokenGrant {
    pub auth: FirestoreAuthStore,
    pub store: AegisDb,
    pub issuer: Arc<JwtIssuer>,
    pub api_audience: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AegisAgentTokenExtra {
    pub host_id: HostId,
    pub credential_kind: AegisCredentialKind,
}

#[async_trait::async_trait]
impl JsonRefreshTokenGrant for AegisAgentTokenGrant {
    type Extra = AegisAgentTokenExtra;

    fn issuer(&self) -> Arc<JwtIssuer> {
        self.issuer.clone()
    }

    async fn exchange_refresh_token(
        &self,
        request: JsonRefreshTokenGrantRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<JsonRefreshTokenExchange<Self::Extra>>> {
        let grant_request = RefreshTokenGrantRequest {
            refresh_token: request.refresh_token,
            client_id: AGENT_CLIENT_ID,
            now_unix: request.now_unix,
        };
        let inspection = match self.auth.inspect_refresh_token(grant_request).await? {
            RefreshTokenValidation::Valid(inspection) => inspection,
            RefreshTokenValidation::Invalid => return Ok(RefreshTokenValidation::Invalid),
        };
        let subject_host_id = aegis_enrollment_host_id_from_subject(&inspection.subject)
            .or_else(|_| aegis_host_id_from_subject(&inspection.subject));
        let Ok(host_id) = subject_host_id else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        if self
            .store
            .fetch_aegis_enrollment(&host_id)
            .await?
            .filter(|enrollment| {
                enrollment_matches_session(Some(enrollment), &inspection.sid, request.now_unix)
            })
            .is_some()
        {
            return Ok(RefreshTokenValidation::Valid(JsonRefreshTokenExchange {
                access_grant: AccessTokenGrant {
                    subject: inspection.subject,
                    client_id: AGENT_CLIENT_ID.to_string(),
                    audience: vec![self.api_audience.clone()],
                    scope: enrollment_access_scopes()?,
                    sid: Some(inspection.sid),
                    refresh_expires_unix: inspection.expires_unix,
                    extra: AegisAgentTokenExtra {
                        host_id,
                        credential_kind: AegisCredentialKind::Enrollment,
                    },
                },
                refresh_token: request.refresh_token.to_string(),
            }));
        }
        if aegis_host_id_from_subject(&inspection.subject).is_err()
            || !self
                .store
                .fetch_aegis_host(&host_id)
                .await?
                .is_some_and(|host| !host.pending)
        {
            return Ok(RefreshTokenValidation::Invalid);
        }
        let exchange = match self.auth.exchange_refresh_token(grant_request).await? {
            RefreshTokenValidation::Valid(exchange) => exchange,
            RefreshTokenValidation::Invalid => return Ok(RefreshTokenValidation::Invalid),
        };
        let Some(_) = self
            .store
            .fetch_aegis_host(&host_id)
            .await?
            .filter(|host| !host.pending)
        else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        Ok(RefreshTokenValidation::Valid(JsonRefreshTokenExchange {
            access_grant: AccessTokenGrant {
                subject: exchange.subject,
                client_id: AGENT_CLIENT_ID.to_string(),
                audience: vec![self.api_audience.clone()],
                scope: agent_access_scopes()?,
                sid: Some(exchange.sid),
                refresh_expires_unix: exchange.expires_unix,
                extra: AegisAgentTokenExtra {
                    host_id,
                    credential_kind: AegisCredentialKind::Agent,
                },
            },
            refresh_token: exchange.refresh_token,
        }))
    }
}

pub(crate) trait CredentialSessionStore: Send + Sync {
    fn issue_refresh_session<'a>(
        &'a self,
        request: RefreshTokenIssueRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<IssuedCredentialSession>> + Send + 'a>>;

    fn revoke_refresh_sessions<'a>(
        &'a self,
        subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<usize>> + Send + 'a>>;

    fn revoke_refresh_session<'a>(
        &'a self,
        session_id: &'a str,
        expected_subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;

    fn transition_refresh_session_subject<'a>(
        &'a self,
        session_id: &'a str,
        expected_subject: &'a Subject,
        next_subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RefreshSessionSubjectTransition>> + Send + 'a>>;

    fn revoke_refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}

pub(crate) struct IssuedCredentialSession {
    session_id: String,
    refresh_token: String,
}

impl CredentialSessionStore for FirestoreAuthStore {
    fn issue_refresh_session<'a>(
        &'a self,
        request: RefreshTokenIssueRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<IssuedCredentialSession>> + Send + 'a>> {
        Box::pin(async move {
            FirestoreAuthStore::issue_refresh_token(self, request)
                .await
                .map(|issued| IssuedCredentialSession {
                    session_id: issued.session_id().to_string(),
                    refresh_token: issued.refresh_token().to_string(),
                })
        })
    }

    fn revoke_refresh_sessions<'a>(
        &'a self,
        subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            self.revoke_refresh_sessions_for_subject(subject, AGENT_CLIENT_ID, now_unix)
                .await
        })
    }

    fn revoke_refresh_session<'a>(
        &'a self,
        session_id: &'a str,
        expected_subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            FirestoreAuthStore::revoke_refresh_session(
                self,
                session_id,
                expected_subject,
                AGENT_CLIENT_ID,
                now_unix,
            )
            .await
        })
    }

    fn transition_refresh_session_subject<'a>(
        &'a self,
        session_id: &'a str,
        expected_subject: &'a Subject,
        next_subject: &'a Subject,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RefreshSessionSubjectTransition>> + Send + 'a>>
    {
        Box::pin(async move {
            FirestoreAuthStore::transition_refresh_session_subject(
                self,
                session_id,
                expected_subject,
                next_subject,
                AGENT_CLIENT_ID,
                now_unix,
            )
            .await
        })
    }

    fn revoke_refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
        now_unix: i64,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.revoke_oauth_refresh_token_value(refresh_token, now_unix)
                .await
        })
    }
}

#[cfg(test)]
mod tests_refactor {
    use aegis_dto::protocol::{
        AegisAgentHealth, AegisAgentStatus, AegisDirectClientCertRequest,
        AegisDirectClientCertResponse, AegisDirectGatewayConfig, AegisDirectGatewayInventory,
        AegisDirectGatewayPublishRequest, AegisDirectGatewayReport, AegisDirectPeerObservation,
        AegisDirectTargetListResponse, AegisEgressConfig, AegisEgressEnableRequest,
        AegisEgressInventory, AegisEgressOutcome, AegisEgressPolicy, AegisEgressResult,
        AegisEgressStatus, AegisHost, AegisHostClientCertRequest, AegisHostListResponse,
        AegisHostMessage, AegisHostMessageLevel, AegisHostReportResponse, AegisNetworkConfig,
        AegisNetworkWireGuardConfig, AegisObservedPublicIps, AegisPrincipalGrant,
        AegisPutHostRequest, AegisPutHostSsh, AegisSatelliteCreateRequest,
        AegisSatelliteProvisionResponse,
    };

    use super::{
        AEGIS_ADMIN_SCOPE, AEGIS_READ_SCOPE, AEGIS_TOOL_CLIENT_ID, AEGIS_USER_SCOPE,
        AGENT_CLIENT_ID, AegisState, AegisStateParts, PRINCIPAL_CLIENT_CERT_TTL_SECONDS,
        agent_access_scopes, delete_agent_token, delete_direct_gateway, delete_egress,
        delete_enrollment, delete_host, delete_host_alias, delete_satellite, get_alias,
        get_client_ca_public_key, get_direct_gateway_inventory, get_egress, get_egress_inventory,
        get_enrollment, get_enrollments, get_host, get_hosts, get_network, get_network_member,
        get_network_members, get_networks, get_satellite, get_satellite_targets, get_satellites,
        get_server_ca_public_key, get_tls_root_ca_certificate, post_dns_sync, post_egress_result,
        post_enrollment, post_enrollment_activate, post_enrollment_credential,
        post_enrollment_heartbeat, post_enrollment_prepare, post_host_agent_token,
        post_host_alias_promote, post_network_member_client_cert, post_network_member_server_cert,
        post_satellite_client_cert, put_direct_gateway, put_egress, put_egress_identity, put_host,
        put_host_alias, put_host_report, put_network_member, put_satellite, satellite_status,
    };
    use crate::{
        aegis_store::{
            AegisAliasWriteError, AegisDirectGatewayRecord, AegisDirectWireGuardRecord,
            AegisDirectWriteError, AegisEgressSnapshot, AegisEgressWriteError,
            AegisEnrollmentPreparation, AegisEnrollmentPrepared, AegisEnrollmentRecord,
            AegisEnrollmentWriteError, AegisHostDeleteError, AegisHostRecord, AegisHostRecordSsh,
            AegisHostReportUpdate, AegisHostWriteError, AegisNetworkMemberRecord,
            AegisSatelliteBrokerUseRecord, AegisSatelliteRecord, AegisStore, AegisUserIdentity,
            enrollment_phase_rank, prepared_host_matches_enrollment, validate_current_enrollment,
        },
        config::{
            AegisConfig, ClientCaConfig, DirectClientCaConfig, ServerCaConfig, TlsCaConfig,
            TlsConfig,
        },
        path,
    };
    use aegis_dto::{
        AegisHostMode, HostAlias, HostAliases, HostId,
        protocol::{
            AegisAliasResponse, AegisEnrollment, AegisEnrollmentActivateResponse,
            AegisEnrollmentCreateRequest, AegisEnrollmentCredentialResponse,
            AegisEnrollmentHeartbeatRequest, AegisEnrollmentPhase, AegisEnrollmentPrepareRequest,
            AegisEnrollmentPrepareResponse, AegisEnrollmentSsh, AegisHostReportRequest,
            AegisMeshConfig, AegisWireGuardAddressPool, AgentTokenIssueResponse,
            AgentTokenRevokeRequest, ErrorResponse, SshCaPublicKeyResponse, SshIssueCertResponse,
            aegis_direct_cert_principal, aegis_user_cert_principal,
        },
    };
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{
            HeaderMap, HeaderValue, Method, Request, StatusCode,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
        routing::{delete, get, post, put},
    };
    use phylax_core::{JwtConfig, JwtIssuer, ScopeSet, Subject, backend::RefreshTokenCodec};
    use phylax_gcp::{RefreshSessionSubjectTransition, RefreshTokenIssueRequest};
    use ssh_key::{Certificate, PublicKey, certificate::CertType};
    use std::{
        collections::BTreeMap,
        future::Future,
        net::IpAddr,
        pin::Pin,
        sync::{Arc, Mutex},
    };
    use time::OffsetDateTime;
    use tower::ServiceExt;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct IssuedHostRefreshSession {
        sid: String,
        host_id: HostId,
        subject: Subject,
        family_id: String,
        token_id: String,
    }

    #[derive(Clone)]
    struct MemoryHostRefreshIssuer {
        issued: Arc<Mutex<Vec<IssuedHostRefreshSession>>>,
        host_refresh_tokens: RefreshTokenCodec,
    }

    impl Default for MemoryHostRefreshIssuer {
        fn default() -> Self {
            Self {
                issued: Arc::default(),
                host_refresh_tokens: RefreshTokenCodec::new(
                    "hrt",
                    "test-refresh-pepper",
                    2_592_000,
                )
                .expect("test refresh token codec should be valid"),
            }
        }
    }

    const TEST_CLIENT_CA_PRIVATE_KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAD9ZfkCf08dQAi3KEyjffstt6BznuDNG3DaApOXW6q3wAAAJjsNedh7DXn\nYQAAAAtzc2gtZWQyNTUxOQAAACAD9ZfkCf08dQAi3KEyjffstt6BznuDNG3DaApOXW6q3w\nAAAEDM5hn1CmwqsS5zHa5Vh5SB0TV1Um4aYf1+2EkFCztNvQP1l+QJ/Tx1ACLcoTKN9+y2\n3oHOe4M0bcNoCk5dbqrfAAAAEmtob2VrQHNhYnJldG9wLXVidQECAw==\n-----END OPENSSH PRIVATE KEY-----\n";
    const TEST_SERVER_CA_PRIVATE_KEY_PEM: &str = TEST_CLIENT_CA_PRIVATE_KEY_PEM;
    const TEST_USER_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAP1l+QJ/Tx1ACLcoTKN9+y23oHOe4M0bcNoCk5dbqrf user@test";
    const TEST_GATEWAY_WIREGUARD_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TEST_DIRECT_PEER_WIREGUARD_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const TEST_THIRD_WIREGUARD_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const TEST_ISSUER_URL: &str = "https://issuer.example";
    const TEST_JWT_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJrDacL3YbnqbSgqln/U3xQDJecnkbomYj2epYq1kOrs\n-----END PRIVATE KEY-----\n";
    const TEST_JWT_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAKs4Q7xlLOlFhkhFnJixaYKFlK0AK1R6pMizMX68Ujcw=\n-----END PUBLIC KEY-----\n";
    const TEST_API_AUDIENCE: &str = "api.example";

    fn host_id(seed: &str) -> HostId {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        format!(
            "00000000-0000-4000-8000-{:012x}",
            hasher.finish() & 0x0000_ffff_ffff_ffff
        )
        .parse()
        .expect("test host id should parse")
    }

    fn aliases(primary: &str) -> HostAliases {
        HostAliases::new(vec![primary.parse().expect("test host alias should parse")])
            .expect("test aliases should be valid")
    }

    #[derive(Clone)]
    struct MemoryStore {
        egress: Arc<Mutex<MemoryEgressState>>,
        direct_gateways: Arc<Mutex<BTreeMap<HostId, AegisDirectGatewayRecord>>>,
        satellites: Arc<Mutex<BTreeMap<String, AegisSatelliteRecord>>>,
        hosts: Arc<Mutex<BTreeMap<HostId, AegisHostRecord>>>,
        enrollments: Arc<Mutex<BTreeMap<HostId, AegisEnrollmentRecord>>>,
        aliases: Arc<Mutex<BTreeMap<HostAlias, HostId>>>,
        network_members: Arc<Mutex<BTreeMap<String, BTreeMap<HostId, AegisNetworkMemberRecord>>>>,
        users: Arc<Mutex<BTreeMap<String, AegisUserIdentity>>>,
    }

    impl Default for MemoryStore {
        fn default() -> Self {
            Self {
                egress: Arc::default(),
                direct_gateways: Arc::default(),
                satellites: Arc::default(),
                hosts: Arc::default(),
                enrollments: Arc::default(),
                aliases: Arc::default(),
                network_members: Arc::default(),
                users: Arc::new(Mutex::new(BTreeMap::from([(
                    "user-1".to_string(),
                    AegisUserIdentity {
                        user_id: "user-1".to_string(),
                        disabled: false,
                        admin: true,
                    },
                )]))),
            }
        }
    }

    #[derive(Default)]
    struct MemoryEgressState {
        generation: u64,
        policies: BTreeMap<HostId, AegisEgressPolicy>,
    }

    impl MemoryStore {
        fn with_hosts(hosts: Vec<AegisHostRecord>) -> Self {
            let mut entries = BTreeMap::new();
            let mut alias_entries = BTreeMap::new();
            for host in hosts {
                for alias in &host.aliases {
                    alias_entries.insert(alias.clone(), host.host_id);
                }
                entries.insert(host.host_id, host);
            }
            Self {
                hosts: Arc::new(Mutex::new(entries)),
                aliases: Arc::new(Mutex::new(alias_entries)),
                ..Self::default()
            }
        }

        fn add_user(&self, user_id: &str) {
            self.users.lock().expect("lock").insert(
                user_id.to_string(),
                AegisUserIdentity {
                    user_id: user_id.to_string(),
                    disabled: false,
                    admin: false,
                },
            );
        }

        fn set_user_disabled(&self, user_id: &str, disabled: bool) {
            self.users
                .lock()
                .expect("lock")
                .get_mut(user_id)
                .expect("user should exist")
                .disabled = disabled;
        }

        fn allocate_direct_wireguard(
            &self,
            wireguard: &AegisDirectWireGuardRecord,
            pool: &AegisWireGuardAddressPool,
        ) -> Result<AegisDirectWireGuardRecord, AegisDirectWriteError> {
            let satellites = self.satellites.lock().expect("lock");
            if let Some(existing) = satellites
                .values()
                .find(|existing| existing.wireguard.public_key == wireguard.public_key)
            {
                return Err(AegisDirectWriteError::DuplicatePublicKey {
                    resource: existing.slug.clone(),
                });
            }
            let reserved_ipv4 = aegis_dto::wireguard_ipv4_for_host_id(pool, 1)
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            let reserved_ipv6 = aegis_dto::wireguard_ipv6_for_host_id(pool, 1)
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            let mut used = vec![(reserved_ipv4.as_str(), reserved_ipv6.as_str())];
            used.extend(satellites.values().map(|satellite| {
                (
                    satellite.wireguard.ipv4.as_str(),
                    satellite.wireguard.ipv6.as_str(),
                )
            }));
            let host_id = aegis_dto::allocate_lowest_free_wireguard_host_id(pool, used)
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            drop(satellites);
            let mut stored = wireguard.clone();
            stored.ipv4 = aegis_dto::wireguard_ipv4_for_host_id(pool, host_id)
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            stored.ipv6 = aegis_dto::wireguard_ipv6_for_host_id(pool, host_id)
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            Ok(stored)
        }

        fn write_host(
            &self,
            host: &AegisHostRecord,
        ) -> Result<AegisHostRecord, AegisHostWriteError> {
            let mut egress = self.egress.lock().expect("lock");
            let next_generation = egress.generation.checked_add(1).ok_or_else(|| {
                AegisHostWriteError::Internal(anyhow::anyhow!(
                    "egress topology generation is exhausted"
                ))
            })?;
            let mut stored = host.clone();
            if let Some(existing) = self.hosts.lock().expect("lock").get(&host.host_id) {
                stored.created_unix = existing.created_unix;
            }
            self.hosts
                .lock()
                .expect("lock")
                .insert(stored.host_id, stored.clone());
            for alias in &stored.aliases {
                self.aliases
                    .lock()
                    .expect("lock")
                    .insert(alias.clone(), stored.host_id);
            }
            egress.generation = next_generation;
            Ok(stored)
        }

        fn write_network_member(
            &self,
            network: &str,
            member: &AegisNetworkMemberRecord,
            config: &AegisNetworkConfig,
        ) -> Result<AegisNetworkMemberRecord, AegisHostWriteError> {
            let mut egress = self.egress.lock().expect("lock");
            let next_generation = egress.generation.checked_add(1).ok_or_else(|| {
                AegisHostWriteError::Internal(anyhow::anyhow!(
                    "egress topology generation is exhausted"
                ))
            })?;
            let network_members = self.network_members.lock().expect("lock");
            let members = network_members.get(network);
            let existing = members
                .and_then(|members| members.get(&member.host_id))
                .cloned();
            let peers = members
                .into_iter()
                .flat_map(|members| members.values().cloned())
                .collect::<Vec<_>>();
            drop(network_members);

            let mut stored = member.clone();
            if let Some(existing) = &existing {
                stored.created_unix = existing.created_unix;
            }
            let wireguard_pool = config.wireguard.address_pool();
            crate::firestore::maybe_allocate_wireguard_identity(
                &mut stored,
                existing.as_ref(),
                &peers,
                &wireguard_pool,
            )?;
            if let Some(mesh) = config.mesh.as_ref() {
                crate::firestore::maybe_allocate_internal_addresses(
                    &mut stored,
                    existing.as_ref(),
                    &peers,
                    mesh,
                )?;
            } else {
                stored.internal_ipv4 = None;
                stored.internal_ipv6 = None;
            }
            self.network_members
                .lock()
                .expect("lock")
                .entry(network.to_string())
                .or_default()
                .insert(stored.host_id, stored.clone());
            egress.generation = next_generation;
            Ok(stored)
        }
    }

    #[async_trait::async_trait]
    impl AegisStore for MemoryStore {
        async fn user_session_active(
            &self,
            claims: &phylax_core::AccessClaims,
            _: i64,
        ) -> anyhow::Result<bool> {
            Ok(claims.sid.as_deref() == Some("test-user-session"))
        }

        async fn fetch_aegis_user_by_id(
            &self,
            user_id: &str,
        ) -> anyhow::Result<Option<AegisUserIdentity>> {
            Ok(self.users.lock().expect("lock").get(user_id).cloned())
        }

        async fn list_aegis_enrollments(&self) -> anyhow::Result<Vec<AegisEnrollmentRecord>> {
            Ok(self
                .enrollments
                .lock()
                .expect("lock")
                .values()
                .cloned()
                .collect())
        }

        async fn fetch_aegis_enrollment(
            &self,
            host_id: &HostId,
        ) -> anyhow::Result<Option<AegisEnrollmentRecord>> {
            Ok(self.enrollments.lock().expect("lock").get(host_id).cloned())
        }

        async fn create_aegis_enrollment(
            &self,
            enrollment: &AegisEnrollmentRecord,
        ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
            if self
                .hosts
                .lock()
                .expect("lock")
                .contains_key(&enrollment.host_id)
            {
                return Err(AegisEnrollmentWriteError::HostAlreadyExists {
                    host_id: enrollment.host_id,
                });
            }
            if self
                .enrollments
                .lock()
                .expect("lock")
                .contains_key(&enrollment.host_id)
            {
                return Err(AegisEnrollmentWriteError::AlreadyExists {
                    host_id: enrollment.host_id,
                });
            }
            for alias in &enrollment.aliases {
                if let Some(host_id) = self.aliases.lock().expect("lock").get(alias).copied() {
                    return Err(AegisEnrollmentWriteError::AliasAlreadyAssigned {
                        alias: alias.clone(),
                        host_id,
                    });
                }
                if self
                    .satellites
                    .lock()
                    .expect("lock")
                    .contains_key(alias.as_str())
                {
                    return Err(AegisEnrollmentWriteError::AliasAssignedToSatellite {
                        alias: alias.clone(),
                    });
                }
            }
            self.enrollments
                .lock()
                .expect("lock")
                .insert(enrollment.host_id, enrollment.clone());
            for alias in &enrollment.aliases {
                self.aliases
                    .lock()
                    .expect("lock")
                    .insert(alias.clone(), enrollment.host_id);
            }
            Ok(enrollment.clone())
        }

        async fn replace_aegis_enrollment_credential(
            &self,
            host_id: &HostId,
            expected_session_id: Option<&str>,
            next_session_id: &str,
            updated_unix: i64,
        ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
            let mut enrollments = self.enrollments.lock().expect("lock");
            let enrollment = enrollments
                .get_mut(host_id)
                .ok_or(AegisEnrollmentWriteError::NotFound { host_id: *host_id })?;
            if updated_unix >= enrollment.expires_unix {
                return Err(AegisEnrollmentWriteError::Expired {
                    host_id: *host_id,
                    expires_unix: enrollment.expires_unix,
                });
            }
            if enrollment.credential_session_id.as_deref() != expected_session_id {
                return Err(AegisEnrollmentWriteError::CredentialMismatch { host_id: *host_id });
            }
            enrollment.credential_session_id = Some(next_session_id.to_string());
            enrollment.updated_unix = updated_unix;
            Ok(enrollment.clone())
        }

        async fn update_aegis_enrollment_phase(
            &self,
            host_id: &HostId,
            credential_session_id: &str,
            phase: AegisEnrollmentPhase,
            updated_unix: i64,
        ) -> Result<AegisEnrollmentRecord, AegisEnrollmentWriteError> {
            let mut enrollments = self.enrollments.lock().expect("lock");
            let enrollment = enrollments
                .get_mut(host_id)
                .ok_or(AegisEnrollmentWriteError::NotFound { host_id: *host_id })?;
            validate_current_enrollment(enrollment, credential_session_id, updated_unix)?;
            if enrollment_phase_rank(phase) > enrollment_phase_rank(enrollment.phase) {
                enrollment.phase = phase;
            }
            enrollment.updated_unix = updated_unix;
            Ok(enrollment.clone())
        }

        async fn prepare_aegis_enrollment(
            &self,
            host_id: &HostId,
            credential_session_id: &str,
            preparation: AegisEnrollmentPreparation<'_>,
        ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError> {
            let AegisEnrollmentPreparation {
                host_public_key,
                wireguard_public_key,
                wireguard_endpoints,
                network,
                updated_unix,
            } = preparation;
            let mut enrollment = self
                .enrollments
                .lock()
                .expect("lock")
                .get(host_id)
                .cloned()
                .ok_or(AegisEnrollmentWriteError::NotFound { host_id: *host_id })?;
            validate_current_enrollment(&enrollment, credential_session_id, updated_unix)?;
            crate::aegis_store::validate_enrollment_host_public_key(&enrollment, host_public_key)?;
            let existing_host = self.hosts.lock().expect("lock").get(host_id).cloned();
            let existing_member = self
                .network_members
                .lock()
                .expect("lock")
                .get(&enrollment.network)
                .and_then(|members| members.get(host_id))
                .cloned();
            if let (Some(host), Some(member)) = (existing_host.as_ref(), existing_member.as_ref()) {
                if !host.pending
                    || !member.pending
                    || !prepared_host_matches_enrollment(&enrollment, host, member)
                    || host.ssh.as_ref().and_then(|ssh| ssh.public_key.as_deref())
                        != host_public_key
                    || member.wireguard_public_key.as_deref() != Some(wireguard_public_key)
                    || member.wireguard_endpoints != wireguard_endpoints
                {
                    return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                        host_id: *host_id,
                    });
                }
                enrollment.phase = AegisEnrollmentPhase::Prepared;
                enrollment.updated_unix = updated_unix;
                self.enrollments
                    .lock()
                    .expect("lock")
                    .insert(*host_id, enrollment.clone());
                return Ok(AegisEnrollmentPrepared {
                    enrollment,
                    host: host.clone(),
                    member: member.clone(),
                });
            }
            if existing_host.is_some() || existing_member.is_some() {
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
            let principal = format!("enrollment:{host_id}");
            let host = self.write_host(&AegisHostRecord {
                host_id: *host_id,
                aliases: enrollment.aliases.clone(),
                ssh: enrollment.ssh.as_ref().map(|ssh| AegisHostRecordSsh {
                    port: ssh.port,
                    public_key: host_public_key.map(str::to_string),
                    external_principals: ssh.external_principals.clone(),
                }),
                egress_public_key: None,
                messages: Vec::new(),
                agent: None,
                principal_grants: Vec::new(),
                ssh_lockdown_enabled: None,
                direct_gateway_report: None,
                observed_public_ips: Default::default(),
                transient: enrollment.transient,
                pending: true,
                created_unix: updated_unix,
                updated_unix,
                updated_by_principal: principal.clone(),
            })?;
            let member = self.write_network_member(
                &enrollment.network,
                &AegisNetworkMemberRecord {
                    host_id: *host_id,
                    mode: enrollment.mode,
                    wireguard_public_key: Some(wireguard_public_key.to_string()),
                    wireguard_ipv4: None,
                    wireguard_ipv6: None,
                    wireguard_endpoints: wireguard_endpoints.to_vec(),
                    internal_ipv4: None,
                    internal_ipv6: None,
                    pending: true,
                    created_unix: updated_unix,
                    updated_unix,
                    updated_by_principal: principal,
                },
                network,
            )?;
            enrollment.phase = AegisEnrollmentPhase::Prepared;
            enrollment.updated_unix = updated_unix;
            self.enrollments
                .lock()
                .expect("lock")
                .insert(*host_id, enrollment.clone());
            Ok(AegisEnrollmentPrepared {
                enrollment,
                host,
                member,
            })
        }

        async fn activate_aegis_enrollment(
            &self,
            host_id: &HostId,
            credential_session_id: &str,
            updated_unix: i64,
        ) -> Result<AegisEnrollmentPrepared, AegisEnrollmentWriteError> {
            let mut enrollment = self
                .enrollments
                .lock()
                .expect("lock")
                .get(host_id)
                .cloned()
                .ok_or(AegisEnrollmentWriteError::NotFound { host_id: *host_id })?;
            validate_current_enrollment(&enrollment, credential_session_id, updated_unix)?;
            if enrollment_phase_rank(enrollment.phase)
                < enrollment_phase_rank(AegisEnrollmentPhase::Prepared)
            {
                return Err(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id });
            }
            let mut host = self
                .hosts
                .lock()
                .expect("lock")
                .get(host_id)
                .cloned()
                .ok_or(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id })?;
            let mut member = self
                .network_members
                .lock()
                .expect("lock")
                .get(&enrollment.network)
                .and_then(|members| members.get(host_id))
                .cloned()
                .ok_or(AegisEnrollmentWriteError::NotPrepared { host_id: *host_id })?;
            if !host.pending
                || !member.pending
                || !prepared_host_matches_enrollment(&enrollment, &host, &member)
            {
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
            host.pending = false;
            host.updated_unix = updated_unix;
            member.pending = false;
            member.updated_unix = updated_unix;
            self.hosts
                .lock()
                .expect("lock")
                .insert(*host_id, host.clone());
            self.network_members
                .lock()
                .expect("lock")
                .get_mut(&enrollment.network)
                .expect("prepared network exists")
                .insert(*host_id, member.clone());
            enrollment.phase = AegisEnrollmentPhase::Activating;
            enrollment.updated_unix = updated_unix;
            self.enrollments.lock().expect("lock").remove(host_id);
            Ok(AegisEnrollmentPrepared {
                enrollment,
                host,
                member,
            })
        }

        async fn cancel_aegis_enrollment(
            &self,
            host_id: &HostId,
        ) -> Result<Option<AegisEnrollmentRecord>, AegisEnrollmentWriteError> {
            let Some(enrollment) = self.enrollments.lock().expect("lock").get(host_id).cloned()
            else {
                return Ok(None);
            };
            if self
                .hosts
                .lock()
                .expect("lock")
                .get(host_id)
                .is_some_and(|host| !host.pending)
                || self
                    .network_members
                    .lock()
                    .expect("lock")
                    .get(&enrollment.network)
                    .and_then(|members| members.get(host_id))
                    .is_some_and(|member| !member.pending)
            {
                return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                    host_id: *host_id,
                });
            }
            for alias in &enrollment.aliases {
                if self.aliases.lock().expect("lock").get(alias).copied() != Some(*host_id) {
                    return Err(AegisEnrollmentWriteError::InconsistentPreparedHost {
                        host_id: *host_id,
                    });
                }
            }
            self.enrollments.lock().expect("lock").remove(host_id);
            self.hosts.lock().expect("lock").remove(host_id);
            if let Some(members) = self
                .network_members
                .lock()
                .expect("lock")
                .get_mut(&enrollment.network)
            {
                members.remove(host_id);
            }
            for alias in &enrollment.aliases {
                self.aliases.lock().expect("lock").remove(alias);
            }
            Ok(Some(enrollment))
        }

        async fn read_aegis_egress_snapshot(&self) -> anyhow::Result<AegisEgressSnapshot> {
            let state = self.egress.lock().expect("lock");
            Ok(AegisEgressSnapshot {
                generation: state.generation,
                policies: state.policies.values().cloned().collect(),
            })
        }

        async fn fetch_aegis_egress_policy(
            &self,
            source_host_id: &HostId,
        ) -> anyhow::Result<Option<AegisEgressPolicy>> {
            Ok(self
                .egress
                .lock()
                .expect("lock")
                .policies
                .get(source_host_id)
                .cloned())
        }

        async fn compare_and_set_aegis_egress_policy(
            &self,
            source_host_id: &HostId,
            expected_generation: u64,
            expected_revision: Option<u64>,
            replacement: Option<&AegisEgressPolicy>,
        ) -> Result<(), AegisEgressWriteError> {
            let mut state = self.egress.lock().expect("lock");
            if state.generation != expected_generation
                || state
                    .policies
                    .get(source_host_id)
                    .map(|policy| policy.revision)
                    != expected_revision
            {
                return Err(AegisEgressWriteError::ConcurrentWrite {
                    source_host_id: *source_host_id,
                });
            }
            if replacement.is_some_and(|policy| {
                policy.source_host_id != *source_host_id
                    || policy.revision != expected_generation.saturating_add(1)
            }) {
                return Err(AegisEgressWriteError::Internal(anyhow::anyhow!(
                    "invalid replacement egress policy revision"
                )));
            }
            let next_generation = state.generation.checked_add(1).ok_or_else(|| {
                AegisEgressWriteError::Internal(anyhow::anyhow!(
                    "egress topology generation is exhausted"
                ))
            })?;
            match replacement {
                Some(policy) => {
                    state.policies.insert(*source_host_id, policy.clone());
                }
                None if state.policies.remove(source_host_id).is_some() => {}
                None => {
                    return Err(AegisEgressWriteError::NotFound {
                        source_host_id: *source_host_id,
                    });
                }
            }
            state.generation = next_generation;
            Ok(())
        }

        async fn list_aegis_direct_gateways(
            &self,
        ) -> anyhow::Result<Vec<AegisDirectGatewayRecord>> {
            Ok(self
                .direct_gateways
                .lock()
                .expect("lock")
                .values()
                .cloned()
                .collect())
        }

        async fn fetch_aegis_direct_gateway(
            &self,
            host_id: &HostId,
        ) -> anyhow::Result<Option<AegisDirectGatewayRecord>> {
            Ok(self
                .direct_gateways
                .lock()
                .expect("lock")
                .get(host_id)
                .cloned())
        }

        async fn put_aegis_direct_gateway(
            &self,
            gateway: &AegisDirectGatewayRecord,
        ) -> Result<AegisDirectGatewayRecord, AegisDirectWriteError> {
            if let Some((host_id, _)) =
                self.direct_gateways
                    .lock()
                    .expect("lock")
                    .iter()
                    .find(|(host_id, existing)| {
                        *host_id != &gateway.host_id
                            && existing.wireguard.public_key == gateway.wireguard.public_key
                    })
            {
                return Err(AegisDirectWriteError::DuplicatePublicKey {
                    resource: host_id.to_string(),
                });
            }
            let mut gateways = self.direct_gateways.lock().expect("lock");
            let mut stored = gateway.clone();
            if let Some(existing) = gateways.get(&gateway.host_id) {
                stored.created_unix = existing.created_unix;
            }
            gateways.insert(stored.host_id, stored.clone());
            Ok(stored)
        }

        async fn delete_aegis_direct_gateway(&self, host_id: &HostId) -> anyhow::Result<bool> {
            Ok(self
                .direct_gateways
                .lock()
                .expect("lock")
                .remove(host_id)
                .is_some())
        }

        async fn list_aegis_satellites(&self) -> anyhow::Result<Vec<AegisSatelliteRecord>> {
            Ok(self
                .satellites
                .lock()
                .expect("lock")
                .values()
                .cloned()
                .collect())
        }

        async fn create_aegis_satellite(
            &self,
            satellite: &AegisSatelliteRecord,
            pool: &AegisWireGuardAddressPool,
        ) -> Result<AegisSatelliteRecord, AegisDirectWriteError> {
            let satellite_exists = self
                .satellites
                .lock()
                .expect("lock")
                .contains_key(&satellite.slug);
            if satellite_exists {
                return Err(AegisDirectWriteError::AlreadyExists {
                    resource: satellite.slug.clone(),
                });
            }
            let alias = HostAlias::parse(satellite.slug.clone())
                .map_err(|error| AegisDirectWriteError::Internal(anyhow::anyhow!(error)))?;
            if let Some(host_id) = self.aliases.lock().expect("lock").get(&alias).copied() {
                return Err(AegisDirectWriteError::HostAliasExists { alias, host_id });
            }
            let allocated = self.allocate_direct_wireguard(&satellite.wireguard, pool)?;
            let mut stored = satellite.clone();
            stored.wireguard = allocated;
            self.satellites
                .lock()
                .expect("lock")
                .insert(stored.slug.clone(), stored.clone());
            Ok(stored)
        }

        async fn fetch_aegis_satellite(
            &self,
            slug: &str,
        ) -> anyhow::Result<Option<AegisSatelliteRecord>> {
            Ok(self.satellites.lock().expect("lock").get(slug).cloned())
        }

        async fn record_aegis_satellite_broker_use(
            &self,
            slug: &str,
            activity: &AegisSatelliteBrokerUseRecord,
        ) -> anyhow::Result<bool> {
            let mut satellites = self.satellites.lock().expect("lock");
            let Some(satellite) = satellites.get_mut(slug) else {
                return Ok(false);
            };
            if satellite
                .broker_uses
                .get(&activity.target_host_id)
                .is_none_or(|current| activity.used_unix >= current.used_unix)
            {
                satellite
                    .broker_uses
                    .insert(activity.target_host_id, activity.clone());
            }
            Ok(true)
        }

        async fn delete_aegis_satellite(&self, slug: &str) -> anyhow::Result<bool> {
            Ok(self.satellites.lock().expect("lock").remove(slug).is_some())
        }

        async fn list_aegis_hosts(&self) -> anyhow::Result<Vec<AegisHostRecord>> {
            Ok(self.hosts.lock().expect("lock").values().cloned().collect())
        }

        async fn fetch_aegis_host(
            &self,
            host_id: &HostId,
        ) -> anyhow::Result<Option<AegisHostRecord>> {
            Ok(self.hosts.lock().expect("lock").get(host_id).cloned())
        }

        async fn fetch_host_id_by_alias(
            &self,
            alias: &HostAlias,
        ) -> anyhow::Result<Option<HostId>> {
            Ok(self.aliases.lock().expect("lock").get(alias).copied())
        }

        async fn resolve_enrolled_host_alias(
            &self,
            alias: &HostAlias,
        ) -> anyhow::Result<Option<HostId>> {
            let Some(host_id) = self.aliases.lock().expect("lock").get(alias).copied() else {
                return Ok(None);
            };
            if let Some(host) = self.hosts.lock().expect("lock").get(&host_id) {
                if !host.aliases.contains(alias) {
                    anyhow::bail!(
                        "alias claim `{alias}` points to host `{host_id}` whose authoritative alias list does not contain it"
                    );
                }
                if !host.pending {
                    return Ok(Some(host_id));
                }
            }
            if let Some(enrollment) = self.enrollments.lock().expect("lock").get(&host_id) {
                if enrollment.aliases.contains(alias) {
                    return Ok(None);
                }
                anyhow::bail!(
                    "alias claim `{alias}` points to enrollment `{host_id}` whose authoritative alias list does not contain it"
                );
            }
            anyhow::bail!(
                "alias claim `{alias}` points to `{host_id}` without an enrolled host or enrollment"
            )
        }

        async fn add_host_alias(
            &self,
            host_id: &HostId,
            alias: &HostAlias,
            updated_by_principal: &str,
            updated_unix: i64,
        ) -> Result<AegisHostRecord, AegisAliasWriteError> {
            match self.hosts.lock().expect("lock").get(host_id) {
                None => return Err(AegisAliasWriteError::HostNotFound { host_id: *host_id }),
                Some(host) if host.pending => {
                    return Err(AegisAliasWriteError::EnrollmentPending { host_id: *host_id });
                }
                Some(_) => {}
            }
            if self
                .satellites
                .lock()
                .expect("lock")
                .contains_key(alias.as_str())
            {
                return Err(AegisAliasWriteError::AssignedToSatellite {
                    alias: alias.clone(),
                });
            }
            if let Some(owner) = self.aliases.lock().expect("lock").get(alias).copied()
                && owner != *host_id
            {
                return Err(AegisAliasWriteError::AlreadyAssigned {
                    alias: alias.clone(),
                    host_id: owner,
                });
            }
            let mut hosts = self.hosts.lock().expect("lock");
            let host = hosts
                .get_mut(host_id)
                .ok_or(AegisAliasWriteError::HostNotFound { host_id: *host_id })?;
            host.aliases = host.aliases.added(alias.clone())?;
            host.updated_by_principal = updated_by_principal.to_string();
            host.updated_unix = updated_unix;
            self.aliases
                .lock()
                .expect("lock")
                .insert(alias.clone(), *host_id);
            Ok(host.clone())
        }

        async fn promote_host_alias(
            &self,
            host_id: &HostId,
            alias: &HostAlias,
            updated_by_principal: &str,
            updated_unix: i64,
        ) -> Result<AegisHostRecord, AegisAliasWriteError> {
            let mut hosts = self.hosts.lock().expect("lock");
            let host = hosts
                .get_mut(host_id)
                .ok_or(AegisAliasWriteError::HostNotFound { host_id: *host_id })?;
            if host.pending {
                return Err(AegisAliasWriteError::EnrollmentPending { host_id: *host_id });
            }
            host.aliases = host.aliases.promoted(alias).ok_or_else(|| {
                AegisAliasWriteError::AliasNotFound {
                    host_id: *host_id,
                    alias: alias.clone(),
                }
            })?;
            host.updated_by_principal = updated_by_principal.to_string();
            host.updated_unix = updated_unix;
            Ok(host.clone())
        }

        async fn remove_host_alias(
            &self,
            host_id: &HostId,
            alias: &HostAlias,
            updated_by_principal: &str,
            updated_unix: i64,
        ) -> Result<AegisHostRecord, AegisAliasWriteError> {
            let mut hosts = self.hosts.lock().expect("lock");
            let host = hosts
                .get_mut(host_id)
                .ok_or(AegisAliasWriteError::HostNotFound { host_id: *host_id })?;
            if host.pending {
                return Err(AegisAliasWriteError::EnrollmentPending { host_id: *host_id });
            }
            host.aliases = host.aliases.removed(alias)?.ok_or_else(|| {
                AegisAliasWriteError::AliasNotFound {
                    host_id: *host_id,
                    alias: alias.clone(),
                }
            })?;
            host.updated_by_principal = updated_by_principal.to_string();
            host.updated_unix = updated_unix;
            self.aliases.lock().expect("lock").remove(alias);
            Ok(host.clone())
        }

        async fn list_aegis_network_members(
            &self,
            network: &str,
        ) -> anyhow::Result<Vec<AegisNetworkMemberRecord>> {
            Ok(self
                .network_members
                .lock()
                .expect("lock")
                .get(network)
                .into_iter()
                .flat_map(|members| members.values().cloned())
                .collect())
        }

        async fn fetch_aegis_network_member(
            &self,
            network: &str,
            host_id: &HostId,
        ) -> anyhow::Result<Option<AegisNetworkMemberRecord>> {
            Ok(self
                .network_members
                .lock()
                .expect("lock")
                .get(network)
                .and_then(|members| members.get(host_id))
                .cloned())
        }

        async fn update_aegis_host(
            &self,
            host: &AegisHostRecord,
        ) -> Result<AegisHostRecord, AegisHostWriteError> {
            match self.hosts.lock().expect("lock").get(&host.host_id) {
                None => {
                    return Err(AegisHostWriteError::NotFound {
                        host_id: host.host_id,
                    });
                }
                Some(existing) if existing.pending => {
                    return Err(AegisHostWriteError::EnrollmentPending {
                        host_id: host.host_id,
                    });
                }
                Some(_) => {}
            }
            self.write_host(host)
        }

        async fn update_aegis_network_member(
            &self,
            network: &str,
            member: &AegisNetworkMemberRecord,
            config: &AegisNetworkConfig,
        ) -> Result<AegisNetworkMemberRecord, AegisHostWriteError> {
            let existing = self
                .network_members
                .lock()
                .expect("lock")
                .get(network)
                .and_then(|members| members.get(&member.host_id))
                .cloned();
            match existing {
                None => {
                    return Err(AegisHostWriteError::NotFound {
                        host_id: member.host_id,
                    });
                }
                Some(existing) if existing.pending => {
                    return Err(AegisHostWriteError::EnrollmentPending {
                        host_id: member.host_id,
                    });
                }
                Some(_) => {}
            }
            self.write_network_member(network, member, config)
        }

        async fn update_aegis_host_report(
            &self,
            host_id: &HostId,
            update: AegisHostReportUpdate,
        ) -> anyhow::Result<bool> {
            let mut hosts = self.hosts.lock().expect("lock");
            let Some(host) = hosts.get_mut(host_id) else {
                return Ok(false);
            };
            let direct_gateway_report = crate::aegis_store::merge_direct_gateway_handshakes(
                host.direct_gateway_report.as_ref(),
                update.direct_gateway_report,
            );
            host.messages = update.messages;
            host.agent = Some(update.agent);
            host.principal_grants = update.principal_grants;
            host.ssh_lockdown_enabled = Some(update.ssh_lockdown_enabled);
            host.direct_gateway_report = Some(direct_gateway_report);
            if let Some((ip, observed_unix)) = update.observed_public_ip {
                let ip_text = ip.to_string();
                let current = match ip {
                    IpAddr::V4(_) => &mut host.observed_public_ips.ipv4,
                    IpAddr::V6(_) => &mut host.observed_public_ips.ipv6,
                };
                if current.as_ref().map(|observed| observed.ip.as_str()) != Some(ip_text.as_str()) {
                    *current = Some(aegis_dto::protocol::AegisObservedPublicIp {
                        ip: ip_text,
                        observed_unix,
                    });
                }
            }
            Ok(true)
        }

        async fn delete_aegis_host(
            &self,
            host_id: &HostId,
            networks: &[String],
        ) -> Result<bool, AegisHostDeleteError> {
            if self
                .hosts
                .lock()
                .expect("lock")
                .get(host_id)
                .is_some_and(|host| host.pending)
            {
                return Err(AegisHostDeleteError::EnrollmentPending { host_id: *host_id });
            }
            let mut egress = self.egress.lock().expect("lock");
            let next_generation = egress.generation.checked_add(1).ok_or_else(|| {
                AegisHostDeleteError::Internal(anyhow::anyhow!(
                    "egress topology generation is exhausted"
                ))
            })?;
            let mut blocking_sources = egress
                .policies
                .values()
                .filter(|policy| {
                    policy.source_host_id != *host_id
                        && (policy.active_via == Some(*host_id)
                            || policy.desired_via == Some(*host_id))
                })
                .map(|policy| policy.source_host_id)
                .collect::<Vec<_>>();
            blocking_sources.sort();
            blocking_sources.dedup();
            if !blocking_sources.is_empty() {
                return Err(AegisHostDeleteError::EgressTargetInUse {
                    host_id: *host_id,
                    source_host_ids: blocking_sources,
                });
            }
            let mut found = egress.policies.remove(host_id).is_some();

            if let Some(host) = self.hosts.lock().expect("lock").remove(host_id) {
                found = true;
                for alias in &host.aliases {
                    self.aliases.lock().expect("lock").remove(alias);
                }
            }
            let mut members = self.network_members.lock().expect("lock");
            for network in networks {
                if let Some(network_members) = members.get_mut(network) {
                    found |= network_members.remove(host_id).is_some();
                }
            }
            drop(members);

            found |= self
                .direct_gateways
                .lock()
                .expect("lock")
                .remove(host_id)
                .is_some();
            if found {
                egress.generation = next_generation;
            }
            Ok(found)
        }
    }

    impl super::CredentialSessionStore for MemoryHostRefreshIssuer {
        fn issue_refresh_session<'a>(
            &'a self,
            request: RefreshTokenIssueRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<super::IssuedCredentialSession>> + Send + 'a>>
        {
            Box::pin(async move {
                let issued = self.host_refresh_tokens.issue(request.now_unix)?;
                let host_id = super::aegis_host_id_from_subject(&request.subject)
                    .or_else(|_| super::aegis_enrollment_host_id_from_subject(&request.subject))?;
                self.issued
                    .lock()
                    .expect("lock")
                    .push(IssuedHostRefreshSession {
                        sid: issued.sid().to_string(),
                        host_id,
                        subject: request.subject.clone(),
                        family_id: issued.family_id().to_string(),
                        token_id: issued.token_id().to_string(),
                    });
                Ok(super::IssuedCredentialSession {
                    session_id: issued.sid().to_string(),
                    refresh_token: issued.value().to_string(),
                })
            })
        }

        fn revoke_refresh_sessions<'a>(
            &'a self,
            subject: &'a Subject,
            _now_unix: i64,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<usize>> + Send + 'a>> {
            Box::pin(async move {
                let mut issued = self.issued.lock().expect("lock");
                let before = issued.len();
                issued.retain(|session| session.subject != *subject);
                Ok(before - issued.len())
            })
        }

        fn revoke_refresh_session<'a>(
            &'a self,
            session_id: &'a str,
            expected_subject: &'a Subject,
            _now_unix: i64,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
            Box::pin(async move {
                let mut issued = self.issued.lock().expect("lock");
                let before = issued.len();
                issued.retain(|session| {
                    session.sid != session_id || session.subject != *expected_subject
                });
                Ok(before != issued.len())
            })
        }

        fn transition_refresh_session_subject<'a>(
            &'a self,
            session_id: &'a str,
            expected_subject: &'a Subject,
            next_subject: &'a Subject,
            _now_unix: i64,
        ) -> Pin<
            Box<dyn Future<Output = anyhow::Result<RefreshSessionSubjectTransition>> + Send + 'a>,
        > {
            Box::pin(async move {
                let mut issued = self.issued.lock().expect("lock");
                let session = issued
                    .iter_mut()
                    .find(|session| session.sid == session_id)
                    .ok_or_else(|| anyhow::anyhow!("unknown refresh session `{session_id}`"))?;
                if session.subject == *next_subject {
                    return Ok(RefreshSessionSubjectTransition::AlreadyTransitioned);
                }
                if session.subject != *expected_subject {
                    anyhow::bail!("refresh session subject mismatch");
                }
                session.subject = next_subject.clone();
                Ok(RefreshSessionSubjectTransition::Transitioned)
            })
        }

        fn revoke_refresh_token<'a>(
            &'a self,
            refresh_token: &'a str,
            _now_unix: i64,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                let Some(parsed) = self.host_refresh_tokens.parse(refresh_token)? else {
                    return Ok(());
                };
                self.issued
                    .lock()
                    .expect("lock")
                    .retain(|session| session.token_id != parsed.id());
                Ok(())
            })
        }
    }

    fn test_mesh_config() -> AegisMeshConfig {
        AegisMeshConfig {
            endpoint_port: 51_820,
            overlay_mtu: 1_360,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: Some("aegis.x.hoek.io".to_string()),
        }
    }

    fn test_issuer() -> JwtIssuer {
        JwtIssuer::from_config(&JwtConfig {
            iss: TEST_ISSUER_URL.to_string(),
            private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            kid: "test-kid".to_string(),
            ttl_seconds: 300,
        })
        .expect("test issuer config should be valid")
    }

    fn test_network_config() -> AegisNetworkConfig {
        let mesh = test_mesh_config();
        AegisNetworkConfig {
            name: "aegis".to_string(),
            wireguard: AegisNetworkWireGuardConfig {
                interface: "wg-aegis".to_string(),
                endpoint_port: mesh.endpoint_port,
                mtu: 1_420,
                fwmark: 44_641,
                subnet_ipv4: mesh.wireguard_subnet_ipv4.clone(),
                subnet_ipv6: mesh.wireguard_subnet_ipv6.clone(),
            },
            mesh: Some(mesh),
            managed_ssh: true,
            host_dns_suffix: Some("aegis.x.hoek.io".to_string()),
        }
    }

    fn test_direct_gateway_config() -> AegisDirectGatewayConfig {
        AegisDirectGatewayConfig {
            interface: "wg-aegis-direct".to_string(),
            endpoint_port: 51_822,
            mtu: 1_420,
            fwmark: 44_641,
            subnet_ipv4: "10.77.1.0/24".to_string(),
            subnet_ipv6: "fd77::1:0/120".to_string(),
            full_tunnel_dns: Vec::new(),
        }
    }

    fn test_egress_config() -> AegisEgressConfig {
        AegisEgressConfig {
            network: "aegis".to_string(),
            interface: "wg-aegis-egress".to_string(),
            endpoint_port: 51_823,
            mtu: 1_280,
            fwmark: 44_641,
            routing_table: 51_823,
            main_rule_priority: 11_000,
            egress_rule_priority: 11_010,
            subnet_ipv4: "10.78.1.0/24".to_string(),
            subnet_ipv6: "fd78::1:0/120".to_string(),
            dns_subnet_ipv4: "10.78.0.0/24".to_string(),
            dns_subnet_ipv6: "fd78::/120".to_string(),
        }
    }

    fn test_state_with_auth(
        store: MemoryStore,
        auth: Arc<dyn super::CredentialSessionStore>,
    ) -> AegisState<MemoryStore> {
        AegisState::new(AegisStateParts {
            store,
            auth,
            issuer: Arc::new(test_issuer()),
            client_ca: &ClientCaConfig {
                private_key_pem: TEST_CLIENT_CA_PRIVATE_KEY_PEM.to_string(),
                passphrase: None,
                cert_ttl_seconds: 300,
            },
            direct_client_ca: &DirectClientCaConfig {
                private_key_pem: TEST_CLIENT_CA_PRIVATE_KEY_PEM.to_string(),
                passphrase: None,
            },
            server_ca: &ServerCaConfig {
                private_key_pem: TEST_SERVER_CA_PRIVATE_KEY_PEM.to_string(),
                passphrase: None,
                cert_ttl_seconds: 86_400,
            },
            tls: &TlsConfig {
                root: TlsCaConfig {
                    certificate_pem:
                        "-----BEGIN CERTIFICATE-----\ntest-root\n-----END CERTIFICATE-----\n"
                            .to_string(),
                    private_key_pem:
                        "-----BEGIN PRIVATE KEY-----\ntest-root-key\n-----END PRIVATE KEY-----\n"
                            .to_string(),
                },
                issuing: TlsCaConfig {
                    certificate_pem:
                        "-----BEGIN CERTIFICATE-----\ntest-issuing\n-----END CERTIFICATE-----\n"
                            .to_string(),
                    private_key_pem:
                        "-----BEGIN PRIVATE KEY-----\ntest-issuing-key\n-----END PRIVATE KEY-----\n"
                            .to_string(),
                },
                issuing_crl_pem: "-----BEGIN X509 CRL-----\ntest-crl\n-----END X509 CRL-----\n"
                    .to_string(),
            },
            api_issuer: "https://api.hoek.io/v2",
            api_audience: TEST_API_AUDIENCE,
            user_api_audience: TEST_API_AUDIENCE,
            namespace: "test".parse().unwrap(),
            cfg: &AegisConfig {
                networks: BTreeMap::from([("aegis".to_string(), test_network_config())]),
                direct_gateway: test_direct_gateway_config(),
                egress: test_egress_config(),
                dns: None,
            },
        })
        .expect("test aegis state should build")
    }

    fn test_app(store: MemoryStore) -> Router {
        test_app_with_auth(store, Arc::new(MemoryHostRefreshIssuer::default()))
    }

    fn test_app_with_auth(
        store: MemoryStore,
        auth: Arc<dyn super::CredentialSessionStore>,
    ) -> Router {
        test_app_with_state(test_state_with_auth(store, auth))
    }

    fn test_app_with_state(state: AegisState<MemoryStore>) -> Router {
        Router::new().nest(
            "/v2",
            Router::new()
                .route(path::AEGIS_NETWORKS, get(get_networks))
                .route(path::AEGIS_NETWORK, get(get_network))
                .route(path::AEGIS_NETWORK_MEMBERS, get(get_network_members))
                .route(
                    path::AEGIS_NETWORK_MEMBER,
                    get(get_network_member).put(put_network_member),
                )
                .route(
                    path::AEGIS_NETWORK_MEMBER_CLIENT_CERT,
                    post(post_network_member_client_cert),
                )
                .route(
                    path::AEGIS_NETWORK_MEMBER_SERVER_CERT,
                    post(post_network_member_server_cert),
                )
                .route(
                    path::AEGIS_DIRECT_GATEWAY,
                    put(put_direct_gateway).delete(delete_direct_gateway),
                )
                .route(
                    path::AEGIS_DIRECT_GATEWAY_INVENTORY,
                    get(get_direct_gateway_inventory),
                )
                .route(
                    path::AEGIS_EGRESS,
                    get(get_egress).put(put_egress).delete(delete_egress),
                )
                .route(path::AEGIS_EGRESS_INVENTORY, get(get_egress_inventory))
                .route(path::AEGIS_EGRESS_RESULT, post(post_egress_result))
                .route(path::AEGIS_SATELLITES, get(get_satellites))
                .route(
                    path::AEGIS_SATELLITE,
                    get(get_satellite)
                        .put(put_satellite)
                        .delete(delete_satellite),
                )
                .route(path::AEGIS_SATELLITE_TARGETS, get(get_satellite_targets))
                .route(
                    path::AEGIS_SATELLITE_CLIENT_CERT,
                    post(post_satellite_client_cert),
                )
                .route(path::AEGIS_DNS_SYNC, post(post_dns_sync))
                .route(path::AEGIS_AGENT_TOKEN, delete(delete_agent_token))
                .route(path::AEGIS_HOST_REPORT, put(put_host_report))
                .route(path::AEGIS_HOSTS, get(get_hosts))
                .route(
                    path::AEGIS_ENROLLMENTS,
                    get(get_enrollments).post(post_enrollment),
                )
                .route(
                    path::AEGIS_ENROLLMENT,
                    get(get_enrollment).delete(delete_enrollment),
                )
                .route(
                    path::AEGIS_ENROLLMENT_CREDENTIAL,
                    post(post_enrollment_credential),
                )
                .route(
                    path::AEGIS_ENROLLMENT_PREPARE,
                    post(post_enrollment_prepare),
                )
                .route(
                    path::AEGIS_ENROLLMENT_HEARTBEAT,
                    post(post_enrollment_heartbeat),
                )
                .route(
                    path::AEGIS_ENROLLMENT_ACTIVATE,
                    post(post_enrollment_activate),
                )
                .route(
                    path::AEGIS_HOST,
                    get(get_host).put(put_host).delete(delete_host),
                )
                .route(
                    path::AEGIS_HOST_ALIAS,
                    put(put_host_alias).delete(delete_host_alias),
                )
                .route(
                    path::AEGIS_HOST_ALIAS_PROMOTE,
                    post(post_host_alias_promote),
                )
                .route(path::AEGIS_ALIAS, get(get_alias))
                .route(path::AEGIS_HOST_EGRESS, put(put_egress_identity))
                .route(path::AEGIS_HOST_AGENT_TOKEN, post(post_host_agent_token))
                .route(path::AEGIS_USER_SSH_CA, get(get_client_ca_public_key))
                .route(path::AEGIS_HOST_SSH_CA, get(get_server_ca_public_key))
                .route(path::AEGIS_TLS_ROOT_CA, get(get_tls_root_ca_certificate))
                .with_state(state),
        )
    }

    fn user_token(admin: bool) -> String {
        user_token_for_client(admin, AEGIS_TOOL_CLIENT_ID)
    }

    fn namespace_state(name: &str, store: MemoryStore) -> AegisState<MemoryStore> {
        let mut state = test_state_with_auth(store, Arc::new(MemoryHostRefreshIssuer::default()));
        state.namespace = name.parse().expect("namespace");
        state.api_audience = format!("{TEST_API_AUDIENCE}/aegis/namespaces/{name}");
        state.client_ca_key = Arc::new(
            ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .expect("namespace CA"),
        );
        state
    }

    #[tokio::test]
    async fn namespace_membership_overrides_global_admin_claims_and_is_checked_live() {
        let alice = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        let bob = MemoryStore::with_hosts(vec![sample_host("alpha", 20)]);
        bob.users.lock().expect("lock").clear();
        let state = namespace_state("alice", alice.clone());
        let app = test_app_with_state(state.clone());
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", user_token(false)).parse().unwrap(),
        );
        assert!(
            super::UserAdminBearer::from_headers(&headers, &state)
                .await
                .is_ok()
        );

        let request = || {
            Request::builder()
                .uri("/v2/aegis/hosts")
                .header(AUTHORIZATION, format!("Bearer {}", user_token(true)))
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let hosts: AegisHostListResponse = json_body(response).await;
        assert_eq!(1, hosts.hosts.len());
        let denied = test_app_with_state(namespace_state("bob", bob))
            .oneshot(request())
            .await
            .unwrap();
        assert!(denied.status().is_client_error());

        alice.users.lock().unwrap().get_mut("user-1").unwrap().admin = false;
        assert!(
            super::UserAdminBearer::from_headers(&headers, &state)
                .await
                .is_err()
        );
        alice.users.lock().unwrap().clear();
        assert!(
            app.oneshot(request())
                .await
                .unwrap()
                .status()
                .is_client_error()
        );
    }

    #[tokio::test]
    async fn namespace_agent_audience_rejects_foreign_inventory_and_broker_access() {
        let alice = namespace_state("alice", active_hub_store());
        let bob = namespace_state("bob", active_hub_store());
        let token = test_issuer()
            .sign_access(
                super::aegis_host_subject(&host_id("hub-a")).unwrap(),
                AGENT_CLIENT_ID,
                [&alice.api_audience],
                agent_access_scopes().unwrap(),
                Some("agent-session".into()),
            )
            .unwrap();
        let request = |path: &str| {
            Request::builder()
                .uri(path)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };
        let response = test_app_with_state(alice)
            .oneshot(request("/v2/aegis/hosts"))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let bob_app = test_app_with_state(bob);
        for path in ["/v2/aegis/hosts", "/v2/aegis/satellites/phone/targets"] {
            assert!(
                bob_app
                    .clone()
                    .oneshot(request(path))
                    .await
                    .unwrap()
                    .status()
                    .is_client_error()
            );
        }
    }

    #[tokio::test]
    async fn namespace_membership_and_role_gate_certificate_and_agent_credential_issuance() {
        let store = active_hub_store();
        let credentials = Arc::new(MemoryHostRefreshIssuer::default());
        let mut state = namespace_state("alice", store.clone());
        state.auth = credentials.clone();
        let app = test_app_with_state(state);
        let cert_request = || {
            json_request(
                Method::POST,
                &format!(
                    "/v2/aegis/networks/aegis/members/{}/client-cert",
                    host_id("hub-a")
                ),
                &user_token(true),
                &AegisHostClientCertRequest {
                    ed25519_public_key: TEST_USER_PUBLIC_KEY.into(),
                },
            )
        };
        let token_request = || {
            empty_request(
                Method::POST,
                &format!("/v2/aegis/hosts/{}/agent-token", host_id("hub-a")),
                &user_token(true),
            )
        };
        assert_eq!(
            StatusCode::OK,
            app.clone().oneshot(token_request()).await.unwrap().status()
        );
        assert_eq!(1, credentials.issued.lock().unwrap().len());

        // A stale administrator claim cannot override the current namespace role.
        store.users.lock().unwrap().get_mut("user-1").unwrap().admin = false;
        assert_eq!(
            StatusCode::FORBIDDEN,
            app.clone().oneshot(token_request()).await.unwrap().status()
        );
        assert_eq!(1, credentials.issued.lock().unwrap().len());
        assert_eq!(
            StatusCode::OK,
            app.clone().oneshot(cert_request()).await.unwrap().status()
        );

        // Even an existing host login grant does not survive namespace removal.
        store.users.lock().unwrap().clear();
        for request in [cert_request(), token_request()] {
            assert_eq!(
                StatusCode::FORBIDDEN,
                app.clone().oneshot(request).await.unwrap().status()
            );
        }
        assert_eq!(1, credentials.issued.lock().unwrap().len());
    }

    #[tokio::test]
    async fn server_certificate_issuance_rejects_foreign_and_unscoped_agent_tokens() {
        let alice = namespace_state("alice", active_hub_store());
        let bob = namespace_state("bob", active_hub_store());
        let sign = |audience: &str| {
            test_issuer()
                .sign_access(
                    super::aegis_host_subject(&host_id("hub-a")).unwrap(),
                    AGENT_CLIENT_ID,
                    [audience],
                    agent_access_scopes().unwrap(),
                    Some("agent-session".into()),
                )
                .unwrap()
        };
        let own_token = sign(&alice.api_audience);
        let foreign_token = sign(&bob.api_audience);
        let unscoped_token = sign(TEST_API_AUDIENCE);
        let app = test_app_with_state(alice);
        for (token, expected) in [
            (own_token, StatusCode::OK),
            (foreign_token, StatusCode::UNAUTHORIZED),
            (unscoped_token, StatusCode::UNAUTHORIZED),
        ] {
            let request = empty_request(
                Method::POST,
                &format!(
                    "/v2/aegis/networks/aegis/members/{}/server-cert",
                    host_id("hub-a")
                ),
                &token,
            );
            assert_eq!(
                expected,
                app.clone().oneshot(request).await.unwrap().status()
            );
        }
    }

    #[tokio::test]
    async fn identical_host_ids_in_namespaces_use_distinct_certificate_authorities() {
        let alice = namespace_state("alice", active_hub_store());
        let bob = namespace_state("bob", active_hub_store());
        let alice_ca = alice
            .client_ca_key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256);
        let bob_ca = bob
            .client_ca_key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256);
        let request = || {
            json_request(
                Method::POST,
                &format!(
                    "/v2/aegis/networks/aegis/members/{}/client-cert",
                    host_id("hub-a")
                ),
                &user_token(false),
                &AegisHostClientCertRequest {
                    ed25519_public_key: TEST_USER_PUBLIC_KEY.into(),
                },
            )
        };
        for (state, own, foreign) in [(alice, &alice_ca, &bob_ca), (bob, &bob_ca, &alice_ca)] {
            let response = test_app_with_state(state).oneshot(request()).await.unwrap();
            assert_eq!(StatusCode::OK, response.status());
            let issued: SshIssueCertResponse = json_body(response).await;
            let certificate = Certificate::from_openssh(&issued.certificate).unwrap();
            assert!(certificate.validate([own]).is_ok());
            assert!(certificate.validate([foreign]).is_err());
        }
    }

    fn user_token_for_client(admin: bool, client_id: &str) -> String {
        user_token_for_client_and_subject(admin, client_id, "user-1")
    }

    fn user_token_for_client_and_subject(admin: bool, client_id: &str, subject: &str) -> String {
        let scopes = ScopeSet::new(
            [AEGIS_READ_SCOPE, AEGIS_USER_SCOPE]
                .into_iter()
                .chain(admin.then_some(AEGIS_ADMIN_SCOPE)),
        )
        .expect("user scopes should build");
        test_issuer()
            .sign_access(
                super::aegis_user_subject(subject).expect("user subject should build"),
                client_id,
                [TEST_API_AUDIENCE],
                scopes,
                Some("test-user-session".to_string()),
            )
            .expect("user token should sign")
    }

    fn agent_token(alias: Option<&str>) -> String {
        agent_token_for_client(alias, AGENT_CLIENT_ID)
    }

    fn agent_token_for_client(alias: Option<&str>, client_id: &str) -> String {
        let host_id = host_id(alias.expect("agent tests require a host alias"));
        test_issuer()
            .sign_access(
                super::aegis_host_subject(&host_id).expect("host subject should build"),
                client_id,
                [TEST_API_AUDIENCE],
                agent_access_scopes().expect("agent scopes should build"),
                Some("test-agent-session".to_string()),
            )
            .expect("agent token should sign")
    }

    fn enrollment_token(host_id: &HostId, session_id: &str) -> String {
        test_issuer()
            .sign_access(
                super::aegis_enrollment_subject(host_id).expect("enrollment subject should build"),
                AGENT_CLIENT_ID,
                [TEST_API_AUDIENCE],
                super::enrollment_access_scopes().expect("enrollment scopes should build"),
                Some(session_id.to_string()),
            )
            .expect("enrollment token should sign")
    }

    async fn json_body<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        serde_json::from_slice(&bytes).expect("response body should deserialize")
    }

    fn sample_host(alias: &str, updated_unix: i64) -> AegisHostRecord {
        AegisHostRecord {
            host_id: host_id(alias),
            aliases: aliases(alias),
            ssh: Some(AegisHostRecordSsh {
                port: Some(22),
                public_key: Some(TEST_USER_PUBLIC_KEY.to_string()),
                external_principals: Vec::new(),
            }),
            egress_public_key: None,
            messages: Vec::new(),
            agent: None,
            principal_grants: Vec::new(),
            ssh_lockdown_enabled: None,
            direct_gateway_report: None,
            observed_public_ips: AegisObservedPublicIps::default(),
            transient: false,
            pending: false,
            created_unix: 100,
            updated_unix,
            updated_by_principal: "user-1".to_string(),
        }
    }

    fn sample_member(
        alias: &str,
        mode: AegisHostMode,
        updated_unix: i64,
    ) -> AegisNetworkMemberRecord {
        AegisNetworkMemberRecord {
            host_id: host_id(alias),
            mode,
            wireguard_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            wireguard_ipv4: Some("10.75.1.42".to_string()),
            wireguard_ipv6: Some("fd75::1:2a".to_string()),
            wireguard_endpoints: Vec::new(),
            internal_ipv4: None,
            internal_ipv6: None,
            pending: false,
            created_unix: 100,
            updated_unix,
            updated_by_principal: "user-1".to_string(),
        }
    }

    fn sample_satellite(slug: &str) -> AegisSatelliteRecord {
        AegisSatelliteRecord {
            slug: slug.to_string(),
            credential_id: "0123456789abcdef0123456789abcdef".to_string(),
            owner_principal: "user-1".to_string(),
            wireguard: crate::aegis_store::AegisDirectWireGuardRecord {
                public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
                ipv4: "10.77.1.2".to_string(),
                ipv6: "fd77::1:2".to_string(),
                endpoints: Vec::new(),
            },
            ssh_public_key: TEST_USER_PUBLIC_KEY.to_string(),
            created_unix: 1,
            created_by_principal: "user-1".to_string(),
            broker_uses: BTreeMap::new(),
        }
    }

    fn active_hub_store() -> MemoryStore {
        let mut hub = sample_host("hub-a", 10);
        hub.principal_grants = vec![AegisPrincipalGrant {
            login_principal: "ubuntu".to_string(),
            user_id: "user-1".to_string(),
        }];
        let store = MemoryStore::with_hosts(vec![hub.clone()]);
        store
            .write_network_member(
                "aegis",
                &sample_member("hub-a", AegisHostMode::Hub, 10),
                &test_network_config(),
            )
            .expect("hub network member should seed");
        store
    }

    fn egress_ready_store() -> MemoryStore {
        let hosts = [
            ("source", TEST_GATEWAY_WIREGUARD_KEY),
            ("target-a", TEST_DIRECT_PEER_WIREGUARD_KEY),
            ("target-b", TEST_THIRD_WIREGUARD_KEY),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (alias, egress_public_key))| {
            let mut host = sample_host(alias, index as i64 + 10);
            host.egress_public_key = Some(egress_public_key.to_string());
            host
        })
        .collect::<Vec<_>>();
        let store = MemoryStore::with_hosts(hosts.clone());
        for (index, host) in hosts.iter().enumerate() {
            let mut member = sample_member(
                host.aliases.primary().as_str(),
                AegisHostMode::Leaf,
                index as i64 + 10,
            );
            member.wireguard_public_key = Some(
                [
                    TEST_GATEWAY_WIREGUARD_KEY,
                    TEST_DIRECT_PEER_WIREGUARD_KEY,
                    TEST_THIRD_WIREGUARD_KEY,
                ][index]
                    .to_string(),
            );
            store
                .write_network_member("aegis", &member, &test_network_config())
                .expect("egress network member should seed");
        }
        store
    }

    fn direct_gateway_store() -> MemoryStore {
        let store = active_hub_store();
        store.direct_gateways.lock().expect("lock").insert(
            host_id("hub-a"),
            AegisDirectGatewayRecord {
                host_id: host_id("hub-a"),
                wireguard: crate::aegis_store::AegisDirectWireGuardRecord {
                    public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
                    ipv4: "10.77.1.1".to_string(),
                    ipv6: "fd77::1:1".to_string(),
                    endpoints: vec!["203.0.113.8".to_string()],
                },
                created_unix: 10,
                updated_unix: 10,
                updated_by_principal: "user-1".to_string(),
            },
        );
        store
    }

    fn json_request<T: serde::Serialize>(
        method: Method,
        uri: &str,
        token: &str,
        body: &T,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(body).expect("request should serialize"),
            ))
            .expect("request should build")
    }

    fn empty_request(method: Method, uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request should build")
    }

    #[tokio::test]
    async fn get_hosts_requires_bearer_token() {
        let app = test_app(MemoryStore::default());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v2/aegis/hosts")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[tokio::test]
    async fn hosts_are_a_separate_global_resource() {
        let app = test_app(MemoryStore::with_hosts(vec![
            sample_host("zeta", 20),
            sample_host("alpha", 10),
        ]));
        let token = user_token(false);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v2/aegis/hosts")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        let payload: AegisHostListResponse = json_body(response).await;
        assert_eq!(2, payload.hosts.len());
        assert_eq!(
            "alpha",
            payload.hosts[&host_id("alpha")].aliases.primary().as_str()
        );
        assert_eq!(
            "zeta",
            payload.hosts[&host_id("zeta")].aliases.primary().as_str()
        );
    }

    #[tokio::test]
    async fn host_alias_lifecycle_preserves_identity_and_enforces_ownership() {
        let alpha_id = host_id("alpha");
        let beta: HostAlias = "beta".parse().expect("test host alias");
        let alpha: HostAlias = "alpha".parse().expect("test host alias");
        let gamma: HostAlias = "gamma".parse().expect("test host alias");
        let app = test_app(MemoryStore::with_hosts(vec![
            sample_host("alpha", 10),
            sample_host("gamma", 20),
        ]));
        let token = user_token(true);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::PUT,
                &format!("/v2{}", path::aegis_host_alias(&alpha_id, &beta)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CREATED, response.status());
        let host: AegisHost = json_body(response).await;
        assert_eq!(aliases("alpha").added(beta.clone()).unwrap(), host.aliases);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&beta)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let resolved: aegis_dto::protocol::AegisAliasResponse = json_body(response).await;
        assert_eq!(alpha_id, resolved.host_id);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2{}", path::aegis_host_alias_promote(&alpha_id, &beta)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let host: AegisHost = json_body(response).await;
        assert_eq!("beta", host.aliases.primary().as_str());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2{}", path::aegis_host_alias(&alpha_id, &beta)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::BAD_REQUEST, response.status());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2{}", path::aegis_host_alias(&alpha_id, &alpha)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let host: AegisHost = json_body(response).await;
        assert_eq!(aliases("beta"), host.aliases);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&alpha)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = app
            .oneshot(empty_request(
                Method::PUT,
                &format!("/v2{}", path::aegis_host_alias(&alpha_id, &gamma)),
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CONFLICT, response.status());
    }

    #[tokio::test]
    async fn alias_resolver_refuses_inconsistent_claims() {
        let alpha_id = host_id("alpha");
        let alpha_alias: HostAlias = "alpha".parse().expect("test host alias");
        let store = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        store
            .hosts
            .lock()
            .expect("lock")
            .get_mut(&alpha_id)
            .expect("host")
            .aliases = aliases("different");
        let response = test_app(store)
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&alpha_alias)),
                &user_token(true),
            ))
            .await
            .expect("request should be handled");
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, response.status());
    }

    #[tokio::test]
    async fn general_host_put_cannot_bypass_explicit_alias_operations() {
        let store = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        let app = test_app(store.clone());
        let response = app
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/hosts/{}", host_id("alpha")),
                &user_token(true),
                &AegisPutHostRequest {
                    aliases: aliases("beta"),
                    ssh: None,
                    transient: false,
                    pending: false,
                },
            ))
            .await
            .expect("host update should be handled");

        assert_eq!(StatusCode::CONFLICT, response.status());
        assert_eq!(
            aliases("alpha"),
            store
                .fetch_aegis_host(&host_id("alpha"))
                .await
                .expect("host read")
                .expect("host should remain")
                .aliases
        );
    }

    #[tokio::test]
    async fn host_alias_cannot_claim_a_satellite_name() {
        let store = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        store
            .satellites
            .lock()
            .expect("lock")
            .insert("pocket-a".to_string(), sample_satellite("pocket-a"));
        let app = test_app(store);
        let alias = "pocket-a".parse().expect("test host alias");
        let response = app
            .oneshot(empty_request(
                Method::PUT,
                &format!("/v2{}", path::aegis_host_alias(&host_id("alpha"), &alias)),
                &user_token(true),
            ))
            .await
            .expect("alias update should be handled");

        assert_eq!(StatusCode::CONFLICT, response.status());
    }

    #[tokio::test]
    async fn satellite_store_cannot_claim_a_host_alias() {
        let alpha_id = host_id("alpha");
        let store = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        let error = store
            .create_aegis_satellite(
                &sample_satellite("alpha"),
                &test_direct_gateway_config().address_pool(),
            )
            .await
            .expect_err("host aliases must remain unavailable to satellites");

        assert!(matches!(
            error,
            AegisDirectWriteError::HostAliasExists { alias, host_id }
                if alias.as_str() == "alpha" && host_id == alpha_id
        ));
    }

    #[tokio::test]
    async fn admin_can_issue_and_revoke_agent_token_for_an_enrolled_host() {
        let issuer = MemoryHostRefreshIssuer::default();
        let app = test_app_with_auth(
            MemoryStore::with_hosts(vec![sample_host("new-host", 10)]),
            Arc::new(issuer.clone()),
        );
        let token = user_token(true);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2/aegis/hosts/{}/agent-token", host_id("new-host")),
                &token,
            ))
            .await
            .expect("token issue request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let issued: AgentTokenIssueResponse = json_body(response).await;
        assert_eq!(host_id("new-host"), issued.host_id);
        assert_eq!("user-1", issued.created_by_principal);
        assert_eq!(1, issuer.issued.lock().expect("lock").len());

        let response = app
            .oneshot(json_request(
                Method::DELETE,
                "/v2/aegis/agent/token",
                &token,
                &AgentTokenRevokeRequest {
                    refresh_token: issued.refresh_token,
                },
            ))
            .await
            .expect("token revoke request should succeed");
        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(issuer.issued.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn enrollment_reserves_intent_then_activates_the_real_machine_identity() {
        let store = MemoryStore::default();
        store.add_user("operator-1");
        let issuer = Arc::new(MemoryHostRefreshIssuer::default());
        let app = test_app_with_auth(store.clone(), issuer.clone());
        let admin_token = user_token(true);
        let alias: HostAlias = "new-machine".parse().expect("test host alias");

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v2/aegis/enrollments",
                &admin_token,
                &AegisEnrollmentCreateRequest {
                    aliases: HostAliases::new(vec![alias.clone()]).expect("test aliases"),
                    network: "aegis".to_string(),
                    mode: AegisHostMode::Hub,
                    ssh: Some(AegisEnrollmentSsh {
                        port: Some(22),
                        external_principals: Vec::new(),
                    }),
                    transient: true,
                    initial_user_id: Some("operator-1".to_string()),
                    ttl_seconds: 3_600,
                },
            ))
            .await
            .expect("enrollment create should be handled");
        assert_eq!(StatusCode::CREATED, response.status());
        let enrollment: AegisEnrollment = json_body(response).await;
        let host_id = enrollment.host_id;
        assert!(!enrollment.credential_issued);
        assert!(store.hosts.lock().expect("lock").is_empty());
        assert!(store.network_members.lock().expect("lock").is_empty());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&alias)),
                &admin_token,
            ))
            .await
            .expect("reserved alias lookup should be handled");
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_credential(&host_id)),
                &admin_token,
            ))
            .await
            .expect("first enrollment credential should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let first: AegisEnrollmentCredentialResponse = json_body(response).await;
        let first_session_id = issuer.issued.lock().expect("lock")[0].sid.clone();
        let superseded_access = enrollment_token(&host_id, &first_session_id);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_credential(&host_id)),
                &admin_token,
            ))
            .await
            .expect("replacement enrollment credential should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let replacement: AegisEnrollmentCredentialResponse = json_body(response).await;
        assert_ne!(first.refresh_token, replacement.refresh_token);
        let issued = issuer.issued.lock().expect("lock").clone();
        assert_eq!(1, issued.len());
        let current_session_id = issued[0].sid.clone();
        let enrollment_access = enrollment_token(&host_id, &current_session_id);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_enrollment(&host_id)),
                &superseded_access,
            ))
            .await
            .expect("superseded credential lookup should be handled");
        assert_eq!(StatusCode::FORBIDDEN, response.status());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_prepare(&host_id)),
                &enrollment_access,
                &AegisEnrollmentPrepareRequest {
                    host_public_key: None,
                    wireguard_public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
                    wireguard_endpoints: vec!["203.0.113.10".to_string()],
                },
            ))
            .await
            .expect("invalid prepare should be handled");
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert!(store.hosts.lock().expect("lock").is_empty());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_prepare(&host_id)),
                &enrollment_access,
                &AegisEnrollmentPrepareRequest {
                    host_public_key: Some(TEST_USER_PUBLIC_KEY.to_string()),
                    wireguard_public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
                    wireguard_endpoints: vec!["203.0.113.10".to_string()],
                },
            ))
            .await
            .expect("prepare should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let prepared: AegisEnrollmentPrepareResponse = json_body(response).await;
        assert!(prepared.host.pending);
        assert!(prepared.member.member.pending);
        let prepared_host_key = prepared
            .host
            .ssh
            .and_then(|ssh| ssh.public_key)
            .expect("prepared SSH enrollment should publish its host key");
        assert_eq!(
            PublicKey::from_openssh(TEST_USER_PUBLIC_KEY)
                .expect("test key")
                .key_data(),
            PublicKey::from_openssh(&prepared_host_key)
                .expect("prepared host key")
                .key_data()
        );
        assert_eq!(
            Some(TEST_GATEWAY_WIREGUARD_KEY),
            prepared
                .member
                .member
                .wireguard
                .as_ref()
                .map(|wireguard| wireguard.public_key.as_str())
        );

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_heartbeat(&host_id)),
                &enrollment_access,
                &AegisEnrollmentHeartbeatRequest {
                    phase: AegisEnrollmentPhase::InstallingAgent,
                },
            ))
            .await
            .expect("installing heartbeat should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let installing: AegisEnrollment = json_body(response).await;
        assert_eq!(AegisEnrollmentPhase::InstallingAgent, installing.phase);

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_heartbeat(&host_id)),
                &enrollment_access,
                &AegisEnrollmentHeartbeatRequest {
                    phase: AegisEnrollmentPhase::PreparingMachine,
                },
            ))
            .await
            .expect("stale heartbeat should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let stale_retry: AegisEnrollment = json_body(response).await;
        assert_eq!(AegisEnrollmentPhase::InstallingAgent, stale_retry.phase);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&alias)),
                &admin_token,
            ))
            .await
            .expect("pending alias lookup should be handled");
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2{}", path::aegis_host(&host_id)),
                &admin_token,
                &AegisPutHostRequest {
                    aliases: HostAliases::new(vec![alias.clone()]).expect("test aliases"),
                    ssh: Some(AegisPutHostSsh {
                        port: Some(22),
                        public_key: Some(TEST_USER_PUBLIC_KEY.to_string()),
                        external_principals: Vec::new(),
                    }),
                    transient: true,
                    pending: true,
                },
            ))
            .await
            .expect("pending host update should be handled");
        assert_eq!(StatusCode::CONFLICT, response.status());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2{}", path::aegis_host(&host_id)),
                &admin_token,
            ))
            .await
            .expect("pending host deletion should be handled");
        assert_eq!(StatusCode::CONFLICT, response.status());

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_activate(&host_id)),
                &enrollment_access,
            ))
            .await
            .expect("activation should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let activated: AegisEnrollmentActivateResponse = json_body(response).await;
        assert!(!activated.host.pending);
        assert!(!activated.member.member.pending);
        assert!(store.enrollments.lock().expect("lock").is_empty());
        assert_eq!(
            super::aegis_host_subject(&host_id).expect("host subject"),
            issuer.issued.lock().expect("lock")[0].subject
        );

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::POST,
                &format!("/v2{}", path::aegis_enrollment_activate(&host_id)),
                &enrollment_access,
            ))
            .await
            .expect("idempotent activation should be handled");
        assert_eq!(StatusCode::OK, response.status());

        let response = app
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2{}", path::aegis_alias(&alias)),
                &admin_token,
            ))
            .await
            .expect("active alias lookup should be handled");
        assert_eq!(StatusCode::OK, response.status());
        let resolved: AegisAliasResponse = json_body(response).await;
        assert_eq!(host_id, resolved.host_id);
    }

    #[tokio::test]
    async fn put_host_cannot_create_an_identity_outside_enrollment() {
        let store = MemoryStore::default();
        let app = test_app(store.clone());
        let token = user_token(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("alpha")))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&AegisPutHostRequest {
                            aliases: aliases("alpha"),
                            ssh: Some(AegisPutHostSsh {
                                port: Some(2222),
                                public_key: Some(TEST_USER_PUBLIC_KEY.to_string()),
                                external_principals: vec!["bastion.example.com".to_string()],
                            }),
                            transient: true,
                            pending: true,
                        })
                        .expect("request should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        assert_eq!(
            StatusCode::NOT_FOUND,
            status,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            store
                .fetch_aegis_host(&host_id("alpha"))
                .await
                .expect("host lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_hosts_accepts_case_insensitive_bearer_scheme() {
        let app = test_app(MemoryStore::with_hosts(vec![sample_host("alpha", 10)]));
        let token = user_token(false);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v2/aegis/hosts")
                    .header("authorization", format!("bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn user_bearer_rejects_email_subjects() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Bearer {}",
                user_token_for_client_and_subject(false, AEGIS_TOOL_CLIENT_ID, "user@example.com")
            ))
            .expect("authorization header should parse"),
        );
        let error = super::UserBearer::from_headers(
            &headers,
            &test_state_with_auth(
                MemoryStore::default(),
                Arc::new(MemoryHostRefreshIssuer::default()),
            ),
        )
        .await
        .expect_err("email subject must be rejected");
        assert!(matches!(
            error,
            arche_web::error::ApiError::Forbidden(message)
                if message == "stable user subject required"
        ));
    }

    #[tokio::test]
    async fn put_host_report_commits_and_returns_canonical_stable_id_grants() {
        let store = MemoryStore::with_hosts(vec![sample_host("alpha", 10)]);
        store.add_user("OpaqueUserID");
        let app = test_app(store.clone());
        let token = agent_token(Some("alpha"));
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let request = AegisHostReportRequest {
            messages: vec![AegisHostMessage {
                level: AegisHostMessageLevel::Warning,
                value: "ssh config drift".to_string(),
            }],
            agent: AegisAgentStatus {
                version: "1.2.3".to_string(),
                health: AegisAgentHealth {
                    boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
                    reconciled_since_boot: true,
                    last_reconcile_unix: Some(now as u64),
                    last_reconcile_warning: None,
                    last_reconcile_error: None,
                    applied_aliases: Some(aliases("alpha")),
                },
                reported_unix: now,
            },
            principal_grants: vec![
                AegisPrincipalGrant {
                    login_principal: "ubuntu".to_string(),
                    user_id: "user-1".to_string(),
                },
                AegisPrincipalGrant {
                    login_principal: "deploy".to_string(),
                    user_id: "OpaqueUserID".to_string(),
                },
            ],
            ssh_lockdown_enabled: true,
            direct_gateway: AegisDirectGatewayReport {
                observed_unix: now,
                peers: Vec::new(),
            },
        };
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v2/aegis/hosts/{}/report", host_id("alpha")))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("request should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let response: AegisHostReportResponse = json_body(response).await;
        assert_eq!(
            vec![
                AegisPrincipalGrant {
                    login_principal: "deploy".to_string(),
                    user_id: "OpaqueUserID".to_string(),
                },
                AegisPrincipalGrant {
                    login_principal: "ubuntu".to_string(),
                    user_id: "user-1".to_string(),
                },
            ],
            response.principal_grants
        );
        let stored = store
            .fetch_aegis_host(&host_id("alpha"))
            .await
            .expect("store read should succeed")
            .expect("host should exist");
        assert_eq!("ssh config drift", stored.messages[0].value);
        assert_eq!(Some(now), stored.agent.map(|agent| agent.reported_unix));
        assert_eq!(response.principal_grants, stored.principal_grants);
    }

    #[tokio::test]
    async fn host_report_rejects_unknown_user_ids() {
        let error = super::canonicalize_principal_grants(
            &MemoryStore::default(),
            vec![AegisPrincipalGrant {
                login_principal: "ubuntu".to_string(),
                user_id: "unknown-user".to_string(),
            }],
        )
        .await
        .expect_err("unknown user must be rejected");
        assert!(matches!(
            error,
            arche_web::error::ApiError::BadRequest(message)
                if message == "unknown Aegis user id `unknown-user`"
        ));
    }

    #[tokio::test]
    async fn host_report_rejects_non_id_principals() {
        let error = super::canonicalize_principal_grants(
            &MemoryStore::default(),
            vec![AegisPrincipalGrant {
                login_principal: "ubuntu".to_string(),
                user_id: "user@example.com".to_string(),
            }],
        )
        .await
        .expect_err("an email must not be accepted as a user id");
        assert!(matches!(
            error,
            arche_web::error::ApiError::BadRequest(message)
                if message
                    == "Aegis user id must be non-empty, exact, whitespace-free, and contain no `@`"
        ));
    }

    #[tokio::test]
    async fn put_host_rejects_unknown_ssh_principals_field() {
        let app = test_app(MemoryStore::default());
        let token = user_token(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("alpha")))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "mode": "leaf",
                            "ssh": {
                                "user": "ubuntu",
                                "port": 2222,
                                "public_key": TEST_USER_PUBLIC_KEY,
                                "principals": ["bastion.example.com"],
                            },
                            "wireguard": {
                                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                "ipv4": "10.75.1.42",
                                "ipv6": "fd75::1:2a",
                            },
                            "pending": true,
                        }))
                        .expect("request should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let payload: ErrorResponse = json_body(response).await;
        assert!(!payload.error.is_empty());
    }

    #[tokio::test]
    async fn client_and_server_cert_endpoints_return_signed_certificates() {
        let mut alpha = sample_host("alpha", 10);
        alpha.principal_grants = vec![
            AegisPrincipalGrant {
                login_principal: "root".to_string(),
                user_id: "other-user".to_string(),
            },
            AegisPrincipalGrant {
                login_principal: "ubuntu".to_string(),
                user_id: "user-1".to_string(),
            },
            AegisPrincipalGrant {
                login_principal: "deploy".to_string(),
                user_id: "user-1".to_string(),
            },
        ];
        let store = MemoryStore::with_hosts(vec![alpha.clone()]);
        store
            .write_network_member(
                "aegis",
                &sample_member("alpha", AegisHostMode::Leaf, 10),
                &test_network_config(),
            )
            .expect("network member should seed");
        let app = test_app(store);
        let agent_access_token = agent_token(Some("alpha"));

        let mut expected_client_principals = ["deploy", "ubuntu"]
            .into_iter()
            .map(|login| aegis_user_cert_principal(&host_id("alpha"), login, "user-1"))
            .collect::<Vec<_>>();
        expected_client_principals.sort();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v2/aegis/networks/aegis/members/{}/client-cert",
                        host_id("alpha")
                    ))
                    .header("authorization", format!("Bearer {}", user_token(false)))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&AegisHostClientCertRequest {
                            ed25519_public_key: TEST_USER_PUBLIC_KEY.to_string(),
                        })
                        .expect("request should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        let payload: SshIssueCertResponse = json_body(response).await;
        let cert =
            Certificate::from_openssh(&payload.certificate).expect("certificate should parse");
        assert_eq!(CertType::User, cert.cert_type());
        assert_eq!(
            expected_client_principals,
            cert.valid_principals()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v2/aegis/networks/aegis/members/{}/server-cert",
                        host_id("alpha")
                    ))
                    .header("authorization", format!("Bearer {agent_access_token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        let payload: SshIssueCertResponse = json_body(response).await;
        let cert =
            Certificate::from_openssh(&payload.certificate).expect("certificate should parse");
        assert_eq!(
            vec![
                "alpha",
                "alpha.aegis.x.hoek.io",
                "10.75.1.42",
                "fd75::1:2a",
                "10.75.0.1",
                "fd75::1",
            ],
            cert.valid_principals()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn disabled_users_cannot_obtain_client_certificates() {
        let store = active_hub_store();
        store.set_user_disabled("user-1", true);
        let response = test_app(store)
            .oneshot(json_request(
                Method::POST,
                &format!(
                    "/v2/aegis/networks/aegis/members/{}/client-cert",
                    host_id("hub-a")
                ),
                &user_token(false),
                &AegisHostClientCertRequest {
                    ed25519_public_key: TEST_USER_PUBLIC_KEY.to_string(),
                },
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        let error: ErrorResponse = json_body(response).await;
        assert_eq!("Aegis user is disabled", error.error);
    }

    #[tokio::test]
    async fn direct_gateways_are_permanent_hub_resources_published_after_local_apply() {
        let store = active_hub_store();
        let app = test_app(store.clone());
        let token = user_token(true);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2/aegis/direct-gateways/{}/inventory", host_id("hub-a")),
                &agent_token(Some("hub-a")),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let inventory: AegisDirectGatewayInventory = json_body(response).await;
        assert!(inventory.enabled);
        assert!(inventory.published.is_none());
        assert!(inventory.satellites.is_empty());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/v2/aegis/satellites/pocket-a",
                &token,
                &AegisSatelliteCreateRequest {
                    wireguard_public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
                    ssh_public_key: TEST_USER_PUBLIC_KEY.to_string(),
                },
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CONFLICT, response.status());
        let error: aegis_dto::protocol::ErrorResponse = json_body(response).await;
        assert_eq!(
            "satellite gateways have not reported ready: hub-a",
            error.error
        );
        assert!(store.satellites.lock().expect("lock").is_empty());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/direct-gateways/{}", host_id("hub-a")),
                &agent_token(Some("hub-a")),
                &AegisDirectGatewayPublishRequest {
                    public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
                    endpoints: vec!["203.0.113.8".to_string(), "2001:db8::8".to_string()],
                },
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let hub: aegis_dto::protocol::AegisDirectGateway = json_body(response).await;
        assert_eq!("10.77.1.1", hub.wireguard.ipv4);
        assert_eq!("fd77::1:1", hub.wireguard.ipv6);
        assert_eq!(
            vec!["203.0.113.8".to_string(), "2001:db8::8".to_string()],
            hub.wireguard.endpoints
        );
        assert!(
            store
                .direct_gateways
                .lock()
                .expect("lock")
                .contains_key(&host_id("hub-a")),
            "the PUT is the agent's post-apply readiness publication"
        );

        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/v2/aegis/satellites/pocket-a",
                &token,
                &AegisSatelliteCreateRequest {
                    wireguard_public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
                    ssh_public_key: TEST_USER_PUBLIC_KEY.to_string(),
                },
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CREATED, response.status());
        let provision: AegisSatelliteProvisionResponse = json_body(response).await;
        assert!(provision.gateways.contains_key(&host_id("hub-a")));

        let second_hub = sample_host("hub-b", 11);
        let mut second_member = sample_member("hub-b", AegisHostMode::Hub, 11);
        second_member.wireguard_public_key =
            Some("BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=".to_string());
        second_member.wireguard_ipv4 = Some("10.75.1.43".to_string());
        second_member.wireguard_ipv6 = Some("fd75::1:2b".to_string());
        store
            .write_host(&second_hub)
            .expect("second hub host should seed");
        store
            .write_network_member("aegis", &second_member, &test_network_config())
            .expect("second hub network member should seed");
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/direct-gateways/{}", host_id("hub-b")),
                &agent_token(Some("hub-b")),
                &AegisDirectGatewayPublishRequest {
                    public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
                    endpoints: vec!["203.0.113.9".to_string()],
                },
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CONFLICT, response.status());

        store
            .hosts
            .lock()
            .expect("lock")
            .get_mut(&host_id("hub-a"))
            .expect("hub should exist")
            .ssh
            .as_mut()
            .expect("hub should publish ssh")
            .port = Some(2222);
        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                &format!("/v2/aegis/direct-gateways/{}/inventory", host_id("hub-a")),
                &agent_token(Some("hub-a")),
            ))
            .await
            .expect("request should succeed");
        let inventory: AegisDirectGatewayInventory = json_body(response).await;
        assert!(!inventory.enabled);
        assert!(inventory.published.is_some());

        let response = app
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2/aegis/direct-gateways/{}", host_id("hub-a")),
                &agent_token(Some("hub-a")),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(
            !store
                .direct_gateways
                .lock()
                .expect("lock")
                .contains_key(&host_id("hub-a"))
        );
    }

    #[tokio::test]
    async fn satellite_provisioning_is_global_direct_certificate_authenticated_and_revocable() {
        let store = direct_gateway_store();
        let app = test_app(store.clone());
        let token = user_token(true);
        let request = AegisSatelliteCreateRequest {
            wireguard_public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
            ssh_public_key: TEST_USER_PUBLIC_KEY.to_string(),
        };
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/v2/aegis/satellites/pocket-a",
                &token,
                &request,
            ))
            .await
            .expect("request should succeed");
        if response.status() != StatusCode::CREATED {
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("error response body should collect");
            panic!(
                "satellite creation returned {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let provision: AegisSatelliteProvisionResponse = json_body(response).await;
        assert!(provision.gateways.contains_key(&host_id("hub-a")));
        let gateway_token = agent_token(Some("hub-a"));
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/v2/aegis/satellites/pocket-a",
                &token,
                &request,
            ))
            .await
            .expect("idempotent provisioning request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let resumed: AegisSatelliteProvisionResponse = json_body(response).await;
        assert!(resumed.gateways.contains_key(&host_id("hub-a")));
        assert_eq!("user-1", provision.satellite.owner_principal);
        assert_eq!("10.77.1.2", provision.satellite.wireguard.ipv4);
        assert_eq!("fd77::1:2", provision.satellite.wireguard.ipv6);
        PublicKey::from_openssh(&provision.server_ca_public_key)
            .expect("server CA key should parse");
        let certificate = Certificate::from_openssh(&provision.ssh_certificate)
            .expect("satellite certificate should parse");
        assert_eq!(CertType::User, certificate.cert_type());
        let credential_id = store
            .satellites
            .lock()
            .expect("lock")
            .get("pocket-a")
            .expect("satellite should be stored")
            .credential_id
            .clone();
        assert_eq!(
            vec![aegis_direct_cert_principal(&credential_id).expect("valid credential id")],
            certificate
                .valid_principals()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            Some("10.77.1.2/32,fd77::1:2/128"),
            certificate
                .critical_options()
                .get("source-address")
                .map(String::as_str)
        );
        assert_eq!(
            Some(aegis_dto::layout::SYSTEM_BINARY_PATH.to_string() + " ssh"),
            certificate.critical_options().get("force-command").cloned()
        );
        assert_eq!(
            vec!["permit-pty"],
            certificate
                .extensions()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                "/v2/aegis/satellites/pocket-a/targets",
                &gateway_token,
            ))
            .await
            .expect("target request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let targets: AegisDirectTargetListResponse = json_body(response).await;
        assert_eq!(1, targets.targets.len());
        assert_eq!(host_id("hub-a"), targets.targets[0].host_id);
        assert_eq!("hub-a", targets.targets[0].aliases.primary().as_str());
        assert_eq!(vec!["ubuntu"], targets.targets[0].login_principals);

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v2/aegis/satellites/pocket-a/client-cert",
                &gateway_token,
                &AegisDirectClientCertRequest {
                    target_host_id: host_id("hub-a"),
                    login_principal: "ubuntu".to_string(),
                    ed25519_public_key: TEST_USER_PUBLIC_KEY.to_string(),
                },
            ))
            .await
            .expect("direct client certificate request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let brokered: AegisDirectClientCertResponse = json_body(response).await;
        assert_eq!(host_id("hub-a"), brokered.target.host_id);
        assert_eq!("ubuntu", brokered.login_principal);
        let brokered_certificate = Certificate::from_openssh(&brokered.certificate)
            .expect("brokered certificate should parse");
        assert_eq!(CertType::User, brokered_certificate.cert_type());
        assert_eq!(
            vec![aegis_user_cert_principal(
                &host_id("hub-a"),
                "ubuntu",
                "user-1"
            )],
            brokered_certificate
                .valid_principals()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
        assert!(
            brokered_certificate
                .valid_before()
                .saturating_sub(OffsetDateTime::now_utc().unix_timestamp() as u64)
                <= PRINCIPAL_CLIENT_CERT_TTL_SECONDS as u64
        );
        let activity = store
            .satellites
            .lock()
            .expect("lock")
            .get("pocket-a")
            .expect("satellite should remain stored")
            .broker_uses
            .get(&host_id("hub-a"))
            .expect("broker use should be recorded")
            .clone();
        assert_eq!(host_id("hub-a"), activity.gateway_host_id);
        assert_eq!(host_id("hub-a"), activity.target_host_id);
        assert!(activity.used_unix > 0);

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                "/v2/aegis/satellites/pocket-a/targets",
                &token,
            ))
            .await
            .expect("non-agent target request should be rejected");
        assert_eq!(StatusCode::FORBIDDEN, response.status());

        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                "/v2/aegis/satellites/pocket-b",
                &token,
                &request,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CONFLICT, response.status());
        let error: ErrorResponse = json_body(response).await;
        assert!(error.error.contains("WireGuard public key"));

        let response = app
            .clone()
            .oneshot(empty_request(
                Method::DELETE,
                "/v2/aegis/satellites/pocket-a",
                &token,
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(
            store
                .satellites
                .lock()
                .expect("lock")
                .get("pocket-a")
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_satellite_owners_cannot_use_persistent_broker_credentials() {
        let store = direct_gateway_store();
        store
            .satellites
            .lock()
            .expect("lock")
            .insert("pocket-a".to_string(), sample_satellite("pocket-a"));
        store.set_user_disabled("user-1", true);
        let response = test_app(store)
            .oneshot(empty_request(
                Method::GET,
                "/v2/aegis/satellites/pocket-a/targets",
                &agent_token(Some("hub-a")),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        let error: ErrorResponse = json_body(response).await;
        assert_eq!("Aegis user is disabled", error.error);
    }

    #[tokio::test]
    async fn delete_missing_host_returns_not_found() {
        let app = test_app(MemoryStore::default());
        let token = user_token(true);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("missing")))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::NOT_FOUND, response.status());
        let payload: ErrorResponse = json_body(response).await;
        assert_eq!(
            format!("unknown host or network member `{}`", host_id("missing")),
            payload.error
        );
    }

    #[tokio::test]
    async fn delete_host_cascades_to_every_network_membership() {
        let alpha = sample_host("alpha", 10);
        let store = MemoryStore::with_hosts(vec![alpha.clone()]);
        store
            .write_network_member(
                "aegis",
                &sample_member("alpha", AegisHostMode::Leaf, 10),
                &test_network_config(),
            )
            .expect("network member should seed");
        let app = test_app(store.clone());
        let token = user_token(true);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("alpha")))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(
            store
                .fetch_aegis_host(&host_id("alpha"))
                .await
                .expect("host lookup should succeed")
                .is_none()
        );
        assert!(
            store
                .fetch_aegis_network_member("aegis", &host_id("alpha"))
                .await
                .expect("network-member lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn orphan_delete_removes_a_network_only_member() {
        let store = MemoryStore::default();
        let mut member = sample_member("orphaned", AegisHostMode::Leaf, 10);
        member.wireguard_ipv4 = Some("10.75.1.44".to_string());
        member.wireguard_ipv6 = Some("fd75::1:2c".to_string());
        store
            .write_network_member("aegis", &member, &test_network_config())
            .expect("network-only member should seed");
        let app = test_app(store.clone());
        let response = app
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2/aegis/hosts/{}", host_id("orphaned")),
                &user_token(true),
            ))
            .await
            .expect("request should succeed");

        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(
            store
                .fetch_aegis_network_member("aegis", &host_id("orphaned"))
                .await
                .expect("network member lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_host_also_removes_its_direct_gateway() {
        let store = direct_gateway_store();
        let app = test_app(store.clone());
        let response = app
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2/aegis/hosts/{}", host_id("hub-a")),
                &user_token(true),
            ))
            .await
            .expect("request should succeed");

        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert!(store.direct_gateways.lock().expect("lock").is_empty());
        assert!(
            !store
                .hosts
                .lock()
                .expect("lock")
                .contains_key(&host_id("hub-a"))
        );
    }

    #[tokio::test]
    async fn public_ca_endpoints_return_parseable_keys() {
        let app = test_app(MemoryStore::default());
        for uri in ["/v2/aegis/ssh/ca/user", "/v2/aegis/ssh/ca/host"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("request should succeed");
            assert_eq!(StatusCode::OK, response.status());
            let payload: SshCaPublicKeyResponse = json_body(response).await;
            let public_key =
                PublicKey::from_openssh(&payload.public_key).expect("public key should parse");
            assert_eq!(ssh_key::Algorithm::Ed25519, public_key.algorithm());
        }
    }

    #[tokio::test]
    async fn tls_root_ca_endpoint_returns_public_pem_without_auth() {
        let app = test_app(MemoryStore::default());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v2/aegis/tls/cas/root.pem")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::OK, response.status());
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should collect");
        let body = String::from_utf8(body.to_vec()).expect("body should be UTF-8");
        assert_eq!(
            "-----BEGIN CERTIFICATE-----\ntest-root\n-----END CERTIFICATE-----\n",
            body
        );
    }

    #[tokio::test]
    async fn egress_selection_needs_only_the_source_and_retains_the_old_route_until_applied() {
        let store = egress_ready_store();
        let app = test_app(store.clone());
        let uri = format!("/v2/aegis/egress/{}", host_id("source"));
        let result_uri = format!("{uri}/result");
        let inventory = app
            .clone()
            .oneshot(empty_request(
                Method::GET,
                "/v2/aegis/egress",
                &agent_token(Some("source")),
            ))
            .await
            .unwrap();
        let inventory: AegisEgressInventory = json_body(inventory).await;
        assert_eq!(3, inventory.hosts.len());
        assert!(inventory.policies.is_empty());
        let mut previous = None;
        let initial_generation = store.read_aegis_egress_snapshot().await.unwrap().generation;
        for (target, revision) in [
            ("target-a", initial_generation + 1),
            ("target-b", initial_generation + 3),
        ] {
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::PUT,
                    &uri,
                    &user_token(true),
                    &AegisEgressEnableRequest {
                        via: host_id(target),
                    },
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::ACCEPTED, response.status());
            let pending: AegisEgressStatus = json_body(response).await;
            let pending = pending.policy.unwrap();
            assert_eq!(previous, pending.active_via);
            assert_eq!(Some(host_id(target)), pending.desired_via);
            assert_eq!(revision, pending.revision);
            // Gateways cannot acknowledge or mutate a source's route.
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    &result_uri,
                    &agent_token(Some(target)),
                    &AegisEgressResult {
                        revision,
                        outcome: AegisEgressOutcome::Applied,
                    },
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::FORBIDDEN, response.status());
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    &result_uri,
                    &agent_token(Some("source")),
                    &AegisEgressResult {
                        revision: revision + 1,
                        outcome: AegisEgressOutcome::Applied,
                    },
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::CONFLICT, response.status());
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    &result_uri,
                    &agent_token(Some("source")),
                    &AegisEgressResult {
                        revision,
                        outcome: AegisEgressOutcome::Applied,
                    },
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::OK, response.status());
            let applied: AegisEgressStatus = json_body(response).await;
            assert!(applied.policy.as_ref().unwrap().is_steady());
            previous = Some(host_id(target));
            assert_eq!(previous, applied.policy.unwrap().active_via);
        }
        let response = app
            .clone()
            .oneshot(empty_request(Method::DELETE, &uri, &user_token(true)))
            .await
            .unwrap();
        assert_eq!(StatusCode::ACCEPTED, response.status());
        let policy = store
            .fetch_aegis_egress_policy(&host_id("source"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(previous, policy.active_via);
        assert_eq!(None, policy.desired_via);
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &result_uri,
                &agent_token(Some("source")),
                &AegisEgressResult {
                    revision: policy.revision,
                    outcome: AegisEgressOutcome::Applied,
                },
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert!(
            store
                .fetch_aegis_egress_policy(&host_id("source"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn egress_revisions_are_not_reused_after_disable_and_reenable() {
        let store = egress_ready_store();
        let app = test_app(store);
        let uri = format!("/v2/aegis/egress/{}", host_id("source"));
        let result_uri = format!("{uri}/result");
        let request = AegisEgressEnableRequest {
            via: host_id("target-a"),
        };
        let pending: AegisEgressStatus = json_body(
            app.clone()
                .oneshot(json_request(Method::PUT, &uri, &user_token(true), &request))
                .await
                .unwrap(),
        )
        .await;
        let old_revision = pending.policy.unwrap().revision;
        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                &result_uri,
                &agent_token(Some("source")),
                &AegisEgressResult {
                    revision: old_revision,
                    outcome: AegisEgressOutcome::Rejected,
                },
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let pending: AegisEgressStatus = json_body(
            app.clone()
                .oneshot(json_request(Method::PUT, &uri, &user_token(true), &request))
                .await
                .unwrap(),
        )
        .await;
        assert!(pending.policy.unwrap().revision > old_revision);
        let response = app
            .oneshot(json_request(
                Method::POST,
                &result_uri,
                &agent_token(Some("source")),
                &AegisEgressResult {
                    revision: old_revision,
                    outcome: AegisEgressOutcome::Applied,
                },
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::CONFLICT, response.status());
    }

    #[tokio::test]
    async fn egress_policy_rejects_cycles_non_admins_and_unrelated_overlapping_mutations() {
        let store = egress_ready_store();
        store.egress.lock().expect("lock").policies.extend([
            (
                host_id("source"),
                AegisEgressPolicy {
                    source_host_id: host_id("source"),
                    revision: 1,
                    active_via: Some(host_id("target-a")),
                    desired_via: Some(host_id("target-a")),

                    updated_unix: 1,
                    updated_by_principal: "test".to_string(),
                },
            ),
            (
                host_id("target-a"),
                AegisEgressPolicy {
                    source_host_id: host_id("target-a"),
                    revision: 1,
                    active_via: Some(host_id("target-b")),
                    desired_via: Some(host_id("target-b")),

                    updated_unix: 1,
                    updated_by_principal: "test".to_string(),
                },
            ),
        ]);
        let app = test_app(store.clone());
        let request = AegisEgressEnableRequest {
            via: host_id("source"),
        };
        store.users.lock().unwrap().get_mut("user-1").unwrap().admin = false;
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/egress/{}", host_id("target-b")),
                &user_token(false),
                &request,
            ))
            .await
            .expect("non-admin request should be handled");
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        store.users.lock().unwrap().get_mut("user-1").unwrap().admin = true;
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/egress/{}", host_id("target-b")),
                &user_token(true),
                &request,
            ))
            .await
            .expect("cycle request should be handled");
        assert_eq!(StatusCode::CONFLICT, response.status());

        let mut reconciling = store
            .fetch_aegis_egress_policy(&host_id("source"))
            .await
            .expect("policy lookup")
            .expect("seeded policy");
        reconciling.desired_via = Some(host_id("target-b"));
        store
            .egress
            .lock()
            .expect("lock")
            .policies
            .insert(host_id("source"), reconciling);
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/egress/{}", host_id("target-a")),
                &user_token(true),
                &AegisEgressEnableRequest {
                    via: host_id("source"),
                },
            ))
            .await
            .expect("transient cycle request should be handled");
        assert_eq!(StatusCode::CONFLICT, response.status());
        let response = app
            .oneshot(empty_request(
                Method::DELETE,
                &format!("/v2/aegis/egress/{}", host_id("source")),
                &user_token(true),
            ))
            .await
            .expect("concurrent disable must not supersede a source operation");
        assert_eq!(StatusCode::CONFLICT, response.status());
        let disabling = store
            .fetch_aegis_egress_policy(&host_id("source"))
            .await
            .expect("policy lookup")
            .expect("disable transition");
        assert_eq!(Some(host_id("target-a")), disabling.active_via);
        assert_eq!(Some(host_id("target-b")), disabling.desired_via);
    }

    #[tokio::test]
    async fn rejected_egress_operation_releases_only_its_own_reservation() {
        for previous in [None, Some(host_id("target-a"))] {
            let store = egress_ready_store();
            store.egress.lock().unwrap().policies.insert(
                host_id("source"),
                AegisEgressPolicy {
                    source_host_id: host_id("source"),
                    revision: 4,
                    active_via: previous,
                    desired_via: Some(host_id("target-b")),
                    updated_unix: 1,
                    updated_by_principal: "test".into(),
                },
            );
            let app = test_app(store.clone());
            let uri = format!("/v2/aegis/egress/{}/result", host_id("source"));
            let response = app
                .oneshot(json_request(
                    Method::POST,
                    &uri,
                    &agent_token(Some("source")),
                    &AegisEgressResult {
                        revision: 4,
                        outcome: AegisEgressOutcome::Rejected,
                    },
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::OK, response.status());
            let status: AegisEgressStatus = json_body(response).await;
            assert_eq!(
                previous,
                status.policy.as_ref().and_then(|policy| policy.active_via)
            );
            assert!(
                status
                    .policy
                    .as_ref()
                    .is_none_or(AegisEgressPolicy::is_steady)
            );
        }
    }

    #[tokio::test]
    async fn egress_policy_writes_are_serialized_across_sources() {
        let store = egress_ready_store();
        let generation = store
            .read_aegis_egress_snapshot()
            .await
            .expect("snapshot should load")
            .generation;
        let source_policy = AegisEgressPolicy {
            source_host_id: host_id("source"),
            revision: generation + 1,
            active_via: None,
            desired_via: Some(host_id("target-a")),

            updated_unix: 1,
            updated_by_principal: "test".to_string(),
        };
        store
            .compare_and_set_aegis_egress_policy(
                &host_id("source"),
                generation,
                None,
                Some(&source_policy),
            )
            .await
            .expect("first policy write should succeed");

        let target_policy = AegisEgressPolicy {
            source_host_id: host_id("target-a"),
            desired_via: Some(host_id("target-b")),
            ..source_policy
        };
        assert!(matches!(
            store
                .compare_and_set_aegis_egress_policy(
                    &host_id("target-a"),
                    generation,
                    None,
                    Some(&target_policy),
                )
                .await,
            Err(AegisEgressWriteError::ConcurrentWrite { .. })
        ));
    }

    #[tokio::test]
    async fn host_deletion_never_turns_a_dependent_egress_policy_direct() {
        let store = egress_ready_store();
        store.egress.lock().expect("lock").policies.insert(
            host_id("source"),
            AegisEgressPolicy {
                source_host_id: host_id("source"),
                revision: 3,
                active_via: Some(host_id("target-a")),
                desired_via: Some(host_id("target-a")),

                updated_unix: 1,
                updated_by_principal: "user-1".to_string(),
            },
        );
        let app = test_app(store.clone());
        let token = user_token(true);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("target-a")))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::CONFLICT, response.status());
        assert!(
            store
                .hosts
                .lock()
                .expect("lock")
                .contains_key(&host_id("target-a"))
        );
        assert_eq!(
            Some(host_id("target-a")),
            store
                .egress
                .lock()
                .expect("lock")
                .policies
                .get(&host_id("source"))
                .and_then(|policy| policy.active_via)
        );

        store.egress.lock().expect("lock").policies.insert(
            host_id("source"),
            AegisEgressPolicy {
                source_host_id: host_id("source"),
                revision: 6,
                active_via: Some(host_id("target-b")),
                desired_via: Some(host_id("target-b")),

                updated_unix: 2,
                updated_by_principal: "agent:source".to_string(),
            },
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v2/aegis/hosts/{}", host_id("target-a")))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(StatusCode::NO_CONTENT, response.status());
        let egress = store.egress.lock().expect("lock");
        let policies = &egress.policies;
        let policy = policies
            .get(&host_id("source"))
            .expect("source policy should remain");
        assert_eq!(Some(host_id("target-b")), policy.active_via);
        assert_eq!(6, policy.revision);
    }

    #[tokio::test]
    async fn only_the_host_agent_can_publish_an_egress_identity() {
        let host = sample_host("source", 10);
        let store = MemoryStore::with_hosts(vec![host.clone()]);
        store
            .write_network_member(
                "aegis",
                &sample_member("source", AegisHostMode::Leaf, 10),
                &test_network_config(),
            )
            .expect("network member should seed");
        let app = test_app(store.clone());
        let body = aegis_dto::protocol::AegisEgressIdentityRequest {
            public_key: TEST_GATEWAY_WIREGUARD_KEY.to_string(),
        };
        let response = app
            .clone()
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/hosts/{}/egress", host_id("source")),
                &agent_token(Some("target-a")),
                &body,
            ))
            .await
            .expect("wrong agent request should be handled");
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        let response = app
            .oneshot(json_request(
                Method::PUT,
                &format!("/v2/aegis/hosts/{}/egress", host_id("source")),
                &agent_token(Some("source")),
                &body,
            ))
            .await
            .expect("identity request should succeed");
        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert_eq!(
            Some(TEST_GATEWAY_WIREGUARD_KEY),
            store
                .fetch_aegis_host(&host_id("source"))
                .await
                .expect("host lookup")
                .and_then(|host| host.egress_public_key)
                .as_deref()
        );
    }

    #[test]
    fn satellite_status_aggregates_presence_across_every_gateway() {
        let satellite = AegisSatelliteRecord {
            slug: "pocket-a".to_string(),
            credential_id: "0123456789abcdef0123456789abcdef".to_string(),
            owner_principal: "user-1".to_string(),
            wireguard: crate::aegis_store::AegisDirectWireGuardRecord {
                public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
                ipv4: "10.77.1.2".to_string(),
                ipv6: "fd77::1:2".to_string(),
                endpoints: Vec::new(),
            },
            ssh_public_key: TEST_USER_PUBLIC_KEY.to_string(),
            created_unix: 1,
            created_by_principal: "user-1".to_string(),
            broker_uses: [(
                host_id("leaf-a"),
                AegisSatelliteBrokerUseRecord {
                    used_unix: 40,
                    gateway_host_id: host_id("hub-b"),
                    target_host_id: host_id("leaf-a"),
                },
            )]
            .into_iter()
            .collect(),
        };
        let mut hub_a = sample_host("hub-a", 10);
        hub_a.direct_gateway_report = Some(AegisDirectGatewayReport {
            observed_unix: 60,
            peers: vec![AegisDirectPeerObservation {
                public_key: TEST_DIRECT_PEER_WIREGUARD_KEY.to_string(),
                latest_handshake_unix: Some(55),
            }],
        });
        let mut hub_b = sample_host("hub-b", 10);
        hub_b.direct_gateway_report = Some(AegisDirectGatewayReport {
            observed_unix: 61,
            peers: Vec::new(),
        });
        let hosts = [
            (host_id("hub-a"), hub_a),
            (host_id("hub-b"), hub_b),
            (host_id("leaf-a"), sample_host("leaf-a", 10)),
        ]
        .into_iter()
        .collect();
        let gateways = [host_id("hub-a"), host_id("hub-b")].into_iter().collect();

        let status = satellite_status(&satellite, &gateways, &hosts);

        assert!(status.gateways[&host_id("hub-a")].installed);
        assert_eq!(
            Some(55),
            status.gateways[&host_id("hub-a")].latest_handshake_unix
        );
        assert!(!status.gateways[&host_id("hub-b")].installed);
        assert_eq!(Some(61), status.gateways[&host_id("hub-b")].observed_unix);
        assert_eq!(
            Some(host_id("leaf-a")),
            status
                .last_broker_use
                .as_ref()
                .map(|broker_use| broker_use.target_host_id)
        );
    }
}

impl<S> AegisState<S> {
    pub(crate) fn new(parts: AegisStateParts<'_, S>) -> anyhow::Result<Self> {
        Ok(Self {
            store: parts.store,
            auth: parts.auth,
            issuer: parts.issuer,
            client_ca: parts.client_ca.clone(),
            client_ca_key: Arc::new(load_ca_private_key(
                &parts.client_ca.private_key_pem,
                parts.client_ca.passphrase.as_deref(),
            )?),
            direct_client_ca_key: Arc::new(load_ca_private_key(
                &parts.direct_client_ca.private_key_pem,
                parts.direct_client_ca.passphrase.as_deref(),
            )?),
            server_ca: parts.server_ca.clone(),
            server_ca_key: Arc::new(load_ca_private_key(
                &parts.server_ca.private_key_pem,
                parts.server_ca.passphrase.as_deref(),
            )?),
            tls: parts.tls.clone(),
            api_issuer: parts.api_issuer.to_string(),
            api_audience: parts.api_audience.to_string(),
            user_api_audience: parts.user_api_audience.to_string(),
            namespace: parts.namespace,
            cfg: parts.cfg.clone(),
        })
    }
}

struct PutHostOutcome {
    host: AegisHost,
}

struct PutNetworkMemberOutcome {
    member: AegisNetworkMember,
}

#[derive(Clone, Debug)]
struct UserBearer {
    claims: AccessClaims,
    admin: bool,
}

#[derive(Clone, Debug)]
struct UserAdminBearer {
    claims: AccessClaims,
}

#[derive(Clone, Debug)]
struct AgentPrincipal {
    host_id: HostId,
}

#[derive(Clone, Debug)]
struct HostSelfPrincipal {
    host_id: HostId,
}

#[derive(Clone, Debug)]
struct EnrollmentPrincipal {
    session_id: String,
}

trait FleetReader {}

impl FleetReader for UserBearer {}
impl FleetReader for AgentPrincipal {}

trait ServerCertIssuer {}

impl ServerCertIssuer for UserAdminBearer {}
impl ServerCertIssuer for HostSelfPrincipal {}
impl ServerCertIssuer for EnrollmentPrincipal {}

trait HostWriter {
    fn updated_by_principal(&self) -> String;
}

impl HostWriter for UserAdminBearer {
    fn updated_by_principal(&self) -> String {
        self.principal().to_string()
    }
}

impl HostWriter for HostSelfPrincipal {
    fn updated_by_principal(&self) -> String {
        format!("agent:{}", self.host_id())
    }
}

impl UserBearer {
    async fn from_headers<S: AegisStore + Sync>(
        headers: &HeaderMap,
        state: &AegisState<S>,
    ) -> Result<Self, ApiError> {
        let claims = state
            .issuer
            .decode_access(bearer_token(headers)?, &state.user_api_audience)
            .map_err(|_| ApiError::Unauthorized("invalid access token".into()))?;
        let user_id = claims
            .sub
            .strip_kind("user")
            .ok_or_else(|| ApiError::Forbidden("user subject required".into()))?;
        validate_aegis_user_id(user_id)
            .map_err(|_| ApiError::Forbidden("stable user subject required".into()))?;
        require_client_binding(&claims, AEGIS_TOOL_CLIENT_ID)?;
        require_scope(&claims, AEGIS_USER_SCOPE)?;
        if !state
            .store
            .user_session_active(&claims, OffsetDateTime::now_utc().unix_timestamp())
            .await?
        {
            return Err(ApiError::Unauthorized(
                "user session expired or revoked".into(),
            ));
        }

        let user = resolve_active_aegis_user(&state.store, user_id)
            .await?
            .ok_or_else(|| ApiError::Forbidden("namespace membership required".into()))?;
        Ok(Self {
            claims,
            admin: user.admin,
        })
    }

    fn principal(&self) -> &str {
        self.claims
            .sub
            .strip_kind("user")
            .expect("constructor requires user subject")
    }
}

impl UserAdminBearer {
    async fn from_headers<S: AegisStore + Sync>(
        headers: &HeaderMap,
        state: &AegisState<S>,
    ) -> Result<Self, ApiError> {
        let bearer = UserBearer::from_headers(headers, state).await?;
        if !bearer.admin {
            return Err(ApiError::Forbidden(
                "namespace administrator required".into(),
            ));
        }
        Ok(Self {
            claims: bearer.claims,
        })
    }

    fn principal(&self) -> &str {
        self.claims
            .sub
            .strip_kind("user")
            .expect("constructor requires user subject")
    }
}

impl AgentPrincipal {
    fn from_headers(
        headers: &HeaderMap,
        issuer: &JwtIssuer,
        audience: &str,
    ) -> Result<Self, ApiError> {
        let claims = issuer
            .decode_access(bearer_token(headers)?, audience)
            .map_err(|_| ApiError::Unauthorized("invalid access token".into()))?;
        let host_id = aegis_host_id_from_subject(&claims.sub)
            .map_err(|_| ApiError::Forbidden("host subject required".into()))?;
        require_client_binding(&claims, AGENT_CLIENT_ID)?;
        require_scope(&claims, AEGIS_HOST_SELF_SCOPE)?;
        Ok(Self { host_id })
    }
}

impl EnrollmentPrincipal {
    fn from_headers(
        headers: &HeaderMap,
        issuer: &JwtIssuer,
        audience: &str,
        expected_host_id: &HostId,
    ) -> Result<Self, ApiError> {
        let claims = issuer
            .decode_access(bearer_token(headers)?, audience)
            .map_err(|_| ApiError::Unauthorized("invalid access token".into()))?;
        require_client_binding(&claims, AGENT_CLIENT_ID)?;
        require_scope(&claims, AEGIS_ENROLL_SCOPE)?;
        let host_id = aegis_enrollment_host_id_from_subject(&claims.sub)
            .or_else(|_| aegis_host_id_from_subject(&claims.sub))
            .map_err(|_| ApiError::Forbidden("enrollment subject required".into()))?;
        if host_id != *expected_host_id {
            return Err(ApiError::Forbidden(format!(
                "enrollment credential for host `{expected_host_id}` required"
            )));
        }
        let session_id = claims
            .sid
            .filter(|session_id| !session_id.trim().is_empty())
            .ok_or_else(|| ApiError::Forbidden("enrollment session binding required".into()))?;
        Ok(Self { session_id })
    }
}

impl HostSelfPrincipal {
    fn from_headers(
        headers: &HeaderMap,
        issuer: &JwtIssuer,
        audience: &str,
        host_id: &HostId,
    ) -> Result<Self, ApiError> {
        let bearer = AgentPrincipal::from_headers(headers, issuer, audience)?;
        if bearer.host_id() != *host_id {
            return Err(ApiError::Forbidden(format!(
                "agent token for host `{host_id}` required"
            )));
        }
        Ok(Self {
            host_id: bearer.host_id,
        })
    }

    fn host_id(&self) -> HostId {
        self.host_id
    }
}

impl AgentPrincipal {
    fn host_id(&self) -> HostId {
        self.host_id
    }
}

fn require_scope(claims: &AccessClaims, scope: &str) -> Result<(), ApiError> {
    if claims.has_scope(scope) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(format!("scope `{scope}` required")))
    }
}

fn require_client_binding(claims: &AccessClaims, client_id: &str) -> Result<(), ApiError> {
    if claims.client_id == client_id && claims.authorized_party.as_deref() == Some(client_id) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(format!(
            "access token for client `{client_id}` required"
        )))
    }
}

fn agent_access_scopes() -> anyhow::Result<ScopeSet> {
    ScopeSet::new([AEGIS_READ_SCOPE, AEGIS_HOST_SELF_SCOPE])
}

fn enrollment_access_scopes() -> anyhow::Result<ScopeSet> {
    ScopeSet::new([AEGIS_ENROLL_SCOPE])
}

fn aegis_host_subject(host_id: &HostId) -> anyhow::Result<Subject> {
    Subject::new(format!("host:{host_id}"))
}

fn aegis_enrollment_subject(host_id: &HostId) -> anyhow::Result<Subject> {
    Subject::new(format!("enrollment:{host_id}"))
}

#[cfg(test)]
fn aegis_user_subject(user_id: &str) -> anyhow::Result<Subject> {
    Subject::new(format!("user:{user_id}"))
}

fn aegis_host_id_from_subject(subject: &Subject) -> anyhow::Result<HostId> {
    subject
        .strip_kind("host")
        .ok_or_else(|| anyhow::anyhow!("refresh token subject is not an Aegis host"))?
        .parse()
        .context("refresh token subject contains an invalid Aegis host id")
}

fn aegis_enrollment_host_id_from_subject(subject: &Subject) -> anyhow::Result<HostId> {
    subject
        .strip_kind("enrollment")
        .ok_or_else(|| anyhow::anyhow!("refresh token subject is not an Aegis enrollment"))?
        .parse()
        .context("refresh token subject contains an invalid Aegis enrollment host id")
}

fn enrollment_matches_session(
    enrollment: Option<&AegisEnrollmentRecord>,
    session_id: &str,
    now_unix: i64,
) -> bool {
    enrollment.is_some_and(|enrollment| {
        now_unix < enrollment.expires_unix
            && enrollment.credential_session_id.as_deref() == Some(session_id)
    })
}

pub async fn get_egress<S>(
    State(state): State<AegisState<S>>,
    Path(source_host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisEgressStatus>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if UserBearer::from_headers(&headers, &state).await.is_err() {
        HostSelfPrincipal::from_headers(
            &headers,
            state.issuer.as_ref(),
            &state.api_audience,
            &source_host_id,
        )?;
    }
    require_active_egress_host(&state, &source_host_id).await?;
    Ok(Json(egress_status(&state, &source_host_id).await?))
}

pub async fn put_egress<S>(
    State(state): State<AegisState<S>>,
    Path(source_host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisEgressEnableRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AegisEgressStatus>), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    if source_host_id == request.via {
        return Err(ApiError::BadRequest(
            "an Aegis host cannot use itself as its egress target".into(),
        ));
    }
    let (inventory, expected_generation) = build_egress_inventory_snapshot(&state).await?;
    for host_id in [&source_host_id, &request.via] {
        if !inventory.hosts.contains_key(host_id) {
            return Err(ApiError::Conflict(format!(
                "host `{host_id}` has not published a usable Aegis egress identity"
            )));
        }
    }
    let existing = inventory.policies.get(&source_host_id).cloned();
    if let Some(existing) = existing.as_ref() {
        if existing.desired_via == Some(request.via) {
            return Ok((
                StatusCode::OK,
                Json(AegisEgressStatus {
                    source_host_id,
                    aliases: inventory.hosts[&source_host_id].aliases.clone(),
                    config: state.cfg.egress.clone(),
                    policy: Some(existing.clone()),
                }),
            ));
        }
        if !existing.is_steady() {
            return Err(ApiError::Conflict(format!(
                "egress operation for `{source_host_id}` is still pending at revision {}",
                existing.revision
            )));
        }
    }
    validate_egress_graph_change(&inventory.policies, &source_host_id, Some(&request.via))?;
    let expected_revision = existing.as_ref().map(|policy| policy.revision);
    let policy = AegisEgressPolicy {
        source_host_id,
        revision: next_egress_revision(expected_generation)?,
        active_via: existing.as_ref().and_then(|policy| policy.active_via),
        desired_via: Some(request.via),

        updated_unix: OffsetDateTime::now_utc().unix_timestamp(),
        updated_by_principal: admin.principal().to_string(),
    };
    state
        .store
        .compare_and_set_aegis_egress_policy(
            &source_host_id,
            expected_generation,
            expected_revision,
            Some(&policy),
        )
        .await
        .map_err(map_egress_write_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AegisEgressStatus {
            source_host_id,
            aliases: inventory.hosts[&source_host_id].aliases.clone(),
            config: state.cfg.egress.clone(),
            policy: Some(policy),
        }),
    ))
}

pub async fn delete_egress<S>(
    State(state): State<AegisState<S>>,
    Path(source_host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let snapshot = state
        .store
        .read_aegis_egress_snapshot()
        .await
        .map_err(ApiError::Internal)?;
    let Some(existing) = snapshot
        .policies
        .into_iter()
        .find(|policy| policy.source_host_id == source_host_id)
    else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if existing.desired_via.is_none() {
        return Ok(StatusCode::ACCEPTED);
    }
    if !existing.is_steady() {
        return Err(ApiError::Conflict(
            "a source operation is pending; cancel it through the source agent".into(),
        ));
    }
    let policy = AegisEgressPolicy {
        source_host_id,
        revision: next_egress_revision(snapshot.generation)?,
        active_via: existing.active_via,
        desired_via: None,

        updated_unix: OffsetDateTime::now_utc().unix_timestamp(),
        updated_by_principal: admin.principal().to_string(),
    };
    state
        .store
        .compare_and_set_aegis_egress_policy(
            &source_host_id,
            snapshot.generation,
            Some(existing.revision),
            Some(&policy),
        )
        .await
        .map_err(map_egress_write_error)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn put_egress_identity<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisEgressIdentityRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    let public_key = normalize_wireguard_key(&request.public_key)
        .map_err(|error| ApiError::BadRequest(format!("invalid egress public key: {error}")))?;
    let mut host = require_active_egress_host(&state, &host_id).await?;
    if host.egress_public_key.as_deref() == Some(public_key.as_str()) {
        return Ok(StatusCode::NO_CONTENT);
    }
    if let Some(owner) = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .find(|candidate| {
            candidate.host_id != host_id
                && candidate.egress_public_key.as_deref() == Some(public_key.as_str())
        })
    {
        return Err(ApiError::Conflict(format!(
            "egress public key is already assigned to host `{}`",
            owner.host_id
        )));
    }
    host.egress_public_key = Some(public_key);
    host.updated_unix = OffsetDateTime::now_utc().unix_timestamp();
    host.updated_by_principal = format!("agent:{host_id}");
    state
        .store
        .update_aegis_host(&host)
        .await
        .map_err(map_host_write_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_egress_inventory<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<AegisEgressInventory>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience).is_err() {
        UserAdminBearer::from_headers(&headers, &state).await?;
    }
    Ok(Json(build_egress_inventory(&state).await?))
}

pub async fn post_egress_result<S>(
    State(state): State<AegisState<S>>,
    Path(source_host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisEgressResult>, JsonRejection>,
) -> Result<Json<AegisEgressStatus>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(result) = json.map_err(map_json_rejection)?;
    HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &source_host_id,
    )?;
    let snapshot = state
        .store
        .read_aegis_egress_snapshot()
        .await
        .map_err(ApiError::Internal)?;
    let existing = snapshot
        .policies
        .into_iter()
        .find(|policy| policy.source_host_id == source_host_id)
        .ok_or_else(|| ApiError::Conflict("egress operation no longer exists".into()))?;
    if existing.is_steady() {
        return Err(ApiError::Conflict("no source operation is pending".into()));
    }
    if existing.revision != result.revision {
        return Err(ApiError::Conflict(format!(
            "egress policy for `{source_host_id}` is revision {}, not {}",
            existing.revision, result.revision
        )));
    }
    let via = match result.outcome {
        AegisEgressOutcome::Applied => existing.desired_via,
        AegisEgressOutcome::Rejected => existing.active_via,
    };
    let revision = next_egress_revision(snapshot.generation)?;
    let replacement = via.map(|via| AegisEgressPolicy {
        revision,
        active_via: Some(via),
        desired_via: Some(via),
        updated_unix: OffsetDateTime::now_utc().unix_timestamp(),
        updated_by_principal: format!("agent:{source_host_id}"),
        ..existing.clone()
    });
    state
        .store
        .compare_and_set_aegis_egress_policy(
            &source_host_id,
            snapshot.generation,
            Some(existing.revision),
            replacement.as_ref(),
        )
        .await
        .map_err(map_egress_write_error)?;
    Ok(Json(AegisEgressStatus {
        source_host_id,
        aliases: fetch_host_aliases(&state, &source_host_id).await?,
        config: state.cfg.egress.clone(),
        policy: replacement,
    }))
}

async fn egress_status<S>(
    state: &AegisState<S>,
    source_host_id: &HostId,
) -> Result<AegisEgressStatus, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(AegisEgressStatus {
        source_host_id: *source_host_id,
        aliases: fetch_host_aliases(state, source_host_id).await?,
        config: state.cfg.egress.clone(),
        policy: state
            .store
            .fetch_aegis_egress_policy(source_host_id)
            .await
            .map_err(ApiError::Internal)?,
    })
}

async fn build_egress_inventory<S>(state: &AegisState<S>) -> Result<AegisEgressInventory, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(build_egress_inventory_snapshot(state).await?.0)
}

async fn build_egress_inventory_snapshot<S>(
    state: &AegisState<S>,
) -> Result<(AegisEgressInventory, u64), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let network = network_config(&state.cfg, &state.cfg.egress.network)?;
    let mesh = network.mesh.as_ref().ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!(
            "egress network `{}` is not a mesh network",
            state.cfg.egress.network
        ))
    })?;
    let internal_pool = aegis_dto::protocol::AegisWireGuardAddressPool {
        subnet_ipv4: mesh.subnet_ipv4.clone(),
        subnet_ipv6: mesh.subnet_ipv6.clone(),
    };
    let egress_pool = state.cfg.egress.address_pool();
    let dns_pool = state.cfg.egress.dns_address_pool();
    for _ in 0..4 {
        let before = state
            .store
            .read_aegis_egress_snapshot()
            .await
            .map_err(ApiError::Internal)?;
        let hosts = state
            .store
            .list_aegis_hosts()
            .await
            .map_err(ApiError::Internal)?
            .into_iter()
            .map(|host| (host.host_id, host))
            .collect::<BTreeMap<_, _>>();
        let members = state
            .store
            .list_aegis_network_members(&state.cfg.egress.network)
            .await
            .map_err(ApiError::Internal)?;
        let after = state
            .store
            .read_aegis_egress_snapshot()
            .await
            .map_err(ApiError::Internal)?;
        if before.generation != after.generation {
            continue;
        }
        let mut inventory_hosts = BTreeMap::new();
        for member in members {
            let Some(host) = hosts.get(&member.host_id) else {
                continue;
            };
            if member.pending || host.pending {
                continue;
            }
            let (Some(public_key), Some(internal_ipv4), Some(internal_ipv6)) = (
                host.egress_public_key.as_ref(),
                member.internal_ipv4.as_ref(),
                member.internal_ipv6.as_ref(),
            ) else {
                continue;
            };
            let host_id = aegis_dto::wireguard_host_id_from_addresses(
                &internal_pool,
                internal_ipv4,
                internal_ipv6,
            )
            .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
            let host = AegisEgressHost {
                host_id: member.host_id,
                aliases: host.aliases.clone(),
                public_key: public_key.clone(),
                ipv4: aegis_dto::wireguard_ipv4_for_host_id(&egress_pool, host_id)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
                ipv6: aegis_dto::wireguard_ipv6_for_host_id(&egress_pool, host_id)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
                internal_ipv4: internal_ipv4.clone(),
                internal_ipv6: internal_ipv6.clone(),
                dns_ipv4: aegis_dto::wireguard_ipv4_for_host_id(&dns_pool, host_id)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
                dns_ipv6: aegis_dto::wireguard_ipv6_for_host_id(&dns_pool, host_id)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
            };
            inventory_hosts.insert(host.host_id, host);
        }
        let policies = after
            .policies
            .into_iter()
            .map(|policy| (policy.source_host_id, policy))
            .collect();
        return Ok((
            AegisEgressInventory {
                config: state.cfg.egress.clone(),
                hosts: inventory_hosts,
                policies,
            },
            after.generation,
        ));
    }
    Err(ApiError::Conflict(
        "egress topology changed repeatedly while reading it".into(),
    ))
}

async fn require_active_egress_host<S>(
    state: &AegisState<S>,
    host_id: &HostId,
) -> Result<AegisHostRecord, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let host = state
        .store
        .fetch_aegis_host(host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis host `{host_id}`")))?;
    let member = state
        .store
        .fetch_aegis_network_member(&state.cfg.egress.network, host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::Conflict(format!(
                "host `{host_id}` is not enrolled in egress network `{}`",
                state.cfg.egress.network
            ))
        })?;
    if host.pending || member.pending {
        return Err(ApiError::Conflict(format!(
            "host `{host_id}` is not fully enrolled"
        )));
    }
    Ok(host)
}

fn next_egress_revision(current: u64) -> Result<u64, ApiError> {
    current
        .checked_add(1)
        .ok_or_else(|| ApiError::Conflict("egress policy revision is exhausted".into()))
}

fn validate_egress_graph_change(
    policies: &BTreeMap<HostId, AegisEgressPolicy>,
    source_host_id: &HostId,
    desired_via: Option<&HostId>,
) -> Result<(), ApiError> {
    let mut edges = BTreeMap::<HostId, BTreeSet<HostId>>::new();
    for (source, policy) in policies {
        if source == source_host_id {
            if let Some(target) = policy.active_via.as_ref() {
                edges.entry(*source).or_default().insert(*target);
            }
            continue;
        }
        for target in [policy.active_via.as_ref(), policy.desired_via.as_ref()]
            .into_iter()
            .flatten()
        {
            edges.entry(*source).or_default().insert(*target);
        }
    }
    if let Some(target) = desired_via {
        edges.entry(*source_host_id).or_default().insert(*target);
    }

    fn visit(
        node: &HostId,
        edges: &BTreeMap<HostId, BTreeSet<HostId>>,
        active: &mut HashSet<HostId>,
        complete: &mut HashSet<HostId>,
    ) -> Option<HostId> {
        if complete.contains(node) {
            return None;
        }
        if !active.insert(*node) {
            return Some(*node);
        }
        for target in edges.get(node).into_iter().flatten() {
            if let Some(cycle) = visit(target, edges, active, complete) {
                return Some(cycle);
            }
        }
        active.remove(node);
        complete.insert(*node);
        None
    }

    let mut complete = HashSet::new();
    for source in edges.keys() {
        if let Some(cycle) = visit(source, &edges, &mut HashSet::new(), &mut complete) {
            return Err(ApiError::Conflict(format!(
                "egress selection would create a routing cycle containing `{cycle}`"
            )));
        }
    }
    Ok(())
}

fn map_egress_write_error(error: AegisEgressWriteError) -> ApiError {
    match error {
        AegisEgressWriteError::NotFound { .. } => ApiError::NotFound(error.to_string()),
        AegisEgressWriteError::ConcurrentWrite { .. } => ApiError::Conflict(error.to_string()),
        AegisEgressWriteError::Internal(error) => ApiError::Internal(error),
    }
}

struct ServerCertPrincipals {
    internal: Vec<String>,
    combined: Vec<String>,
}

pub async fn get_direct_gateway_inventory<S>(
    State(state): State<AegisState<S>>,
    Path(hub_host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisDirectGatewayInventory>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &hub_host_id,
    )?;
    let enabled = eligible_direct_gateway_host_ids(&state)
        .await?
        .contains(&hub_host_id);
    let config = direct_gateway_config(&state.cfg);
    let aliases = fetch_host_aliases(&state, &hub_host_id).await?;
    let published = state
        .store
        .fetch_aegis_direct_gateway(&hub_host_id)
        .await
        .map_err(ApiError::Internal)?
        .map(|gateway| direct_gateway_from_record(gateway, aliases));
    let satellites = if enabled {
        state
            .store
            .list_aegis_satellites()
            .await
            .map_err(ApiError::Internal)?
            .into_iter()
            .map(direct_satellite_from_record)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(Json(AegisDirectGatewayInventory {
        config: config.clone(),
        enabled,
        published,
        direct_client_ca_public_key: ssh_public_key_line(state.direct_client_ca_key.as_ref())?,
        satellites,
    }))
}

pub async fn put_direct_gateway<S>(
    State(state): State<AegisState<S>>,
    Path(hub_host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisDirectGatewayPublishRequest>, JsonRejection>,
) -> Result<Json<AegisDirectGateway>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    let agent = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &hub_host_id,
    )?;
    if !eligible_direct_gateway_host_ids(&state)
        .await?
        .contains(&hub_host_id)
    {
        return Err(ApiError::Conflict(format!(
            "host `{hub_host_id}` is not an active Aegis hub with managed SSH"
        )));
    }
    let endpoints = normalize_wireguard_endpoints(request.endpoints)?;
    if endpoints.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one public direct-gateway endpoint is required".into(),
        ));
    }
    let config = direct_gateway_config(&state.cfg);
    let pool = config.address_pool();
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let existing = state
        .store
        .fetch_aegis_direct_gateway(&hub_host_id)
        .await
        .map_err(ApiError::Internal)?;
    let gateway = state
        .store
        .put_aegis_direct_gateway(&AegisDirectGatewayRecord {
            host_id: hub_host_id,
            wireguard: AegisDirectWireGuardRecord {
                public_key: normalize_wireguard_key(&request.public_key)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?,
                ipv4: aegis_dto::wireguard_ipv4_for_host_id(&pool, 1)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
                ipv6: aegis_dto::wireguard_ipv6_for_host_id(&pool, 1)
                    .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?,
                endpoints,
            },
            created_unix: existing
                .as_ref()
                .map(|gateway| gateway.created_unix)
                .unwrap_or(now_unix),
            updated_unix: now_unix,
            updated_by_principal: agent.updated_by_principal(),
        })
        .await
        .map_err(map_direct_write_error)?;
    Ok(Json(direct_gateway_from_record(
        gateway,
        fetch_host_aliases(&state, &hub_host_id).await?,
    )))
}

pub async fn delete_direct_gateway<S>(
    State(state): State<AegisState<S>>,
    Path(hub_host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &hub_host_id,
    )?;
    state
        .store
        .delete_aegis_direct_gateway(&hub_host_id)
        .await
        .map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn eligible_direct_gateway_host_ids<S>(
    state: &AegisState<S>,
) -> Result<BTreeSet<HostId>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    Ok(state
        .store
        .list_aegis_network_members(aegis_dto::DEFAULT_AEGIS_NETWORK)
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .filter(|member| member.mode == AegisHostMode::Hub && !member.pending)
        .filter_map(|member| {
            hosts
                .get(&member.host_id)
                .filter(|host| {
                    !host.pending && host.ssh.as_ref().and_then(|ssh| ssh.port) == Some(22)
                })
                .map(|_| member.host_id)
        })
        .collect())
}

async fn require_ready_direct_gateways<S>(
    state: &AegisState<S>,
) -> Result<BTreeMap<HostId, AegisDirectGateway>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let eligible = eligible_direct_gateway_host_ids(state).await?;
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host.aliases))
        .collect::<BTreeMap<_, _>>();
    let ready = state
        .store
        .list_aegis_direct_gateways()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .filter(|gateway| eligible.contains(&gateway.host_id))
        .map(|record| {
            let aliases = hosts.get(&record.host_id).cloned().ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!(
                    "direct gateway `{}` has no host",
                    record.host_id
                ))
            })?;
            let gateway = direct_gateway_from_record(record, aliases);
            Ok((gateway.host_id, gateway))
        })
        .collect::<Result<BTreeMap<_, _>, ApiError>>()?;
    let missing = eligible
        .into_iter()
        .filter(|host_id| !ready.contains_key(host_id))
        .map(|host_id| {
            hosts
                .get(&host_id)
                .map(|aliases| aliases.primary().to_string())
                .unwrap_or_else(|| host_id.to_string())
        })
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(ApiError::Conflict(format!(
            "satellite gateways have not reported ready: {}",
            missing.join(", ")
        )));
    }
    Ok(ready)
}

pub async fn get_satellites<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<AegisSatelliteListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    UserAdminBearer::from_headers(&headers, &state).await?;
    let eligible = eligible_direct_gateway_host_ids(&state).await?;
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    let satellites = state
        .store
        .list_aegis_satellites()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|record| {
            let status = satellite_status(&record, &eligible, &hosts);
            satellite_from_record(record, status)
                .map(|satellite| (satellite.slug.clone(), satellite))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(Json(AegisSatelliteListResponse { satellites }))
}

async fn satellite_details<S>(
    state: &AegisState<S>,
    slug: &str,
) -> Result<AegisSatelliteDetailsResponse, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let satellite = state
        .store
        .fetch_aegis_satellite(slug)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown satellite `{slug}`")))?;
    let eligible = eligible_direct_gateway_host_ids(state).await?;
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    let gateways = state
        .store
        .list_aegis_direct_gateways()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .filter(|gateway| eligible.contains(&gateway.host_id))
        .map(|gateway| {
            let aliases = hosts
                .get(&gateway.host_id)
                .map(|host| host.aliases.clone())
                .ok_or_else(|| {
                    ApiError::Internal(anyhow::anyhow!(
                        "direct gateway `{}` has no host",
                        gateway.host_id
                    ))
                })?;
            let gateway = direct_gateway_from_record(gateway, aliases);
            Ok((gateway.host_id, gateway))
        })
        .collect::<Result<BTreeMap<_, _>, ApiError>>()?;
    let status = satellite_status(&satellite, &eligible, &hosts);
    Ok(AegisSatelliteDetailsResponse {
        satellite: satellite_from_record(satellite, status)?,
        config: direct_gateway_config(&state.cfg).clone(),
        gateways,
    })
}

fn require_matching_satellite_put(
    existing: &AegisSatelliteRecord,
    owner: &AegisUserIdentity,
    wireguard_public_key: &str,
    ssh_public_key: &str,
) -> Result<(), ApiError> {
    if existing.owner_principal != owner.user_id
        || existing.wireguard.public_key != wireguard_public_key
        || existing.ssh_public_key != ssh_public_key
    {
        return Err(ApiError::Conflict(format!(
            "satellite `{}` already exists with different credentials or ownership",
            existing.slug
        )));
    }
    Ok(())
}

pub async fn put_satellite<S>(
    State(state): State<AegisState<S>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    json: Result<Json<AegisSatelliteCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AegisSatelliteProvisionResponse>), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    validate_satellite_slug(&slug)?;
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let owner = resolve_active_aegis_user(&state.store, admin.principal())
        .await?
        .ok_or_else(|| ApiError::Forbidden("access token refers to an unknown user".into()))?;
    let config = direct_gateway_config(&state.cfg).clone();
    let eligible_gateways = eligible_direct_gateway_host_ids(&state).await?;
    if eligible_gateways.is_empty() {
        return Err(ApiError::Conflict(
            "at least one active Aegis hub with managed SSH is required before pairing a satellite"
                .into(),
        ));
    }
    let gateways = require_ready_direct_gateways(&state).await?;
    let ssh_public_key = parse_ed25519_pubkey(&request.ssh_public_key)?;
    let ssh_public_key_text = ssh_public_key
        .to_openssh()
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    let wireguard_public_key = normalize_wireguard_key(&request.wireguard_public_key)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let existing = state
        .store
        .fetch_aegis_satellite(&slug)
        .await
        .map_err(ApiError::Internal)?;
    let (satellite, created) = if let Some(existing) = existing {
        require_matching_satellite_put(
            &existing,
            &owner,
            &wireguard_public_key,
            &ssh_public_key_text,
        )?;
        (existing, false)
    } else {
        require_unenrolled_direct_slug(&state, &slug).await?;
        let now_unix = OffsetDateTime::now_utc().unix_timestamp();
        let candidate = AegisSatelliteRecord {
            slug: slug.clone(),
            credential_id: direct_credential_id(),
            owner_principal: owner.user_id.clone(),
            wireguard: AegisDirectWireGuardRecord {
                public_key: wireguard_public_key.clone(),
                ipv4: String::new(),
                ipv6: String::new(),
                endpoints: Vec::new(),
            },
            ssh_public_key: ssh_public_key_text.clone(),
            created_unix: now_unix,
            created_by_principal: owner.user_id.clone(),
            broker_uses: BTreeMap::new(),
        };
        match state
            .store
            .create_aegis_satellite(&candidate, &config.address_pool())
            .await
        {
            Ok(satellite) => (satellite, true),
            Err(AegisDirectWriteError::AlreadyExists { .. }) => {
                let existing = state
                    .store
                    .fetch_aegis_satellite(&slug)
                    .await
                    .map_err(ApiError::Internal)?
                    .ok_or_else(|| {
                        ApiError::Conflict(format!(
                            "direct resource `{slug}` was created concurrently"
                        ))
                    })?;
                require_matching_satellite_put(
                    &existing,
                    &owner,
                    &wireguard_public_key,
                    &ssh_public_key_text,
                )?;
                (existing, false)
            }
            Err(error) => return Err(map_direct_write_error(error)),
        }
    };
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    let gateway_host_ids = gateways.keys().copied().collect::<BTreeSet<_>>();
    let status = satellite_status(&satellite, &gateway_host_ids, &hosts);
    let provision = (|| {
        let certificate = sign_direct_user_certificate(
            state.direct_client_ca_key.as_ref(),
            ssh_public_key,
            &aegis_direct_cert_principal(&satellite.credential_id).ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!("generated invalid credential id"))
            })?,
            &format!("satellite:{}:{}", satellite.slug, owner.user_id),
            &satellite.wireguard,
        )?;
        Ok::<_, ApiError>(AegisSatelliteProvisionResponse {
            satellite: satellite_from_record(satellite.clone(), status)?,
            config,
            gateways,
            ssh_certificate: certificate,
            server_ca_public_key: ssh_public_key_line(state.server_ca_key.as_ref())?,
        })
    })();
    let provision = match provision {
        Ok(provision) => provision,
        Err(error) if created => {
            if let Err(cleanup_error) = state.store.delete_aegis_satellite(&slug).await {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "satellite provisioning failed ({error}); rollback also failed: {cleanup_error:#}"
                )));
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(provision),
    ))
}

pub async fn delete_satellite<S>(
    State(state): State<AegisState<S>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_satellite_slug(&slug)?;
    UserAdminBearer::from_headers(&headers, &state).await?;
    if !state
        .store
        .delete_aegis_satellite(&slug)
        .await
        .map_err(ApiError::Internal)?
    {
        return Err(ApiError::NotFound(format!("unknown satellite `{slug}`")));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_satellite<S>(
    State(state): State<AegisState<S>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AegisSatelliteDetailsResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_satellite_slug(&slug)?;
    UserAdminBearer::from_headers(&headers, &state).await?;
    Ok(Json(satellite_details(&state, &slug).await?))
}

pub async fn get_satellite_targets<S>(
    State(state): State<AegisState<S>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AegisDirectTargetListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_satellite_slug(&slug)?;
    require_direct_gateway(&state, &headers).await?;
    let satellite = state
        .store
        .fetch_aegis_satellite(&slug)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown satellite `{slug}`")))?;
    let owner = satellite_owner(&state, &satellite).await?;
    Ok(Json(AegisDirectTargetListResponse {
        targets: direct_targets(&state, &satellite, &owner).await?,
    }))
}

pub async fn post_satellite_client_cert<S>(
    State(state): State<AegisState<S>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    json: Result<Json<AegisDirectClientCertRequest>, JsonRejection>,
) -> Result<Json<AegisDirectClientCertResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    validate_satellite_slug(&slug)?;
    validate_login_principal(&request.login_principal)?;
    let gateway_host_id = require_direct_gateway(&state, &headers).await?;
    let satellite = state
        .store
        .fetch_aegis_satellite(&slug)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown satellite `{slug}`")))?;
    let owner = satellite_owner(&state, &satellite).await?;
    let target = direct_targets(&state, &satellite, &owner)
        .await?
        .into_iter()
        .find(|target| target.host_id == request.target_host_id)
        .ok_or_else(|| {
            ApiError::Forbidden(format!(
                "satellite `{slug}` is not allowed to log in to `{}`",
                request.target_host_id
            ))
        })?;
    if !target.login_principals.contains(&request.login_principal) {
        return Err(ApiError::Forbidden(format!(
            "satellite `{slug}` is not allowed to log in to `{}` as `{}`",
            target.aliases.primary(),
            request.login_principal
        )));
    }
    let principal =
        aegis_user_cert_principal(&target.host_id, &request.login_principal, &owner.user_id);
    let certificate = sign_user_certificate(
        state.client_ca_key.as_ref(),
        parse_ed25519_pubkey(&request.ed25519_public_key)?,
        &[principal],
        &format!("direct:{slug}:{gateway_host_id}:{}", target.host_id),
        PRINCIPAL_CLIENT_CERT_TTL_SECONDS.min(state.client_ca.cert_ttl_seconds as i64),
    )?;
    let activity = AegisSatelliteBrokerUseRecord {
        used_unix: OffsetDateTime::now_utc().unix_timestamp(),
        gateway_host_id,
        target_host_id: target.host_id,
    };
    if !state
        .store
        .record_aegis_satellite_broker_use(&slug, &activity)
        .await
        .map_err(ApiError::Internal)?
    {
        return Err(ApiError::NotFound(format!("unknown satellite `{slug}`")));
    }
    Ok(Json(AegisDirectClientCertResponse {
        target,
        login_principal: request.login_principal,
        certificate,
        server_ca_public_key: ssh_public_key_line(state.server_ca_key.as_ref())?,
    }))
}

async fn require_direct_gateway<S>(
    state: &AegisState<S>,
    headers: &HeaderMap,
) -> Result<HostId, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let agent = AgentPrincipal::from_headers(headers, state.issuer.as_ref(), &state.api_audience)?;
    let hub_host_id = agent.host_id();
    if state
        .store
        .fetch_aegis_direct_gateway(&hub_host_id)
        .await
        .map_err(ApiError::Internal)?
        .is_none()
    {
        return Err(ApiError::Forbidden(format!(
            "host `{hub_host_id}` is not a ready direct gateway"
        )));
    }
    Ok(hub_host_id)
}

async fn direct_targets<S>(
    state: &AegisState<S>,
    satellite: &AegisSatelliteRecord,
    owner: &AegisUserIdentity,
) -> Result<Vec<AegisDirectTarget>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host))
        .collect::<BTreeMap<_, _>>();
    let mut targets = Vec::new();
    for member in state
        .store
        .list_aegis_network_members(aegis_dto::DEFAULT_AEGIS_NETWORK)
        .await
        .map_err(ApiError::Internal)?
    {
        if member.pending {
            continue;
        }
        let (Some(wireguard_ipv4), Some(wireguard_ipv6), Some(host)) = (
            member.wireguard_ipv4,
            member.wireguard_ipv6,
            hosts.get(&member.host_id),
        ) else {
            continue;
        };
        let Some(ssh_port) = host.ssh.as_ref().and_then(|ssh| ssh.port) else {
            continue;
        };
        let mut login_principals = host
            .principal_grants
            .iter()
            .filter(|grant| grant.user_id == owner.user_id)
            .map(|grant| grant.login_principal.clone())
            .collect::<Vec<_>>();
        login_principals.sort();
        login_principals.dedup();
        if !login_principals.is_empty() {
            targets.push(AegisDirectTarget {
                host_id: member.host_id,
                aliases: host.aliases.clone(),
                mode: member.mode,
                ssh_port,
                wireguard_ipv4,
                wireguard_ipv6,
                login_principals,
            });
        }
    }
    targets.sort_by(|left, right| {
        let left_hub = left.mode == AegisHostMode::Hub;
        let right_hub = right.mode == AegisHostMode::Hub;
        left_hub
            .cmp(&right_hub)
            .then_with(|| {
                satellite
                    .broker_uses
                    .get(&right.host_id)
                    .map(|activity| activity.used_unix)
                    .unwrap_or_default()
                    .cmp(
                        &satellite
                            .broker_uses
                            .get(&left.host_id)
                            .map(|activity| activity.used_unix)
                            .unwrap_or_default(),
                    )
            })
            .then_with(|| left.aliases.primary().cmp(right.aliases.primary()))
    });
    Ok(targets)
}

async fn satellite_owner<S>(
    state: &AegisState<S>,
    satellite: &AegisSatelliteRecord,
) -> Result<AegisUserIdentity, ApiError>
where
    S: AegisStore + Sync,
{
    resolve_active_aegis_user(&state.store, &satellite.owner_principal)
        .await?
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "satellite `{}` refers to unknown owner `{}`",
                satellite.slug,
                satellite.owner_principal
            ))
        })
}

pub async fn get_networks<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<AegisNetworkListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_networks_for_reader(state, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_networks_for_reader(state, reader).await
}

async fn get_networks_for_reader<S, R>(
    state: AegisState<S>,
    _reader: R,
) -> Result<Json<AegisNetworkListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    Ok(Json(AegisNetworkListResponse {
        networks: state.cfg.networks.clone(),
    }))
}

pub async fn get_network<S>(
    State(state): State<AegisState<S>>,
    Path(network): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AegisNetworkResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_network_name(&network)?;
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_network_for_reader(state, network, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_network_for_reader(state, network, reader).await
}

async fn get_network_for_reader<S, R>(
    state: AegisState<S>,
    network: String,
    _reader: R,
) -> Result<Json<AegisNetworkResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    Ok(Json(AegisNetworkResponse {
        network: network_config(&state.cfg, &network)?.clone(),
    }))
}

pub async fn get_network_members<S>(
    State(state): State<AegisState<S>>,
    Path(network): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AegisNetworkMemberListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_network_name(&network)?;
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_network_members_for_reader(state, network, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_network_members_for_reader(state, network, reader).await
}

async fn get_network_members_for_reader<S, R>(
    state: AegisState<S>,
    network: String,
    _reader: R,
) -> Result<Json<AegisNetworkMemberListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    network_config(&state.cfg, &network)?;
    let aliases = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|host| (host.host_id, host.aliases))
        .collect::<BTreeMap<_, _>>();
    let members = state
        .store
        .list_aegis_network_members(&network)
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|record| {
            let host_id = record.host_id;
            let aliases = aliases.get(&host_id).cloned().ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!(
                    "network member `{network}/{host_id}` has no host"
                ))
            })?;
            network_member_summary_from_record(record, aliases).map(|member| (host_id, member))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    Ok(Json(AegisNetworkMemberListResponse { network, members }))
}

pub async fn get_network_member<S>(
    State(state): State<AegisState<S>>,
    Path((network, host_id)): Path<(String, HostId)>,
    headers: HeaderMap,
) -> Result<Json<AegisNetworkMemberResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_network_name(&network)?;
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_network_member_for_reader(state, network, host_id, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_network_member_for_reader(state, network, host_id, reader).await
}

async fn get_network_member_for_reader<S, R>(
    state: AegisState<S>,
    network: String,
    host_id: HostId,
    _reader: R,
) -> Result<Json<AegisNetworkMemberResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    network_config(&state.cfg, &network)?;
    let member = state
        .store
        .fetch_aegis_network_member(&network, &host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("unknown network member `{network}/{host_id}`"))
        })?;
    Ok(Json(AegisNetworkMemberResponse {
        network,
        host_id,
        member: network_member_summary_from_record(
            member,
            fetch_host_aliases(&state, &host_id).await?,
        )?,
    }))
}

pub async fn post_enrollment<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
    json: Result<Json<AegisEnrollmentCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AegisEnrollment>), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let Json(mut request) = json.map_err(map_json_rejection)?;
    validate_network_name(&request.network)?;
    if request.ttl_seconds == 0 || request.ttl_seconds > MAX_AEGIS_ENROLLMENT_TTL_SECONDS {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds must be between 1 and {MAX_AEGIS_ENROLLMENT_TTL_SECONDS}"
        )));
    }
    if let Some(ssh) = request.ssh.as_mut() {
        validate_ssh_port(ssh.port)?;
        ssh.external_principals = normalize_external_ssh_principals(&ssh.external_principals)?;
    }
    let initial_user_id = request
        .initial_user_id
        .as_deref()
        .unwrap_or_else(|| admin.principal());
    let initial_user_id = resolve_active_aegis_user(&state.store, initial_user_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("unknown Aegis user id `{initial_user_id}`")))?
        .user_id;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let ttl_seconds = i64::try_from(request.ttl_seconds)
        .map_err(|_| ApiError::BadRequest("ttl_seconds exceeds i64".into()))?;
    let expires_unix = now_unix
        .checked_add(ttl_seconds)
        .ok_or_else(|| ApiError::BadRequest("enrollment expiry overflows unix time".into()))?;
    let enrollment = AegisEnrollmentRecord {
        host_id: HostId::new_v4(),
        aliases: request.aliases,
        network: request.network,
        mode: request.mode,
        ssh: request.ssh,
        transient: request.transient,
        initial_user_id,
        phase: AegisEnrollmentPhase::AwaitingMachine,
        credential_session_id: None,
        created_unix: now_unix,
        expires_unix,
        updated_unix: now_unix,
        created_by_principal: admin.principal().to_string(),
    };
    let enrollment = state
        .store
        .create_aegis_enrollment(&enrollment)
        .await
        .map_err(map_enrollment_write_error)?;
    Ok((StatusCode::CREATED, Json(enrollment_response(enrollment))))
}

pub async fn get_enrollments<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<AegisEnrollmentListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let enrollments = state
        .store
        .list_aegis_enrollments()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|enrollment| (enrollment.host_id, enrollment_response(enrollment)))
        .collect();
    Ok(Json(AegisEnrollmentListResponse { enrollments }))
}

pub async fn get_enrollment<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisEnrollment>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let enrollment_principal = if UserAdminBearer::from_headers(&headers, &state)
        .await
        .is_ok()
    {
        None
    } else {
        Some(EnrollmentPrincipal::from_headers(
            &headers,
            state.issuer.as_ref(),
            &state.api_audience,
            &host_id,
        )?)
    };
    let enrollment = state
        .store
        .fetch_aegis_enrollment(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    if let Some(principal) = enrollment_principal
        && !enrollment_matches_session(
            Some(&enrollment),
            &principal.session_id,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
    {
        return Err(ApiError::Forbidden(
            "enrollment credential is expired or superseded".into(),
        ));
    }
    Ok(Json(enrollment_response(enrollment)))
}

pub async fn post_enrollment_credential<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisEnrollmentCredentialResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let enrollment = state
        .store
        .fetch_aegis_enrollment(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if now_unix >= enrollment.expires_unix {
        return Err(ApiError::Forbidden(format!(
            "enrollment for host `{host_id}` expired at {}",
            enrollment.expires_unix
        )));
    }
    let subject = aegis_enrollment_subject(&host_id)?;
    let issued = state
        .auth
        .issue_refresh_session(RefreshTokenIssueRequest {
            subject: subject.clone(),
            client_id: AGENT_CLIENT_ID,
            now_unix,
        })
        .await
        .map_err(ApiError::Internal)?;
    let updated = match state
        .store
        .replace_aegis_enrollment_credential(
            &host_id,
            enrollment.credential_session_id.as_deref(),
            &issued.session_id,
            now_unix,
        )
        .await
    {
        Ok(updated) => updated,
        Err(error) => {
            if let Err(cleanup_error) = state
                .auth
                .revoke_refresh_session(&issued.session_id, &subject, now_unix)
                .await
            {
                tracing::error!(
                    host_id = %host_id,
                    session_id = %issued.session_id,
                    error = ?cleanup_error,
                    "failed to revoke an unbound enrollment credential after enrollment update failure"
                );
            }
            return Err(map_enrollment_write_error(error));
        }
    };
    if let Some(previous_session_id) = enrollment.credential_session_id.as_deref() {
        let revoked = state
            .auth
            .revoke_refresh_session(previous_session_id, &subject, now_unix)
            .await;
        match revoked {
            Ok(true) => {}
            Ok(false) => {
                let host_subject = aegis_host_subject(&host_id)?;
                if let Err(error) = state
                    .auth
                    .revoke_refresh_session(previous_session_id, &host_subject, now_unix)
                    .await
                {
                    tracing::warn!(
                        host_id = %host_id,
                        session_id = previous_session_id,
                        error = ?error,
                        "new enrollment credential is committed; superseded session cleanup failed"
                    );
                }
            }
            Err(error) => tracing::warn!(
                host_id = %host_id,
                session_id = previous_session_id,
                error = ?error,
                "new enrollment credential is committed; superseded session cleanup failed"
            ),
        }
    }
    Ok(Json(AegisEnrollmentCredentialResponse {
        api_base: state.api_issuer.clone(),
        enrollment: enrollment_response(updated),
        refresh_token: issued.refresh_token,
    }))
}

pub async fn delete_enrollment<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let enrollment = state
        .store
        .fetch_aegis_enrollment(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let enrollment_subject = aegis_enrollment_subject(&host_id)?;
    state
        .auth
        .revoke_refresh_sessions(&enrollment_subject, now_unix)
        .await
        .map_err(ApiError::Internal)?;
    if let Some(session_id) = enrollment.credential_session_id.as_deref() {
        let host_subject = aegis_host_subject(&host_id)?;
        state
            .auth
            .revoke_refresh_session(session_id, &host_subject, now_unix)
            .await
            .map_err(ApiError::Internal)?;
    }
    state
        .store
        .cancel_aegis_enrollment(&host_id)
        .await
        .map_err(map_enrollment_write_error)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn post_enrollment_prepare<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisEnrollmentPrepareRequest>, JsonRejection>,
) -> Result<Json<AegisEnrollmentPrepareResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let principal = EnrollmentPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    let Json(request) = json.map_err(map_json_rejection)?;
    let host_public_key = normalize_optional_host_public_key(request.host_public_key)?;
    let wireguard_public_key = normalize_wireguard_key(&request.wireguard_public_key)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let wireguard_endpoints = normalize_wireguard_endpoints(request.wireguard_endpoints)?;
    let enrollment = state
        .store
        .fetch_aegis_enrollment(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    let network = network_config(&state.cfg, &enrollment.network)?.clone();
    let prepared = state
        .store
        .prepare_aegis_enrollment(
            &host_id,
            &principal.session_id,
            AegisEnrollmentPreparation {
                host_public_key: host_public_key.as_deref(),
                wireguard_public_key: &wireguard_public_key,
                wireguard_endpoints: &wireguard_endpoints,
                network: &network,
                updated_unix: OffsetDateTime::now_utc().unix_timestamp(),
            },
        )
        .await
        .map_err(map_enrollment_write_error)?;
    let server_certificate = if prepared
        .host
        .ssh
        .as_ref()
        .and_then(|ssh| ssh.public_key.as_ref())
        .is_some()
    {
        Some(
            post_network_member_server_cert_for_issuer(
                state.clone(),
                prepared.enrollment.network.clone(),
                host_id,
                network.host_dns_suffix.clone(),
                principal,
            )
            .await?
            .0
            .certificate,
        )
    } else {
        None
    };
    let (active_hosts, active_members) =
        active_enrollment_inventory(&state, &prepared.enrollment.network).await?;
    Ok(Json(enrollment_prepare_response(
        prepared,
        network,
        active_hosts,
        active_members,
        server_certificate,
    )?))
}

pub async fn post_enrollment_heartbeat<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisEnrollmentHeartbeatRequest>, JsonRejection>,
) -> Result<Json<AegisEnrollment>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let principal = EnrollmentPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    let Json(request) = json.map_err(map_json_rejection)?;
    let enrollment = state
        .store
        .update_aegis_enrollment_phase(
            &host_id,
            &principal.session_id,
            request.phase,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(map_enrollment_write_error)?;
    Ok(Json(enrollment_response(enrollment)))
}

pub async fn post_enrollment_activate<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisEnrollmentActivateResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let principal = EnrollmentPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let enrollment = state
        .store
        .fetch_aegis_enrollment(&host_id)
        .await
        .map_err(ApiError::Internal)?;
    let Some(enrollment) = enrollment else {
        sync_dns_after_topology_change(&state, "enrollment activation recovery").await?;
        return active_enrollment_response(&state, &host_id).await.map(Json);
    };
    if !enrollment_matches_session(Some(&enrollment), &principal.session_id, now_unix) {
        return Err(ApiError::Forbidden(
            "enrollment credential is expired or superseded".into(),
        ));
    }
    state
        .auth
        .transition_refresh_session_subject(
            &principal.session_id,
            &aegis_enrollment_subject(&host_id)?,
            &aegis_host_subject(&host_id)?,
            now_unix,
        )
        .await
        .map_err(ApiError::Internal)?;
    let prepared = state
        .store
        .activate_aegis_enrollment(&host_id, &principal.session_id, now_unix)
        .await
        .map_err(map_enrollment_write_error)?;
    sync_dns_after_topology_change(&state, "enrollment activation").await?;
    Ok(Json(enrollment_activate_response(prepared)?))
}

pub async fn post_host_agent_token<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AgentTokenIssueResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let host = state
        .store
        .fetch_aegis_host(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis host `{host_id}`")))?;
    if host.pending {
        return Err(ApiError::Conflict(format!(
            "host `{host_id}` has not completed enrollment"
        )));
    }

    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let refresh = state
        .auth
        .issue_refresh_session(RefreshTokenIssueRequest {
            subject: aegis_host_subject(&host_id)?,
            client_id: AGENT_CLIENT_ID,
            now_unix,
        })
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(AgentTokenIssueResponse {
        host_id,
        aliases: host.aliases,
        created_by_principal: admin.principal().to_string(),
        refresh_token: refresh.refresh_token,
    }))
}

pub async fn delete_agent_token<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
    json: Result<Json<AgentTokenRevokeRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    if request.refresh_token.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "agent refresh token must not be empty".into(),
        ));
    }
    state
        .auth
        .revoke_refresh_token(
            request.refresh_token.trim(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_tls_root_ca_certificate<S>(
    State(state): State<AegisState<S>>,
) -> Result<String, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(state.tls.root.certificate_pem.clone())
}

pub async fn post_tls_sync(
    State(state): State<AegisState<AegisDb>>,
    headers: HeaderMap,
    json: Result<Json<AegisTlsSyncRequest>, JsonRejection>,
) -> Result<Json<AegisTlsSyncResponse>, ApiError> {
    let Json(request) = json.map_err(map_json_rejection)?;
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    sync_tls_cert_configs(&state.store, &request.desired, request.dry_run)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

pub async fn get_tls_issuing_ca_certificate<S>(
    State(state): State<AegisState<S>>,
) -> Result<String, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(state.tls.issuing.certificate_pem.clone())
}

pub async fn get_tls_issuing_crl<S>(State(state): State<AegisState<S>>) -> Result<String, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(state.tls.issuing_crl_pem.clone())
}

pub async fn get_tls_certificate(
    State(state): State<AegisState<AegisDb>>,
    Path(label): Path<String>,
    headers: HeaderMap,
) -> Result<String, ApiError> {
    let configured = fetch_tls_cert_config(&state.store, &label)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("TLS certificate `{label}` is not configured"))
        })?;
    let _agent = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &configured.host_id,
    )?;
    if configured.public_key_pem.is_none() {
        return Err(ApiError::NotFound(format!(
            "TLS certificate `{label}` public key has not been submitted"
        )));
    }
    configured.certificate_chain_pem.ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!(
            "TLS certificate `{label}` has a public key but no issued certificate"
        ))
    })
}

pub async fn put_tls_certificate_public_key(
    State(state): State<AegisState<AegisDb>>,
    Path(label): Path<String>,
    headers: HeaderMap,
    public_key_pem: String,
) -> Result<StatusCode, ApiError> {
    let configured = fetch_tls_cert_config(&state.store, &label)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("TLS certificate `{label}` is not configured"))
        })?;
    let _agent = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &configured.host_id,
    )?;
    put_tls_cert_public_key(
        &state.store,
        &state.tls.issuing,
        &state.api_issuer,
        &label,
        &public_key_pem,
    )
    .await
    .map_err(ApiError::Internal)?
    .ok_or_else(|| ApiError::NotFound(format!("TLS certificate `{label}` is not configured")))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_namespace_context<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<aegis_dto::namespace::NamespaceContext>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let user = UserBearer::from_headers(&headers, &state).await?;
    Ok(Json(aegis_dto::namespace::NamespaceContext {
        namespace: state.namespace,
        role: if user.admin {
            aegis_dto::NamespaceRole::Admin
        } else {
            aegis_dto::NamespaceRole::Member
        },
    }))
}

pub async fn get_hosts<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
) -> Result<Json<AegisHostListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_hosts_for_reader(state, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_hosts_for_reader(state, reader).await
}

async fn get_hosts_for_reader<S, R>(
    state: AegisState<S>,
    _reader: R,
) -> Result<Json<AegisHostListResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .map(|record| {
            let host_id = record.host_id;
            host_summary_from_record(record).map(|host| (host_id, host))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    Ok(Json(AegisHostListResponse { hosts }))
}

pub async fn put_host_report<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisHostReportRequest>, JsonRejection>,
) -> Result<Json<AegisHostReportResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(req) = json.map_err(map_json_rejection)?;
    HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let messages = normalize_host_messages(req.messages)?;
    let agent = normalize_agent_status(req.agent, now_unix)?;
    let principal_grants =
        canonicalize_principal_grants(&state.store, req.principal_grants).await?;
    let ssh_lockdown_enabled = req.ssh_lockdown_enabled;
    let direct_gateway_report = normalize_direct_gateway_report(req.direct_gateway, now_unix)?;
    let found = state
        .store
        .update_aegis_host_report(
            &host_id,
            AegisHostReportUpdate {
                messages,
                agent,
                principal_grants: principal_grants.clone(),
                ssh_lockdown_enabled,
                direct_gateway_report,
                observed_public_ip: observed_public_ip_from_headers(&headers)
                    .map(|ip| (ip, now_unix)),
            },
        )
        .await
        .map_err(ApiError::Internal)?;
    if !found {
        return Err(ApiError::NotFound(format!("unknown host `{host_id}`")));
    }
    Ok(Json(AegisHostReportResponse { principal_grants }))
}

pub async fn get_host<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<Json<AegisHost>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if let Ok(reader) = UserBearer::from_headers(&headers, &state).await {
        return get_host_for_reader(state, host_id, reader).await;
    }
    let reader =
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    get_host_for_reader(state, host_id, reader).await
}

async fn get_host_for_reader<S, R>(
    state: AegisState<S>,
    host_id: HostId,
    _reader: R,
) -> Result<Json<AegisHost>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    R: FleetReader,
{
    let host = state
        .store
        .fetch_aegis_host(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown host `{host_id}`")))?;
    Ok(Json(host_summary_from_record(host)?))
}

pub async fn get_alias<S>(
    State(state): State<AegisState<S>>,
    Path(alias): Path<HostAlias>,
    headers: HeaderMap,
) -> Result<Json<AegisAliasResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if UserBearer::from_headers(&headers, &state).await.is_err() {
        AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)?;
    }
    let host_id = state
        .store
        .resolve_enrolled_host_alias(&alias)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown host alias `{alias}`")))?;
    Ok(Json(AegisAliasResponse { alias, host_id }))
}

pub async fn put_host_alias<S>(
    State(state): State<AegisState<S>>,
    Path((host_id, alias)): Path<(HostId, HostAlias)>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<AegisHost>), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    require_aliases_not_satellites(&state, std::slice::from_ref(&alias)).await?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let existed = state
        .store
        .fetch_host_id_by_alias(&alias)
        .await
        .map_err(ApiError::Internal)?
        == Some(host_id);
    let host = state
        .store
        .add_host_alias(&host_id, &alias, admin.principal(), now_unix)
        .await
        .map_err(map_alias_write_error)?;
    sync_dns_after_topology_change(&state, "host alias addition").await?;
    Ok((
        if existed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(host_summary_from_record(host)?),
    ))
}

pub async fn post_host_alias_promote<S>(
    State(state): State<AegisState<S>>,
    Path((host_id, alias)): Path<(HostId, HostAlias)>,
    headers: HeaderMap,
) -> Result<Json<AegisHost>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let host = state
        .store
        .promote_host_alias(
            &host_id,
            &alias,
            admin.principal(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(map_alias_write_error)?;
    sync_dns_after_topology_change(&state, "primary host alias change").await?;
    Ok(Json(host_summary_from_record(host)?))
}

pub async fn delete_host_alias<S>(
    State(state): State<AegisState<S>>,
    Path((host_id, alias)): Path<(HostId, HostAlias)>,
    headers: HeaderMap,
) -> Result<Json<AegisHost>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let host = state
        .store
        .remove_host_alias(
            &host_id,
            &alias,
            admin.principal(),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(map_alias_write_error)?;
    sync_dns_after_topology_change(&state, "host alias removal").await?;
    Ok(Json(host_summary_from_record(host)?))
}

fn map_alias_write_error(error: AegisAliasWriteError) -> ApiError {
    match error {
        AegisAliasWriteError::HostNotFound { .. } | AegisAliasWriteError::AliasNotFound { .. } => {
            ApiError::NotFound(error.to_string())
        }
        AegisAliasWriteError::AlreadyAssigned { .. }
        | AegisAliasWriteError::AssignedToSatellite { .. }
        | AegisAliasWriteError::EnrollmentPending { .. }
        | AegisAliasWriteError::ConcurrentWrite => ApiError::Conflict(error.to_string()),
        AegisAliasWriteError::InvalidAliases(_) => ApiError::BadRequest(error.to_string()),
        AegisAliasWriteError::Internal(error) => ApiError::Internal(error),
    }
}

pub async fn get_client_ca_public_key<S>(
    State(state): State<AegisState<S>>,
) -> Result<Json<SshCaPublicKeyResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(Json(SshCaPublicKeyResponse {
        public_key: ssh_public_key_line(state.client_ca_key.as_ref())?,
    }))
}

pub async fn get_server_ca_public_key<S>(
    State(state): State<AegisState<S>>,
) -> Result<Json<SshCaPublicKeyResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    Ok(Json(SshCaPublicKeyResponse {
        public_key: ssh_public_key_line(state.server_ca_key.as_ref())?,
    }))
}

pub async fn post_network_member_client_cert<S>(
    State(state): State<AegisState<S>>,
    Path((network, host_id)): Path<(String, HostId)>,
    headers: HeaderMap,
    json: Result<Json<AegisHostClientCertRequest>, JsonRejection>,
) -> Result<Json<SshIssueCertResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(req) = json.map_err(map_json_rejection)?;
    validate_network_name(&network)?;
    let config = network_config(&state.cfg, &network)?;
    if !config.managed_ssh {
        return Err(ApiError::BadRequest(format!(
            "network `{network}` does not use managed ssh"
        )));
    }
    let user = match UserBearer::from_headers(&headers, &state).await {
        Ok(user) => user,
        Err(error) => {
            if AgentPrincipal::from_headers(&headers, state.issuer.as_ref(), &state.api_audience)
                .is_ok()
            {
                return Err(ApiError::Forbidden("user token required".into()));
            }
            return Err(error);
        }
    };

    let _member = state
        .store
        .fetch_aegis_network_member(&network, &host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("unknown network member `{network}/{host_id}`"))
        })?;
    let host = state
        .store
        .fetch_aegis_host(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown host `{host_id}`")))?;
    host.ssh
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest(format!("host `{host_id}` offers no SSH access")))?;
    let identity = resolve_active_aegis_user(&state.store, user.principal())
        .await?
        .ok_or_else(|| ApiError::Forbidden("access token refers to an unknown user".into()))?;
    let mut cert_principals = host
        .principal_grants
        .iter()
        .filter(|grant| grant.user_id == identity.user_id)
        .map(|grant| aegis_user_cert_principal(&host_id, &grant.login_principal, &identity.user_id))
        .collect::<Vec<_>>();
    cert_principals.sort();
    cert_principals.dedup();
    if cert_principals.is_empty() {
        return Err(ApiError::Forbidden(format!(
            "user `{}` is not allowed to log in to `{}`",
            identity.user_id,
            host.aliases.primary()
        )));
    }
    let user_pub = parse_ed25519_pubkey(&req.ed25519_public_key)?;
    let cert_line = sign_user_certificate(
        state.client_ca_key.as_ref(),
        user_pub,
        &cert_principals,
        &format!("{network}:{host_id}:{}", identity.user_id),
        PRINCIPAL_CLIENT_CERT_TTL_SECONDS.min(state.client_ca.cert_ttl_seconds as i64),
    )?;

    Ok(Json(SshIssueCertResponse {
        certificate: cert_line,
    }))
}

pub async fn post_network_member_server_cert<S>(
    State(state): State<AegisState<S>>,
    Path((network, host_id)): Path<(String, HostId)>,
    headers: HeaderMap,
) -> Result<Json<SshIssueCertResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_network_name(&network)?;
    let config = network_config(&state.cfg, &network)?;
    if !config.managed_ssh {
        return Err(ApiError::BadRequest(format!(
            "network `{network}` does not use managed ssh"
        )));
    }
    let host_dns_suffix = config.host_dns_suffix.clone();
    if let Ok(actor) = UserAdminBearer::from_headers(&headers, &state).await {
        return post_network_member_server_cert_for_issuer(
            state,
            network,
            host_id,
            host_dns_suffix,
            actor,
        )
        .await;
    }
    let actor = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    post_network_member_server_cert_for_issuer(state, network, host_id, host_dns_suffix, actor)
        .await
}

async fn post_network_member_server_cert_for_issuer<S, I>(
    state: AegisState<S>,
    network: String,
    host_id: HostId,
    host_dns_suffix: Option<String>,
    _issuer: I,
) -> Result<Json<SshIssueCertResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    I: ServerCertIssuer,
{
    let member = state
        .store
        .fetch_aegis_network_member(&network, &host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("unknown network member `{network}/{host_id}`"))
        })?;
    let host = state
        .store
        .fetch_aegis_host(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown host `{host_id}`")))?;
    let ssh = host
        .ssh
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest(format!("host `{host_id}` offers no SSH access")))?;

    let mut principals = resolve_server_cert_principals(
        member.wireguard_ipv4.as_deref(),
        member.wireguard_ipv6.as_deref(),
        member.internal_ipv4.as_deref(),
        member.internal_ipv6.as_deref(),
        host_dns_principals(&host.aliases, host_dns_suffix.as_deref()),
        &ssh.external_principals,
    )?;
    if let Some(direct_gateway) = state
        .store
        .fetch_aegis_direct_gateway(&host_id)
        .await
        .map_err(ApiError::Internal)?
    {
        for principal in [direct_gateway.wireguard.ipv4, direct_gateway.wireguard.ipv6] {
            if !principals.combined.contains(&principal) {
                principals.internal.push(principal.clone());
                principals.combined.push(principal);
            }
        }
    }
    let host_pub = parse_ed25519_pubkey(ssh.public_key.as_deref().ok_or_else(|| {
        ApiError::BadRequest(format!("member `{network}/{host_id}` has no public_key"))
    })?)?;
    let cert_line = sign_host_certificate(
        state.server_ca_key.as_ref(),
        host_pub,
        &principals.combined,
        &format!("host:{network}:{host_id}"),
        state.server_ca.cert_ttl_seconds as i64,
    )?;

    Ok(Json(SshIssueCertResponse {
        certificate: cert_line,
    }))
}

pub async fn put_host<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
    json: Result<Json<AegisPutHostRequest>, JsonRejection>,
) -> Result<Response, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(req) = json.map_err(map_json_rejection)?;
    if let Ok(writer) = UserAdminBearer::from_headers(&headers, &state).await {
        return put_host_for_writer(state, host_id, req, writer).await;
    }
    let writer = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    put_host_for_writer(state, host_id, req, writer).await
}

pub async fn put_network_member<S>(
    State(state): State<AegisState<S>>,
    Path((network, host_id)): Path<(String, HostId)>,
    headers: HeaderMap,
    json: Result<Json<AegisPutNetworkMemberRequest>, JsonRejection>,
) -> Result<Response, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(req) = json.map_err(map_json_rejection)?;
    validate_network_name(&network)?;
    if let Ok(writer) = UserAdminBearer::from_headers(&headers, &state).await {
        return put_network_member_for_writer(state, network, host_id, req, writer).await;
    }
    let writer = HostSelfPrincipal::from_headers(
        &headers,
        state.issuer.as_ref(),
        &state.api_audience,
        &host_id,
    )?;
    put_network_member_for_writer(state, network, host_id, req, writer).await
}

async fn put_host_for_writer<S, W>(
    state: AegisState<S>,
    host_id: HostId,
    req: AegisPutHostRequest,
    writer: W,
) -> Result<Response, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    W: HostWriter,
{
    let outcome = persist_host(state.clone(), writer.updated_by_principal(), host_id, req).await?;
    Ok((StatusCode::OK, Json(outcome.host)).into_response())
}

async fn put_network_member_for_writer<S, W>(
    state: AegisState<S>,
    network: String,
    host_id: HostId,
    req: AegisPutNetworkMemberRequest,
    writer: W,
) -> Result<Response, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
    W: HostWriter,
{
    let outcome = persist_network_member(
        state.clone(),
        writer.updated_by_principal(),
        network.clone(),
        host_id,
        req,
    )
    .await?;
    sync_dns_after_topology_change(&state, "network member update").await?;
    Ok((
        StatusCode::OK,
        Json(AegisNetworkMemberResponse {
            network,
            host_id,
            member: outcome.member,
        }),
    )
        .into_response())
}

pub async fn post_dns_sync<S>(
    State(state): State<AegisState<S>>,
    headers: HeaderMap,
    json: Result<Json<AegisDnsSyncRequest>, JsonRejection>,
) -> Result<Json<AegisDnsSyncResponse>, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let Json(request) = json.map_err(map_json_rejection)?;
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    super::aegis_dns::sync(&state, request.dry_run)
        .await
        .map(Json)
        .map_err(|error| ApiError::Unavailable(format!("Aegis DNS sync failed: {error:#}")))
}

async fn sync_dns_after_topology_change<S>(
    state: &AegisState<S>,
    operation: &str,
) -> Result<(), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    super::aegis_dns::sync_if_configured(state, false)
        .await
        .map(|_| ())
        .map_err(|error| {
            ApiError::Unavailable(format!(
                "{operation} was committed, but Aegis DNS sync failed: {error:#}; retry the request or run `aegis manage sync-dns`"
            ))
        })
}

async fn persist_host<S>(
    state: AegisState<S>,
    updated_by_principal: String,
    host_id: HostId,
    mut req: AegisPutHostRequest,
) -> Result<PutHostOutcome, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if let Some(ssh) = req.ssh.as_ref() {
        validate_ssh_port(ssh.port)?;
    }
    let normalized_host_key =
        normalize_optional_host_public_key(req.ssh.as_mut().and_then(|ssh| ssh.public_key.take()))?;
    let external_server_cert_principals = normalize_external_ssh_principals(
        req.ssh
            .as_ref()
            .map(|ssh| ssh.external_principals.as_slice())
            .unwrap_or(&[]),
    )?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let existing = state
        .store
        .fetch_aegis_host(&host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis host `{host_id}`")))?;
    if existing.aliases != req.aliases {
        return Err(ApiError::Conflict(
            "host aliases can be changed only through the explicit alias endpoints".to_string(),
        ));
    }
    if existing.pending != req.pending {
        return Err(ApiError::Conflict(
            "host pending state is controlled by the enrollment workflow".to_string(),
        ));
    }
    let observed_public_ips = existing.observed_public_ips.clone();
    let principal_grants = existing.principal_grants.clone();
    let ssh_lockdown_enabled = existing.ssh_lockdown_enabled;
    let direct_gateway_report = existing.direct_gateway_report.clone();
    let agent = existing.agent.clone();
    let egress_public_key = existing.egress_public_key.clone();
    let host = AegisHostRecord {
        host_id,
        aliases: req.aliases,
        ssh: req.ssh.map(|ssh| AegisHostRecordSsh {
            port: ssh.port,
            public_key: normalized_host_key,
            external_principals: external_server_cert_principals,
        }),
        egress_public_key,
        messages: existing.messages.clone(),
        agent,
        principal_grants,
        ssh_lockdown_enabled,
        direct_gateway_report,
        observed_public_ips,
        transient: req.transient,
        pending: req.pending,
        created_unix: existing.created_unix,
        updated_unix: now_unix,
        updated_by_principal,
    };
    let host = state
        .store
        .update_aegis_host(&host)
        .await
        .map_err(map_host_write_error)?;

    Ok(PutHostOutcome {
        host: host_summary_from_record(host)?,
    })
}

async fn persist_network_member<S>(
    state: AegisState<S>,
    updated_by_principal: String,
    network: String,
    host_id: HostId,
    mut req: AegisPutNetworkMemberRequest,
) -> Result<PutNetworkMemberOutcome, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    validate_network_name(&network)?;
    let config = network_config(&state.cfg, &network)?.clone();
    let wireguard_pool = config.wireguard.address_pool();
    let mode = req.mode;
    let (
        wireguard_public_key,
        requested_wireguard_ipv4,
        requested_wireguard_ipv6,
        wireguard_endpoints,
    ) = match req.wireguard.take() {
        Some(wireguard) => (
            Some(wireguard.public_key),
            wireguard.ipv4,
            wireguard.ipv6,
            normalize_wireguard_endpoints(wireguard.endpoints)?,
        ),
        None => (None, None, None, Vec::new()),
    };
    let wireguard_public_key = normalize_optional_wireguard_public_key(wireguard_public_key)?;
    let wireguard_ipv4 = normalize_optional_wireguard_ipv4(requested_wireguard_ipv4)?;
    let wireguard_ipv6 = normalize_optional_wireguard_ipv6(requested_wireguard_ipv6)?;
    let wireguard_identity = match (wireguard_ipv4.as_deref(), wireguard_ipv6.as_deref()) {
        (None, None) => None,
        (Some(wireguard_ipv4), Some(wireguard_ipv6)) => Some(
            wireguard_host_identity_from_addresses(&wireguard_pool, wireguard_ipv4, wireguard_ipv6)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?,
        ),
        _ => {
            return Err(ApiError::BadRequest(
                "wireguard identities must include both IPv4 and IPv6 when present".into(),
            ));
        }
    };
    if wireguard_public_key.is_none() && wireguard_identity.is_some() {
        return Err(ApiError::BadRequest(
            "wireguard_public_key is required when wireguard addresses are assigned".into(),
        ));
    }
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let existing = state
        .store
        .fetch_aegis_network_member(&network, &host_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("unknown network member `{network}/{host_id}`"))
        })?;
    if existing.pending != req.pending {
        return Err(ApiError::Conflict(
            "network-member pending state is controlled by the enrollment workflow".to_string(),
        ));
    }
    let member = AegisNetworkMemberRecord {
        host_id,
        mode,
        wireguard_public_key,
        wireguard_ipv4,
        wireguard_ipv6,
        wireguard_endpoints,
        internal_ipv4: existing.internal_ipv4.clone(),
        internal_ipv6: existing.internal_ipv6.clone(),
        pending: req.pending,
        created_unix: existing.created_unix,
        updated_unix: now_unix,
        updated_by_principal,
    };
    let member = state
        .store
        .update_aegis_network_member(&network, &member, &config)
        .await
        .map_err(map_host_write_error)?;

    Ok(PutNetworkMemberOutcome {
        member: network_member_summary_from_record(
            member,
            fetch_host_aliases(&state, &host_id).await?,
        )?,
    })
}

fn map_host_write_error(error: AegisHostWriteError) -> ApiError {
    match error {
        AegisHostWriteError::NotFound { .. } => ApiError::NotFound(error.to_string()),
        AegisHostWriteError::ConcurrentWrite | AegisHostWriteError::EnrollmentPending { .. } => {
            ApiError::Conflict(error.to_string())
        }
        AegisHostWriteError::AliasesChanged | AegisHostWriteError::InvalidWireguardIdentity(..) => {
            ApiError::BadRequest(error.to_string())
        }
        AegisHostWriteError::DuplicateWireguardIpv4 { .. }
        | AegisHostWriteError::DuplicateWireguardIpv6 { .. }
        | AegisHostWriteError::DuplicateEgressPublicKey { .. }
        | AegisHostWriteError::DuplicateInternalIpv4 { .. }
        | AegisHostWriteError::DuplicateInternalIpv6 { .. }
        | AegisHostWriteError::NoAvailableInternalIp { .. }
        | AegisHostWriteError::NoAvailableWireguardHostId { .. } => {
            ApiError::Conflict(error.to_string())
        }
        AegisHostWriteError::Internal(error) => ApiError::Internal(error),
    }
}

pub async fn delete_host<S>(
    State(state): State<AegisState<S>>,
    Path(host_id): Path<HostId>,
    headers: HeaderMap,
) -> Result<axum::http::StatusCode, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let _admin = UserAdminBearer::from_headers(&headers, &state).await?;
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let deleted = state
        .store
        .delete_aegis_host(
            &host_id,
            &state.cfg.networks.keys().cloned().collect::<Vec<_>>(),
        )
        .await
        .map_err(map_host_delete_error)?;
    state
        .auth
        .revoke_refresh_sessions(&aegis_host_subject(&host_id)?, now_unix)
        .await
        .map_err(ApiError::Internal)?;
    if !deleted {
        return Err(ApiError::NotFound(format!(
            "unknown host or network member `{host_id}`"
        )));
    }
    sync_dns_after_topology_change(&state, "host deletion").await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

fn map_host_delete_error(error: AegisHostDeleteError) -> ApiError {
    match error {
        AegisHostDeleteError::EnrollmentPending { .. }
        | AegisHostDeleteError::EgressTargetInUse { .. }
        | AegisHostDeleteError::ConcurrentWrite => ApiError::Conflict(error.to_string()),
        AegisHostDeleteError::Internal(error) => ApiError::Internal(error),
    }
}

fn map_enrollment_write_error(error: AegisEnrollmentWriteError) -> ApiError {
    match error {
        AegisEnrollmentWriteError::NotFound { .. } => ApiError::NotFound(error.to_string()),
        AegisEnrollmentWriteError::Expired { .. }
        | AegisEnrollmentWriteError::CredentialMissing { .. }
        | AegisEnrollmentWriteError::CredentialMismatch { .. } => {
            ApiError::Forbidden(error.to_string())
        }
        AegisEnrollmentWriteError::SshHostPublicKeyRequired { .. }
        | AegisEnrollmentWriteError::SshHostPublicKeyUnexpected { .. } => {
            ApiError::BadRequest(error.to_string())
        }
        AegisEnrollmentWriteError::Internal(error) => ApiError::Internal(error),
        AegisEnrollmentWriteError::Host(AegisHostWriteError::Internal(error)) => {
            ApiError::Internal(error)
        }
        error => ApiError::Conflict(error.to_string()),
    }
}

fn enrollment_response(record: AegisEnrollmentRecord) -> AegisEnrollment {
    AegisEnrollment {
        host_id: record.host_id,
        aliases: record.aliases,
        network: record.network,
        mode: record.mode,
        ssh: record.ssh,
        transient: record.transient,
        initial_user_id: record.initial_user_id,
        phase: record.phase,
        credential_issued: record.credential_session_id.is_some(),
        created_unix: record.created_unix,
        expires_unix: record.expires_unix,
        updated_unix: record.updated_unix,
        created_by_principal: record.created_by_principal,
    }
}

fn enrollment_prepare_response(
    prepared: AegisEnrollmentPrepared,
    network_config: AegisNetworkConfig,
    active_hosts: AegisHostListResponse,
    active_members: AegisNetworkMemberListResponse,
    server_certificate: Option<String>,
) -> Result<AegisEnrollmentPrepareResponse, ApiError> {
    let network = prepared.enrollment.network.clone();
    let aliases = prepared.host.aliases.clone();
    Ok(AegisEnrollmentPrepareResponse {
        enrollment: enrollment_response(prepared.enrollment),
        host: host_summary_from_record(prepared.host)?,
        member: AegisNetworkMemberResponse {
            network,
            host_id: prepared.member.host_id,
            member: network_member_summary_from_record(prepared.member, aliases)?,
        },
        network: network_config,
        active_hosts,
        active_members,
        server_certificate,
    })
}

async fn active_enrollment_inventory<S>(
    state: &AegisState<S>,
    network: &str,
) -> Result<(AegisHostListResponse, AegisNetworkMemberListResponse), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let hosts = state
        .store
        .list_aegis_hosts()
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .filter(|host| !host.pending)
        .map(|host| {
            let host_id = host.host_id;
            host_summary_from_record(host).map(|host| (host_id, host))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let members = state
        .store
        .list_aegis_network_members(network)
        .await
        .map_err(ApiError::Internal)?
        .into_iter()
        .filter(|member| !member.pending && hosts.contains_key(&member.host_id))
        .map(|member| {
            let host_id = member.host_id;
            let aliases = hosts
                .get(&host_id)
                .expect("member host presence was checked")
                .aliases
                .clone();
            network_member_summary_from_record(member, aliases).map(|member| (host_id, member))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok((
        AegisHostListResponse { hosts },
        AegisNetworkMemberListResponse {
            network: network.to_string(),
            members,
        },
    ))
}

fn enrollment_activate_response(
    prepared: AegisEnrollmentPrepared,
) -> Result<AegisEnrollmentActivateResponse, ApiError> {
    let network = prepared.enrollment.network;
    let aliases = prepared.host.aliases.clone();
    Ok(AegisEnrollmentActivateResponse {
        host: host_summary_from_record(prepared.host)?,
        member: AegisNetworkMemberResponse {
            network,
            host_id: prepared.member.host_id,
            member: network_member_summary_from_record(prepared.member, aliases)?,
        },
    })
}

async fn active_enrollment_response<S>(
    state: &AegisState<S>,
    host_id: &HostId,
) -> Result<AegisEnrollmentActivateResponse, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    let host = state
        .store
        .fetch_aegis_host(host_id)
        .await
        .map_err(ApiError::Internal)?
        .filter(|host| !host.pending)
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis enrollment `{host_id}`")))?;
    let mut found = None;
    for network in state.cfg.networks.keys() {
        if let Some(member) = state
            .store
            .fetch_aegis_network_member(network, host_id)
            .await
            .map_err(ApiError::Internal)?
            .filter(|member| !member.pending)
        {
            if found.is_some() {
                return Err(ApiError::Conflict(format!(
                    "active host `{host_id}` belongs to multiple networks"
                )));
            }
            found = Some((network.clone(), member));
        }
    }
    let (network, member) = found.ok_or_else(|| {
        ApiError::NotFound(format!(
            "active host `{host_id}` has no active network membership"
        ))
    })?;
    let aliases = host.aliases.clone();
    Ok(AegisEnrollmentActivateResponse {
        host: host_summary_from_record(host)?,
        member: AegisNetworkMemberResponse {
            network,
            host_id: *host_id,
            member: network_member_summary_from_record(member, aliases)?,
        },
    })
}

fn host_summary_from_record(record: AegisHostRecord) -> Result<AegisHost, ApiError> {
    let AegisHostRecord {
        aliases,
        ssh,
        egress_public_key,
        messages,
        agent,
        observed_public_ips,
        transient,
        pending,
        updated_unix,
        ..
    } = record;
    Ok(AegisHost {
        aliases,
        ssh: ssh.map(|ssh| AegisHostSsh {
            port: ssh.port,
            public_key: ssh.public_key,
            external_principals: ssh.external_principals,
        }),
        egress: egress_public_key.map(|public_key| AegisHostEgress { public_key }),
        report: aegis_dto::protocol::AegisHostReport {
            messages,
            agent,
            ssh_lockdown_enabled: record.ssh_lockdown_enabled.unwrap_or(false),
            observed_public_ips,
        },
        transient,
        pending,
        updated_unix,
    })
}

async fn fetch_host_aliases<S>(
    state: &AegisState<S>,
    host_id: &HostId,
) -> Result<HostAliases, ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    state
        .store
        .fetch_aegis_host(host_id)
        .await
        .map_err(ApiError::Internal)?
        .map(|host| host.aliases)
        .ok_or_else(|| ApiError::NotFound(format!("unknown Aegis host `{host_id}`")))
}

fn network_member_summary_from_record(
    record: AegisNetworkMemberRecord,
    aliases: HostAliases,
) -> Result<AegisNetworkMember, ApiError> {
    let wireguard = match (
        record.wireguard_public_key,
        record.wireguard_ipv4,
        record.wireguard_ipv6,
    ) {
        (Some(public_key), Some(ipv4), Some(ipv6)) => Some(AegisNetworkMemberWireGuard {
            public_key,
            ipv4,
            ipv6,
            endpoints: record.wireguard_endpoints,
        }),
        (None, None, None) => None,
        (public_key, ipv4, ipv6) => {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "network member had incomplete WireGuard identity: public_key={public_key:?} ipv4={ipv4:?} ipv6={ipv6:?}"
            )));
        }
    };
    let internal = match (record.internal_ipv4, record.internal_ipv6) {
        (Some(ipv4), Some(ipv6)) => {
            Some(aegis_dto::protocol::AegisNetworkMemberInternalAddresses { ipv4, ipv6 })
        }
        (None, None) => None,
        (ipv4, ipv6) => {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "network member had incomplete internal addresses: ipv4={ipv4:?} ipv6={ipv6:?}"
            )));
        }
    };
    Ok(AegisNetworkMember {
        aliases,
        mode: record.mode,
        wireguard,
        internal,
        pending: record.pending,
        updated_unix: record.updated_unix,
    })
}

fn network_config<'a>(
    cfg: &'a AegisConfig,
    network: &str,
) -> Result<&'a AegisNetworkConfig, ApiError> {
    cfg.networks
        .get(network)
        .ok_or_else(|| ApiError::NotFound(format!("unknown aegis network `{network}`")))
}

fn direct_gateway_config(cfg: &AegisConfig) -> &AegisDirectGatewayConfig {
    &cfg.direct_gateway
}

fn direct_wireguard_from_record(record: AegisDirectWireGuardRecord) -> AegisDirectWireGuard {
    AegisDirectWireGuard {
        public_key: record.public_key,
        ipv4: record.ipv4,
        ipv6: record.ipv6,
        endpoints: record.endpoints,
    }
}

fn direct_gateway_from_record(
    record: AegisDirectGatewayRecord,
    aliases: HostAliases,
) -> AegisDirectGateway {
    AegisDirectGateway {
        host_id: record.host_id,
        aliases,
        wireguard: direct_wireguard_from_record(record.wireguard),
        updated_unix: record.updated_unix,
    }
}

fn direct_satellite_from_record(
    satellite: AegisSatelliteRecord,
) -> Result<AegisDirectSatellite, ApiError> {
    Ok(AegisDirectSatellite {
        slug: satellite.slug,
        account: aegis_direct_account(&satellite.credential_id).ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("satellite has an invalid credential id"))
        })?,
        ssh_principal: aegis_direct_cert_principal(&satellite.credential_id).ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("satellite has an invalid credential id"))
        })?,
        wireguard: direct_wireguard_from_record(satellite.wireguard),
    })
}

fn satellite_status(
    satellite: &AegisSatelliteRecord,
    gateway_host_ids: &BTreeSet<HostId>,
    hosts: &BTreeMap<HostId, AegisHostRecord>,
) -> AegisSatelliteStatus {
    let gateways = gateway_host_ids
        .iter()
        .filter_map(|host_id| {
            let host = hosts.get(host_id)?;
            let report = host.direct_gateway_report.as_ref();
            let peer = report.and_then(|report| {
                report
                    .peers
                    .iter()
                    .find(|peer| peer.public_key == satellite.wireguard.public_key)
            });
            Some((
                *host_id,
                AegisSatelliteGatewayStatus {
                    aliases: host.aliases.clone(),
                    installed: peer.is_some(),
                    observed_unix: report.map(|report| report.observed_unix),
                    latest_handshake_unix: peer.and_then(|peer| peer.latest_handshake_unix),
                },
            ))
        })
        .collect();
    AegisSatelliteStatus {
        gateways,
        last_broker_use: satellite
            .broker_uses
            .values()
            .max_by_key(|activity| activity.used_unix)
            .and_then(|activity| satellite_broker_use_from_record(activity, hosts)),
    }
}

fn satellite_broker_use_from_record(
    activity: &AegisSatelliteBrokerUseRecord,
    hosts: &BTreeMap<HostId, AegisHostRecord>,
) -> Option<AegisSatelliteBrokerUse> {
    Some(AegisSatelliteBrokerUse {
        used_unix: activity.used_unix,
        gateway_host_id: activity.gateway_host_id,
        gateway_aliases: hosts.get(&activity.gateway_host_id)?.aliases.clone(),
        target_host_id: activity.target_host_id,
        target_aliases: hosts.get(&activity.target_host_id)?.aliases.clone(),
    })
}

fn satellite_from_record(
    satellite: AegisSatelliteRecord,
    status: AegisSatelliteStatus,
) -> Result<AegisSatellite, ApiError> {
    Ok(AegisSatellite {
        slug: satellite.slug,
        account: aegis_direct_account(&satellite.credential_id).ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("satellite has an invalid credential id"))
        })?,
        owner_principal: satellite.owner_principal,
        wireguard: direct_wireguard_from_record(satellite.wireguard),
        created_unix: satellite.created_unix,
        created_by_principal: satellite.created_by_principal,
        status,
    })
}

async fn require_unenrolled_direct_slug<S>(
    state: &AegisState<S>,
    slug: &str,
) -> Result<(), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    if let Ok(alias) = HostAlias::parse(slug.to_string())
        && let Some(host_id) = state
            .store
            .fetch_host_id_by_alias(&alias)
            .await
            .map_err(ApiError::Internal)?
    {
        return Err(ApiError::Conflict(format!(
            "`{slug}` is already an alias of host `{host_id}`"
        )));
    }
    Ok(())
}

async fn require_aliases_not_satellites<S>(
    state: &AegisState<S>,
    aliases: &[HostAlias],
) -> Result<(), ApiError>
where
    S: AegisStore + Clone + Send + Sync + 'static,
{
    for alias in aliases {
        if state
            .store
            .fetch_aegis_satellite(alias.as_str())
            .await
            .map_err(ApiError::Internal)?
            .is_some()
        {
            return Err(ApiError::Conflict(format!(
                "host alias `{alias}` is already assigned to a satellite"
            )));
        }
    }
    Ok(())
}

fn map_direct_write_error(error: AegisDirectWriteError) -> ApiError {
    match error {
        AegisDirectWriteError::AlreadyExists { .. }
        | AegisDirectWriteError::HostAliasExists { .. }
        | AegisDirectWriteError::DuplicatePublicKey { .. }
        | AegisDirectWriteError::ConcurrentWrite
        | AegisDirectWriteError::NoAvailableAddress { .. } => ApiError::Conflict(error.to_string()),
        AegisDirectWriteError::Internal(error) => ApiError::Internal(error),
    }
}

fn load_ca_private_key(pem: &str, passphrase: Option<&str>) -> anyhow::Result<PrivateKey> {
    let mut ca_key = PrivateKey::from_openssh(pem)?;
    if ca_key.is_encrypted() {
        let passphrase =
            passphrase.ok_or_else(|| anyhow::anyhow!("encrypted CA key requires passphrase"))?;
        ca_key = ca_key.decrypt(passphrase)?;
    }
    Ok(ca_key)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let auth = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".into()))?
        .to_str()
        .map_err(|_| ApiError::Unauthorized("bad header".into()))?;
    let (scheme, token) = auth
        .split_once(' ')
        .ok_or_else(|| ApiError::Unauthorized("use Bearer".into()))?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(ApiError::Unauthorized("use Bearer".into()));
    }
    Ok(token)
}

fn observed_public_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    header_public_ips(headers, "x-forwarded-for")
        .into_iter()
        .chain(header_public_ips(headers, "x-real-ip"))
        .chain(forwarded_header_public_ips(headers))
        .next()
}

fn header_public_ips(headers: &HeaderMap, name: &str) -> Vec<IpAddr> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(parse_forwarded_ip)
        .filter(is_public_ip)
        .collect()
}

fn forwarded_header_public_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    headers
        .get_all("forwarded")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .flat_map(|entry| entry.split(';'))
        .filter_map(|part| part.trim().strip_prefix("for="))
        .filter_map(parse_forwarded_ip)
        .filter(is_public_ip)
        .collect()
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some((host, _port)) = value.rsplit_once(':')
        && host.parse::<Ipv4Addr>().is_ok()
    {
        return host.parse::<IpAddr>().ok();
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, _rest) = rest.split_once(']')?;
        return host.parse::<IpAddr>().ok();
    }
    None
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0))
}

fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        && (segments[0] & 0xe000) == 0x2000
}

fn normalize_external_ssh_principals(principals: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for principal in principals {
        let principal = principal.trim();
        validate_hostname_or_principal(principal, "ssh.external_principals")?;
        if !out.iter().any(|existing| existing == principal) {
            out.push(principal.to_string());
        }
    }
    Ok(out)
}

fn normalize_host_messages(
    messages: Vec<AegisHostMessage>,
) -> Result<Vec<AegisHostMessage>, ApiError> {
    let mut out = Vec::new();
    for message in messages {
        let value = message.value.trim();
        if value.is_empty() {
            return Err(ApiError::BadRequest(
                "messages.msg entries must not be empty".into(),
            ));
        }
        if value.contains('\n') || value.contains('\r') {
            return Err(ApiError::BadRequest(
                "messages.msg entries must be single-line strings".into(),
            ));
        }
        let normalized = AegisHostMessage {
            level: message.level,
            value: value.to_string(),
        };
        if !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

fn normalize_direct_gateway_report(
    report: AegisDirectGatewayReport,
    now_unix: i64,
) -> Result<AegisDirectGatewayReport, ApiError> {
    if report.observed_unix.abs_diff(now_unix) > HOST_REPORT_MAX_SKEW_SECONDS as u64 {
        return Err(ApiError::BadRequest(
            "direct-gateway observation timestamp is outside the permitted clock skew".into(),
        ));
    }
    let mut public_keys = BTreeSet::new();
    let mut peers = Vec::with_capacity(report.peers.len());
    for peer in report.peers {
        let public_key = normalize_wireguard_key(&peer.public_key)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        if !public_keys.insert(public_key.clone()) {
            return Err(ApiError::BadRequest(
                "direct-gateway observations contain a duplicate WireGuard public key".into(),
            ));
        }
        if peer.latest_handshake_unix.is_some_and(|handshake| {
            handshake <= 0
                || handshake
                    > report
                        .observed_unix
                        .saturating_add(HOST_REPORT_MAX_SKEW_SECONDS)
        }) {
            return Err(ApiError::BadRequest(
                "direct-gateway handshake timestamp is invalid".into(),
            ));
        }
        peers.push(AegisDirectPeerObservation {
            public_key,
            latest_handshake_unix: peer.latest_handshake_unix,
        });
    }
    peers.sort_by(|left, right| left.public_key.cmp(&right.public_key));
    Ok(AegisDirectGatewayReport {
        observed_unix: report.observed_unix,
        peers,
    })
}

fn normalize_agent_report(
    report: AegisAgentReport,
    reported_unix: i64,
) -> Result<AegisAgentStatus, ApiError> {
    let version = report.version.trim();
    if version.is_empty() {
        return Err(ApiError::BadRequest(
            "agent report version must not be empty".into(),
        ));
    }
    let version = semver::Version::parse(version)
        .map_err(|_| ApiError::BadRequest(format!("invalid agent version `{version}`")))?
        .to_string();
    let boot_id = report.health.boot_id.trim();
    if boot_id.is_empty()
        || boot_id.len() > 128
        || !boot_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(ApiError::BadRequest(format!(
            "invalid agent boot id `{boot_id}`"
        )));
    }
    if report
        .health
        .last_reconcile_unix
        .is_some_and(|reconciled| reconciled > reported_unix.saturating_add(300) as u64)
    {
        return Err(ApiError::BadRequest(
            "agent reconcile timestamp is in the future".into(),
        ));
    }
    Ok(AegisAgentStatus {
        version,
        health: aegis_dto::protocol::AegisAgentHealth {
            boot_id: boot_id.to_string(),
            reconciled_since_boot: report.health.reconciled_since_boot,
            applied_aliases: report.health.applied_aliases,
            last_reconcile_unix: report.health.last_reconcile_unix,
            last_reconcile_warning: normalize_agent_health_detail(
                report.health.last_reconcile_warning,
                "warning",
            )?,
            last_reconcile_error: normalize_agent_health_detail(
                report.health.last_reconcile_error,
                "error",
            )?,
        },
        reported_unix,
    })
}

fn normalize_agent_status(
    status: AegisAgentStatus,
    now_unix: i64,
) -> Result<AegisAgentStatus, ApiError> {
    if status.reported_unix < now_unix.saturating_sub(HOST_REPORT_MAX_SKEW_SECONDS)
        || status.reported_unix > now_unix.saturating_add(HOST_REPORT_MAX_SKEW_SECONDS)
    {
        return Err(ApiError::BadRequest(
            "agent report timestamp is outside the accepted window".into(),
        ));
    }
    normalize_agent_report(
        AegisAgentReport {
            version: status.version,
            health: status.health,
        },
        status.reported_unix,
    )
}

fn normalize_agent_health_detail(
    detail: Option<String>,
    label: &str,
) -> Result<Option<String>, ApiError> {
    let Some(detail) = detail else {
        return Ok(None);
    };
    let detail = detail.trim();
    if detail.is_empty() {
        return Ok(None);
    }
    if detail.len() > 8_192 {
        return Err(ApiError::BadRequest(format!(
            "agent reconcile {label} is too long"
        )));
    }
    Ok(Some(detail.to_string()))
}

async fn canonicalize_principal_grants<S>(
    store: &S,
    grants: Vec<AegisPrincipalGrant>,
) -> Result<Vec<AegisPrincipalGrant>, ApiError>
where
    S: AegisStore + Sync,
{
    let mut out = Vec::new();
    let mut user_ids = BTreeSet::new();
    for grant in grants {
        let login_principal = grant.login_principal.trim();
        validate_login_principal(login_principal)?;
        let user_id = grant.user_id;
        if user_ids.insert(user_id.clone()) {
            resolve_aegis_user(store, &user_id).await?.ok_or_else(|| {
                ApiError::BadRequest(format!("unknown Aegis user id `{user_id}`"))
            })?;
        }
        let normalized = AegisPrincipalGrant {
            login_principal: login_principal.to_string(),
            user_id,
        };
        if !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out.sort();
    Ok(out)
}

fn validate_aegis_user_id(user_id: &str) -> Result<(), ApiError> {
    if !is_valid_aegis_user_id(user_id) {
        return Err(ApiError::BadRequest(
            "Aegis user id must be non-empty, exact, whitespace-free, and contain no `@`".into(),
        ));
    }
    Ok(())
}

async fn resolve_aegis_user<S>(
    store: &S,
    user_id: &str,
) -> Result<Option<AegisUserIdentity>, ApiError>
where
    S: AegisStore + Sync,
{
    validate_aegis_user_id(user_id)?;
    let identity = store
        .fetch_aegis_user_by_id(user_id)
        .await
        .map_err(ApiError::Internal)?
        .map(validate_aegis_user_identity)
        .transpose()?;
    if identity
        .as_ref()
        .is_some_and(|identity| identity.user_id != user_id)
    {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Aegis user lookup returned a different stable id"
        )));
    }
    Ok(identity)
}

async fn resolve_active_aegis_user<S>(
    store: &S,
    user_id: &str,
) -> Result<Option<AegisUserIdentity>, ApiError>
where
    S: AegisStore + Sync,
{
    let identity = resolve_aegis_user(store, user_id).await?;
    if identity.as_ref().is_some_and(|identity| identity.disabled) {
        return Err(ApiError::Forbidden("Aegis user is disabled".into()));
    }
    Ok(identity)
}

fn validate_aegis_user_identity(
    identity: AegisUserIdentity,
) -> Result<AegisUserIdentity, ApiError> {
    if !is_valid_aegis_user_id(&identity.user_id) {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Aegis user record has an invalid stable id"
        )));
    }
    Ok(identity)
}

fn is_valid_aegis_user_id(user_id: &str) -> bool {
    !user_id.is_empty() && !user_id.contains(char::is_whitespace) && !user_id.contains('@')
}

fn resolve_server_cert_principals(
    wireguard_ipv4: Option<&str>,
    wireguard_ipv6: Option<&str>,
    internal_ipv4: Option<&str>,
    internal_ipv6: Option<&str>,
    dns_principals: Vec<String>,
    external_principals: &[String],
) -> Result<ServerCertPrincipals, ApiError> {
    let internal = internal_server_cert_principals(
        wireguard_ipv4,
        wireguard_ipv6,
        internal_ipv4,
        internal_ipv6,
    );
    let external = normalize_external_ssh_principals(external_principals)?;
    let combined = combined_server_cert_principals(&internal, &dns_principals, &external)?;
    Ok(ServerCertPrincipals { internal, combined })
}

fn host_dns_principals(aliases: &aegis_dto::HostAliases, suffix: Option<&str>) -> Vec<String> {
    let suffix = suffix
        .map(str::trim)
        .filter(|suffix| !suffix.is_empty())
        .map(|suffix| suffix.trim_start_matches('.'));
    aliases
        .iter()
        .flat_map(|alias| {
            std::iter::once(alias.to_string())
                .chain(suffix.map(|suffix| format!("{alias}.{suffix}")))
        })
        .collect()
}

fn ssh_public_key_line(ca_key: &PrivateKey) -> Result<String, ApiError> {
    ca_key
        .public_key()
        .to_openssh()
        .map_err(|error| ApiError::Internal(error.into()))
}

fn parse_ed25519_pubkey(input: &str) -> Result<PublicKey, ApiError> {
    if !input.starts_with("ssh-ed25519 ") {
        return Err(ApiError::BadRequest(
            "ed25519 public key must be OpenSSH 'ssh-ed25519 ...'".into(),
        ));
    }
    PublicKey::from_openssh(input).map_err(|_| ApiError::BadRequest("invalid ssh-ed25519".into()))
}

fn direct_credential_id() -> String {
    Sha256::digest(random_urlsafe_string(32).as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn normalize_optional_host_public_key(value: Option<String>) -> Result<Option<String>, ApiError> {
    match value.map(|value| value.trim().to_string()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => parse_ed25519_pubkey(&value)?
            .to_openssh()
            .map(Some)
            .map_err(|error| ApiError::BadRequest(format!("public_key encoding: {error}"))),
        None => Ok(None),
    }
}

fn sign_user_certificate(
    ca_key: &PrivateKey,
    user_pub: PublicKey,
    principals: &[String],
    key_id: &str,
    ttl_seconds: i64,
) -> Result<String, ApiError> {
    let now = OffsetDateTime::now_utc();
    let valid_before = (now + Duration::seconds(ttl_seconds)).unix_timestamp() as u64;
    sign_user_certificate_at(ca_key, user_pub, principals, key_id, now, valid_before)
}

fn sign_user_certificate_at(
    ca_key: &PrivateKey,
    user_pub: PublicKey,
    principals: &[String],
    key_id: &str,
    now: OffsetDateTime,
    valid_before: u64,
) -> Result<String, ApiError> {
    let valid_after =
        (now - Duration::seconds(SSH_CERT_VALID_AFTER_BACKDATE_SECONDS)).unix_timestamp() as u64;
    let serial = now.unix_timestamp_nanos() as u64;

    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        user_pub,
        valid_after,
        valid_before,
    )
    .map_err(|error| ApiError::BadRequest(format!("builder: {error}")))?;
    builder
        .cert_type(certificate::CertType::User)
        .map_err(|error| ApiError::BadRequest(format!("type: {error}")))?;
    builder
        .serial(serial)
        .map_err(|error| ApiError::BadRequest(format!("serial: {error}")))?;
    builder
        .key_id(key_id)
        .map_err(|error| ApiError::BadRequest(format!("key_id: {error}")))?;
    for principal in principals {
        builder
            .valid_principal(principal)
            .map_err(|error| ApiError::BadRequest(format!("principal: {error}")))?;
    }
    for (name, data) in USER_CERT_EXTENSIONS {
        builder
            .extension((*name).to_string(), (*data).to_string())
            .map_err(|error| ApiError::BadRequest(format!("extension: {error}")))?;
    }

    builder
        .sign(ca_key)
        .and_then(|certificate| certificate.to_openssh())
        .map_err(|error| ApiError::Internal(error.into()))
}

fn sign_direct_user_certificate(
    ca_key: &PrivateKey,
    user_pub: PublicKey,
    principal: &str,
    key_id: &str,
    source: &AegisDirectWireGuardRecord,
) -> Result<String, ApiError> {
    let valid_after = (OffsetDateTime::now_utc()
        - Duration::seconds(SSH_CERT_VALID_AFTER_BACKDATE_SECONDS))
    .unix_timestamp() as u64;
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        user_pub,
        valid_after,
        i64::MAX as u64,
    )
    .map_err(|error| ApiError::BadRequest(format!("builder: {error}")))?;
    builder
        .cert_type(certificate::CertType::User)
        .map_err(|error| ApiError::BadRequest(format!("type: {error}")))?;
    builder
        .serial(OffsetDateTime::now_utc().unix_timestamp_nanos() as u64)
        .map_err(|error| ApiError::BadRequest(format!("serial: {error}")))?;
    builder
        .key_id(key_id)
        .map_err(|error| ApiError::BadRequest(format!("key_id: {error}")))?;
    builder
        .valid_principal(principal)
        .map_err(|error| ApiError::BadRequest(format!("principal: {error}")))?;
    builder
        .critical_option(
            "source-address".to_string(),
            format!("{}/32,{}/128", source.ipv4, source.ipv6),
        )
        .map_err(|error| ApiError::BadRequest(format!("source-address: {error}")))?;
    builder
        .critical_option(
            "force-command".to_string(),
            format!("{} ssh", aegis_dto::layout::SYSTEM_BINARY_PATH),
        )
        .map_err(|error| ApiError::BadRequest(format!("force-command: {error}")))?;
    builder
        .extension("permit-pty".to_string(), String::new())
        .map_err(|error| ApiError::BadRequest(format!("extension: {error}")))?;
    builder
        .sign(ca_key)
        .and_then(|certificate| certificate.to_openssh())
        .map_err(|error| ApiError::Internal(error.into()))
}

fn sign_host_certificate(
    ca_key: &PrivateKey,
    host_pub: PublicKey,
    principals: &[String],
    key_id: &str,
    ttl_seconds: i64,
) -> Result<String, ApiError> {
    let now = OffsetDateTime::now_utc();
    let valid_after =
        (now - Duration::seconds(SSH_CERT_VALID_AFTER_BACKDATE_SECONDS)).unix_timestamp() as u64;
    let valid_before = (now + Duration::seconds(ttl_seconds)).unix_timestamp() as u64;
    let serial = now.unix_timestamp_nanos() as u64;

    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        host_pub,
        valid_after,
        valid_before,
    )
    .map_err(|error| ApiError::BadRequest(format!("builder: {error}")))?;
    builder
        .cert_type(certificate::CertType::Host)
        .map_err(|error| ApiError::BadRequest(format!("type: {error}")))?;
    builder
        .serial(serial)
        .map_err(|error| ApiError::BadRequest(format!("serial: {error}")))?;
    builder
        .key_id(key_id)
        .map_err(|error| ApiError::BadRequest(format!("key_id: {error}")))?;
    for principal in principals {
        builder
            .valid_principal(principal)
            .map_err(|error| ApiError::BadRequest(format!("principal: {error}")))?;
    }

    builder
        .sign(ca_key)
        .and_then(|certificate| certificate.to_openssh())
        .map_err(|error| ApiError::Internal(error.into()))
}

fn validate_satellite_slug(slug: &str) -> Result<(), ApiError> {
    aegis_dto::validate_satellite_slug(slug)
        .map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn validate_network_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "network name must not be empty".into(),
        ));
    }
    if name.len() > 63
        || name.starts_with('-')
        || name.ends_with('-')
        || !name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(ApiError::BadRequest(
            "network name must be a lowercase DNS label".into(),
        ));
    }
    Ok(())
}

fn validate_hostname_or_principal(value: &str, field: &str) -> Result<(), ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return Err(ApiError::BadRequest(format!("{field} must be non-empty")));
    }
    Ok(())
}

fn validate_login_principal(value: &str) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::BadRequest(
            "login_principal must not be empty".into(),
        ));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ApiError::BadRequest(
            "login_principal must use ascii letters, digits, '.', '-' or '_'".into(),
        ));
    }
    Ok(())
}

fn validate_ssh_port(port: Option<u16>) -> Result<(), ApiError> {
    if port == Some(0) {
        return Err(ApiError::BadRequest(
            "ssh.port must be between 1 and 65535".into(),
        ));
    }
    Ok(())
}

fn combined_server_cert_principals(
    internal_principals: &[String],
    dns_principals: &[String],
    external_principals: &[String],
) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for principal in dns_principals {
        validate_hostname_or_principal(principal, "ssh.dns_principals")?;
        if !out.contains(principal) {
            out.push(principal.clone());
        }
    }
    for principal in internal_principals {
        validate_hostname_or_principal(principal, "ssh.internal_principals")?;
        if !out.contains(principal) {
            out.push(principal.clone());
        }
    }
    for principal in external_principals {
        validate_hostname_or_principal(principal, "ssh.external_principals")?;
        if !out.contains(principal) {
            out.push(principal.clone());
        }
    }

    if out.is_empty() {
        return Err(ApiError::BadRequest(
            "ssh.external_principals are required when no internal principals are available".into(),
        ));
    }
    Ok(out)
}

fn internal_server_cert_principals(
    wireguard_ipv4: Option<&str>,
    wireguard_ipv6: Option<&str>,
    internal_ipv4: Option<&str>,
    internal_ipv6: Option<&str>,
) -> Vec<String> {
    let mut required = Vec::new();
    if let Some(wireguard_ipv4) = wireguard_ipv4 {
        required.push(wireguard_ipv4.to_string());
    }
    if let Some(wireguard_ipv6) = wireguard_ipv6 {
        required.push(wireguard_ipv6.to_string());
    }
    if let Some(internal_ipv4) = internal_ipv4
        && !required.iter().any(|existing| existing == internal_ipv4)
    {
        required.push(internal_ipv4.to_string());
    }
    if let Some(internal_ipv6) = internal_ipv6
        && !required.iter().any(|existing| existing == internal_ipv6)
    {
        required.push(internal_ipv6.to_string());
    }
    required
}

fn map_json_rejection(rejection: JsonRejection) -> ApiError {
    ApiError::BadRequest(rejection.body_text())
}

fn normalize_optional_wireguard_public_key(
    value: Option<String>,
) -> Result<Option<String>, ApiError> {
    match value.map(|value| value.trim().to_string()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => normalize_wireguard_key(&value)
            .map(Some)
            .map_err(|error| ApiError::BadRequest(error.to_string())),
        None => Ok(None),
    }
}

fn normalize_optional_wireguard_ipv4(value: Option<String>) -> Result<Option<String>, ApiError> {
    match value.map(|value| value.trim().to_string()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => normalize_wireguard_ipv4(&value)
            .map(Some)
            .map_err(|error| ApiError::BadRequest(error.to_string())),
        None => Ok(None),
    }
}

fn normalize_optional_wireguard_ipv6(value: Option<String>) -> Result<Option<String>, ApiError> {
    match value.map(|value| value.trim().to_string()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => normalize_wireguard_ipv6(&value)
            .map(Some)
            .map_err(|error| ApiError::BadRequest(error.to_string())),
        None => Ok(None),
    }
}

fn normalize_wireguard_endpoints(endpoints: Vec<String>) -> Result<Vec<String>, ApiError> {
    let mut normalized = Vec::with_capacity(endpoints.len());
    let mut seen = HashSet::new();
    for endpoint in endpoints {
        let normalized_ip = normalize_wireguard_ipv4(&endpoint)
            .or_else(|_| normalize_wireguard_ipv6(&endpoint))
            .map_err(|_| {
                ApiError::BadRequest(format!(
                    "wireguard.endpoints entries must be IPv4 or IPv6 literals, got `{}`",
                    endpoint.trim()
                ))
            })?;
        if seen.insert(normalized_ip.clone()) {
            normalized.push(normalized_ip);
        }
    }
    Ok(normalized)
}
