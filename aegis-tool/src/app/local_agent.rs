use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use aegis_dto::{
    layout::AGENT_CONFIG_PATH,
    v1::{
        AegisDirectClientCertRequest, AegisDirectClientCertResponse, AegisDirectTargetListResponse,
        AegisPrincipalGrant,
    },
};
use anyhow::{Context, Result};
use reqwest::{StatusCode, blocking::Client as HttpClient};
use serde::{Deserialize, Serialize};

use aegis_dto::DEFAULT_AEGIS_NETWORK;

use crate::agent::{
    AEGIS_AGENT_DIRECT_CLIENT_CERT_PATH, AEGIS_AGENT_DIRECT_TARGETS_PATH, AEGIS_AGENT_EGRESS_PATH,
    AEGIS_AGENT_PRINCIPAL_GRANTS_PATH, AEGIS_AGENT_REFRESH_CREDENTIALS_PATH,
    AEGIS_AGENT_REFRESH_PATH, AEGIS_AGENT_REISSUE_TOKEN_PATH, AEGIS_AGENT_STATUS_PATH,
    AEGIS_AGENT_VERSION_PATH, AgentStatusResponse,
};
use crate::config::{AEGIS_AGENT_SOCKET_PATH, CachedHost, SHARED_CACHE_PATH, load_cached_network};
use crate::ui::{self, TaskOptions, TaskVisibility};

const REFRESH_TIMEOUT: Duration = Duration::from_secs(45);
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const MESH_READY_WAIT: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
pub(super) struct AgentVersionResponse {
    pub(super) version: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct RedeployResponse {
    pub(super) unit: String,
    pub(super) job: String,
    pub(super) version: String,
    pub(super) started: bool,
}

#[derive(Deserialize)]
pub(super) struct PrincipalGrantResponse {
    pub(super) login_principal: String,
    pub(super) grants: Vec<AegisPrincipalGrant>,
}

#[derive(Serialize)]
struct PrincipalGrantMutationRequest<'a> {
    user_id: &'a str,
}

#[derive(Serialize)]
struct AgentTokenReissueRequest<'a> {
    refresh_token: &'a str,
}

pub(super) struct HostRefresh {
    pub(super) hosts: Vec<CachedHost>,
    pub(super) warning: Option<String>,
}

pub(super) struct MeshReadinessWait<'a> {
    message: &'a str,
}

impl<'a> MeshReadinessWait<'a> {
    pub(super) fn new(message: &'a str) -> Self {
        Self { message }
    }

    pub(super) fn wait(&self) -> Result<()> {
        if !Path::new(AGENT_CONFIG_PATH).exists() {
            return Ok(());
        }

        let client = http_client(Duration::from_secs(2))?;
        let mut task = Some(ui::task(TaskOptions {
            label: self.message.to_string(),
            deadline: Some(MESH_READY_WAIT),
            visibility: TaskVisibility::Immediate,
            ..TaskOptions::default()
        })?);
        let deadline = Instant::now() + MESH_READY_WAIT;
        let mut last_status = None;
        let mut last_error = None;
        loop {
            match status(&client) {
                Ok(Some(status)) if status.ready => {
                    if let Some(task) = task.take() {
                        task.finish("Local mesh routing is ready");
                    }
                    return Ok(());
                }
                Ok(Some(status)) => {
                    if let Some(task) = task.as_ref() {
                        task.set_phase(self.wait_message(&status));
                    }
                    last_status = Some(status);
                }
                Ok(None) => {
                    if let Some(task) = task.take() {
                        task.abandon("Continuing without local mesh readiness status");
                    }
                    ui::warn(
                        "local aegis-agent does not expose mesh readiness; reinstall or restart the agent to enable startup waits",
                    );
                    return Ok(());
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                }
            }

            if Instant::now() >= deadline {
                if let Some(task) = task.take() {
                    task.abandon("Continuing before local mesh routing reported ready");
                }
                if let Some(status) = last_status {
                    warn_about_unready_mesh(&status);
                } else if let Some(error) = last_error {
                    ui::warn(&format!(
                        "local aegis-agent did not report mesh readiness before timeout: {error}"
                    ));
                }
                return Ok(());
            }
            ui::sleep(Duration::from_millis(250))?;
        }
    }

    fn wait_message(&self, status: &AgentStatusResponse) -> String {
        if !status.reconciled_since_boot {
            return format!("{} (waiting for first local reconcile)", self.message);
        }
        if let Some(route_update) = status.babel.latest_route_update.as_deref() {
            return format!(
                "{} ({} learned routes, latest {route_update})",
                self.message, status.babel.learned_route_count
            );
        }
        format!(
            "{} ({} learned routes)",
            self.message, status.babel.learned_route_count
        )
    }
}

pub(super) fn http_client(timeout: Duration) -> Result<HttpClient> {
    HttpClient::builder()
        .timeout(timeout)
        .unix_socket(AEGIS_AGENT_SOCKET_PATH)
        .build()
        .map_err(Into::into)
}

pub(super) fn refresh_host_cache() -> Result<HostRefresh> {
    refresh_host_cache_for_network(DEFAULT_AEGIS_NETWORK)
}

pub(super) fn refresh_host_cache_for_network(network: &str) -> Result<HostRefresh> {
    let client = http_client(REFRESH_TIMEOUT)?;
    let deadline = Instant::now() + CONNECT_RETRY_TIMEOUT;
    let mut backoff = Duration::from_millis(100);
    let cache_modified_before = shared_cache_modified();
    loop {
        match client
            .post(local_url(AEGIS_AGENT_REFRESH_PATH))
            .body(Vec::new())
            .send()
        {
            Ok(response) => {
                if !response.status().is_success() {
                    let status_code = response.status();
                    let response_body = response
                        .text()
                        .context("failed to read local aegis-agent refresh error")?;
                    let detail = agent_refresh_failure_detail(status_code, &response_body);
                    if shared_cache_was_updated(cache_modified_before) {
                        return Ok(HostRefresh {
                            hosts: load_shared_host_cache_for_network(network)?,
                            warning: Some(format!(
                                "local aegis-agent refreshed and persisted the shared inventory, but local data-plane reconciliation failed: {detail}"
                            )),
                        });
                    }
                    anyhow::bail!("local aegis-agent refresh request failed: {detail}");
                }
                return Ok(HostRefresh {
                    hosts: load_shared_host_cache_for_network(network)?,
                    warning: status(&client)?.and_then(|status| status.last_reconcile_warning),
                });
            }
            Err(error) if error.is_connect() && Instant::now() < deadline => {
                ui::sleep(backoff.min(deadline.saturating_duration_since(Instant::now())))?;
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(error) => {
                if let Ok(hosts) = load_shared_host_cache_for_network(network) {
                    return Ok(HostRefresh {
                        hosts,
                        warning: Some(format!(
                            "local aegis-agent refresh failed; using cached host inventory: {error}"
                        )),
                    });
                }
                return Err(error)
                    .context("failed to contact the local aegis-agent refresh endpoint");
            }
        }
    }
}

fn shared_cache_modified() -> Option<SystemTime> {
    fs::metadata(SHARED_CACHE_PATH)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn shared_cache_was_updated(before: Option<SystemTime>) -> bool {
    let Some(after) = shared_cache_modified() else {
        return false;
    };
    before.is_none_or(|before| after > before)
}

fn agent_refresh_failure_detail(status: StatusCode, body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {body}")
    }
}

pub(super) fn refresh_credentials() -> Result<()> {
    http_client(Duration::from_secs(120))?
        .post(local_url(AEGIS_AGENT_REFRESH_CREDENTIALS_PATH))
        .body(Vec::new())
        .send()
        .context("failed to contact the local aegis-agent credential refresh endpoint")?
        .error_for_status()
        .context(
            "local aegis-agent rejected the CA refresh request; redeploy the local agent if this host is running an older aegis-agent",
        )?;
    Ok(())
}

pub(super) fn status(client: &HttpClient) -> Result<Option<AgentStatusResponse>> {
    let response = client
        .get(local_url(AEGIS_AGENT_STATUS_PATH))
        .send()
        .context("failed to contact the local aegis-agent status endpoint")?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    response
        .error_for_status()
        .context("local aegis-agent rejected the status request")?
        .json::<AgentStatusResponse>()
        .map(Some)
        .context("failed to parse the local aegis-agent status response")
}

pub(super) fn version(client: &HttpClient) -> Result<AgentVersionResponse> {
    client
        .get(local_url(AEGIS_AGENT_VERSION_PATH))
        .send()
        .context("failed to contact the local aegis-agent version endpoint")?
        .error_for_status()
        .context("local aegis-agent rejected the version request")?
        .json::<AgentVersionResponse>()
        .context("failed to parse the local aegis-agent version response")
}

pub(super) fn schedule_redeploy(target_version: &str) -> Result<RedeployResponse> {
    let target = capulus::managed::VersionTarget::Exact(target_version.to_string());
    let outcome =
        crate::managed::schedule(target).context("local aegis redeploy scheduling failed")?;
    Ok(RedeployResponse {
        unit: outcome.unit,
        job: outcome.job.to_string(),
        version: outcome.version,
        started: outcome.started,
    })
}

pub(super) fn reissue_agent_token(refresh_token: &str) -> Result<Option<AgentStatusResponse>> {
    let client = http_client(Duration::from_secs(30))?;
    client
        .post(local_url(AEGIS_AGENT_REISSUE_TOKEN_PATH))
        .json(&AgentTokenReissueRequest { refresh_token })
        .send()
        .context("failed to contact the local aegis-agent token reissue endpoint")?
        .error_for_status()
        .context("local aegis-agent rejected the token reissue request")?;
    status(&client)
}

pub(super) fn list_principal_grants() -> Result<PrincipalGrantResponse> {
    http_client(Duration::from_secs(10))?
        .get(local_url(AEGIS_AGENT_PRINCIPAL_GRANTS_PATH))
        .send()
        .context("failed to contact the local aegis-agent principal grants endpoint")?
        .error_for_status()
        .context("local aegis-agent rejected the principal grants request")?
        .json::<PrincipalGrantResponse>()
        .context("failed to parse the local aegis-agent principal grants response")
}

pub(super) fn direct_targets() -> Result<Option<AegisDirectTargetListResponse>> {
    let response = http_client(Duration::from_secs(30))?
        .get(local_url(AEGIS_AGENT_DIRECT_TARGETS_PATH))
        .send()
        .context("failed to contact the local aegis-agent direct-session endpoint")?;
    if response.status() == StatusCode::FORBIDDEN {
        return Ok(None);
    }
    response
        .error_for_status()
        .context("local aegis-agent rejected the direct target request")?
        .json::<AegisDirectTargetListResponse>()
        .map(Some)
        .context("failed to parse the local aegis-agent direct target response")
}

pub(super) fn request_direct_client_cert(
    request: &AegisDirectClientCertRequest,
) -> Result<AegisDirectClientCertResponse> {
    http_client(Duration::from_secs(30))?
        .post(local_url(AEGIS_AGENT_DIRECT_CLIENT_CERT_PATH))
        .json(request)
        .send()
        .context("failed to contact the local aegis-agent direct certificate endpoint")?
        .error_for_status()
        .context("local aegis-agent rejected the direct certificate request")?
        .json::<AegisDirectClientCertResponse>()
        .context("failed to parse the local aegis-agent direct certificate response")
}

pub(super) fn get_egress(access_token: &str) -> Result<crate::tunnel_operation::Status> {
    http_client(Duration::from_secs(30))?
        .get(local_url(AEGIS_AGENT_EGRESS_PATH))
        .bearer_auth(access_token)
        .send()
        .context("failed to contact the local aegis-agent tunnel endpoint")?
        .error_for_status()
        .context("local aegis-agent rejected the tunnel status request")?
        .json::<crate::tunnel_operation::Status>()
        .context("failed to parse the local aegis-agent tunnel response")
}

pub(super) fn start_tunnel_operation(
    access_token: &str,
    request: &crate::tunnel_operation::Request,
) -> Result<crate::tunnel_operation::Snapshot> {
    let response = http_client(Duration::from_secs(3))?
        .post(local_url(crate::tunnel_operation::PATH))
        .bearer_auth(access_token)
        .json(request)
        .send()
        .context("failed to start local tunnel operation")?;
    tunnel_operation_response(response)
}

pub(super) fn poll_tunnel_operation(id: u64) -> Result<crate::tunnel_operation::Snapshot> {
    let response = http_client(Duration::from_secs(2))?
        .get(local_url(&format!(
            "{}/{id}",
            crate::tunnel_operation::PATH
        )))
        .send()
        .context("failed to read local tunnel operation")?;
    tunnel_operation_response(response)
}

pub(super) fn cancel_tunnel_operation(id: u64) -> Result<crate::tunnel_operation::Snapshot> {
    let response = http_client(Duration::from_secs(2))?
        .delete(local_url(&format!(
            "{}/{id}",
            crate::tunnel_operation::PATH
        )))
        .send()
        .context("failed to cancel local tunnel operation")?;
    tunnel_operation_response(response)
}

fn tunnel_operation_response(
    response: reqwest::blocking::Response,
) -> Result<crate::tunnel_operation::Snapshot> {
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "local tunnel request failed (HTTP {status}): {}",
            response.text()?.trim()
        );
    }
    response
        .json()
        .context("invalid local tunnel operation response")
}

pub(super) fn is_unauthorized(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<reqwest::Error>()
        .and_then(reqwest::Error::status)
        == Some(StatusCode::UNAUTHORIZED)
}

pub(super) fn allow_principal_grant(user_id: &str) -> Result<PrincipalGrantResponse> {
    mutate_principal_grant("allow", reqwest::Method::POST, user_id)
}

pub(super) fn revoke_principal_grant(user_id: &str) -> Result<PrincipalGrantResponse> {
    mutate_principal_grant("revoke", reqwest::Method::DELETE, user_id)
}

fn mutate_principal_grant(
    action: &str,
    method: reqwest::Method,
    user_id: &str,
) -> Result<PrincipalGrantResponse> {
    http_client(Duration::from_secs(45))?
        .request(method, local_url(AEGIS_AGENT_PRINCIPAL_GRANTS_PATH))
        .json(&PrincipalGrantMutationRequest { user_id })
        .send()
        .with_context(|| {
            format!("failed to contact the local aegis-agent principal grants {action} endpoint")
        })?
        .error_for_status()
        .with_context(|| {
            format!("local aegis-agent rejected the principal grants {action} request")
        })?
        .json::<PrincipalGrantResponse>()
        .context("failed to parse the local aegis-agent principal grants response")
}

fn load_shared_host_cache_for_network(network: &str) -> Result<Vec<CachedHost>> {
    load_cached_network(Path::new(SHARED_CACHE_PATH), network)?
        .map(|network| network.hosts)
        .with_context(|| format!("unknown aegis network `{network}`"))
}

fn warn_about_unready_mesh(status: &AgentStatusResponse) {
    if let Some(error) = status
        .babel
        .last_error
        .as_deref()
        .or(status.last_reconcile_error.as_deref())
    {
        ui::warn(&format!("local mesh routing is not fully ready: {error}"));
    } else {
        ui::warn("local mesh routing did not report ready before timeout");
    }
}

fn local_url(path: &str) -> String {
    format!("http://aegis.local{path}")
}
