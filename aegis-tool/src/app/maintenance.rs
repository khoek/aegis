use std::path::Path;
use std::time::{Duration, Instant};

use aegis_types::DEFAULT_AEGIS_NETWORK;
use anyhow::{Context, Result, anyhow, bail};
use capulus::managed::{UserProgramUpdateOptions, VersionTarget};

use crate::api::AuthenticatedApiClient;
use crate::cli::{
    AgentTokenRotateArgs, ReconcileArgs, RedeployArgs, RedeployStatusArgs, RefreshCredentialsArgs,
    UpdateUserArgs,
};
use crate::redeploy_version::{RedeployTarget, RedeployVersion};
use crate::ui::{self, TaskOptions, TaskVisibility};

use super::{
    AEGIS_AUTHORIZED_PRINCIPALS_DIR, AEGIS_CLIENT_CA_PATH, AEGIS_SSHD_DROPIN,
    REMOTE_HOST_CERT_PATH, REMOTE_HOST_KEY_PATH, install, line_with_newline, list, local_agent,
    local_state,
    redeploy_job::{RedeployJob, RedeployJobState},
    system,
};

const LOCAL_REDEPLOY_WAIT_TIMEOUT: Duration = Duration::from_secs(40 * 60);
const LOCAL_REDEPLOY_PROBE_INTERVAL: Duration = Duration::from_secs(5);
const LOCAL_AGENT_RESTART_TIMEOUT: Duration = Duration::from_secs(90);

pub(super) struct RefreshCredentialsCommand<'a> {
    api_base_override: Option<&'a str>,
    _args: &'a RefreshCredentialsArgs,
}

impl<'a> RefreshCredentialsCommand<'a> {
    pub(super) fn new(
        api_base_override: Option<&'a str>,
        args: &'a RefreshCredentialsArgs,
    ) -> Self {
        Self {
            api_base_override,
            _args: args,
        }
    }

    pub(super) fn run(&self) -> Result<i32> {
        if !system::LocalRoot::is_running() {
            if self.api_base_override.is_some() {
                ui::warn(
                    "`aegis advanced refresh-credentials` is handled by the local aegis-agent and uses the agent's configured API base",
                );
            }
            let task = ui::task(TaskOptions {
                label: "Refreshing machine-local Aegis credentials".to_string(),
                deadline: Some(Duration::from_secs(120)),
                ..TaskOptions::default()
            })?;
            local_agent::refresh_credentials()?;
            task.finish_and_clear();
            ui::success("aegis machine-local certificates refreshed.");
            return Ok(0);
        }

        let task = ui::task(TaskOptions {
            label: "Refreshing machine-local Aegis credentials".to_string(),
            visibility: TaskVisibility::Immediate,
            ..TaskOptions::default()
        })?;
        task.set_phase("loading managed host state");
        let managed_state = local_state::ManagedHostStateStore::load()?.ok_or_else(|| {
            anyhow!("no aegis-managed host state found; run `aegis advanced install` first")
        })?;
        let api_base = self.api_base_override.unwrap_or(&managed_state.api_base);
        task.set_phase("loading agent credentials");
        let mut api = install::load_authenticated_api(api_base)?;
        task.set_phase("refreshing host inventory and certificates");
        list::refresh_host_cache(Some(api_base))?
            .into_iter()
            .find(|host| host.host_id == managed_state.host_id)
            .ok_or_else(|| {
                anyhow!(
                    "host `{}` is missing from the aegis API",
                    managed_state.host_id
                )
            })?;
        let server_certificate = api
            .request_network_member_server_cert(DEFAULT_AEGIS_NETWORK, &managed_state.host_id)?
            .certificate;
        let client_ca = api.get_client_ca_public_key()?;
        system::TextFile::new(Path::new(AEGIS_CLIENT_CA_PATH))
            .write_atomic(&line_with_newline(&client_ca.public_key), 0o644)?;
        system::TextFile::new(Path::new(REMOTE_HOST_CERT_PATH))
            .write_atomic(&line_with_newline(&server_certificate), 0o644)?;
        capulus::store::ensure_directory(Path::new(AEGIS_AUTHORIZED_PRINCIPALS_DIR), Some(0o755))?;
        system::Sshd::write_dropin(
            Path::new(AEGIS_SSHD_DROPIN),
            &aegis_types::sshd_install_dropin_contents(
                AEGIS_CLIENT_CA_PATH,
                &format!("{AEGIS_AUTHORIZED_PRINCIPALS_DIR}/%u"),
                Some(REMOTE_HOST_KEY_PATH),
                Some(REMOTE_HOST_CERT_PATH),
            ),
        )?;
        system::Sshd::reload()?;
        task.finish_and_clear();
        ui::success("aegis machine-local certificates refreshed.");
        Ok(0)
    }
}

pub(super) struct RedeployCommand<'a> {
    args: &'a RedeployArgs,
}

impl<'a> RedeployCommand<'a> {
    pub(super) fn new(args: &'a RedeployArgs) -> Self {
        Self { args }
    }

    pub(super) fn run(&self) -> Result<i32> {
        let schedule = ui::task(TaskOptions {
            label: "Preparing Aegis release from crates.io".to_string(),
            deadline: Some(Duration::from_secs(60 * 60)),
            visibility: TaskVisibility::Immediate,
            ..TaskOptions::default()
        })?;
        schedule.set_phase("validating requested version");
        let target = RedeployTarget::requested(self.args.version.as_deref())?;
        if matches!(&target, RedeployTarget::Latest) {
            schedule.set_phase("resolving the latest published aegis-tool version");
        }
        let release = crate::managed::resolve(match &target {
            RedeployTarget::Latest => VersionTarget::Latest,
            RedeployTarget::Exact(version) => VersionTarget::Exact(version.to_string()),
        })?;
        if let RedeployTarget::Exact(expected) = &target
            && release.version != *expected.semver()
        {
            bail!(
                "redeploy resolved unexpected version {}; requested {expected}",
                release.version
            );
        }
        let target_version = RedeployVersion::explicit(&release.version.to_string())
            .context("local Aegis agent returned an invalid redeploy version")?;
        if !user_program_is_current(&target_version) {
            schedule.set_phase(format!(
                "updating this login user's aegis CLI to v{target_version}"
            ));
            if let Err(error) = install_user_program(&target_version) {
                schedule.abandon("User CLI update failed; no system redeploy was scheduled");
                return Err(error);
            }
        }
        schedule.set_phase("asking the local agent to start the systemd job");
        let response = local_agent::schedule_redeploy(&target_version.to_string())?;
        let target_version_text = target_version.to_string();
        let job = RedeployJob::new(response.unit.clone(), response.job.clone())?;
        let schedule_message = if response.started {
            format!(
                "Scheduled aegis redeploy via transient Capulus unit {} (target version {}).",
                job.unit(),
                response.version
            )
        } else {
            format!(
                "A matching aegis redeploy is already running via transient Capulus unit {} (target version {}).",
                job.unit(),
                response.version
            )
        };
        schedule.finish(schedule_message);
        if self.args.json {
            println!("{}", serde_json::to_string(&response)?);
            return Ok(0);
        }
        if self.args.wait {
            wait_for_local_redeploy(&job, &target_version_text)?;
            ui::success(&format!(
                "Managed aegis v{target_version} is running; this login user's CLI was updated before the system cutover."
            ));
        }
        Ok(0)
    }
}

pub(super) fn update_user(args: &UpdateUserArgs) -> Result<i32> {
    let version = RedeployVersion::explicit(&args.version)?;
    let task = ui::task(TaskOptions {
        label: format!("Updating this login user's aegis CLI to v{version}"),
        deadline: Some(Duration::from_secs(60 * 60)),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    task.set_phase("resolving the exact published release");
    resolve_exact_release(&version)?;
    let changed = if user_program_is_current(&version) {
        false
    } else {
        task.set_phase("running the invoking user's Cargo installation");
        if let Err(error) = install_user_program(&version) {
            task.abandon("User CLI update failed");
            return Err(error);
        }
        true
    };
    task.finish(if changed {
        format!("Updated this login user's aegis CLI to v{version}")
    } else {
        format!("This login user's aegis CLI is already v{version}")
    });
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "version": version.to_string(), "changed": changed })
        );
    }
    Ok(0)
}

pub(super) fn ensure_user_program(version: &RedeployVersion) -> Result<bool> {
    if user_program_is_current(version) {
        Ok(false)
    } else {
        resolve_exact_release(version)?;
        install_user_program(version)?;
        Ok(true)
    }
}

fn resolve_exact_release(
    version: &RedeployVersion,
) -> Result<capulus::managed::ResolvedReleaseInfo> {
    let release = crate::managed::resolve(VersionTarget::Exact(version.to_string()))?;
    if release.version != *version.semver() {
        bail!(
            "release resolution returned unexpected version {}; requested {version}",
            release.version
        );
    }
    Ok(release)
}

pub(super) fn user_program_is_current(version: &RedeployVersion) -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    user_program_update(version).is_ok_and(|update| update.is_current())
}

fn install_user_program(version: &RedeployVersion) -> Result<()> {
    if rustix::process::geteuid().is_root() {
        return Ok(());
    }
    let update = user_program_update(version)?;
    ui::suspend(|| update.install(ui::current().cancellation()))
}

fn user_program_update(version: &RedeployVersion) -> Result<capulus::managed::UserProgramUpdate> {
    UserProgramUpdateOptions {
        package: "aegis-tool".to_string(),
        cargo_binary: "aegis".to_string(),
        version: version.to_string(),
        registry: Some("crates-io".into()),
        cargo_root: capulus::managed::current_user_cargo_root()?,
        timeout: Duration::from_secs(60 * 60),
    }
    .validate()
}

pub(super) fn redeploy_status(args: &RedeployStatusArgs) -> Result<i32> {
    let status = crate::managed::status(capulus::managed::JobId::parse(&args.job)?)?;
    if args.json {
        println!("{}", serde_json::to_string(&status)?);
    } else {
        println!(
            "{} v{}: {:?}: {}",
            status.product, status.version, status.phase, status.detail
        );
    }
    Ok(0)
}

fn wait_for_local_redeploy(job: &RedeployJob, target_version: &str) -> Result<()> {
    let task = ui::task(TaskOptions {
        label: format!("Waiting for managed aegis v{target_version} reinstall"),
        deadline: Some(LOCAL_REDEPLOY_WAIT_TIMEOUT),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    let deadline = Instant::now() + LOCAL_REDEPLOY_WAIT_TIMEOUT;
    let mut last_detail = None;
    loop {
        let state = job.probe_local();
        let detail = state.detail().to_string();
        if last_detail.as_deref() != Some(detail.as_str()) {
            task.set_phase(detail.clone());
            last_detail = Some(detail.clone());
        }
        match state {
            RedeployJobState::Complete(_) => {
                task.finish(format!("Aegis v{target_version} reinstall completed"));
                return wait_for_local_agent_restart(target_version);
            }
            RedeployJobState::Failed(_) => {
                task.fail(format!("Managed redeploy failed: {detail}"));
                bail!("managed aegis redeploy failed: {detail}");
            }
            RedeployJobState::Active(_) | RedeployJobState::Unknown(_) => {}
        }
        if Instant::now() >= deadline {
            task.abandon(format!(
                "Timed out; systemd unit {} may still be running",
                job.unit()
            ));
            bail!(
                "timed out after {} minutes waiting for managed aegis redeploy; last status: {detail}",
                LOCAL_REDEPLOY_WAIT_TIMEOUT.as_secs() / 60
            );
        }
        if let Err(error) = ui::sleep(LOCAL_REDEPLOY_PROBE_INTERVAL) {
            task.abandon(format!(
                "Wait interrupted; systemd unit {} continues independently",
                job.unit()
            ));
            return Err(error).with_context(|| {
                format!(
                    "redeploy wait interrupted; systemd unit {} continues independently",
                    job.unit()
                )
            });
        }
    }
}

fn wait_for_local_agent_restart(target_version: &str) -> Result<()> {
    let task = ui::task(TaskOptions {
        label: format!("Confirming aegis-agent v{target_version} restarted"),
        deadline: Some(LOCAL_AGENT_RESTART_TIMEOUT),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    let deadline = Instant::now() + LOCAL_AGENT_RESTART_TIMEOUT;
    loop {
        let last_detail = match local_agent::http_client(Duration::from_secs(3))
            .and_then(|client| local_agent::version(&client))
        {
            Ok(response) if response.version == target_version => {
                task.finish(format!("aegis-agent v{target_version} is ready"));
                return Ok(());
            }
            Ok(response) => format!(
                "agent reported v{} instead of v{target_version}",
                response.version
            ),
            Err(error) => format!("{error:#}"),
        };
        task.set_detail(last_detail.clone());
        if Instant::now() >= deadline {
            task.abandon(format!(
                "Redeploy completed, but agent readiness timed out: {last_detail}"
            ));
            bail!(
                "managed redeploy completed, but aegis-agent v{target_version} did not become ready within {} seconds: {last_detail}",
                LOCAL_AGENT_RESTART_TIMEOUT.as_secs()
            );
        }
        if let Err(error) = ui::sleep(Duration::from_secs(2)) {
            task.abandon("Readiness wait interrupted after the managed redeploy completed");
            return Err(error)
                .context("agent readiness wait interrupted after the managed redeploy completed");
        }
    }
}

pub(super) struct ReconcileCommand<'a> {
    _args: &'a ReconcileArgs,
}

impl<'a> ReconcileCommand<'a> {
    pub(super) fn new(args: &'a ReconcileArgs) -> Self {
        Self { _args: args }
    }

    pub(super) fn run(&self) -> Result<i32> {
        let task = ui::task(TaskOptions {
            label: "Reconciling the local Aegis agent".to_string(),
            deadline: Some(Duration::from_secs(50)),
            ..TaskOptions::default()
        })?;
        let refreshed = local_agent::refresh_host_cache()?;
        task.finish_and_clear();
        ui::success(&format!(
            "Local aegis-agent reconciled {} hosts.",
            refreshed.hosts.len()
        ));
        if let Some(warning) = refreshed.warning {
            ui::warn(&warning);
        }
        Ok(0)
    }
}

pub(super) struct AgentTokenRotateCommand<'a> {
    api_base_override: Option<&'a str>,
    _args: &'a AgentTokenRotateArgs,
}

impl<'a> AgentTokenRotateCommand<'a> {
    pub(super) fn new(api_base_override: Option<&'a str>, args: &'a AgentTokenRotateArgs) -> Self {
        Self {
            api_base_override,
            _args: args,
        }
    }

    pub(super) fn run(&self) -> Result<i32> {
        let task = ui::task(TaskOptions {
            label: "Rotating the local aegis-agent credential".to_string(),
            visibility: TaskVisibility::Immediate,
            ..TaskOptions::default()
        })?;
        task.set_phase("resolving the local host identity");
        let host_id = local_state::LocalHostIdentity::host_id_from_managed_state_or_cache()?
            .ok_or_else(|| {
                anyhow!("failed to resolve the local aegis host UUID; run this on a managed host")
            })?;
        task.set_phase("checking administrator authorization");
        let mut api = AuthenticatedApiClient::load(self.api_base_override)?;
        api.require_user_admin("aegis manage agent-token rotate")?;
        task.set_phase("issuing a replacement credential");
        let refresh_token = api.issue_agent_token(&host_id)?;
        task.set_phase("installing the replacement credential in the local agent");
        let status = match local_agent::reissue_agent_token(&refresh_token) {
            Ok(status) => status,
            Err(error) => {
                task.abandon(format!(
                    "Replacement credential was issued but not installed for `{host_id}`"
                ));
                return Err(error).context(
                    "a replacement agent credential was issued, but the local agent did not install it; revoke the unused credential or retry rotation",
                );
            }
        };
        task.finish_and_clear();
        ui::success(&format!("Reissued local aegis-agent token for {host_id}."));
        if let Some(status) = status {
            if let Some(error) = status.last_reconcile_error.as_deref() {
                ui::warn(&format!(
                    "local aegis-agent accepted the new token, but local data-plane reconcile is still failing: {error}"
                ));
            } else if let Some(warning) = status.last_reconcile_warning.as_deref() {
                ui::warn(&format!(
                    "local aegis-agent accepted the new token, but local control-plane sync is degraded: {warning}"
                ));
            }
        }
        Ok(0)
    }
}
