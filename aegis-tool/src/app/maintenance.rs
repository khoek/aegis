use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use aegis_dto::DEFAULT_AEGIS_NETWORK;
use anyhow::{Context, Result, anyhow, bail, ensure};
use capulus::managed::VersionTarget;

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
const USER_PROGRAM_INSTALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const USER_VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const USER_VERSION_PROBE_OUTPUT_LIMIT: u64 = 4096;

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
            &aegis_dto::sshd_install_dropin_contents(
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
        let platform = crate::platform::detect()?;
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
        if user_program_requires_update(&target_version)? {
            schedule.set_phase(format!(
                "updating this login user's aegis CLI to v{target_version}"
            ));
            if let Err(error) = install_user_program(&target_version) {
                schedule.abandon("User CLI update failed; no system redeploy was scheduled");
                return Err(error);
            }
        }
        schedule.set_phase("asking the local agent to start the managed redeploy job");
        let response = local_agent::schedule_redeploy(&target_version.to_string())?;
        let target_version_text = target_version.to_string();
        let job = RedeployJob::new(platform, response.unit.clone(), response.job.clone())?;
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
            ui::success(&format!("Managed aegis v{target_version} is running."));
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
    let changed = if !user_program_requires_update(&version)? {
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
        "User CLI ready; system installations follow the managed agent release".to_string()
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
    if !user_program_requires_update(version)? {
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

pub(super) fn user_program_requires_update(version: &RedeployVersion) -> Result<bool> {
    if rustix::process::geteuid().is_root() {
        return Ok(false);
    }
    user_program_requires_update_at(version, capulus::managed::current_user_cargo_root()?)
}

fn user_program_requires_update_at(version: &RedeployVersion, cargo_root: PathBuf) -> Result<bool> {
    if existing_user_program_at(cargo_root.clone())?.is_none() {
        return Ok(false);
    }
    Ok(!user_program_is_current(
        &cargo_root.join("bin/aegis"),
        version,
        USER_VERSION_PROBE_TIMEOUT,
    )?)
}

fn user_program_is_current(
    binary: &Path,
    version: &RedeployVersion,
    timeout: Duration,
) -> Result<bool> {
    // Bound the child and its descendants through the shared process runner,
    // without requiring an external platform-specific timeout executable.
    let output = capulus::process::CaptureOptions {
        timeout,
        max_output_bytes: USER_VERSION_PROBE_OUTPUT_LIMIT,
        cancellation: ui::cancellation(),
    }
    .validate()?
    .run(Command::new(binary).arg("--version"), None);
    match output {
        Ok(output) => {
            let expected = version.to_string();
            Ok(output.status.success()
                && output.stdout.split_whitespace().last() == Some(expected.as_str()))
        }
        Err(error) if capulus::error_is_cancelled(&error) => Err(error),
        // An unknown installed version must not suppress a requested update.
        Err(_) => Ok(false),
    }
}

fn install_user_program(version: &RedeployVersion) -> Result<()> {
    if rustix::process::geteuid().is_root() {
        return Ok(());
    }
    if let Some(root) = existing_user_program_at(capulus::managed::current_user_cargo_root()?)? {
        ui::suspend(|| install_user_program_at(version, &root))?;
    }
    Ok(())
}

fn install_user_program_at(version: &RedeployVersion, cargo_root: &Path) -> Result<()> {
    ensure!(
        !rustix::process::geteuid().is_root(),
        "a user CLI update must not run as root"
    );
    let capture = capulus::process::CaptureOptions {
        timeout: USER_PROGRAM_INSTALL_TIMEOUT,
        cancellation: ui::cancellation(),
        ..Default::default()
    }
    .validate()?;
    let build = tempfile::Builder::new()
        .prefix("aegis-user-build-")
        .tempdir_in(cargo_root)
        .context("create temporary user CLI build directory")?;
    // Cargo's location is independent of the installation root (for example,
    // Homebrew Cargo with a CLI installed under ~/.cargo). Use the invoking PATH.
    let result = capture
        .run_streaming(
            Command::new("cargo")
                .args(["install", "--locked", "--force", "--version"])
                .arg(version.to_string())
                .args([
                    "aegis-tool",
                    "--bin",
                    "aegis",
                    "--registry",
                    "crates-io",
                    "--root",
                ])
                .arg(cargo_root)
                .arg("--target-dir")
                .arg(build.path())
                .env("CARGO_TARGET_DIR", build.path()),
            None,
        )
        .and_then(|output| {
            ensure!(
                output.status.success(),
                "Cargo failed to install aegis v{version}: {}",
                output.status
            );
            Ok(())
        });
    let location = build.path().display().to_string();
    match (result, build.close()) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(error).with_context(|| format!(
            "user CLI was installed, but temporary build output could not be removed from {location}"
        )),
        (Err(error), Err(cleanup)) => Err(error.context(format!(
            "temporary build output could not be removed from {location}: {cleanup}"
        ))),
    }
}

fn existing_user_program_at(cargo_root: PathBuf) -> Result<Option<PathBuf>> {
    ensure!(
        cargo_root.is_absolute()
            && cargo_root != Path::new("/")
            && !cargo_root.components().any(|part| matches!(
                part,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )),
        "user CLI installation root must be a normalized absolute path"
    );
    match std::fs::symlink_metadata(cargo_root.join("bin/aegis")) {
        Ok(_) => Ok(Some(cargo_root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to inspect the user Aegis installation"),
    }
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
                "Timed out; managed redeploy job {} may still be running",
                job.unit()
            ));
            bail!(
                "timed out after {} minutes waiting for managed aegis redeploy; last status: {detail}",
                LOCAL_REDEPLOY_WAIT_TIMEOUT.as_secs() / 60
            );
        }
        if let Err(error) = ui::sleep(LOCAL_REDEPLOY_PROBE_INTERVAL) {
            task.abandon(format!(
                "Wait interrupted; managed redeploy job {} continues independently",
                job.unit()
            ));
            return Err(error).with_context(|| {
                format!(
                    "redeploy wait interrupted; managed redeploy job {} continues independently",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn user_install_fixture() {
        let Some(root) = std::env::var_os("AEGIS_TEST_USER_INSTALL_ROOT") else {
            return;
        };
        match install_user_program_at(
            &RedeployVersion::explicit("1.2.3").unwrap(),
            Path::new(&root),
        ) {
            Ok(()) => eprintln!("INSTALLED"),
            Err(error) => eprintln!("INSTALL_FAILED={error:#}"),
        }
    }

    #[test]
    fn user_install_finds_cargo_on_path_and_cleans_build_output() {
        for exit in [0, 7] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("user-install");
            let toolchain = directory.path().join("toolchain");
            std::fs::create_dir_all(root.join("bin")).unwrap();
            std::fs::create_dir(&toolchain).unwrap();
            std::fs::write(root.join("bin/aegis"), "old CLI").unwrap();
            let cargo = toolchain.join("cargo");
            std::fs::write(
                &cargo,
                r#"#!/bin/sh
printf '%s\n' "$@" > "$AEGIS_TEST_USER_INSTALL_RECORD/args"
printf '%s' "$CARGO_TARGET_DIR" > "$AEGIS_TEST_USER_INSTALL_RECORD/target"
printf artifact > "$CARGO_TARGET_DIR/artifact"
if test "$AEGIS_TEST_USER_INSTALL_EXIT" = 0; then
  printf 'new CLI' > "$AEGIS_TEST_USER_INSTALL_ROOT/bin/aegis"
fi
exit "$AEGIS_TEST_USER_INSTALL_EXIT"
"#,
            )
            .unwrap();
            std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
            let paths = std::env::join_paths(std::iter::once(toolchain).chain(
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
            ))
            .unwrap();
            let output = capulus::process::CaptureOptions::default()
                .validate()
                .unwrap()
                .run(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "app::maintenance::tests::user_install_fixture",
                            "--exact",
                            "--nocapture",
                        ])
                        .env("PATH", paths)
                        .env("AEGIS_TEST_USER_INSTALL_ROOT", &root)
                        .env("AEGIS_TEST_USER_INSTALL_RECORD", directory.path())
                        .env("AEGIS_TEST_USER_INSTALL_EXIT", exit.to_string()),
                    None,
                )
                .unwrap();
            assert!(output.status.success(), "{}", output.stderr);
            assert!(
                output.stderr.contains(if exit == 0 {
                    "INSTALLED"
                } else {
                    "INSTALL_FAILED"
                }),
                "{}",
                output.stderr
            );
            assert!(!root.join("bin/cargo").exists());
            let args = std::fs::read_to_string(directory.path().join("args")).unwrap();
            assert!(args.contains("--locked\n"));
            assert!(args.contains("--version\n1.2.3\n"));
            assert!(args.contains(&format!("--root\n{}\n", root.display())));
            let build =
                PathBuf::from(std::fs::read_to_string(directory.path().join("target")).unwrap());
            assert!(build.starts_with(&root));
            assert!(!build.exists());
            assert_eq!(
                std::fs::read_to_string(root.join("bin/aegis")).unwrap(),
                if exit == 0 { "new CLI" } else { "old CLI" }
            );
        }
    }

    #[test]
    fn managed_system_users_do_not_need_a_cargo_installation() {
        let directory = tempfile::tempdir().unwrap();
        let cargo_root = directory.path().join(".cargo");
        let version = RedeployVersion::explicit("1.2.3").unwrap();
        assert!(
            existing_user_program_at(cargo_root.clone())
                .unwrap()
                .is_none()
        );
        assert!(!user_program_requires_update_at(&version, cargo_root.clone()).unwrap());
        assert!(!cargo_root.exists());
        std::fs::create_dir_all(cargo_root.join("bin")).unwrap();
        assert!(
            existing_user_program_at(cargo_root.clone())
                .unwrap()
                .is_none()
        );
        assert!(!user_program_requires_update_at(&version, cargo_root).unwrap());
    }

    #[test]
    fn existing_user_installations_are_checked_independently_of_the_system() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("bin/aegis");
        std::fs::create_dir(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, "#!/bin/sh\necho aegis 1.2.3\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (version, current) in [("1.2.3", true), ("1.2.4", false)] {
            let requires_update = user_program_requires_update_at(
                &RedeployVersion::explicit(version).unwrap(),
                directory.path().to_path_buf(),
            )
            .unwrap();
            assert_eq!(requires_update, !current);
        }
    }

    #[test]
    fn failed_malformed_and_oversized_user_versions_require_an_update() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("bin/aegis");
        std::fs::create_dir(binary.parent().unwrap()).unwrap();
        let version = RedeployVersion::explicit("1.2.3").unwrap();
        for body in [
            "echo aegis 1.2.3; exit 1",
            "echo aegis 1.2.3 >&2",
            "echo unknown-version",
            "printf '%5000s' x; echo ' aegis 1.2.3'",
            "printf '\\377'; echo ' aegis 1.2.3'",
        ] {
            std::fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                user_program_requires_update_at(&version, directory.path().to_path_buf()).unwrap(),
                "{body}"
            );
        }
    }

    #[test]
    fn a_hung_user_version_probe_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("aegis");
        std::fs::write(
            &binary,
            "#!/bin/sh\nprintf started > \"$0.started\"\nexec sleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        assert!(
            !user_program_is_current(
                &binary,
                &RedeployVersion::explicit("1.2.3").unwrap(),
                Duration::from_secs(1),
            )
            .unwrap()
        );
        assert!(directory.path().join("aegis.started").exists());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
