use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

use aegis_dto::{
    AegisHostMode, DEFAULT_AEGIS_NETWORK, HostAlias, HostId, layout::AGENT_CONFIG_PATH,
    normalize_wireguard_key,
};
use anyhow::{Context, Result, anyhow, bail};
use capulus::managed::{AgentInfo, ManagedProduct};
use capulus::shell::shell_quote as sh_quote;
use reqwest::StatusCode;
use ssh_key::PublicKey;

use crate::api::{ApiClient, ApiClientError, AuthenticatedApiClient, HostAgentApiClient};
use crate::cli::{
    AdvancedCommands, AgentMode, AgentTokenCommands, Commands, EnrollArgs, EnrollmentAdminCommands,
    ManageCommands, UnenrollArgs,
};
use crate::command::CommandOutput;
use crate::config::{
    CachedHost, SHARED_CACHE_PATH, ensure_client_dirs, resolve_api_base, scoped_private_key_path,
};
use crate::ui::{self, Task, TaskKind, TaskOptions, TaskVisibility};

mod agent_version;
mod connect;
mod control_plane;
pub(crate) mod enroll_install;
mod enroll_target;
mod fleet;
mod host;
mod host_alias;
mod host_list;
pub(crate) mod install;
mod list;
mod local_agent;
mod local_state;
pub(crate) mod lockdown;
pub(crate) mod login;
mod maintenance;
mod mesh_bootstrap;
mod mesh_refresh;
mod mesh_route;
mod namespace;
mod principal;
mod progress_list;
mod redeploy_job;
mod remote;
mod satellite;
mod ssh;
mod system;
mod transfer;
mod tunnel;
mod wireguard;

use enroll_target::{EnrollTarget, EnrollmentPlan, RemoteTarget};

const AEGIS_DIR_ETC: &str = "/etc/ssh/aegis";
const AEGIS_CLIENT_CA_PATH: &str = "/etc/ssh/aegis/client_ca.pub";
const AEGIS_AUTHORIZED_PRINCIPALS_DIR: &str = aegis_dto::layout::AUTHORIZED_PRINCIPALS_DIRECTORY;
const AEGIS_STATE_PATH: &str = "/etc/ssh/aegis/state.toml";
pub(crate) const AEGIS_SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/90-aegis.conf";
const AEGIS_LOCKDOWN_DROPIN: &str = "/etc/ssh/sshd_config.d/95-aegis-lockdown.conf";
const AEGIS_AGENT_DIR: &str = aegis_dto::layout::STATE_DIRECTORY;
const SYSTEM_AEGIS_BIN: &str = crate::platform::SYSTEM_BINARY_PATH;
const REMOTE_HOST_KEY_PATH: &str = "/etc/ssh/ssh_host_ed25519_key";
const REMOTE_HOST_CERT_PATH: &str = "/etc/ssh/ssh_host_ed25519_key-cert.pub";
const WIREGUARD_DIR: &str = aegis_dto::layout::WIREGUARD_DIRECTORY;
const WIREGUARD_INTERFACE: &str = "wg-aegis";
const WIREGUARD_CONFIG_PATH: &str = "/etc/aegis/wireguard/wg-aegis.conf";
const WIREGUARD_PRIVATE_KEY_PATH: &str = "/etc/aegis/wireguard/wg-aegis.key";
const WIREGUARD_PUBLIC_KEY_PATH: &str = "/etc/aegis/wireguard/wg-aegis.pub";
const WIREGUARD_UNIT_TEMPLATE_PATH: &str = aegis_dto::layout::WIREGUARD_SYSTEMD_UNIT_TEMPLATE_PATH;
const WIREGUARD_UNIT_PREFIX: &str = aegis_dto::layout::WIREGUARD_SYSTEMD_UNIT_PREFIX;
#[cfg(target_os = "linux")]
const AEGIS_AGENT_UNIT_PATH: &str = aegis_dto::layout::AGENT_SYSTEMD_UNIT_PATH;
pub(crate) const AEGIS_AGENT_SERVICE_NAME: &str = aegis_dto::layout::AGENT_SYSTEMD_SERVICE_NAME;
const BIRD_SERVICE_NAME: &str = "bird";
const AEGIS_AGENT_REFRESH_TOKEN_ENV: &str = "AEGIS_AGENT_REFRESH_TOKEN_B64";
const FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT: Duration = Duration::from_secs(40 * 60);
const REMOTE_SUDO_PASSWORD_HELPER_PATH: &str = "$HOME/.cache/aegis/remote-sudo-password.sh";

pub fn run(cli: crate::cli::Cli) -> Result<i32> {
    let result = run_inner(cli);
    ui::check_cancelled()?;
    result
}

pub(crate) fn run_direct_ssh() -> Result<i32> {
    let result = ssh::run_direct_endpoint();
    if result.as_ref().is_err_and(capulus::error_is_cancelled) {
        return result;
    }
    if let Err(error) = &result {
        // A direct SSH endpoint is itself the user's terminal process. Keep the
        // diagnostic visible long enough for phone SSH clients to display it
        // before the forced command exits and closes the connection.
        ui::error(&error.to_string());
        let task = ui::task(TaskOptions {
            label: "Closing SSH connection after error".to_string(),
            kind: TaskKind::Countdown { total: 5 },
            deadline: Some(Duration::from_secs(6)),
            visibility: TaskVisibility::Immediate,
        })?;
        for elapsed in 0..5 {
            task.set_position(elapsed);
            ui::sleep(Duration::from_secs(1))?;
        }
        task.set_position(5);
        task.finish("SSH connection closing");
    }
    ui::check_cancelled()?;
    result
}

pub(crate) fn application_agent_info(product: &ManagedProduct) -> Result<AgentInfo> {
    let client = local_agent::http_client(Duration::from_secs(3))?;
    let status = local_agent::status(&client)?
        .ok_or_else(|| anyhow!("aegis-agent does not expose readiness status"))?;
    if !status.ready {
        bail!("aegis-agent has not completed a healthy reconciliation");
    }
    Ok(AgentInfo {
        product: product.name().to_string(),
        package: product.package().to_string(),
        version: local_agent::version(&client)?.version,
        protocol_major: capulus::managed::PROTOCOL_MAJOR,
    })
}

fn run_inner(cli: crate::cli::Cli) -> Result<i32> {
    warn_if_agent_version_mismatch();
    let _system_lock = match command_system_lock_policy(&cli.command) {
        SystemLockPolicy::FullCommand => Some(crate::locks::local_system_lock()?),
        SystemLockPolicy::None | SystemLockPolicy::SshSetup => None,
    };
    let invitation_selected = matches!(&cli.command, Commands::Manage(args)
        if matches!(&args.command, ManageCommands::Enroll(args) if args.invitation.is_some()));
    let selected_api_base = match cli.api_base {
        Some(base) => Some(base),
        None if invitation_selected => None,
        None => crate::config::UserContext::load()?.map(|context| context.api_base),
    };
    let api_base_override = match cli.namespace {
        Some(namespace) => {
            let base = resolve_api_base(
                selected_api_base.as_deref(),
                crate::api::installed_agent_api_base()?.as_deref(),
            )?;
            Some(
                aegis_dto::namespace::ApiEndpoint::parse(&base)
                    .map_err(anyhow::Error::msg)?
                    .with_namespace(namespace)
                    .base_url(),
            )
        }
        None => selected_api_base,
    };
    match cli.command {
        Commands::Agent(_) => unreachable!("agent commands bypass the interactive CLI"),
        Commands::List(args) => list::run(api_base_override.as_deref(), &args),
        Commands::Ssh(args) => ssh::run(api_base_override.as_deref(), &args),
        Commands::Push(args) => transfer::run(
            api_base_override.as_deref(),
            &args,
            transfer::Direction::Push,
        ),
        Commands::Pull(args) => transfer::run(
            api_base_override.as_deref(),
            &args,
            transfer::Direction::Pull,
        ),
        Commands::Tunnel(args) => tunnel::run(api_base_override.as_deref(), &args),
        Commands::Manage(args) => match args.command {
            ManageCommands::Namespace(args) => namespace::run(api_base_override.as_deref(), &args),
            ManageCommands::Host(args) => host_alias::run(api_base_override.as_deref(), &args),
            ManageCommands::Satellite(args) => satellite::run(api_base_override.as_deref(), &args),
            ManageCommands::Principal(args) => {
                require_local_namespace(api_base_override.as_deref())?;
                principal::run(&args)
            }
            ManageCommands::Login(args) => {
                login::BrowserLogin::from_cli(api_base_override.as_deref(), &args).run()
            }
            ManageCommands::AgentToken(args) => match args.command {
                AgentTokenCommands::Issue(args) => {
                    control_plane::issue_agent_token(api_base_override.as_deref(), &args)
                }
                AgentTokenCommands::Rotate(args) => {
                    require_local_namespace(api_base_override.as_deref())?;
                    maintenance::AgentTokenRotateCommand::new(api_base_override.as_deref(), &args)
                        .run()
                }
                AgentTokenCommands::Revoke(args) => {
                    control_plane::revoke_agent_token(api_base_override.as_deref(), &args)
                }
            },
            ManageCommands::Enrollment(args) => match args.command {
                EnrollmentAdminCommands::Create(args) => {
                    control_plane::create_enrollment(api_base_override.as_deref(), &args)
                }
                EnrollmentAdminCommands::List(args) => {
                    control_plane::list_enrollments(api_base_override.as_deref(), &args)
                }
                EnrollmentAdminCommands::Get(args) => {
                    control_plane::get_enrollment(api_base_override.as_deref(), &args)
                }
                EnrollmentAdminCommands::Credential(args) => {
                    control_plane::issue_enrollment_credential(api_base_override.as_deref(), &args)
                }
                EnrollmentAdminCommands::Cancel(args) => {
                    control_plane::cancel_enrollment(api_base_override.as_deref(), &args)
                }
            },
            ManageCommands::SyncDns(args) => {
                control_plane::sync_dns(api_base_override.as_deref(), &args)
            }
            ManageCommands::SyncTls(args) => {
                control_plane::sync_tls(api_base_override.as_deref(), &args)
            }
            ManageCommands::Unenroll(args) => run_unenroll(api_base_override.as_deref(), &args),
            ManageCommands::Enroll(args) => run_enroll(api_base_override.as_deref(), &args),
            ManageCommands::Lockdown(args) => {
                require_local_namespace(api_base_override.as_deref())?;
                lockdown::run(api_base_override.as_deref(), &args)
            }
        },
        Commands::Advanced(args) => match args.command {
            AdvancedCommands::Install(args) => install::run(api_base_override.as_deref(), &args),
            AdvancedCommands::RefreshCredentials(args) => {
                require_local_namespace(api_base_override.as_deref())?;
                maintenance::RefreshCredentialsCommand::new(api_base_override.as_deref(), &args)
                    .run()
            }
            AdvancedCommands::Reconcile(args) => {
                require_local_namespace(api_base_override.as_deref())?;
                maintenance::ReconcileCommand::new(&args).run()
            }
            AdvancedCommands::Redeploy(args) => {
                require_local_namespace(api_base_override.as_deref())?;
                maintenance::RedeployCommand::new(&args).run()
            }
            AdvancedCommands::UpdateUser(args) => maintenance::update_user(&args),
            AdvancedCommands::RedeployStatus(args) => maintenance::redeploy_status(&args),
            AdvancedCommands::Fleet(args) => fleet::run(api_base_override.as_deref(), &args),
        },
    }
}

fn require_local_namespace(api_base_override: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        crate::api::uses_local_agent(api_base_override)?,
        "this operation changes the local machine; select its enrolled namespace"
    );
    Ok(())
}

fn warn_if_agent_version_mismatch() {
    if system::LocalRoot::is_running() || !Path::new(AGENT_CONFIG_PATH).exists() {
        return;
    }
    let Ok(client) = local_agent::http_client(Duration::from_millis(80)) else {
        return;
    };
    let Ok(response) = local_agent::version(&client) else {
        return;
    };
    if response.version != env!("CARGO_PKG_VERSION") {
        ui::warn(&format!(
            "local aegis-agent is v{} but this aegis CLI is v{}; run `aegis advanced redeploy` to align them",
            response.version,
            env!("CARGO_PKG_VERSION")
        ));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemLockPolicy {
    None,
    SshSetup,
    FullCommand,
}

fn command_system_lock_policy(command: &Commands) -> SystemLockPolicy {
    match command {
        Commands::Agent(_) | Commands::List(_) | Commands::Tunnel(_) => SystemLockPolicy::None,
        Commands::Ssh(_) | Commands::Push(_) | Commands::Pull(_) => SystemLockPolicy::SshSetup,
        Commands::Manage(args) => manage_command_system_lock_policy(&args.command),
        Commands::Advanced(args) => advanced_command_system_lock_policy(&args.command),
    }
}

fn manage_command_system_lock_policy(command: &ManageCommands) -> SystemLockPolicy {
    match command {
        ManageCommands::Host(_) | ManageCommands::Namespace(_) => SystemLockPolicy::None,
        ManageCommands::Lockdown(args) => match &args.command {
            crate::cli::LockdownCommands::Status => SystemLockPolicy::None,
            crate::cli::LockdownCommands::Enable(_) | crate::cli::LockdownCommands::Disable => {
                SystemLockPolicy::FullCommand
            }
        },
        ManageCommands::Enroll(args) => {
            if args.local {
                SystemLockPolicy::FullCommand
            } else {
                SystemLockPolicy::None
            }
        }
        ManageCommands::Unenroll(args) => {
            if args.local {
                SystemLockPolicy::FullCommand
            } else {
                SystemLockPolicy::None
            }
        }
        ManageCommands::Login(_)
        | ManageCommands::Principal(_)
        | ManageCommands::Satellite(_)
        | ManageCommands::AgentToken(_)
        | ManageCommands::Enrollment(_)
        | ManageCommands::SyncDns(_)
        | ManageCommands::SyncTls(_) => SystemLockPolicy::None,
    }
}

fn advanced_command_system_lock_policy(command: &AdvancedCommands) -> SystemLockPolicy {
    match command {
        AdvancedCommands::Install(_) => SystemLockPolicy::FullCommand,
        AdvancedCommands::RefreshCredentials(_)
        | AdvancedCommands::Reconcile(_)
        | AdvancedCommands::Redeploy(_)
        | AdvancedCommands::UpdateUser(_)
        | AdvancedCommands::RedeployStatus(_)
        | AdvancedCommands::Fleet(_) => SystemLockPolicy::None,
    }
}

fn cached_network_members_from_response(
    hosts: aegis_dto::protocol::AegisHostListResponse,
    response: aegis_dto::protocol::AegisNetworkMemberListResponse,
) -> Result<Vec<CachedHost>> {
    response
        .members
        .into_iter()
        .map(|(host_id, member)| {
            let host = hosts
                .hosts
                .get(&host_id)
                .cloned()
                .ok_or_else(|| anyhow!("network member `{host_id}` has no matching host"))?;
            let aliases = host.aliases.clone();
            Ok(CachedHost {
                host_id,
                aliases,
                host: aegis_dto::protocol::AegisNetworkHost::resolve(host, member),
            })
        })
        .collect()
}

fn command_output_failure_detail(output: &CommandOutput) -> String {
    compact_line(&command_output_full_failure_detail(output))
}

fn command_output_full_failure_detail(output: &CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    format!("exit status {}", output.status.code().unwrap_or(1))
}

fn probe_local_agent_version_detail(target: &semver::Version) -> agent_version::ProbeResult {
    match local_agent::http_client(Duration::from_secs(5))
        .and_then(|client| local_agent::version(&client))
    {
        Ok(response) => agent_version::from_text(&response.version, target),
        Err(error) => agent_version::ProbeResult::unknown(format!(
            "local agent version probe failed: {}",
            single_line_error(&error)
        )),
    }
}

fn single_line_error(error: &anyhow::Error) -> String {
    compact_line(&full_error(error))
}

fn full_error(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

fn compact_line(value: &str) -> String {
    let line = value.lines().next().unwrap_or("unknown error").trim();
    if line.chars().count() > 96 {
        format!("{}...", line.chars().take(93).collect::<String>())
    } else {
        line.to_string()
    }
}

fn run_unenroll(api_base_override: Option<&str>, args: &UnenrollArgs) -> Result<i32> {
    let target = if args.orphan {
        None
    } else {
        let target = EnrollTarget::parse_unenroll(args)?;
        if matches!(target, EnrollTarget::Local(_)) {
            if let Some(code) = system::LocalRoot::reexec_if_needed()? {
                return Ok(code);
            }
        }
        Some(target)
    };
    let installed_agent_api_base =
        install::load_optional_agent_config()?.map(|config| config.api_base);
    let api_base = resolve_api_base(api_base_override, installed_agent_api_base.as_deref())?;
    if args.orphan {
        let workflow = ui::task(TaskOptions {
            label: format!("Removing orphaned host `{}`", args.host),
            visibility: TaskVisibility::Immediate,
            ..TaskOptions::default()
        })?;
        workflow.set_phase("deleting the control-plane host identity");
        delete_host_from_api(&api_base, args.api_token.as_deref(), &args.host)?;
        workflow.set_phase("notifying the reachable fleet of the topology change");
        mesh_refresh::refresh_after_topology_change(api_base_override);
        workflow.finish(format!(
            "Removed orphaned host `{}` from the Aegis control plane. No connection to the lost host was attempted.",
            args.host
        ));
        return Ok(0);
    }

    match target.as_ref().expect("non-orphan unenroll target") {
        EnrollTarget::Local(_) => {
            let workflow = ui::task(TaskOptions {
                label: format!("Unenrolling local host `{}`", args.host),
                visibility: TaskVisibility::Immediate,
                ..TaskOptions::default()
            })?;
            workflow.set_phase("removing local SSH, mesh, and agent integration");
            let managed_state = match remove_local_aegis_management(
                api_base_override,
                args.api_token.as_deref(),
            ) {
                Ok(state) => state,
                Err(error) => {
                    workflow.abandon(
                        "Local removal stopped part-way through; inspect installed Aegis state before retrying",
                    );
                    return Err(error);
                }
            };
            if !args.skip_api_delete {
                let deleted_host = managed_state
                    .as_ref()
                    .map(|state| state.host_id.to_string())
                    .unwrap_or_else(|| args.host.clone());
                workflow.set_phase("deleting the control-plane host identity");
                if let Err(error) =
                    delete_host_from_api(&api_base, args.api_token.as_deref(), &deleted_host)
                {
                    workflow.abandon(format!(
                        "Local Aegis integration was removed, but control-plane host `{deleted_host}` may remain"
                    ));
                    return Err(error).context(
                        "local Aegis integration was removed, but the control-plane host deletion failed",
                    );
                }
                workflow.set_phase("notifying the reachable fleet of the topology change");
                mesh_refresh::refresh_after_topology_change(api_base_override);
            }
            workflow.finish("Aegis SSH, mesh, and local agent integration removed");
        }
        EnrollTarget::Remote(remote) => {
            let session = remote::BootstrapSession::open(
                remote,
                "ambient-unenroll.sock",
                remote::PasswordPrompt::new(&format!(
                    "Remote sudo requires the password for {}@{}.",
                    remote.user, remote.host
                )),
            )?;
            let workflow = ui::task(TaskOptions {
                label: format!("Unenrolling remote host `{}`", args.host),
                visibility: TaskVisibility::Immediate,
                ..TaskOptions::default()
            })?;
            workflow.set_phase("validating the trusted remote system Aegis binary");
            if !session.has_trusted_system_aegis()? {
                bail!(
                    "remote host `{}` has no trusted root-owned system Aegis binary; repair it or use --orphan explicitly",
                    args.host
                );
            }
            workflow.set_phase("removing Aegis integration on the remote host");
            let result = ui::suspend(|| session.run_aegis_unenroll(&api_base, &args.host));
            let _ = session.cleanup();
            if let Err(error) = result {
                workflow.abandon(
                    "Remote removal did not complete; the control-plane identity was retained",
                );
                return Err(error);
            }
            if !args.skip_api_delete {
                workflow.set_phase("deleting the control-plane host identity");
                if let Err(error) =
                    delete_host_from_api(&api_base, args.api_token.as_deref(), &args.host)
                {
                    workflow.abandon(format!(
                        "Remote integration was removed, but control-plane host `{}` may remain",
                        args.host
                    ));
                    return Err(error).context(
                        "remote Aegis integration was removed, but the control-plane host deletion failed",
                    );
                }
                workflow.set_phase("notifying the reachable fleet of the topology change");
                mesh_refresh::refresh_after_topology_change(api_base_override);
            }
            workflow.finish(format!("Removed Aegis from remote host `{}`", args.host));
        }
    }
    Ok(0)
}

fn remove_local_aegis_management(
    api_base_override: Option<&str>,
    api_token: Option<&str>,
) -> Result<Option<local_state::ManagedHostState>> {
    require_local_namespace(api_base_override)?;
    let api_base = resolve_api_base(
        api_base_override,
        crate::api::installed_agent_api_base()?.as_deref(),
    )?;
    let owns_management_group = Path::new(AGENT_CONFIG_PATH).is_file();
    let managed_state = match local_state::ManagedHostStateStore::load()? {
        Some(state) => Some(state),
        None => match local_state::ManagedHostStateStore::recover(api_base_override, api_token) {
            Ok(Some(state)) => {
                ui::warn(
                    "managed aegis state was missing; recovered the local host identity from the WireGuard runtime",
                );
                Some(state)
            }
            Ok(None) => None,
            Err(error) => {
                ui::warn(&format!(
                    "managed aegis state was missing and the local host identity could not be recovered: {error}"
                ));
                None
            }
        },
    };
    #[cfg(target_os = "macos")]
    let (native_runtime, mut native_removal) = {
        use capulus::managed::{JobId, RedeployCoordinator, SystemUninstallation};
        let product = std::sync::Arc::new(crate::managed::product()?);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        anyhow::ensure!(
            RedeployCoordinator::new(std::sync::Arc::clone(&product))?
                .active()?
                .is_none(),
            "a managed upgrade is still active; wait for it before unenrolling"
        );
        let mut removal =
            runtime.block_on(SystemUninstallation::prepare(&product, JobId::random()))?;
        runtime.block_on(removal.deactivate())?;
        crate::agent::remove_native_resources().context(
            "agent stopped; native ownership journals and installation journal retained for repair",
        )?;
        (runtime, removal)
    };
    #[cfg(target_os = "macos")]
    crate::ssh_service::remove_certificate_integration()?;
    system::Sshd::remove_dropin(Path::new(AEGIS_SSHD_DROPIN))?;
    #[cfg(target_os = "linux")]
    {
        system::Sshd::remove_dropin(Path::new(AEGIS_LOCKDOWN_DROPIN))?;
        system::Sshd::remove_dropin(Path::new(aegis_dto::layout::DIRECT_SSHD_DROPIN_PATH))?;
        system::SystemdUnit::new(crate::managed::APPLICATION_SOCKET_NAME).disable_now()?;
        system::SystemdUnit::new(crate::managed::MANAGEMENT_SOCKET_NAME).disable_now()?;
        system::SystemdUnit::new(AEGIS_AGENT_SERVICE_NAME).disable_now()?;
        remove_local_egress_policy()?;
        for interface in managed_wireguard_interfaces_in(Path::new(WIREGUARD_DIR))? {
            system::SystemdUnit::new(format!("{WIREGUARD_UNIT_PREFIX}{interface}"))
                .disable_now()?;
        }
        crate::apparmor::remove_wireguard_access()?;
        system::SystemdUnit::new(BIRD_SERVICE_NAME).disable_now()?;
        system::TextFile::new(Path::new(AEGIS_AGENT_UNIT_PATH)).remove_if_exists()?;
        system::TextFile::new(Path::new("/etc/systemd/system/aegis-agent.socket"))
            .remove_if_exists()?;
        system::TextFile::new(Path::new("/etc/systemd/system/aegis-capulus.socket"))
            .remove_if_exists()?;
    }
    system::TextFile::new(Path::new(AGENT_CONFIG_PATH)).remove_if_exists()?;
    system::TextFile::new(Path::new(SHARED_CACHE_PATH)).remove_if_exists()?;
    system::TextFile::new(Path::new(crate::config::AGENT_CONTEXT_PATH)).remove_if_exists()?;
    #[cfg(target_os = "linux")]
    system::TextFile::new(Path::new(crate::platform::bird_config_path(
        crate::platform::detect()?,
    )?))
    .remove_if_exists()?;
    system::TextFile::new(Path::new(WIREGUARD_CONFIG_PATH)).remove_if_exists()?;
    system::TextFile::new(Path::new(WIREGUARD_PRIVATE_KEY_PATH)).remove_if_exists()?;
    system::TextFile::new(Path::new(WIREGUARD_PUBLIC_KEY_PATH)).remove_if_exists()?;
    #[cfg(target_os = "linux")]
    system::TextFile::new(Path::new(WIREGUARD_UNIT_TEMPLATE_PATH)).remove_if_exists()?;
    system::TextFile::new(Path::new(REMOTE_HOST_CERT_PATH)).remove_if_exists()?;
    if Path::new(AEGIS_DIR_ETC).exists() {
        fs::remove_dir_all(AEGIS_DIR_ETC)
            .with_context(|| format!("failed to remove {AEGIS_DIR_ETC}"))?;
    }
    if Path::new(AEGIS_AGENT_DIR).exists() {
        fs::remove_dir_all(AEGIS_AGENT_DIR)
            .with_context(|| format!("failed to remove {AEGIS_AGENT_DIR}"))?;
    }
    #[cfg(target_os = "linux")]
    system::Systemd::daemon_reload()?;
    if crate::ssh_service::active()? {
        system::Sshd::reload()?;
    }
    if let Some(state) = managed_state.as_ref() {
        remove_local_host_artifacts(&api_base, &state.host_id)?;
        system::TextFile::new(Path::new(AEGIS_STATE_PATH)).remove_if_exists()?;
    } else {
        ui::warn("no aegis state was found; the host-specific client artifacts were not removed");
        system::TextFile::new(Path::new(AEGIS_STATE_PATH)).remove_if_exists()?;
    }
    #[cfg(target_os = "linux")]
    system::TextFile::new(Path::new(SYSTEM_AEGIS_BIN)).remove_if_exists()?;
    #[cfg(target_os = "macos")]
    {
        native_removal.remove_files().context(
            "host configuration removed; managed installation journal retained for repair",
        )?;
        native_runtime.block_on(native_removal.finalize())?;
    }
    if owns_management_group {
        crate::system_user::remove_management_group()?;
    }
    Ok(managed_state)
}

#[cfg(target_os = "linux")]
fn remove_local_egress_policy() -> Result<()> {
    let script = Path::new(aegis_dto::layout::EGRESS_POLICY_SCRIPT_PATH);
    if script.exists() {
        system::LocalRoot::run_script(&format!(
            "/bin/bash {} remove\n",
            sh_quote(aegis_dto::layout::EGRESS_POLICY_SCRIPT_PATH)
        ))?;
    }
    system::SystemdUnit::new(aegis_dto::layout::EGRESS_POLICY_SYSTEMD_SERVICE_NAME)
        .disable_now()?;
    system::TextFile::new(Path::new(
        aegis_dto::layout::EGRESS_POLICY_SYSTEMD_UNIT_PATH,
    ))
    .remove_if_exists()?;
    let resolved_dropin = Path::new(aegis_dto::layout::EGRESS_RESOLVED_DROPIN_PATH);
    let restart_resolved = resolved_dropin.exists();
    system::TextFile::new(resolved_dropin).remove_if_exists()?;
    if restart_resolved {
        system::LocalRoot::run_script("systemctl try-restart systemd-resolved.service\n")?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn managed_wireguard_interfaces_in(directory: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", directory.display()));
        }
    };
    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to inspect {}", directory.display()))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or_else(|| {
            anyhow!(
                "managed WireGuard directory contains a non-UTF-8 filename at {}",
                entry.path().display()
            )
        })?;
        let Some(interface) = file_name.strip_suffix(".conf") else {
            continue;
        };
        aegis_dto::validate_wireguard_interface_name(interface).with_context(|| {
            format!(
                "managed WireGuard configuration {} has an invalid interface name",
                entry.path().display()
            )
        })?;
        interfaces.push(interface.to_string());
    }
    interfaces.sort();
    interfaces.dedup();
    Ok(interfaces)
}

fn delete_host_from_api(api_base: &str, api_token: Option<&str>, host: &str) -> Result<()> {
    if let Some(api_token) = api_token {
        let api = ApiClient::new(api_base)?;
        let host_id = match host.parse::<HostId>() {
            Ok(host_id) => host_id,
            Err(_) => {
                let alias = HostAlias::parse(host.to_string())?;
                match api.get_alias(api_token, &alias) {
                    Ok(response) => response.host_id,
                    Err(ApiClientError::Status {
                        status: StatusCode::NOT_FOUND,
                        ..
                    }) => {
                        ui::warn(&format!(
                            "host `{host}` was already absent from the aegis API"
                        ));
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        };
        return match api.delete_host(api_token, &host_id) {
            Ok(()) => Ok(()),
            Err(ApiClientError::Status {
                status: StatusCode::NOT_FOUND,
                ..
            }) => {
                ui::warn(&format!(
                    "host `{host}` was already absent from the aegis API"
                ));
                Ok(())
            }
            Err(error) => Err(error.into()),
        };
    }

    let mut api = AuthenticatedApiClient::load(Some(api_base)).map_err(|error| {
        anyhow!(
            "failed to remove host `{host}` from the aegis API: {error}. Run `aegis manage login` or pass `--api-token`."
        )
    })?;
    let host_id = match api.resolve_host_id(host) {
        Ok(host_id) => host_id,
        Err(error) if api_error_status(&error) == Some(StatusCode::NOT_FOUND) => {
            ui::warn(&format!(
                "host `{host}` was already absent from the aegis API"
            ));
            return Ok(());
        }
        Err(error) => {
            return Err(anyhow!(
                "failed to resolve host `{host}` in the aegis API: {error}"
            ));
        }
    };
    match api.delete_host(&host_id) {
        Ok(()) => Ok(()),
        Err(error) if api_error_status(&error) == Some(StatusCode::NOT_FOUND) => {
            ui::warn(&format!(
                "host `{host}` was already absent from the aegis API"
            ));
            Ok(())
        }
        Err(error) => Err(anyhow!(
            "failed to remove host `{host}` from the aegis API: {error}. Run `aegis manage login` or pass `--api-token`."
        )),
    }
}

fn api_error_status(error: &anyhow::Error) -> Option<StatusCode> {
    error
        .downcast_ref::<ApiClientError>()
        .and_then(|error| match error {
            ApiClientError::Status { status, .. } => Some(*status),
            ApiClientError::Transport(_) => None,
        })
}

struct EnrollApi {
    client: HostAgentApiClient,
}

impl EnrollApi {
    fn load(invitation: &aegis_dto::protocol::AegisEnrollmentCredentialResponse) -> Result<Self> {
        let client = HostAgentApiClient::from_refresh_token(
            &invitation.api_base,
            &invitation.refresh_token,
        )?;
        anyhow::ensure!(
            client.host_id() == invitation.enrollment.host_id,
            "invitation host does not match its credential"
        );
        Ok(Self { client })
    }
    fn host_id(&self) -> HostId {
        self.client.host_id()
    }

    fn credential_kind(&self) -> aegis_dto::protocol::AegisCredentialKind {
        self.client.credential_kind()
    }

    fn refresh_token(&self) -> &str {
        self.client.refresh_token()
    }

    fn enrollment(&mut self) -> Result<aegis_dto::protocol::AegisEnrollment> {
        self.client.get_enrollment()
    }

    fn heartbeat(&mut self, phase: aegis_dto::protocol::AegisEnrollmentPhase) -> Result<()> {
        self.client.heartbeat_enrollment(
            &aegis_dto::protocol::AegisEnrollmentHeartbeatRequest { phase },
        )?;
        Ok(())
    }

    fn prepare(
        &mut self,
        identity: &EnrollTargetIdentity,
        wireguard_endpoints: Vec<String>,
    ) -> Result<aegis_dto::protocol::AegisEnrollmentPrepareResponse> {
        self.client
            .prepare_enrollment(&aegis_dto::protocol::AegisEnrollmentPrepareRequest {
                platform: identity.platform,
                host_public_key: identity.host_public_key.clone(),
                wireguard_public_key: identity.wireguard_public_key.clone(),
                wireguard_endpoints,
            })
    }

    fn activate(&mut self) -> Result<aegis_dto::protocol::AegisEnrollmentActivateResponse> {
        self.client.activate_enrollment()
    }
}

fn run_enroll(api_base_override: Option<&str>, args: &EnrollArgs) -> Result<i32> {
    let plan = EnrollmentPlan::parse(args)?;
    if args.local {
        check_local_enrollment_platform()?;
    }
    let (invitation, path) = match args.invitation.as_deref() {
        Some(path) => (crate::invitation::read(path)?, path.to_owned()),
        None => {
            let base = resolve_api_base(
                api_base_override,
                crate::api::installed_agent_api_base()?.as_deref(),
            )?;
            let mut api = AuthenticatedApiClient::load(Some(&base))?;
            let alias = match &args.name {
                Some(alias) => alias.clone(),
                None => match &plan.target {
                    EnrollTarget::Local(_) => local_machine_alias()?,
                    EnrollTarget::Remote(remote) => {
                        HostAlias::parse(remote.host.split('.').next().unwrap_or(&remote.host))
                            .context("machine name is not a valid alias; specify --name")?
                    }
                },
            };
            let enrollment = crate::invitation::reserve(&mut api, alias, AegisHostMode::Leaf)?;
            crate::invitation::issue(&mut api, &enrollment.host_id)?
        }
    };
    if let Some(base) = api_base_override {
        anyhow::ensure!(
            crate::config::canonical_saved_api_base_url(base) == invitation.api_base,
            "explicit API endpoint differs from the enrollment invitation"
        );
    }
    let result = run_enroll_invitation(&invitation, &plan);
    match &result {
        Ok(_) => {
            fs::remove_file(&path).with_context(|| {
                format!(
                    "Machine enrolled; delete the used invitation at {}",
                    path.display()
                )
            })?;
            crate::config::UserContext {
                api_base: invitation.api_base.clone(),
            }
            .persist()?;
        }
        Err(_) => ui::warn(&format!(
            "Invitation retained at {}. Retry with --invitation {}; if the agent has consumed its credential, repair using administrator-issued credentials.",
            path.display(),
            path.display()
        )),
    }
    result
}

fn run_enroll_invitation(
    invitation: &aegis_dto::protocol::AegisEnrollmentCredentialResponse,
    plan: &EnrollmentPlan,
) -> Result<i32> {
    if matches!(plan.target, EnrollTarget::Local(_))
        && let Some(context) = crate::config::AgentContext::load()?
    {
        anyhow::ensure!(
            context.api_base == invitation.api_base
                && context.host_id == invitation.enrollment.host_id,
            "this machine is already enrolled under another identity; unenroll it explicitly first"
        );
        if application_agent_info(&crate::managed::product()?).is_ok() {
            ui::success("This machine is already enrolled and its agent is ready");
            return Ok(0);
        }
    }
    anyhow::ensure!(
        invitation.enrollment.expires_unix > crate::config::now_unix(),
        "enrollment invitation expired; an administrator must issue a fresh enrollment"
    );
    match &plan.target {
        EnrollTarget::Local(_) => run_enroll_with_target(invitation, plan, None),
        EnrollTarget::Remote(remote) => {
            let session = match remote::BootstrapSession::open(
                remote,
                "ambient-enroll.sock",
                remote::PasswordPrompt::new(&format!(
                    "Remote sudo requires the password for {}@{}.",
                    remote.user, remote.host
                )),
            ) {
                Ok(session) => session,
                Err(bootstrap_error) => {
                    return Err(bootstrap_error).context(
                        "remote enrollment requires the explicit bootstrap SSH path until final verification completes",
                    );
                }
            };
            let result = run_enroll_with_target(invitation, plan, Some(&session));
            if let Err(error) = remote::RemoteBootstrapSession::cleanup(&session) {
                ui::warn(&format!(
                    "failed to close the remote bootstrap session cleanly: {error:#}"
                ));
            }
            result
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollTargetIdentity {
    platform: aegis_dto::platform::HostPlatform,
    wireguard_public_key: String,
    host_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollmentProgress {
    prepared: bool,
    activation_attempted: bool,
    activation_committed: bool,
    agent_started: bool,
}

impl EnrollmentProgress {
    fn new() -> Self {
        Self {
            prepared: false,
            activation_attempted: false,
            activation_committed: false,
            agent_started: false,
        }
    }

    fn record_prepared(&mut self) {
        self.prepared = true;
    }

    fn begin_activation(&mut self) {
        self.activation_attempted = true;
    }

    fn commit_activation(&mut self) {
        self.activation_committed = true;
    }

    fn record_agent_started(&mut self) {
        self.agent_started = true;
    }
}

fn run_enroll_with_target(
    invitation: &aegis_dto::protocol::AegisEnrollmentCredentialResponse,
    plan: &EnrollmentPlan,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
) -> Result<i32> {
    ensure_client_dirs()?;
    let api_base = invitation.api_base.clone();
    let api_base_override = Some(api_base.as_str());
    let mut api = EnrollApi::load(invitation)?;
    let host_id = api.host_id();
    let workflow = ui::task(TaskOptions {
        label: format!("Enrolling host `{host_id}`"),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    if api.credential_kind() == aegis_dto::protocol::AegisCredentialKind::Agent {
        return recover_activated_enrollment(&api_base, &api, plan, remote_session, workflow);
    }

    workflow.set_phase("loading authoritative enrollment intent");
    let enrollment = api.enrollment()?;
    if enrollment.host_id != host_id {
        bail!(
            "enrollment credential identifies host `{host_id}`, but the enrollment identifies `{}`",
            enrollment.host_id
        );
    }
    if enrollment.network != DEFAULT_AEGIS_NETWORK {
        bail!(
            "enrollment targets unsupported network `{}`; this client manages `{DEFAULT_AEGIS_NETWORK}`",
            enrollment.network
        );
    }
    let target = &plan.target;
    let target_label = target.label();
    let alias = enrollment.aliases.primary().clone();
    let mut progress = EnrollmentProgress::new();

    let result = (|| -> Result<i32> {
        let platform = match target {
            EnrollTarget::Local(_) => crate::platform::detect()?,
            EnrollTarget::Remote(_) => require_remote_session(remote_session)?.platform()?,
        };
        platform.require_role(enrollment.mode)?;
        api.heartbeat(aegis_dto::protocol::AegisEnrollmentPhase::PreparingMachine)?;
        let identity = prepare_enroll_target_identity(
            target,
            remote_session,
            enrollment.ssh.is_some(),
            &workflow,
        )?;
        workflow.set_phase("preparing the reserved host identity in the control plane");
        let prepared = api.prepare(&identity, target.wireguard_endpoints(enrollment.mode))?;
        progress.record_prepared();
        validate_prepared_enrollment(&enrollment, &prepared)?;
        let pending_member = prepared.member.member.clone();
        let pending_host = CachedHost {
            host_id,
            aliases: prepared.host.aliases.clone(),
            host: aegis_dto::protocol::AegisNetworkHost::resolve(
                prepared.host.clone(),
                pending_member,
            ),
        };
        host::host_wireguard_identity(&pending_host)?;
        prepared.network.mesh.as_ref().ok_or_else(|| {
            anyhow!("`{DEFAULT_AEGIS_NETWORK}` network does not publish a managed mesh")
        })?;
        let hub_peers = if enrollment.mode == AegisHostMode::Hub {
            Vec::new()
        } else {
            let hosts = cached_network_members_from_response(
                prepared.active_hosts.clone(),
                prepared.active_members.clone(),
            )?;
            mesh_bootstrap::HubPeerSelection::new(host_id).select_from_hosts(hosts)?
        };
        let server_certificate = prepared.server_certificate.as_deref();
        if enrollment.ssh.is_some() && server_certificate.is_none() {
            bail!("enrollment preparation did not return the required SSH server certificate");
        }
        let target_agent_token = api.refresh_token().to_string();
        if let (EnrollTarget::Local(_), Some(server_certificate)) = (target, server_certificate) {
            system::LocalRoot::install_server_certificate(server_certificate.as_bytes())?;
        }

        if let EnrollTarget::Local(_) = target
            && platform.operating_system != aegis_dto::platform::OperatingSystem::MacOs
            && !hub_peers.is_empty()
        {
            workflow.set_phase("configuring local WireGuard peers");
            system::LocalRoot::run_script(
                &mesh_bootstrap::BootstrapMeshScript::new(
                    &pending_host,
                    &hub_peers,
                    &prepared.network,
                    agent_mode_from_host_mode(enrollment.mode),
                )
                .render()?,
            )?;
        }

        api.heartbeat(aegis_dto::protocol::AegisEnrollmentPhase::InstallingAgent)?;
        workflow.set_phase(format!("installing Aegis on {target_label}"));
        match target {
            EnrollTarget::Local(_) => {
                enroll_install::LocalTargetInstall::new(enroll_install::LocalTargetInstallOptions {
                    api_base: &api_base,
                    host_id,
                    inbound_ssh: enrollment.ssh.is_some(),
                    install_host_certificate: server_certificate.is_some(),
                    agent_token: &target_agent_token,
                    initial_user_id: Some(&enrollment.initial_user_id),
                })
                .run()?
            }
            EnrollTarget::Remote(remote) => {
                let install_script = enroll_install::RemoteFinalizeInstall::new(
                    enroll_install::RemoteFinalizeInstallParts {
                        api_base: &api_base,
                        pending_host: &pending_host,
                        hub_peers: &hub_peers,
                        network: &prepared.network,
                        server_certificate,
                        agent_token: &target_agent_token,
                        login_principal: &remote.login_principal,
                        initial_user_id: Some(&enrollment.initial_user_id),
                        mode: agent_mode_from_host_mode(enrollment.mode),
                        inbound_ssh: enrollment.ssh.is_some(),
                    },
                )
                .render()?;
                let session = require_remote_session(remote_session)?;
                ui::suspend(|| {
                    session.run_private_shell_streaming_with_tty(
                        &remote::SudoScript::new(&install_script).render(),
                    )
                })?;
            }
        }

        api.heartbeat(aegis_dto::protocol::AegisEnrollmentPhase::Activating)?;
        workflow.set_phase("activating host in the Aegis control plane");
        progress.begin_activation();
        let activated = api.activate()?;
        progress.commit_activation();
        validate_activation_response(host_id, &activated)?;
        restart_enrollment_agent(target, remote_session, &workflow)?;
        progress.record_agent_started();
        finish_activated_enrollment(api_base_override, host_id, plan, remote_session, &workflow)?;
        Ok(0)
    })();

    if result.is_ok() {
        workflow.finish(format!(
            "Enrolled host `{alias}` ({host_id}) with WireGuard address {}",
            enrollment_wireguard_ipv4_from_cache(host_id).unwrap_or_else(|| "assigned".to_string())
        ));
        return result;
    }

    let outcome = if progress.agent_started {
        format!(
            "Host `{host_id}` is active and its agent was started; rerun enrollment to verify final reconciliation"
        )
    } else if progress.activation_committed {
        format!(
            "Host `{host_id}` is active, but its staged agent may still need to be started; rerun enrollment to repair it"
        )
    } else if progress.activation_attempted {
        format!(
            "Activation of host `{host_id}` may have committed; rerun enrollment to discover and finish the exact state"
        )
    } else if progress.prepared {
        format!(
            "The enrollment grant and pending host/member for `{host_id}` were retained for an exact retry"
        )
    } else {
        format!(
            "The enrollment grant for `{host_id}` was retained; no host or network-member record was created"
        )
    };
    workflow.abandon(outcome);

    result
}

fn validate_prepared_enrollment(
    expected: &aegis_dto::protocol::AegisEnrollment,
    prepared: &aegis_dto::protocol::AegisEnrollmentPrepareResponse,
) -> Result<()> {
    if prepared.enrollment.host_id != expected.host_id
        || prepared.member.host_id != expected.host_id
        || prepared.member.network != expected.network
        || prepared.network.name != expected.network
        || prepared.host.aliases != expected.aliases
        || prepared.member.member.aliases != expected.aliases
        || !prepared.host.pending
        || !prepared.member.member.pending
    {
        bail!(
            "control plane returned inconsistent prepared resources for enrollment `{}`",
            expected.host_id
        );
    }
    Ok(())
}

fn validate_activation_response(
    host_id: HostId,
    activated: &aegis_dto::protocol::AegisEnrollmentActivateResponse,
) -> Result<()> {
    if activated.member.host_id != host_id
        || activated.host.pending
        || activated.member.member.pending
    {
        bail!("control plane returned inconsistent activated resources for host `{host_id}`");
    }
    Ok(())
}

fn require_remote_session(
    session: Option<&dyn remote::RemoteBootstrapSession>,
) -> Result<&dyn remote::RemoteBootstrapSession> {
    session.ok_or_else(|| anyhow!("missing remote bootstrap session"))
}

fn load_enroll_target_identity(
    target: &EnrollTarget,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
    publish_ssh: bool,
) -> Result<EnrollTargetIdentity> {
    let (platform, wireguard_public_key, host_public_key) = match target {
        EnrollTarget::Local(_) => (
            crate::platform::detect()?,
            system::LocalRoot::read_file_trimmed(WIREGUARD_PUBLIC_KEY_PATH)
                .context("failed to read the local durable WireGuard public key")?,
            publish_ssh
                .then(|| {
                    system::LocalRoot::read_file_trimmed(&format!("{REMOTE_HOST_KEY_PATH}.pub"))
                        .context("failed to read the local durable SSH host public key")
                })
                .transpose()?,
        ),
        EnrollTarget::Remote(_) => {
            let state = require_remote_session(remote_session)?.load_enroll_state(publish_ssh)?;
            (
                state.platform,
                state.wireguard_public_key,
                state.host_public_key,
            )
        }
    };
    let wireguard_public_key = normalize_wireguard_key(&wireguard_public_key)
        .with_context(|| format!("{} WireGuard public key is invalid", target.label()))?;
    if let Some(host_public_key) = host_public_key.as_deref() {
        PublicKey::from_openssh(host_public_key)
            .with_context(|| format!("{} SSH host public key is invalid", target.label()))?;
    }
    Ok(EnrollTargetIdentity {
        platform,
        wireguard_public_key,
        host_public_key: host_public_key.map(|key| key.trim().to_string()),
    })
}

fn prepare_enroll_target_identity(
    target: &EnrollTarget,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
    publish_ssh: bool,
    workflow: &Task,
) -> Result<EnrollTargetIdentity> {
    match target {
        EnrollTarget::Local(_) => {
            workflow.set_phase("preparing local system prerequisites");
            system::LocalRoot::require_supported_platform()?;
            system::LocalRoot::install_prerequisites()?;
            workflow.set_phase(if publish_ssh {
                "ensuring local WireGuard and SSH identities"
            } else {
                "ensuring the local WireGuard identity"
            });
            system::LocalRoot::run_script(&format!(
                "{}\n{}\n\"$system_aegis\" agent prepare-identity {}\n",
                enroll_install::system_program_bootstrap_script(false),
                crate::platform::BINARY_SHELL_ASSIGNMENT,
                if publish_ssh { "--inbound-ssh" } else { "" }
            ))?;
        }
        EnrollTarget::Remote(_) => {
            workflow.set_phase("preparing remote system prerequisites and identity");
            let session = require_remote_session(remote_session)?;
            ui::suspend(|| {
                session.run_shell_streaming_with_tty(
                    &remote::SudoScript::new(&enroll_install::RemotePrepareHostScript::render(
                        publish_ssh,
                    ))
                    .render(),
                )
            })?;
        }
    }
    load_enroll_target_identity(target, remote_session, publish_ssh)
}

fn restart_enrollment_agent(
    target: &EnrollTarget,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
    workflow: &Task,
) -> Result<()> {
    match target {
        EnrollTarget::Local(_) => {
            workflow.set_phase("starting the local aegis-agent after activation");
            system::LocalRoot::run_script(&enroll_install::system_agent_activation_script())
        }
        EnrollTarget::Remote(_) if remote_session.is_some() => {
            workflow.set_phase("starting and verifying the remote aegis-agent after activation");
            ui::suspend(|| {
                require_remote_session(remote_session)?.run_shell_streaming_with_tty(
                    &remote::SudoScript::new(&enroll_install::system_agent_activation_script())
                        .render(),
                )
            })
        }
        EnrollTarget::Remote(_) => Ok(()),
    }
}

fn finish_activated_enrollment(
    api_base_override: Option<&str>,
    host_id: HostId,
    plan: &EnrollmentPlan,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
    workflow: &Task,
) -> Result<()> {
    match &plan.target {
        EnrollTarget::Local(_) => {
            if crate::platform::detect()?.supports(aegis_dto::platform::Capability::SshLockdown) {
                ui::warn(
                    "SSH lockdown remains disabled during enrollment; enable it after certificate-backed SSH is verified.",
                );
                lockdown::apply_local_disable()?;
            }
            workflow.set_phase("verifying local agent reconciliation and cache persistence");
            let refresh = local_agent::refresh_host_cache()?;
            if let Some(warning) = refresh.warning {
                ui::warn(&warning);
            }
            let host = refresh
                .hosts
                .into_iter()
                .find(|host| host.host_id == host_id)
                .ok_or_else(|| {
                    anyhow!("active host `{host_id}` was not persisted in the local agent cache")
                })?;
            if host.pending {
                bail!("host `{host_id}` is still pending after activation");
            }
        }
        EnrollTarget::Remote(_) => {
            let session = require_remote_session(remote_session).context(
                "remote enrollment finalization requires the original bootstrap SSH path",
            )?;
            let platform = session.platform()?;
            if platform.supports(aegis_dto::platform::Capability::SshLockdown) {
                ui::warn(
                    "SSH lockdown remains disabled during enrollment; enable it after certificate-backed SSH is verified.",
                );
                lockdown::disable_remote(session, workflow)?;
            }
            workflow.set_phase("verifying remote agent reconciliation");
            ui::suspend(|| {
                session.run_shell_streaming_with_tty(&format!(
                    "{} advanced reconcile",
                    sh_quote(crate::platform::system_binary_path(platform))
                ))
            })?;
        }
    }

    workflow.set_phase("notifying the reachable fleet of the topology change");
    mesh_refresh::refresh_after_topology_change(api_base_override);
    Ok(())
}

fn recover_activated_enrollment(
    api_base: &str,
    api: &EnrollApi,
    plan: &EnrollmentPlan,
    remote_session: Option<&dyn remote::RemoteBootstrapSession>,
    workflow: Task,
) -> Result<i32> {
    let host_id = api.host_id();
    workflow.set_phase("repairing credentials after a completed activation");
    match &plan.target {
        EnrollTarget::Local(_) => {
            let config = install::load_agent_config()?;
            if config.host.host_id != host_id {
                bail!(
                    "local agent is configured for host `{}`, but the credential identifies `{host_id}`",
                    config.host.host_id
                );
            }
            install::replace_agent_refresh_token(api.refresh_token())?;
        }
        EnrollTarget::Remote(remote) => {
            let session = require_remote_session(remote_session)
                .context("repairing an activated remote enrollment requires bootstrap SSH")?;
            let token = install::agent_refresh_token_env_assignment(api.refresh_token())?;
            let script = format!(
                "sudo env {token} {binary} --api-base {api_base} advanced install --reinstall --user {user}\n",
                binary = sh_quote(crate::platform::system_binary_path(session.platform()?)),
                api_base = sh_quote(api_base),
                user = sh_quote(&remote.login_principal),
            );
            ui::suspend(|| {
                session.run_private_shell_streaming_with_tty(
                    &remote::SudoScript::new(&script).render(),
                )
            })?;
        }
    }
    restart_enrollment_agent(&plan.target, remote_session, &workflow)?;
    finish_activated_enrollment(None, host_id, plan, remote_session, &workflow)?;
    workflow.finish(format!(
        "Recovered activated enrollment for host `{host_id}` and verified its agent"
    ));
    Ok(0)
}

fn agent_mode_from_host_mode(mode: AegisHostMode) -> AgentMode {
    match mode {
        AegisHostMode::Leaf => AgentMode::Leaf,
        AegisHostMode::Hub => AgentMode::Hub,
    }
}

fn enrollment_wireguard_ipv4_from_cache(host_id: HostId) -> Option<String> {
    crate::config::load_all_hosts(Path::new(SHARED_CACHE_PATH))
        .ok()?
        .into_iter()
        .find(|host| host.host_id == host_id)?
        .wireguard_ipv4()
        .map(str::to_string)
}

fn remove_local_host_artifacts(api_base: &str, host_id: &HostId) -> Result<()> {
    let _lock = crate::locks::host_shell_assets_lock(host_id)?;
    let key = scoped_private_key_path(api_base, host_id)?;
    for path in [
        key.clone(),
        key.with_extension("pub"),
        key.with_file_name(format!("{host_id}-cert.pub")),
    ] {
        system::TextFile::new(&path).remove_if_exists()?;
    }
    Ok(())
}

fn line_with_newline(value: &str) -> String {
    let mut out = value.trim().to_string();
    out.push('\n');
    out
}

fn known_hosts_target(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

pub fn check_local_enrollment_platform() -> Result<()> {
    system::LocalRoot::require_supported_platform()?;
    anyhow::ensure!(
        cfg!(target_os = "macos") || Path::new("/run/systemd/system").is_dir(),
        "Linux enrollment requires systemd; use --no-enroll on an operator-only computer"
    );
    Ok(())
}

pub fn local_machine_alias() -> Result<HostAlias> {
    let system = rustix::system::uname();
    let hostname = system
        .nodename()
        .to_str()
        .context("system hostname is not UTF-8")?;
    HostAlias::parse(hostname.split('.').next().unwrap_or(hostname))
        .context("system hostname is not a valid Aegis alias")
}

pub fn local_machine_ready(api_base: &str, expected: Option<&aegis_dto::HostId>) -> Result<bool> {
    if let Some(context) = crate::config::AgentContext::load()? {
        anyhow::ensure!(
            context.api_base == api_base,
            "this computer belongs to a different deployment; use --no-enroll or unenroll it explicitly"
        );
        anyhow::ensure!(
            expected.is_none_or(|host| *host == context.host_id),
            "local host identity differs from setup receipt"
        );
        let mut ready = application_agent_info(&crate::managed::product()?).is_ok();
        if !ready && expected.is_some() {
            let mut api = AuthenticatedApiClient::load(Some(api_base))?;
            let hosts = api.get_hosts()?;
            let host = hosts
                .hosts
                .get(&context.host_id)
                .context("local setup host is missing from the API")?;
            if !host.pending {
                let task = ui::task(TaskOptions {
                    label: "Resuming the activated local agent".into(),
                    deadline: Some(Duration::from_secs(180)),
                    ..Default::default()
                })?;
                restart_enrollment_agent(
                    &EnrollTarget::Local(enroll_target::LocalTarget),
                    None,
                    &task,
                )?;
                maintenance::ReconcileCommand::new(&crate::cli::ReconcileArgs {}).run()?;
                application_agent_info(&crate::managed::product()?).context(
                    "host is active; installed agent is retained but still requires repair",
                )?;
                task.finish("Local agent is ready");
                ready = true;
            }
        }
        anyhow::ensure!(
            ready || expected.is_some(),
            "existing local agent is unhealthy; repair it before completing setup"
        );
        return Ok(ready);
    }
    Ok(false)
}

pub fn enroll_local_machine(api_base: &str, invitation: std::path::PathBuf) -> Result<()> {
    run_enroll(
        Some(api_base),
        &EnrollArgs {
            invitation: Some(invitation),
            name: None,
            remote: None,
            local: true,
            user: None,
            port: None,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::agent::AEGIS_AGENT_VERSION_PATH;
    use crate::cli::{
        AdvancedArgs, AdvancedCommands, FleetArgs, FleetCommands, FleetRedeployArgs, ManageCommands,
    };

    use super::connect::{
        PreparedConnect, PreparedConnectParts, load_existing_keypair, scanned_key_fields,
    };
    use super::enroll_install;
    use super::enroll_target::{EnrollTarget, EnrollmentPlan, RemoteTarget};
    use super::list::remote_agent_version_probe_command;
    use super::local_state;
    use super::login;
    use super::mesh_bootstrap;
    use super::remote;
    use super::ssh;
    use super::system;
    use super::wireguard;
    use super::{
        AEGIS_AUTHORIZED_PRINCIPALS_DIR, AEGIS_CLIENT_CA_PATH,
        FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT, REMOTE_SUDO_PASSWORD_HELPER_PATH, SystemLockPolicy,
        agent_version, command_system_lock_policy, compact_line, fleet, host, host_list,
        known_hosts_target, lockdown, managed_wireguard_interfaces_in, sh_quote, transfer,
    };
    use crate::cli::{
        AgentMode, Commands, EnrollArgs, InstallArgs, ListArgs, SshArgs, TransferArgs, TunnelArgs,
        TunnelCommands, TunnelStatusArgs, UnenrollArgs,
    };
    use crate::config::{CachedHost, now_unix};
    use aegis_dto::{
        AegisHostMode, HostAlias, HostAliases, HostId,
        protocol::{
            AegisAgentHealth, AegisAgentStatus, AegisHostMessage, AegisHostMessageLevel,
            AegisMeshConfig, AegisNetworkConfig, AegisNetworkHostSsh,
            AegisNetworkMemberInternalAddresses, AegisNetworkMemberWireGuard,
            AegisNetworkWireGuardConfig,
        },
    };
    use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};
    use std::{
        collections::{BTreeSet, HashMap},
        env, fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::Duration,
    };
    use tempfile::{NamedTempFile, tempdir};

    fn host_id(alias: &str) -> HostId {
        let value = alias.bytes().fold(1_u128, |value, byte| {
            value.wrapping_mul(257).wrapping_add(u128::from(byte))
        });
        format!("{value:032x}")
            .parse::<HostId>()
            .expect("test host UUID")
    }

    fn aliases(alias: &str) -> HostAliases {
        HostAliases::new(vec![alias.parse::<HostAlias>().expect("test host alias")])
            .expect("test host aliases")
    }

    fn set_host_alias(host: &mut CachedHost, alias: &str) {
        host.host_id = host_id(alias);
        host.aliases = aliases(alias);
    }

    fn sample_host() -> CachedHost {
        CachedHost {
            host_id: host_id("alpha"),
            aliases: aliases("alpha"),
            host: aegis_dto::protocol::AegisNetworkHost {
                platform: aegis_dto::platform::HostPlatform {
                    operating_system: aegis_dto::platform::OperatingSystem::Ubuntu,
                    architecture: aegis_dto::platform::Architecture::X86_64,
                },
                mode: AegisHostMode::Leaf,
                ssh: Some(AegisNetworkHostSsh {
                    port: Some(22),
                    public_key: Some("ssh-ed25519 AAAA".to_string()),
                    internal_principals: vec!["10.75.1.42".to_string(), "fd75::1:2a".to_string()],
                    external_principals: vec![],
                }),
                wireguard: Some(AegisNetworkMemberWireGuard {
                    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                    ipv4: "10.75.1.42".to_string(),
                    ipv6: "fd75::1:2a".to_string(),
                    endpoints: Vec::new(),
                }),
                egress: None,
                internal: Some(AegisNetworkMemberInternalAddresses {
                    ipv4: "10.75.0.42".to_string(),
                    ipv6: "fd75::42".to_string(),
                }),
                messages: Vec::new(),
                agent: Some(sample_agent_status(env!("CARGO_PKG_VERSION"), now_unix())),
                ssh_lockdown_enabled: false,
                observed_public_ips: aegis_dto::protocol::AegisObservedPublicIps::default(),
                transient: false,
                pending: false,
                updated_unix: 1,
            },
        }
    }

    fn sample_agent_status(version: &str, reported_unix: i64) -> AegisAgentStatus {
        AegisAgentStatus {
            version: version.to_string(),
            health: AegisAgentHealth {
                boot_id: "00000000-0000-0000-0000-000000000001".to_string(),
                reconciled_since_boot: true,
                applied_aliases: None,
                last_reconcile_unix: Some(reported_unix.max(0) as u64),
                last_reconcile_warning: None,
                last_reconcile_error: None,
            },
            reported_unix,
        }
    }

    fn sample_mesh() -> AegisMeshConfig {
        AegisMeshConfig {
            endpoint_port: 51_820,
            overlay_mtu: 1350,
            subnet_ipv4: "10.75.0.0/16".to_string(),
            subnet_ipv6: "fd75::/64".to_string(),
            wireguard_subnet_ipv4: "10.75.1.0/24".to_string(),
            wireguard_subnet_ipv6: "fd75::1:0/120".to_string(),
            host_dns_suffix: None,
        }
    }

    fn sample_network() -> AegisNetworkConfig {
        AegisNetworkConfig {
            name: "aegis".into(),
            wireguard: AegisNetworkWireGuardConfig {
                interface: "wg-aegis".into(),
                endpoint_port: 51820,
                mtu: 1400,
                fwmark: 44641,
                subnet_ipv4: "10.75.1.0/24".into(),
                subnet_ipv6: "fd75::1:0/120".into(),
            },
            mesh: Some(sample_mesh()),
            managed_ssh: true,
            host_dns_suffix: None,
        }
    }

    fn assert_bash_syntax(script: &str) {
        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("bash -n should start");
        child
            .stdin
            .as_mut()
            .expect("bash stdin should be piped")
            .write_all(script.as_bytes())
            .expect("script should be written to bash");
        let status = child.wait().expect("bash -n should exit");
        assert!(status.success(), "rendered bash script has invalid syntax");
    }

    fn sample_hub(alias: &str) -> CachedHost {
        let mut host = sample_host();
        set_host_alias(&mut host, alias);
        host.host.mode = AegisHostMode::Hub;
        host.host.wireguard = Some(AegisNetworkMemberWireGuard {
            public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
            ipv4: "10.75.1.1".to_string(),
            ipv6: "fd75::1:1".to_string(),
            endpoints: vec!["34.1.2.3".to_string(), "2600:1900:4000:fec::1".to_string()],
        });
        host
    }

    fn sample_prepared_connect(strict_server_cert: bool) -> PreparedConnect {
        sample_prepared_connect_to("10.75.1.42", strict_server_cert)
    }

    fn sample_prepared_connect_to(connect_host: &str, strict_server_cert: bool) -> PreparedConnect {
        PreparedConnect::new(PreparedConnectParts {
            host: sample_host(),
            connect_host: connect_host.to_string(),
            login_principal: "ubuntu".to_string(),
            private_key_path: PathBuf::from("/tmp/aegis-test-key"),
            certificate_path: PathBuf::from("/tmp/aegis-test-key-cert.pub"),
            private_key_owner: None,
            certificate_owner: None,
            known_hosts: NamedTempFile::new().expect("known_hosts temp file should create"),
            strict_server_cert,
        })
    }

    fn sample_owned_prepared_connect() -> (PreparedConnect, [PathBuf; 3]) {
        let private_key = NamedTempFile::new().expect("private key temp file should create");
        let certificate = NamedTempFile::new().expect("certificate temp file should create");
        let known_hosts = NamedTempFile::new().expect("known_hosts temp file should create");
        let paths = [
            private_key.path().to_path_buf(),
            certificate.path().to_path_buf(),
            known_hosts.path().to_path_buf(),
        ];
        (
            PreparedConnect::new(PreparedConnectParts {
                host: sample_host(),
                connect_host: "10.75.1.42".to_string(),
                login_principal: "ubuntu".to_string(),
                private_key_path: paths[0].clone(),
                certificate_path: paths[1].clone(),
                private_key_owner: Some(private_key),
                certificate_owner: Some(certificate),
                known_hosts,
                strict_server_cert: true,
            }),
            paths,
        )
    }

    fn sample_transfer_args(paths: &[&str]) -> TransferArgs {
        TransferArgs {
            host: "alpha".to_string(),
            network: "aegis".to_string(),
            user: None,
            paths: paths.iter().map(|path| (*path).to_string()).collect(),
            allow_pending: false,
            use_endpoint: false,
            ipv4: false,
            ipv6: false,
            no_server_cert: false,
            no_compress: false,
            no_checksum: false,
            delete: false,
            dry_run: false,
            fail_if_exists: false,
            rsync_args: Vec::new(),
        }
    }

    fn command_args(command: &std::process::Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn parse_http_request_path_reads_get_request_path() {
        let request = "GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            "/callback?code=abc&state=xyz",
            login::parse_http_request_path(request).expect("request path should parse")
        );
    }

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!("'abc'\"'\"'def'", sh_quote("abc'def"));
    }

    #[test]
    fn managed_wireguard_cleanup_discovers_every_configured_interface() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("wg-aegis.conf"), "").expect("mesh config");
        std::fs::write(directory.path().join("wg-aegis-direct.conf"), "")
            .expect("direct-gateway config");
        std::fs::write(directory.path().join("wg-aegis.key"), "").expect("non-config file");

        assert_eq!(
            vec!["wg-aegis".to_string(), "wg-aegis-direct".to_string()],
            managed_wireguard_interfaces_in(directory.path())
                .expect("managed interfaces should be discovered")
        );
    }

    #[test]
    fn managed_wireguard_cleanup_rejects_unsafe_interface_names() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("invalid interface.conf"), "")
            .expect("invalid config");

        let error = managed_wireguard_interfaces_in(directory.path())
            .expect_err("unsafe interface should be rejected");
        assert!(error.to_string().contains("invalid interface name"));
    }

    #[test]
    fn transfer_sources_default_destination_to_current_directory() {
        let (sources, destination) =
            transfer::sources_and_destination(&["src/".to_string()]).expect("paths should parse");

        assert_eq!(vec!["src/"], sources);
        assert_eq!(".", destination);
    }

    #[test]
    fn transfer_sources_treat_final_path_as_destination() {
        let (sources, destination) = transfer::sources_and_destination(&[
            "a".to_string(),
            "b".to_string(),
            "/srv/app".to_string(),
        ])
        .expect("paths should parse");

        assert_eq!(vec!["a", "b"], sources);
        assert_eq!("/srv/app", destination);
    }

    #[test]
    fn default_rsync_args_enable_recursive_compressed_checksum_transfer() {
        let args = sample_transfer_args(&["src/", "/srv/app"]);
        let rsync_args = transfer::default_rsync_args(&args, true);

        assert!(rsync_args.contains(&"--archive".to_string()));
        assert!(rsync_args.contains(&"--checksum".to_string()));
        assert!(rsync_args.contains(&"--compress".to_string()));
        assert!(rsync_args.contains(&"--partial".to_string()));
        assert!(rsync_args.contains(&"--protect-args".to_string()));
        assert!(rsync_args.contains(&"--info=progress2,stats1".to_string()));
    }

    #[test]
    fn build_rsync_push_command_uses_aegis_ssh_transport() {
        let prepared = sample_prepared_connect(true);
        let args = sample_transfer_args(&["src/", "/srv/app"]);
        let prepared = transfer::PreparedTransfer::new(
            prepared,
            transfer::Direction::Push,
            &["src/".to_string()],
            "/srv/app",
            &args,
            true,
        )
        .expect("rsync command should build");
        let command = prepared.command();
        let command_args = command_args(command);

        #[cfg(target_os = "linux")]
        assert_eq!("rsync", command.get_program().to_string_lossy());
        #[cfg(target_os = "macos")]
        assert!(
            command
                .get_program()
                .to_string_lossy()
                .ends_with("/bin/rsync")
        );
        assert!(command_args.contains(&"--archive".to_string()));
        assert!(command_args.contains(&"--checksum".to_string()));
        assert!(command_args.contains(&"--compress".to_string()));
        assert!(command_args.contains(&"src/".to_string()));
        assert!(command_args.contains(&"ubuntu@10.75.1.42:/srv/app".to_string()));
        let remote_shell = command_args
            .iter()
            .position(|arg| arg == "-e")
            .and_then(|index| command_args.get(index + 1))
            .expect("rsync command should include a remote shell");
        assert!(remote_shell.contains("BatchMode=yes"));
        assert!(remote_shell.contains("PreferredAuthentications=publickey"));
        assert!(remote_shell.contains("CertificateFile=/tmp/aegis-test-key-cert.pub"));
        assert!(!remote_shell.contains("ubuntu@10.75.1.42"));
    }

    #[test]
    fn build_rsync_pull_command_brackets_ipv6_hosts() {
        let prepared = sample_prepared_connect_to("fd75::42", true);
        let args = sample_transfer_args(&["/var/log/app/", "."]);
        let prepared = transfer::PreparedTransfer::new(
            prepared,
            transfer::Direction::Pull,
            &["/var/log/app/".to_string()],
            ".",
            &args,
            true,
        )
        .expect("rsync command should build");
        let command_args = command_args(prepared.command());

        assert!(command_args.contains(&"ubuntu@[fd75::42]:/var/log/app/".to_string()));
        assert_eq!(Some(&".".to_string()), command_args.last());
    }

    #[test]
    fn prepared_transfer_owns_temporary_ssh_assets() {
        let (connection, paths) = sample_owned_prepared_connect();
        let args = sample_transfer_args(&["/var/log/app/", "."]);
        let prepared = transfer::PreparedTransfer::new(
            connection,
            transfer::Direction::Pull,
            &["/var/log/app/".to_string()],
            ".",
            &args,
            false,
        )
        .expect("rsync command should build");

        assert!(paths.iter().all(|path| path.exists()));
        let command_args = command_args(prepared.command());
        let remote_shell = command_args
            .windows(2)
            .find_map(|args| (args[0] == "-e").then_some(&args[1]))
            .expect("rsync command should include a remote shell");
        assert!(
            paths
                .iter()
                .all(|path| remote_shell.contains(&*path.to_string_lossy()))
        );

        drop(prepared);
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn parse_remote_target_splits_user_host_and_default_port() {
        let target =
            RemoteTarget::parse("deploy@example.com", None, None).expect("target should parse");
        assert_eq!("deploy", target.user);
        assert_eq!("example.com", target.host);
        assert_eq!(22, target.port);
    }

    #[test]
    fn parse_remote_target_accepts_host_port_and_flag_user() {
        let target = RemoteTarget::parse("example.com:2222", Some("deploy"), None)
            .expect("target should parse");
        assert_eq!("deploy", target.user);
        assert_eq!("example.com", target.host);
        assert_eq!(2222, target.port);
    }

    #[test]
    fn parse_remote_target_accepts_bracketed_ipv6_with_flag_port() {
        let target = RemoteTarget::parse("[2001:db8::10]", Some("deploy"), Some(2200))
            .expect("target should parse");
        assert_eq!("deploy", target.user);
        assert_eq!("2001:db8::10", target.host);
        assert_eq!(2200, target.port);
    }

    #[test]
    fn parse_enroll_target_accepts_local_mode_without_a_remote_target() {
        let args = EnrollArgs {
            invitation: None,
            name: None,
            remote: None,
            local: true,
            user: None,
            port: None,
        };
        assert!(matches!(
            EnrollmentPlan::parse(&args)
                .expect("local enrollment plan should parse")
                .target,
            EnrollTarget::Local(_)
        ));
    }

    #[test]
    fn direct_root_reinstall_requires_user_only_for_direct_root_reinstalls() {
        let _args = InstallArgs {
            upgrade: false,
            reinstall: true,
            key: None,
            cert: None,
            user: None,
            inbound_ssh: None,
            host_id: None,
            initial_user_id: None,
            staged_enrollment: false,
        };

        assert!(system::DirectRootReinstall::new(true, true, None).requires_explicit_user());
        assert!(
            !system::DirectRootReinstall::new(true, true, Some("ubuntu")).requires_explicit_user()
        );
        assert!(!system::DirectRootReinstall::new(true, false, None).requires_explicit_user());
        assert!(!system::DirectRootReinstall::new(false, true, None).requires_explicit_user());
    }

    #[test]
    fn parse_remote_target_rejects_duplicate_user_sources() {
        let error = RemoteTarget::parse("deploy@example.com", Some("deploy"), None)
            .expect_err("duplicate user should fail");
        assert!(
            error
                .to_string()
                .contains("provided both in the target and via `--user`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parse_remote_target_rejects_duplicate_port_sources() {
        let error = RemoteTarget::parse("example.com:2222", Some("deploy"), Some(2222))
            .expect_err("duplicate port should fail");
        assert!(
            error
                .to_string()
                .contains("provided both in the target and via `--port`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parse_remote_target_requires_a_user_source() {
        let error =
            RemoteTarget::parse("example.com", None, None).expect_err("missing user should fail");
        assert!(
            error.to_string().contains("remote user must be provided"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parse_remote_target_rejects_unbracketed_ipv6() {
        let error = RemoteTarget::parse("deploy@2001:db8::10", None, None)
            .expect_err("unbracketed IPv6 should fail");
        assert!(
            error.to_string().contains("IPv6 targets must be bracketed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_connect_host_defaults_to_internal_mesh_ip() {
        assert_eq!(
            "10.75.0.42",
            host::resolve_connect_host(&sample_host()).expect("mesh ip should resolve")
        );
    }

    #[test]
    fn resolve_connect_host_uses_wireguard_ipv4_without_internal_addresses() {
        let mut host = sample_host();
        host.internal = None;

        assert_eq!(
            "10.75.1.42",
            host::resolve_connect_host(&host).expect("wireguard mesh ip should resolve")
        );
    }

    #[test]
    fn local_host_id_matches_live_wireguard_address_against_cache() {
        let mut alpha = sample_host();
        set_host_alias(&mut alpha, "alpha");
        let mut beta = sample_host();
        set_host_alias(&mut beta, "beta");
        beta.host.wireguard = Some(AegisNetworkMemberWireGuard {
            public_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string(),
            ipv4: "10.75.1.2".to_string(),
            ipv6: "fd75::1:2".to_string(),
            endpoints: Vec::new(),
        });

        assert_eq!(
            Some(host_id("beta")),
            local_state::LocalHostIdentity::host_id_from_hosts_and_addresses(
                &[alpha, beta],
                &BTreeSet::from(["10.75.1.2".to_string()])
            )
        );
    }

    #[test]
    fn ip_address_output_parser_collects_wireguard_addresses_without_root_config() {
        let addresses = local_state::IpAddressOutput::new(
            "8: wg-aegis inet 10.75.1.2/32 scope global wg-aegis\n\
             8: wg-aegis inet6 fd75::1:2/128 scope global\n",
        )
        .parse()
        .expect("ip address output should parse");

        assert!(addresses.contains("10.75.1.2"));
        assert!(addresses.contains("fd75::1:2"));
    }

    #[test]
    fn staged_enrollment_enables_both_sockets_before_the_agent_service() {
        let script = super::enroll_install::system_agent_activation_script();
        let sockets = script
            .find("enable --now aegis-agent.socket aegis-capulus.socket")
            .expect("socket activation should be present");
        let service = script
            .find("enable --now aegis-agent.service")
            .expect("service activation should be present");

        assert!(sockets < service);
        assert!(script.contains(
            "is-active --quiet aegis-agent.socket aegis-capulus.socket aegis-agent.service"
        ));
    }

    #[test]
    fn bootstrap_mesh_script_configures_wireguard_overlays_and_bird() {
        let script = mesh_bootstrap::BootstrapMeshScript::new(
            &sample_host(),
            &[wireguard::HubPeer {
                host_id: host_id("hub-a"),
                endpoint_ip: "34.123.45.67".to_string(),
                public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
                wireguard_ipv4: "10.75.1.1".to_string(),
                wireguard_ipv6: "fd75::1:1".to_string(),
            }],
            &sample_network(),
            AgentMode::Leaf,
        )
        .render()
        .expect("bootstrap mesh script should render");

        assert_bash_syntax(&script);
        assert!(script.contains("sudo tee /etc/aegis/wireguard/wg-aegis.conf"));
        assert!(script.contains("/etc/apparmor.d/local/aegis-wg-quick"));
        assert!(script.contains("apparmor_parser"));
        assert!(script.contains("Address = 10.75.1.42/32,fd75::1:2a/128"));
        assert!(script.contains("MTU = 1400"));
        assert!(script.contains("Endpoint = 34.123.45.67:51820"));
        assert!(script.contains("AllowedIPs = 10.75.1.1/32,fd75::1:1/128"));
        assert!(!script.contains("fe80"));
        assert!(script.contains("ensure_overlay "));
        assert!(script.contains("sudo ip -4 address replace 10.75.0.42/32 dev lo"));
        assert!(script.contains("sudo ip -6 address replace fd75::42/128 dev lo"));
        assert!(script.contains("cat <<'EOF_BIRD' | sudo tee /etc/bird/bird.conf >/dev/null"));
        assert!(script.contains("systemctl restart bird"));
        assert!(script.contains("systemctl restart aegis-wireguard@wg-aegis"));
    }

    #[test]
    fn remote_preparation_bootstraps_before_creating_identity() {
        let script = enroll_install::RemotePrepareHostScript::render(true);

        assert!(script.contains(
            "retry sudo apt-get -o Acquire::Retries=5 -o Acquire::Languages=none update"
        ));
        assert!(script.contains("retry sudo env DEBIAN_FRONTEND=noninteractive apt-get install"));
        assert!(
            script.find("install --locked --force").unwrap()
                < script.find("agent prepare-identity").unwrap()
        );
        assert!(script.contains("agent prepare-identity --inbound-ssh"));
        assert!(script.contains("system_aegis=/Library/PrivilegedHelperTools/aegis"));
        assert_bash_syntax(&script);
        let no_ssh_script = enroll_install::RemotePrepareHostScript::render(false);
        assert!(no_ssh_script.contains("agent prepare-identity"));
        assert!(!no_ssh_script.contains("--inbound-ssh"));
    }

    #[test]
    fn bird3_repo_setup_script_limits_the_repo_to_the_native_architecture() {
        let script = system::Bird3Repository::without_sudo().setup_script();

        assert_bash_syntax(&script);
        assert!(script.contains("bird_arch=\"$(dpkg --print-architecture)\""));
        assert!(
            script
                .contains("retry apt-get -o Acquire::Retries=5 -o Acquire::Languages=none update")
        );
        assert!(script.contains(
            "retry curl --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 --max-time 60"
        ));
        assert!(script.contains("suite_release=\"$(retry curl "));
        assert!(script.contains("https://pkg.labs.nic.cz/bird3/dists/$bird_suite/InRelease"));
        assert!(script.contains("gpg_key_file=\"$(mktemp)\""));
        assert!(script.contains("retry curl "));
        assert!(script.contains("-o \"$gpg_key_file\" https://pkg.labs.nic.cz/gpg"));
        assert!(script.contains("repo_arches=\"$(printf '%s"));
        assert!(script.contains("sed -n 's/^Architectures: //p')\""));
        assert!(
            script.contains(
                "bird3 repo does not support architecture $bird_arch for suite $bird_suite"
            )
        );
        assert!(script.contains("/etc/apt/sources.list.d/cznic-bird3.sources"));
        assert!(script.contains("Types: deb\\nURIs: https://pkg.labs.nic.cz/bird3"));
        assert!(script.contains("Suites: %s\\nComponents: main\\nArchitectures: %s"));
        assert!(script.contains("Signed-By: /usr/share/keyrings/cznic-labs-bird3.gpg"));
        assert!(script.contains(
            "install -o root -g root -m 0644 \"$gpg_keyring_file\" /usr/share/keyrings/cznic-labs-bird3.gpg"
        ));
        assert!(script.contains(
            "install -o root -g root -m 0644 \"$source_file\" /etc/apt/sources.list.d/cznic-bird3.sources"
        ));
        assert!(!script.contains("cat > /etc/apt/sources.list.d/cznic-bird3.sources"));
        assert!(!script.contains("-o /usr/share/keyrings/cznic-labs-bird3.gpg \"$gpg_key_file\""));

        let sudo_script = system::Bird3Repository::with_sudo().setup_script();
        assert_bash_syntax(&sudo_script);
        assert!(sudo_script.contains(
            "sudo install -o root -g root -m 0644 \"$source_file\" /etc/apt/sources.list.d/cznic-bird3.sources"
        ));
    }

    #[test]
    fn wrap_remote_sudo_script_overrides_sudo_without_duplicating_shell_flags() {
        let script = remote::SudoScript::new("set -euo pipefail\nsudo -v\nsudo true\n").render();

        assert!(script.starts_with("set -euo pipefail\nsudo() {"));
        assert_eq!(1, script.matches("set -euo pipefail").count());
        assert!(script.contains(&format!("\"{REMOTE_SUDO_PASSWORD_HELPER_PATH}\"")));
        assert!(script.contains("command sudo -S -p '' -v"));
        assert!(!script.contains("sudo -A"));
        assert!(script.ends_with("sudo -v\nsudo true\n"));
    }

    #[test]
    fn remote_sudo_wrapper_refreshes_without_stealing_pipeline_input() {
        let temp = tempdir().expect("tempdir should be created");
        let home = temp.path().join("home");
        let helper = home.join(".cache/aegis/remote-sudo-password.sh");
        fs::create_dir_all(helper.parent().expect("helper should have a parent"))
            .expect("helper parent should be created");
        fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' test-password\n")
            .expect("helper should be written");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("helper should be executable");

        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).expect("fake bin dir should be created");
        let log = temp.path().join("sudo.log");
        let fake_sudo = bin.join("sudo");
        fs::write(
            &fake_sudo,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> {log}\n\
                 if [ \"$1\" = \"-n\" ] && [ \"$2\" = \"-v\" ]; then exit 1; fi\n\
                 if [ \"$1\" = \"-S\" ] && [ \"$2\" = \"-p\" ] && [ \"$3\" = \"\" ] && [ \"$4\" = \"-v\" ]; then\n\
                   IFS= read -r password\n\
                   printf 'password=%s\\n' \"$password\" >> {log}\n\
                   exit 0\n\
                 fi\n\
                 if [ \"$1\" = \"-v\" ]; then exit 0; fi\n\
                 exec \"$@\"\n",
                log = sh_quote(&log.display().to_string()),
            ),
        )
        .expect("fake sudo should be written");
        fs::set_permissions(&fake_sudo, fs::Permissions::from_mode(0o700))
            .expect("fake sudo should be executable");

        let output_path = temp.path().join("pipeline.out");
        let script = format!(
            "{}printf 'pipeline-data\\n' | sudo tee {} >/dev/null\n",
            remote::SudoScript::new("sudo -v\n").render(),
            sh_quote(&output_path.display().to_string()),
        );
        let output = Command::new("bash")
            .args(["--noprofile", "--norc", "-ceu", &script])
            .env("HOME", &home)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    env::var("PATH").expect("PATH should be set")
                ),
            )
            .output()
            .expect("bash should run");

        assert!(
            output.status.success(),
            "script failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            "pipeline-data\n",
            fs::read_to_string(output_path).expect("pipeline output should be written")
        );
        assert!(
            fs::read_to_string(log)
                .expect("fake sudo log should be readable")
                .contains("password=test-password")
        );
    }

    #[test]
    fn remote_enrollment_invokes_only_the_trusted_system_program_as_root() {
        let pending_host = sample_host();
        let script = enroll_install::RemoteFinalizeInstall::new(
            enroll_install::RemoteFinalizeInstallParts {
                api_base: "https://api.example.test/v2",
                pending_host: &pending_host,
                hub_peers: &[],
                network: &sample_network(),
                server_certificate: None,
                agent_token: "agent-token",
                login_principal: "ubuntu",
                initial_user_id: Some("operator"),
                mode: AgentMode::Hub,
                inbound_ssh: false,
            },
        )
        .render()
        .expect("remote enrollment should render");

        assert_bash_syntax(&script);
        assert!(script.contains("sudo env AEGIS_AGENT_REFRESH_TOKEN_B64="));
        assert!(script.contains(" /usr/local/bin/aegis --api-base "));
        assert!(!script.contains("$login_home/.cargo/bin/aegis --api-base"));
        assert!(!script.contains("aegis-agent"));
    }

    #[test]
    fn hub_peer_configs_use_ipv4_for_the_managed_mesh_mtu_budget() {
        let peers = mesh_bootstrap::HubPeerSelection::new(host_id("leaf-a"))
            .select_from_hosts(vec![sample_hub("hub-a")])
            .expect("hub peer selection should succeed");

        assert_eq!(1, peers.len());
        assert_eq!("34.1.2.3", peers[0].endpoint_ip);
    }

    #[test]
    fn hub_peer_configs_do_not_fall_back_to_ipv6() {
        let mut hub = sample_hub("hub-a");
        hub.wireguard.as_mut().expect("wireguard").endpoints =
            vec!["2600:1900:4000:fec::1".to_string()];

        let error = mesh_bootstrap::HubPeerSelection::new(host_id("leaf-a"))
            .select_from_hosts(vec![hub])
            .expect_err("managed mesh bootstrap must require an IPv4 endpoint");

        assert!(error.to_string().contains("no active hub hosts"));
    }

    #[test]
    fn hub_peer_configs_keep_pending_hubs_available_for_bootstrap() {
        let mut hub = sample_hub("hub-a");
        hub.pending = true;

        let peers = mesh_bootstrap::HubPeerSelection::new(host_id("leaf-a"))
            .select_from_hosts(vec![hub])
            .expect("hub peer selection should succeed");

        assert_eq!(1, peers.len());
        assert_eq!("34.1.2.3", peers[0].endpoint_ip);
    }

    #[test]
    fn wireguard_config_contents_writes_the_expected_peer_configuration() {
        let peers = [wireguard::HubPeer {
            host_id: host_id("hub-a"),
            endpoint_ip: "34.123.45.67".to_string(),
            public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
            wireguard_ipv4: "10.75.1.1".to_string(),
            wireguard_ipv6: "fd75::1:1".to_string(),
        }];
        let config = wireguard::ClientConfig::new(wireguard::ClientConfigOptions {
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            hub_peers: &peers,
            endpoint_port: 51_820,
            mtu: None,
            routing: wireguard::ClientRouting::PeerAddresses,
        })
        .expect("valid client config")
        .contents();

        assert!(config.contains("Address = 10.75.1.42/32,fd75::1:2a/128"));
        assert!(config.contains("Endpoint = 34.123.45.67:51820"));
        assert!(config.contains("AllowedIPs = 10.75.1.1/32,fd75::1:1/128"));
        assert!(!config.contains("fe80"));
    }

    #[test]
    fn wireguard_interface_address_parser_reads_configured_dual_stack_addresses() {
        let config = "[Interface]\nAddress = 10.75.1.42/32,fd75::1:2a/128\n";
        let (ipv4, ipv6) =
            wireguard::parse_interface_addresses(config).expect("wireguard address should parse");

        assert_eq!("10.75.1.42", ipv4);
        assert_eq!(Some("fd75::1:2a".to_string()), ipv6);
    }

    #[test]
    fn wireguard_config_contents_supports_multiple_hub_peers() {
        let peers = [
            wireguard::HubPeer {
                host_id: host_id("hub-a"),
                endpoint_ip: "34.123.45.67".to_string(),
                public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
                wireguard_ipv4: "10.75.1.1".to_string(),
                wireguard_ipv6: "fd75::1:1".to_string(),
            },
            wireguard::HubPeer {
                host_id: host_id("hub-b"),
                endpoint_ip: "34.123.45.68".to_string(),
                public_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string(),
                wireguard_ipv4: "10.75.1.2".to_string(),
                wireguard_ipv6: "fd75::1:2".to_string(),
            },
        ];
        let config = wireguard::ClientConfig::new(wireguard::ClientConfigOptions {
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            hub_peers: &peers,
            endpoint_port: 51_820,
            mtu: None,
            routing: wireguard::ClientRouting::PeerAddresses,
        })
        .expect("valid client config")
        .contents();

        assert_eq!(2, config.matches("\n[Peer]\n").count());
        assert!(config.contains("Endpoint = 34.123.45.67:51820"));
        assert!(config.contains("AllowedIPs = 10.75.1.1/32,fd75::1:1/128"));
        assert!(config.contains("Endpoint = 34.123.45.68:51820"));
        assert!(config.contains("AllowedIPs = 10.75.1.2/32,fd75::1:2/128"));
        assert!(!config.contains("fe80"));
    }

    #[test]
    fn scanned_key_fields_accept_host_prefixed_lines() {
        let (algorithm, base64) =
            scanned_key_fields("10.75.1.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0")
                .expect("host-prefixed keyscan output should parse");
        assert_eq!("ssh-ed25519", algorithm);
        assert_eq!("AAAAC3NzaC1lZDI1NTE5AAAAIB0", base64);
    }

    #[test]
    fn scanned_key_fields_accept_hostless_lines() {
        let (algorithm, base64) =
            scanned_key_fields("ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5")
                .expect("hostless keyscan output should parse");
        assert_eq!("ssh-ed25519-cert-v01@openssh.com", algorithm);
        assert_eq!("AAAAIHNzaC1lZDI1NTE5", base64);
    }

    #[test]
    fn install_dropin_contents_without_server_cert_omits_host_directives() {
        let content = aegis_dto::sshd_install_dropin_contents(
            AEGIS_CLIENT_CA_PATH,
            &format!("{AEGIS_AUTHORIZED_PRINCIPALS_DIR}/%u"),
            None,
            None,
        );
        assert!(content.contains("TrustedUserCAKeys /etc/ssh/aegis/client_ca.pub"));
        assert!(content.contains("AllowAgentForwarding yes"));
        assert!(
            content.contains("AuthorizedPrincipalsFile /etc/ssh/aegis/authorized_principals/%u")
        );
        assert!(!content.contains("HostKey "));
        assert!(!content.contains("HostCertificate "));
    }

    #[test]
    fn install_dropin_contents_with_server_cert_includes_host_directives() {
        let content = aegis_dto::sshd_install_dropin_contents(
            AEGIS_CLIENT_CA_PATH,
            &format!("{AEGIS_AUTHORIZED_PRINCIPALS_DIR}/%u"),
            Some("/etc/ssh/ssh_host_ed25519_key"),
            Some("/etc/ssh/ssh_host_ed25519_key-cert.pub"),
        );
        assert!(content.contains("HostKey /etc/ssh/ssh_host_ed25519_key"));
        assert!(content.contains("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"));
    }

    #[test]
    fn lockdown_dropin_contents_disables_non_certificate_auth_methods() {
        let content =
            lockdown::dropin_contents(&["10.75.1.42".to_string(), "10.75.99.9".to_string()]);
        assert!(content.contains("PasswordAuthentication no"));
        assert!(content.contains("KbdInteractiveAuthentication no"));
        assert!(content.contains("AuthenticationMethods publickey"));
        assert!(content.contains("AuthorizedKeysFile none"));
        assert!(content.contains("Match LocalAddress *,!10.75.1.42"));
        assert!(content.contains(",!10.75.99.9"));
        assert!(content.contains("PubkeyAuthentication no"));
    }

    #[test]
    fn strict_ssh_args_enforce_certificate_only_mode() {
        let prepared = sample_prepared_connect(true);
        let args = prepared.ssh_args(
            &["-v".to_string()],
            Some("printf ok"),
            Some(Path::new("/tmp/aegis-control.sock")),
            true,
        );

        assert!(!args.contains(&"-F".to_string()));
        assert!(!args.contains(&"/dev/null".to_string()));
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"PreferredAuthentications=publickey".to_string()));
        assert!(args.contains(&"PasswordAuthentication=no".to_string()));
        assert!(args.contains(&"KbdInteractiveAuthentication=no".to_string()));
        assert!(args.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(args.contains(&"ForwardAgent=yes".to_string()));
        assert!(!args.contains(&"IdentityAgent=none".to_string()));
        assert!(args.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(args.contains(&"HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com".to_string()));
        assert!(args.contains(&"-M".to_string()));
        assert!(args.contains(&"ControlPersist=no".to_string()));
        assert!(args.contains(&"-N".to_string()));
        assert!(args.contains(&"-S".to_string()));
        assert!(args.contains(&"/tmp/aegis-control.sock".to_string()));
        assert!(args.contains(&"-v".to_string()));
        assert!(args.contains(&"ubuntu@10.75.1.42".to_string()));
        assert!(args.contains(&"printf ok".to_string()));
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("CertificateFile=/tmp/aegis-test-key-cert.pub"))
        );
    }

    #[test]
    fn listed_host_renders_alias_internal_host_and_wireguard_ip() {
        let rendered = host_list::render_listed_host(
            &host_list::listed_host(&sample_host()),
            &host_list::PlainRenderTarget,
        );

        assert!(rendered.contains("alpha"));
        assert!(rendered.contains("leaf"));
        assert!(rendered.contains("10.75.0.42"));
        assert!(rendered.contains("wg 10.75.1.42"));
    }

    #[test]
    fn listed_host_marks_leaf_hosts_with_circle_icon() {
        let mut host = sample_host();
        host.mode = AegisHostMode::Leaf;

        let rendered = host_list::render_listed_host(
            &host_list::listed_host(&host),
            &host_list::PlainRenderTarget,
        );

        assert!(rendered.contains("●"));
        assert!(rendered.contains("leaf"));
    }

    #[test]
    fn healthy_lockdown_is_a_kind_indicator_not_a_warning() {
        let mut host = sample_host();
        host.ssh_lockdown_enabled = true;
        host.messages.clear();

        let listed = host_list::listed_host(&host);
        let rendered = host_list::render_listed_host(&listed, &host_list::PlainRenderTarget);

        assert!(rendered.contains("leaf ▣"));
        assert!(
            ssh::HostMessagesBanner::new(&host)
                .render_for(false)
                .is_none()
        );
    }

    #[test]
    fn listed_host_renders_host_messages_directly() {
        let mut host = sample_host();
        host.messages = vec![AegisHostMessage {
            level: AegisHostMessageLevel::Warning,
            value: "Bird3 apt source is misconfigured".to_string(),
        }];

        let rendered = host_list::render_listed_host(
            &host_list::listed_host(&host),
            &host_list::PlainRenderTarget,
        );

        assert!(rendered.contains("Bird3 apt source is misconfigured"));
    }

    #[test]
    fn listed_host_warns_about_old_agent_from_control_plane_status() {
        let mut host = sample_host();
        host.agent = Some(sample_agent_status("0.1.1", now_unix()));

        let listed = host_list::listed_host(&host);
        let rendered = host_list::render_listed_host(&listed, &host_list::PlainRenderTarget);

        assert!(listed.marker_warning);
        assert!(rendered.contains("old agent v0.1.1"));
        assert!(rendered.contains(&format!("want v{}", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn listed_host_warns_about_stale_agent_report() {
        let mut host = sample_host();
        host.agent = Some(sample_agent_status(
            env!("CARGO_PKG_VERSION"),
            now_unix() - 181,
        ));

        let rendered = host_list::render_listed_host(
            &host_list::listed_host(&host),
            &host_list::PlainRenderTarget,
        );

        assert!(rendered.contains("report 3m1s old"));
    }

    #[test]
    fn host_messages_banner_renders_warnings() {
        let mut host = sample_host();
        host.messages = vec![AegisHostMessage {
            level: AegisHostMessageLevel::Warning,
            value: "Bird3 apt source is misconfigured".to_string(),
        }];

        let banner = ssh::HostMessagesBanner::new(&host)
            .render_for(false)
            .expect("banner should render");

        assert!(banner.contains("Aegis warnings for alpha"));
        assert!(banner.contains("warning: Bird3 apt source is misconfigured"));

        let interactive = ssh::HostMessagesBanner::new(&host)
            .render_for(true)
            .expect("interactive banner should render");
        assert!(interactive.contains("aegis warnings alpha"));
        assert!(interactive.contains("warning: Bird3 apt source is misconfigured"));
    }

    #[test]
    fn elapsed_duration_text_is_compact() {
        assert_eq!(
            "9s",
            host_list::elapsed_duration_text(Duration::from_secs(9))
        );
        assert_eq!(
            "2m5s",
            host_list::elapsed_duration_text(Duration::from_secs(125))
        );
        assert_eq!(
            "1h1m",
            host_list::elapsed_duration_text(Duration::from_secs(3_660))
        );
    }

    #[test]
    fn fleet_redeploy_summary_tracks_each_terminal_bucket() {
        let target_version =
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid");
        let mut installing = fleet::RowState::new(sample_host(), target_version.clone(), false);
        installing.set_status(fleet::Status::Installing(0));

        let mut redeployed_host = sample_host();
        set_host_alias(&mut redeployed_host, "redeployed");
        let mut redeployed = fleet::RowState::new(redeployed_host, target_version.clone(), false);
        redeployed.set_status(fleet::Status::Redeployed);

        let mut no_ssh_host = sample_host();
        set_host_alias(&mut no_ssh_host, "no-ssh");
        no_ssh_host.ssh = None;
        let no_ssh = fleet::RowState::new(no_ssh_host, target_version, false);

        let states = HashMap::from([
            (installing.host.host_id, installing),
            (redeployed.host.host_id, redeployed),
            (no_ssh.host.host_id, no_ssh),
        ]);

        let summary = fleet::summary(&states, Duration::from_secs(65), env!("CARGO_PKG_VERSION"));

        assert!(summary.contains(&format!("target v{}", env!("CARGO_PKG_VERSION"))));
        assert!(summary.contains("2/3 finished"));
        assert!(summary.contains("1 active"));
        assert!(summary.contains("1 redeployed"));
        assert!(summary.contains("1 no ssh"));
        assert!(summary.contains("elapsed 1m5s"));
    }

    #[test]
    fn fleet_redeploy_timeouts_allow_slow_hub_reinstalls() {
        assert_eq!(
            Duration::from_secs(30 * 60),
            fleet::FLEET_REDEPLOY_NO_PROGRESS_TIMEOUT
        );
        assert_eq!(
            Duration::from_secs(2 * 60 * 60),
            fleet::FLEET_REDEPLOY_HARD_TIMEOUT
        );
        assert_eq!(
            Duration::from_secs(40 * 60),
            FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT
        );
        assert_eq!(
            Duration::from_secs(30),
            fleet::FLEET_REDEPLOY_REMOTE_SSH_ASSET_REFRESH_INTERVAL
        );
    }

    #[test]
    fn fleet_redeploy_plain_status_includes_failure_detail() {
        let mut state = fleet::RowState::new(
            sample_host(),
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid"),
            false,
        );
        state.set_status(fleet::Status::Failed {
            detail: "remote fleet redeploy timed out after 40m0s".to_string(),
        });

        assert_eq!(
            "failed: remote fleet redeploy timed out after 40m0s",
            state.status_text()
        );
    }

    #[test]
    fn fleet_redeploy_keeps_the_local_host_eligible_without_ssh() {
        let mut host = sample_host();
        host.ssh = None;
        let state = fleet::RowState::new(
            host,
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid"),
            true,
        );

        assert_eq!("queued", state.status_text());
    }

    #[test]
    fn fleet_redeploy_completion_retains_untruncated_multiline_failure_detail() {
        let mut state = fleet::RowState::new(
            sample_host(),
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid"),
            false,
        );
        let detail = format!(
            "remote fleet redeploy failed: {}\nsecond diagnostic line",
            "x".repeat(140)
        );
        state.set_status(fleet::Status::Failed {
            detail: detail.clone(),
        });
        let states = HashMap::from([(state.host.host_id, state)]);

        assert!(
            states
                .get(&host_id("alpha"))
                .expect("alpha state")
                .status_text()
                .ends_with("...")
        );
        assert_eq!(
            vec![format!("alpha: {detail}")],
            fleet::completion_details(&states, false)
        );
    }

    #[test]
    fn fleet_redeploy_interrupt_reports_full_last_probe_detail() {
        let mut state = fleet::RowState::new(
            sample_host(),
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid"),
            false,
        );
        let detail = "socket unavailable\nsystemd unit remains active".to_string();
        state.set_status(fleet::Status::WaitingForAgent {
            frame: 0,
            detail: Some(detail.clone()),
        });
        let states = HashMap::from([(state.host.host_id, state)]);
        let completion = fleet::completion_details(&states, true);

        assert_eq!(1, completion.len());
        assert!(completion[0].contains(&detail));
    }

    #[test]
    fn compact_line_truncates_unicode_without_splitting_codepoints() {
        let line = "λ".repeat(100);

        assert_eq!(96, compact_line(&line).chars().count());
        assert!(compact_line(&line).ends_with("..."));
    }

    #[test]
    fn fleet_redeploy_waiting_status_includes_probe_detail() {
        let mut state = fleet::RowState::new(
            sample_host(),
            crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                .expect("package version should be valid"),
            false,
        );
        state.set_status(fleet::Status::WaitingForAgent {
            frame: 0,
            detail: Some("agent still reported v0.1.100".to_string()),
        });

        assert!(state.status_text().contains("waiting for agent v"));
        assert!(
            state
                .status_text()
                .contains("agent still reported v0.1.100")
        );
    }

    #[test]
    fn fleet_redeploy_timeout_includes_last_agent_probe_detail() {
        assert_eq!(
            format!(
                "timed out waiting for v{}; last status: ssh agent version probe failed: Permission denied",
                env!("CARGO_PKG_VERSION")
            ),
            fleet::agent_wait_timeout_message(
                &crate::redeploy_version::RedeployVersion::explicit(env!("CARGO_PKG_VERSION"))
                    .expect("package version should be valid"),
                Some("ssh agent version probe failed: Permission denied")
            )
        );
    }

    #[test]
    fn agent_version_probe_reports_empty_and_unparseable_output() {
        let target = agent_version::current();
        let empty = agent_version::from_text("", &target);
        assert_eq!(agent_version::State::Unknown, empty.state);
        assert_eq!(
            Some("agent version probe returned no output"),
            empty.detail.as_deref()
        );

        let unparseable = agent_version::from_text("profile banner", &target);
        assert_eq!(agent_version::State::Unknown, unparseable.state);
        assert_eq!(
            Some("agent version probe returned `profile banner`"),
            unparseable.detail.as_deref()
        );
    }

    #[test]
    fn agent_version_probe_parses_agent_json() {
        let current = agent_version::from_json(
            &format!("{{\"version\":\"{}\"}}", env!("CARGO_PKG_VERSION")),
            &agent_version::current(),
        );
        assert_eq!(agent_version::State::Current, current.state);
        assert_eq!(None, current.detail);

        let invalid = agent_version::from_json("0.1.42", &agent_version::current());
        assert_eq!(agent_version::State::Unknown, invalid.state);
        assert!(
            invalid
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("invalid JSON"))
        );
    }

    #[test]
    fn remote_agent_version_probe_uses_curl_json_endpoint() {
        let command = remote_agent_version_probe_command();

        assert!(command.starts_with("curl -fsS --max-time 5 "));
        assert!(command.contains(AEGIS_AGENT_VERSION_PATH));
        assert!(!command.contains("python3"));
    }

    #[test]
    fn wireguard_config_contents_brackets_ipv6_endpoints() {
        let peers = [wireguard::HubPeer {
            host_id: host_id("hub-a"),
            endpoint_ip: "2001:db8::10".to_string(),
            public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
            wireguard_ipv4: "10.75.1.1".to_string(),
            wireguard_ipv6: "fd75::1:1".to_string(),
        }];
        let config = wireguard::ClientConfig::new(wireguard::ClientConfigOptions {
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            wireguard_ipv4: "10.75.1.42",
            wireguard_ipv6: "fd75::1:2a",
            hub_peers: &peers,
            endpoint_port: 51_820,
            mtu: None,
            routing: wireguard::ClientRouting::PeerAddresses,
        })
        .expect("valid client config")
        .contents();

        assert!(config.contains("Endpoint = [2001:db8::10]:51820"));
    }

    #[test]
    fn resolve_connect_host_prefers_internal_mesh_ipv4_before_ipv6() {
        let host = sample_host();
        assert_eq!(
            "10.75.0.42",
            host::resolve_connect_host(&host).expect("probe connect host should resolve")
        );
    }

    #[test]
    fn resolve_ssh_connect_host_uses_published_addresses_without_dns_dependency() {
        let mut host = sample_host();
        host.wireguard
            .as_mut()
            .expect("sample host should include wireguard")
            .endpoints = vec!["34.1.2.3".to_string()];
        let auto = SshArgs {
            host: Some(host.alias().to_string()),
            network: "aegis".to_string(),
            user: None,
            allow_pending: false,
            refresh: false,
            use_endpoint: false,
            ipv4: false,
            ipv6: false,
            no_server_cert: false,
            command: None,
            ssh_args: Vec::new(),
        };
        assert_eq!(
            "10.75.0.42",
            host::resolve_ssh_connect_host(&host, &auto)
                .expect("mesh ssh connect host should resolve")
        );
        assert_eq!(
            vec!["10.75.0.42".parse::<std::net::IpAddr>().expect("IPv4")],
            host::ssh_mesh_route_targets(&host, &auto).expect("mesh route targets should resolve")
        );
        let endpoint = SshArgs {
            use_endpoint: true,
            ..auto
        };
        assert_eq!(
            "34.1.2.3",
            host::resolve_ssh_connect_host(&host, &endpoint)
                .expect("endpoint ssh connect host should resolve")
        );
        assert!(
            host::ssh_mesh_route_targets(&host, &endpoint)
                .expect("endpoint route targets should resolve")
                .is_empty()
        );
    }

    #[test]
    fn resolve_connect_host_requires_internal_mesh_address() {
        let mut host = sample_host();
        host.host.internal = None;
        host.host.wireguard = None;
        assert!(host::resolve_connect_host(&host).is_err());
    }

    #[test]
    fn strict_ssh_args_use_raw_host_algorithm_when_server_certs_are_disabled() {
        let prepared = sample_prepared_connect(false);
        let args = prepared.ssh_args(&[], None, None, false);

        assert!(args.contains(&"HostKeyAlgorithms=ssh-ed25519".to_string()));
        assert!(!args.contains(&"HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com".to_string()));
    }

    #[test]
    fn load_existing_keypair_returns_public_key_for_valid_pair() {
        let dir = tempdir().expect("tempdir should create");
        let private_path = dir.path().join("alpha");
        let public_path = dir.path().join("alpha.pub");
        let private_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keypair should generate");
        private_key
            .write_openssh_file(&private_path, LineEnding::LF)
            .expect("private key should write");
        std::fs::write(
            &public_path,
            format!(
                "{}\n",
                private_key
                    .public_key()
                    .to_openssh()
                    .expect("public key should encode")
            ),
        )
        .expect("public key should write");

        let loaded = load_existing_keypair(&private_path, &public_path)
            .expect("keypair load should succeed")
            .expect("keypair should be returned");
        assert_eq!(
            private_key
                .public_key()
                .to_openssh()
                .expect("public key should encode"),
            loaded
        );
    }

    #[test]
    fn load_existing_keypair_rejects_mismatched_public_key() {
        let dir = tempdir().expect("tempdir should create");
        let private_path = dir.path().join("alpha");
        let public_path = dir.path().join("alpha.pub");
        let private_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keypair should generate");
        let other_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("other key should generate");
        private_key
            .write_openssh_file(&private_path, LineEnding::LF)
            .expect("private key should write");
        std::fs::write(
            &public_path,
            format!(
                "{}\n",
                other_key
                    .public_key()
                    .to_openssh()
                    .expect("public key should encode")
            ),
        )
        .expect("public key should write");

        let loaded = load_existing_keypair(&private_path, &public_path)
            .expect("keypair load should succeed");
        assert!(loaded.is_none());
    }

    #[test]
    fn known_hosts_target_brackets_non_default_ports() {
        assert_eq!(
            "alpha.example.com",
            known_hosts_target("alpha.example.com", 22)
        );
        assert_eq!(
            "[alpha.example.com]:2222",
            known_hosts_target("alpha.example.com", 2222)
        );
    }

    #[test]
    fn host_visibility_hides_pending_entries_by_default() {
        let mut host = sample_host();
        host.pending = true;

        assert!(!host::host_is_visible(&host, false));
        assert!(host::host_is_visible(&host, true));
    }

    #[test]
    fn filter_visible_hosts_removes_pending_entries_without_flag() {
        let mut pending = sample_host();
        set_host_alias(&mut pending, "pending");
        pending.pending = true;

        let visible = host::filter_visible_hosts(vec![sample_host(), pending.clone()], false);
        assert_eq!(
            vec!["alpha"],
            visible
                .iter()
                .map(|host| host.alias().as_str())
                .collect::<Vec<_>>()
        );

        let with_pending = host::filter_visible_hosts(vec![sample_host(), pending], true);
        assert_eq!(2, with_pending.len());
    }

    #[test]
    fn top_level_system_lock_skips_read_only_and_internally_scoped_commands() {
        let list = Commands::List(ListArgs {
            network: "aegis".to_string(),
            allow_pending: false,
            refresh: false,
        });
        let ssh = Commands::Ssh(SshArgs {
            host: Some("alpha".to_string()),
            network: "aegis".to_string(),
            user: None,
            allow_pending: false,
            refresh: false,
            use_endpoint: false,
            ipv4: false,
            ipv6: false,
            no_server_cert: false,
            command: None,
            ssh_args: Vec::new(),
        });
        let push = Commands::Push(sample_transfer_args(&["src/", "/srv/app"]));
        let pull = Commands::Pull(sample_transfer_args(&["/srv/app/", "."]));
        let tunnel = Commands::Tunnel(TunnelArgs {
            command: TunnelCommands::Status(TunnelStatusArgs { json: false }),
        });
        let fleet = Commands::Advanced(AdvancedArgs {
            command: AdvancedCommands::Fleet(FleetArgs {
                command: FleetCommands::Redeploy(FleetRedeployArgs {
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    network: "aegis".to_string(),
                    user: None,
                }),
            }),
        });
        let refresh_credentials = Commands::Advanced(AdvancedArgs {
            command: AdvancedCommands::RefreshCredentials(crate::cli::RefreshCredentialsArgs {}),
        });

        assert_eq!(SystemLockPolicy::None, command_system_lock_policy(&list));
        assert_eq!(SystemLockPolicy::SshSetup, command_system_lock_policy(&ssh));
        assert_eq!(
            SystemLockPolicy::SshSetup,
            command_system_lock_policy(&push)
        );
        assert_eq!(
            SystemLockPolicy::SshSetup,
            command_system_lock_policy(&pull)
        );
        assert_eq!(SystemLockPolicy::None, command_system_lock_policy(&tunnel));
        assert_eq!(SystemLockPolicy::None, command_system_lock_policy(&fleet));
        assert_eq!(
            SystemLockPolicy::None,
            command_system_lock_policy(&refresh_credentials)
        );
    }

    #[test]
    fn system_lock_keeps_local_system_mutations_serialized() {
        let install = Commands::Advanced(AdvancedArgs {
            command: AdvancedCommands::Install(InstallArgs {
                upgrade: false,
                reinstall: false,
                key: None,
                cert: None,
                user: None,
                inbound_ssh: None,
                host_id: None,
                initial_user_id: None,
                staged_enrollment: false,
            }),
        });
        let unenroll_local = Commands::Manage(crate::cli::ManageArgs {
            command: ManageCommands::Unenroll(UnenrollArgs {
                host: "alpha".to_string(),
                remote: None,
                api_token: None,
                local: true,
                orphan: false,
                user: None,
                port: None,
                skip_api_delete: false,
            }),
        });
        let unenroll_remote = Commands::Manage(crate::cli::ManageArgs {
            command: ManageCommands::Unenroll(UnenrollArgs {
                host: "alpha".to_string(),
                remote: Some("ubuntu@example.com".to_string()),
                api_token: None,
                local: false,
                orphan: false,
                user: None,
                port: None,
                skip_api_delete: false,
            }),
        });

        assert_eq!(
            SystemLockPolicy::FullCommand,
            command_system_lock_policy(&install)
        );
        assert_eq!(
            SystemLockPolicy::FullCommand,
            command_system_lock_policy(&unenroll_local)
        );
        assert_eq!(
            SystemLockPolicy::None,
            command_system_lock_policy(&unenroll_remote)
        );
    }
}
