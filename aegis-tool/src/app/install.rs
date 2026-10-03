use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::api::{ApiClient, AuthenticatedApiClient};
use crate::cli::{Choice, InstallArgs};
use crate::config::{
    AgentAuthConfig, AgentBirdConfigOptions, AgentConfig, AgentConfigOptions,
    AgentHostConfigOptions, SHARED_CACHE_PATH, agent_refresh_token_env_value,
    agent_refresh_token_from_encoded_value, canonical_saved_api_base_url, persist_agent_config,
    resolve_api_base,
};
use crate::ui::{self, Task, TaskOptions, TaskVisibility};
use aegis_dto::{HostId, layout::AGENT_CONFIG_PATH};
use anyhow::{Context, Result, bail};
use capulus::managed::ManagedFile;
use capulus::shell::shell_quote as sh_quote;

use super::{
    AEGIS_AGENT_DIR, AEGIS_AGENT_REFRESH_TOKEN_ENV, AEGIS_AGENT_SERVICE_NAME,
    AEGIS_AGENT_UNIT_PATH, AEGIS_AUTHORIZED_PRINCIPALS_DIR, AEGIS_CLIENT_CA_PATH, AEGIS_DIR_ETC,
    AEGIS_SSHD_DROPIN, BIRD_CONFIG_PATH, BIRD_SERVICE_NAME, REMOTE_HOST_CERT_PATH,
    REMOTE_HOST_KEY_PATH, WIREGUARD_DIR, WIREGUARD_UNIT_TEMPLATE_PATH, line_with_newline,
    local_state, system,
};

pub(super) fn load_agent_config() -> Result<AgentConfig> {
    load_agent_config_from(Path::new(AGENT_CONFIG_PATH))?.ok_or_else(|| {
        anyhow::anyhow!(
            "aegis-agent is not installed on this host; host inventory is only available through the local aegis-agent"
        )
    })
}

pub(super) fn load_optional_agent_config() -> Result<Option<AgentConfig>> {
    load_agent_config_from(Path::new(AGENT_CONFIG_PATH))
}

pub(super) fn replace_agent_refresh_token(refresh_token: &str) -> Result<()> {
    let mut config = load_agent_config()?;
    let refresh_token = refresh_token.trim();
    if refresh_token.is_empty() {
        bail!("replacement agent refresh token must not be empty");
    }
    config.auth.refresh_token = refresh_token.to_string();
    system::TextFile::new(Path::new(AGENT_CONFIG_PATH)).write_atomic(
        &toml::to_string(&config).context("failed to encode aegis-agent config")?,
        0o600,
    )
}

fn load_agent_config_from(path: &Path) -> Result<Option<AgentConfig>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    AgentConfig::parse_toml(&raw)
        .with_context(|| format!("failed to load {}", path.display()))
        .map(Some)
}

#[derive(Debug, Clone)]
struct ResolvedInstall {
    api_base: String,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    host_id: HostId,
    install_auth: InstallAuth,
    initial_oauth_principal: Option<String>,
    login_principal: String,
    inbound_ssh: bool,
    staged_enrollment: bool,
    managed_install_present: bool,
}

#[derive(Debug, Clone)]
enum InstallAuth {
    RefreshToken(String),
}

impl ResolvedInstall {
    fn resolve(api_base_override: Option<&str>, args: &InstallArgs) -> Result<Self> {
        let reuse_existing = args.upgrade || args.reinstall;
        let existing_install = if reuse_existing {
            Some(load_agent_config().with_context(
                || {
                    "`aegis advanced install --upgrade` / `--reinstall` requires an existing local aegis-agent install"
                },
            )?)
        } else {
            load_optional_agent_config()?
        };
        let managed_install_present = existing_install.is_some();
        let api_base = resolve_api_base(
            api_base_override,
            existing_install
                .as_ref()
                .filter(|_| reuse_existing)
                .map(|config| config.api_base.as_str()),
        )?;
        if let Some(existing) = existing_install.as_ref() {
            anyhow::ensure!(
                aegis_dto::namespace::ApiEndpoint::parse(&api_base).map_err(anyhow::Error::msg)?
                    == aegis_dto::namespace::ApiEndpoint::parse(&existing.api_base)
                        .map_err(anyhow::Error::msg)?,
                "the selected namespace differs from this machine's enrollment; select its enrolled namespace to upgrade, or unenroll it before enrolling elsewhere"
            );
        }
        let (key, cert) = if args.key.is_some() || args.cert.is_some() {
            (args.key.clone(), args.cert.clone())
        } else if reuse_existing {
            match existing_install.as_ref() {
                Some(config) => (
                    Some(config.host.host_private_key_path.clone()),
                    Some(config.host.host_certificate_path.clone()),
                ),
                None => (None, None),
            }
        } else {
            (None, None)
        };
        let login_principal = args
            .user
            .clone()
            .or_else(|| {
                existing_install
                    .as_ref()
                    .filter(|_| reuse_existing)
                    .map(|config| config.host.ssh_user.clone())
            })
            .unwrap_or(system::LoginPrincipal::current()?);
        let inbound_ssh = args
            .inbound_ssh
            .map(Choice::as_bool)
            .or_else(|| {
                existing_install
                    .as_ref()
                    .filter(|_| reuse_existing)
                    .map(|config| config.host.port.is_some())
            })
            .unwrap_or(true);
        let host_id = resolve_host_id(args, existing_install.as_ref())?;
        let initial_oauth_principal = args
            .initial_oauth_principal
            .as_deref()
            .map(crate::principal_grants::validate_user_id)
            .transpose()?;
        let install_auth = if let Some(refresh_token) = agent_refresh_token_from_env()? {
            InstallAuth::RefreshToken(refresh_token)
        } else if reuse_existing {
            match existing_install
                .as_ref()
                .map(|config| config.auth.refresh_token.clone())
            {
                Some(refresh_token) => InstallAuth::RefreshToken(refresh_token),
                None => InstallAuth::RefreshToken(issue_agent_token(&api_base, &host_id)?),
            }
        } else {
            InstallAuth::RefreshToken(issue_agent_token(&api_base, &host_id)?)
        };
        Ok(Self {
            api_base,
            key,
            cert,
            host_id,
            install_auth,
            initial_oauth_principal,
            login_principal,
            inbound_ssh,
            staged_enrollment: args.staged_enrollment,
            managed_install_present,
        })
    }

    fn run(self, workflow: &Task) -> Result<String> {
        workflow.set_phase("validating the local Ubuntu host");
        system::LocalRoot::require_ubuntu()?;
        if self.key.is_some() ^ self.cert.is_some() {
            bail!("`aegis advanced install` requires `--key` and `--cert` together");
        }
        workflow.set_phase("installing host prerequisites");
        system::LocalRoot::install_ubuntu_packages_without_sudo(&[
            "build-essential",
            "ca-certificates",
            "curl",
            "iputils-ping",
            "iptables",
            "libssl-dev",
            "nftables",
            "openssh-server",
            "pkg-config",
            "systemd-resolved",
            "wireguard",
            "bird3",
        ])?;
        crate::apparmor::ensure_wireguard_access()?;

        workflow.set_phase("configuring SSH certificate authentication");
        self.apply_ssh_assets()?;
        workflow.set_phase("configuring the initial Aegis user grant");
        self.apply_initial_principal_grant()?;

        workflow.set_phase("validating the trusted system Aegis binary");
        validate_system_aegis_binary()?;

        workflow.set_phase(if self.staged_enrollment {
            "staging the local aegis-agent service for enrollment activation"
        } else {
            "installing and starting the local aegis-agent service"
        });
        self.install_agent_service()?;

        workflow.set_phase("reloading sshd and persisting managed host state");
        system::Sshd::reload()?;
        local_state::ManagedHostStateStore::persist(&self.api_base, self.host_id)?;
        let message = if self.staged_enrollment {
            "Aegis installation staged; the agent remains stopped until enrollment activation"
        } else if self.inbound_ssh {
            "Aegis SSH certificate authentication and local agent service installed"
        } else {
            "Aegis local agent service installed"
        };
        Ok(message.to_string())
    }

    fn apply_ssh_assets(&self) -> Result<()> {
        if !self.inbound_ssh {
            system::TextFile::new(Path::new(AEGIS_SSHD_DROPIN)).remove_if_exists()?;
            return Ok(());
        }

        let client_ca = ApiClient::new(&self.api_base)?.get_client_ca_public_key()?;
        capulus::store::ensure_directory(Path::new(AEGIS_DIR_ETC), Some(0o755))?;
        capulus::store::ensure_directory(Path::new(AEGIS_AUTHORIZED_PRINCIPALS_DIR), Some(0o755))?;
        system::TextFile::new(Path::new(AEGIS_CLIENT_CA_PATH))
            .write_atomic(&line_with_newline(&client_ca.public_key), 0o644)?;

        let host_key_path = self.key.as_ref().map(|path| path.display().to_string());
        let host_cert_path = self.cert.as_ref().map(|path| path.display().to_string());
        system::Sshd::write_dropin(
            Path::new(AEGIS_SSHD_DROPIN),
            &aegis_dto::sshd_install_dropin_contents(
                AEGIS_CLIENT_CA_PATH,
                &format!("{AEGIS_AUTHORIZED_PRINCIPALS_DIR}/%u"),
                host_key_path.as_deref(),
                host_cert_path.as_deref(),
            ),
        )
    }

    fn apply_initial_principal_grant(&self) -> Result<()> {
        let Some(oauth_principal) = self.initial_oauth_principal.as_deref() else {
            return Ok(());
        };
        let mut grants = crate::principal_grants::PrincipalGrantStore::load()?;
        grants.allow(&self.login_principal, oauth_principal)?;
        grants.persist()
    }

    fn install_agent_service(&self) -> Result<()> {
        let management_operator = crate::system_user::ManagementOperatorSetup::prepare(
            &self.login_principal,
            self.managed_install_present,
        )?;
        let host_private_key_path = self
            .key
            .clone()
            .unwrap_or_else(|| PathBuf::from(REMOTE_HOST_KEY_PATH));
        let host_certificate_path = self
            .cert
            .clone()
            .unwrap_or_else(|| PathBuf::from(REMOTE_HOST_CERT_PATH));
        let config: AgentConfig = AgentConfigOptions {
            api_base: canonical_saved_api_base_url(&self.api_base),
            auth: self.agent_auth_config()?,
            cache_path: Some(PathBuf::from(SHARED_CACHE_PATH)),
            host: AgentHostConfigOptions {
                host_id: self.host_id,
                ssh_user: self.login_principal.to_string(),
                port: self.inbound_ssh.then_some(22),
                host_private_key_path: host_private_key_path.clone(),
                host_public_key_path: host_public_key_path(&host_private_key_path),
                host_certificate_path,
                client_ca_path: PathBuf::from(AEGIS_CLIENT_CA_PATH),
                authorized_principals_dir: PathBuf::from(AEGIS_AUTHORIZED_PRINCIPALS_DIR),
                sshd_dropin_path: PathBuf::from(AEGIS_SSHD_DROPIN),
            },
            bird: AgentBirdConfigOptions {
                config_path: PathBuf::from(BIRD_CONFIG_PATH),
                service: BIRD_SERVICE_NAME.to_string(),
            },
        }
        .try_into()?;

        capulus::store::ensure_directory(Path::new(AEGIS_AGENT_DIR), Some(0o755))?;
        capulus::store::ensure_directory(Path::new(WIREGUARD_DIR), Some(0o755))?;
        capulus::store::ensure_directory(Path::new("/var/lib/aegis"), Some(0o755))?;
        persist_agent_config(Path::new(AGENT_CONFIG_PATH), &config)?;
        management_operator.apply()?;
        system::TextFile::new(Path::new(AEGIS_AGENT_UNIT_PATH))
            .write_atomic(&managed_unit_contents(AEGIS_AGENT_UNIT_PATH)?, 0o644)?;
        system::TextFile::new(Path::new("/etc/systemd/system/aegis-agent.socket")).write_atomic(
            &managed_unit_contents("/etc/systemd/system/aegis-agent.socket")?,
            0o644,
        )?;
        system::TextFile::new(Path::new("/etc/systemd/system/aegis-capulus.socket")).write_atomic(
            &managed_unit_contents("/etc/systemd/system/aegis-capulus.socket")?,
            0o644,
        )?;
        system::TextFile::new(Path::new(WIREGUARD_UNIT_TEMPLATE_PATH))
            .write_atomic(&aegis_dto::managed_wireguard_systemd_unit_contents(), 0o644)?;
        system::Systemd::daemon_reload()?;
        if !self.staged_enrollment {
            system::SystemdUnit::new(crate::managed::APPLICATION_SOCKET_NAME).enable_now()?;
            system::SystemdUnit::new(crate::managed::MANAGEMENT_SOCKET_NAME).enable_now()?;
            system::SystemdUnit::new(AEGIS_AGENT_SERVICE_NAME).enable_now()?;
        }
        Ok(())
    }

    fn agent_auth_config(&self) -> Result<AgentAuthConfig> {
        Ok(AgentAuthConfig {
            refresh_token: match &self.install_auth {
                InstallAuth::RefreshToken(refresh_token) => refresh_token.clone(),
            },
        })
    }
}

pub(super) fn run(api_base_override: Option<&str>, args: &InstallArgs) -> Result<i32> {
    if let Some(code) = system::LocalRoot::reexec_if_needed()? {
        return Ok(code);
    }

    if system::LocalRoot::reinstall_requires_explicit_user(args) {
        bail!(
            "`aegis advanced install --reinstall` requires `--user USER` when it is invoked as root without sudo"
        );
    }
    let workflow = ui::task(TaskOptions {
        label: if args.upgrade {
            "Upgrading the local Aegis installation".to_string()
        } else if args.reinstall {
            "Reinstalling the local Aegis installation".to_string()
        } else {
            "Installing Aegis on this host".to_string()
        },
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    workflow.set_phase("resolving and validating install configuration");
    let resolved = ResolvedInstall::resolve(api_base_override, args)?;
    match resolved.run(&workflow) {
        Ok(message) => {
            workflow.finish(message);
            Ok(0)
        }
        Err(error) => {
            workflow.abandon(
                "Install stopped after local changes may have been applied; rerun with `--reinstall` after addressing the error",
            );
            Err(error)
        }
    }
}

fn resolve_host_id(args: &InstallArgs, existing_install: Option<&AgentConfig>) -> Result<HostId> {
    if let Some(host_id) = args.host_id {
        return Ok(host_id);
    }
    if let Some(state) = local_state::ManagedHostStateStore::load()? {
        return Ok(state.host_id);
    }
    if let Some(existing_install) = existing_install {
        return Ok(existing_install.host.host_id);
    }
    bail!(
        "`aegis advanced install` requires a known enrolled host UUID; run it through `aegis manage enroll` first"
    )
}

pub(super) fn agent_refresh_token_from_env() -> Result<Option<String>> {
    let Some(encoded) = env::var(AEGIS_AGENT_REFRESH_TOKEN_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    agent_refresh_token_from_encoded_value(encoded.trim())
        .context("failed to parse embedded aegis-agent refresh token")
        .map(Some)
}

fn issue_agent_token(api_base: &str, host_id: &HostId) -> Result<String> {
    let mut api = load_authenticated_api(api_base)?;
    api.issue_agent_token(host_id)
}

pub(super) fn agent_refresh_token_env_assignment(refresh_token: &str) -> Result<String> {
    Ok(format!(
        "{}={}",
        AEGIS_AGENT_REFRESH_TOKEN_ENV,
        sh_quote(&agent_refresh_token_env_value(refresh_token))
    ))
}

pub(super) fn load_authenticated_api(api_base: &str) -> Result<AuthenticatedApiClient> {
    AuthenticatedApiClient::load(Some(api_base))
}

fn validate_system_aegis_binary() -> Result<()> {
    let product = crate::managed::product()?;
    let installed = product.program().trusted_installed_path()?;
    let expected = fs::canonicalize(installed)?;
    let running = fs::canonicalize("/proc/self/exe")
        .context("failed to resolve the running Aegis executable")?;
    if running != expected {
        bail!(
            "privileged Aegis installation must run from the trusted system binary at {}",
            aegis_dto::layout::SYSTEM_BINARY_PATH
        );
    }
    Ok(())
}

fn host_public_key_path(private_key_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", private_key_path.display()))
}

fn managed_unit_contents(destination: &str) -> Result<String> {
    crate::managed::product()?
        .installation_manifest()
        .files
        .into_iter()
        .find_map(|file| match file {
            ManagedFile::Text {
                destination: path,
                contents,
                ..
            } if path == Path::new(destination) => Some(contents),
            ManagedFile::Binary { .. } | ManagedFile::Text { .. } => None,
        })
        .ok_or_else(|| anyhow::anyhow!("managed unit declaration omitted {destination}"))
}

#[cfg(test)]
mod tests {
    use super::managed_unit_contents;

    #[test]
    fn agent_systemd_unit_retries_forever_at_low_cadence() {
        let unit = managed_unit_contents(super::AEGIS_AGENT_UNIT_PATH).unwrap();
        assert!(unit.contains("User=root\n"));
        assert!(unit.contains("Group=root\n"));
        assert!(unit.contains("Restart=always\n"));
        assert!(unit.contains("RestartSec=60s\n"));
        assert!(unit.contains("StartLimitIntervalSec=0\n"));
    }
}
