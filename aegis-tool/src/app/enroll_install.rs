use aegis_dto::{HostId, protocol::AegisNetworkConfig};
use anyhow::Result;
use capulus::shell::shell_quote as sh_quote;

use crate::cli::AgentMode;

use super::{
    REMOTE_HOST_CERT_PATH, REMOTE_HOST_KEY_PATH, install, mesh_bootstrap, system, wireguard,
};

pub(super) struct RemotePrepareHostScript;

impl RemotePrepareHostScript {
    pub(super) fn render(publish_ssh: bool) -> String {
        format!(
            "{}\n{}\n{}\nsudo \"$system_aegis\" agent prepare-identity {}\n",
            system::prerequisites_script(true),
            system_program_bootstrap_script(true),
            crate::platform::BINARY_SHELL_ASSIGNMENT,
            if publish_ssh { "--inbound-ssh" } else { "" }
        )
    }
}

pub(super) struct RemoteFinalizeInstall<'a> {
    api_base: &'a str,
    pending_host: &'a crate::config::CachedHost,
    hub_peers: &'a [wireguard::HubPeer],
    network: &'a AegisNetworkConfig,
    server_certificate: Option<&'a str>,
    agent_token: &'a str,
    login_principal: &'a str,
    initial_user_id: Option<&'a str>,
    mode: AgentMode,
    inbound_ssh: bool,
}

pub(super) struct RemoteFinalizeInstallParts<'a> {
    pub(super) api_base: &'a str,
    pub(super) pending_host: &'a crate::config::CachedHost,
    pub(super) hub_peers: &'a [wireguard::HubPeer],
    pub(super) network: &'a AegisNetworkConfig,
    pub(super) server_certificate: Option<&'a str>,
    pub(super) agent_token: &'a str,
    pub(super) login_principal: &'a str,
    pub(super) initial_user_id: Option<&'a str>,
    pub(super) mode: AgentMode,
    pub(super) inbound_ssh: bool,
}

impl<'a> RemoteFinalizeInstall<'a> {
    pub(super) fn new(parts: RemoteFinalizeInstallParts<'a>) -> Self {
        Self {
            api_base: parts.api_base,
            pending_host: parts.pending_host,
            hub_peers: parts.hub_peers,
            network: parts.network,
            server_certificate: parts.server_certificate,
            agent_token: parts.agent_token,
            login_principal: parts.login_principal,
            initial_user_id: parts.initial_user_id,
            mode: parts.mode,
            inbound_ssh: parts.inbound_ssh,
        }
    }

    pub(super) fn render(&self) -> Result<String> {
        let mut install_args = format!("--host-id {}", self.pending_host.host_id);
        if self.server_certificate.is_some() {
            install_args.push_str(&format!(
                " --key {} --cert {}",
                sh_quote(REMOTE_HOST_KEY_PATH),
                sh_quote(REMOTE_HOST_CERT_PATH),
            ));
        }
        install_args.push_str(&format!(
            " --user {} --inbound-ssh {} --staged-enrollment",
            sh_quote(self.login_principal),
            if self.inbound_ssh { "yes" } else { "no" }
        ));
        if let Some(principal) = self.initial_user_id {
            install_args.push_str(&format!(" --initial-user-id {}", sh_quote(principal)));
        }
        let agent_refresh_token_env =
            install::agent_refresh_token_env_assignment(self.agent_token)?;
        let wireguard_setup = if self.hub_peers.is_empty()
            || self.pending_host.platform.operating_system
                == aegis_dto::platform::OperatingSystem::MacOs
        {
            String::new()
        } else {
            mesh_bootstrap::BootstrapMeshScript::new(
                self.pending_host,
                self.hub_peers,
                self.network,
                self.mode,
            )
            .render()?
        };
        let host_certificate_bootstrap = self
            .server_certificate
            .map(|server_certificate| {
                format!(
                    "cat <<'EOF_AEGIS_SERVER_CERT' | sudo tee {REMOTE_HOST_CERT_PATH} >/dev/null\n\
{server_certificate}\n\
EOF_AEGIS_SERVER_CERT\n\
sudo chmod 644 {REMOTE_HOST_CERT_PATH}\n"
                )
            })
            .unwrap_or_default();
        Ok(format!(
            "set -euo pipefail\n\
             sudo -v\n\
             login_user={login_user}\n\
             {wireguard_setup}\n\
             {tool_bootstrap}\
             {host_certificate_bootstrap}\
             sudo env {agent_refresh_token_env} {system_binary} --api-base {api_base} advanced install {install_args}\n",
            api_base = sh_quote(self.api_base),
            agent_refresh_token_env = agent_refresh_token_env,
            host_certificate_bootstrap = host_certificate_bootstrap,
            install_args = install_args,
            tool_bootstrap = system_program_bootstrap_script(true),
            login_user = sh_quote(self.login_principal),
            system_binary = crate::platform::system_binary_path(self.pending_host.platform),
            wireguard_setup = wireguard_setup,
        ))
    }
}

pub fn system_program_bootstrap_script(use_sudo: bool) -> String {
    format!(
        "{sudo}bash -seuo pipefail <<'EOF_AEGIS_BOOTSTRAP'\naegis_bootstrap_version={version}\n{script}\nEOF_AEGIS_BOOTSTRAP\n",
        sudo = if use_sudo { "sudo " } else { "" },
        version = sh_quote(env!("CARGO_PKG_VERSION")),
        script = include_str!("../../assets/bootstrap.sh"),
    )
}

pub fn system_agent_activation_script() -> String {
    format!(
        "case $(uname -s) in\nDarwin)\n  if ! sudo launchctl print system/aegis-agent >/dev/null 2>&1; then\n    sudo launchctl bootstrap system /Library/LaunchDaemons/aegis-agent.plist\n  fi\n  sudo launchctl print system/aegis-agent >/dev/null\n  ;;\nLinux)\n  sudo systemctl enable --now {application_socket} {management_socket}\n  sudo systemctl enable --now {service}\n  sudo systemctl is-active --quiet {application_socket} {management_socket} {service}\n  ;;\n*) exit 1 ;;\nesac\n",
        application_socket = sh_quote(crate::managed::APPLICATION_SOCKET_NAME),
        management_socket = sh_quote(crate::managed::MANAGEMENT_SOCKET_NAME),
        service = sh_quote(super::AEGIS_AGENT_SERVICE_NAME)
    )
}

pub(super) struct LocalTargetInstall<'a> {
    api_base: &'a str,
    host_id: HostId,
    inbound_ssh: bool,
    install_host_certificate: bool,
    agent_token: &'a str,
    initial_user_id: Option<&'a str>,
    system_bootstrap: String,
}

pub(super) struct LocalTargetInstallOptions<'a> {
    pub api_base: &'a str,
    pub host_id: HostId,
    pub inbound_ssh: bool,
    pub install_host_certificate: bool,
    pub agent_token: &'a str,
    pub initial_user_id: Option<&'a str>,
}

impl<'a> LocalTargetInstall<'a> {
    pub(super) fn new(options: LocalTargetInstallOptions<'a>) -> Self {
        Self {
            api_base: options.api_base,
            host_id: options.host_id,
            inbound_ssh: options.inbound_ssh,
            install_host_certificate: options.install_host_certificate,
            agent_token: options.agent_token,
            initial_user_id: options.initial_user_id,
            system_bootstrap: system_program_bootstrap_script(false),
        }
    }

    pub(super) fn run(&self) -> Result<()> {
        system::LocalRoot::run_script(&self.system_bootstrap)?;
        let mut install_args = vec![
            "advanced".to_string(),
            "install".to_string(),
            "--staged-enrollment".to_string(),
            "--host-id".to_string(),
            self.host_id.to_string(),
        ];
        if self.install_host_certificate {
            install_args.push("--key".to_string());
            install_args.push(REMOTE_HOST_KEY_PATH.to_string());
            install_args.push("--cert".to_string());
            install_args.push(REMOTE_HOST_CERT_PATH.to_string());
        }
        install_args.push("--inbound-ssh".to_string());
        install_args.push(if self.inbound_ssh {
            "yes".to_string()
        } else {
            "no".to_string()
        });
        if let Some(principal) = self.initial_user_id {
            install_args.push("--initial-user-id".to_string());
            install_args.push(principal.to_string());
        }
        system::LocalRoot::run_aegis_command(self.api_base, &install_args, self.agent_token)
    }
}
