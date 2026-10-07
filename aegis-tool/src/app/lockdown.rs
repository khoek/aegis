use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use aegis_dto::{
    DEFAULT_AEGIS_NETWORK,
    protocol::{AegisHostMessage, AegisHostMessageLevel},
};
use anyhow::{Context, Result, anyhow};
use capulus::shell::shell_quote as sh_quote;

use crate::cli::{LockdownArgs, LockdownCommands};
use crate::config::CachedHost;
use crate::ui::{self, TaskOptions, TaskVisibility};

use super::{
    AEGIS_LOCKDOWN_DROPIN, connect, connect::PreparedConnect, host, install, list, local_state,
    remote, system, wireguard,
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Disabled,
    EnabledManaged {
        wireguard_ipv4: String,
        wireguard_ipv6: Option<String>,
    },
    EnabledCustom,
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::EnabledManaged { .. } | Self::EnabledCustom => "enabled",
        }
    }
}

pub(super) fn run(api_base_override: Option<&str>, args: &LockdownArgs) -> Result<i32> {
    crate::platform::detect()?.require(aegis_dto::platform::Capability::SshLockdown)?;
    match &args.command {
        LockdownCommands::Enable(args) => {
            if let Some(code) = system::LocalRoot::reexec_if_needed()? {
                return Ok(code);
            }
            let workflow = ui::task(TaskOptions {
                label: "Enabling local Aegis SSH lockdown".to_string(),
                visibility: TaskVisibility::Immediate,
                ..TaskOptions::default()
            })?;
            let result = (|| {
                workflow.set_phase("loading the local host identity and SSH assets");
                let target = LocalTarget::load(api_base_override, args.user.clone())?;
                let mut api = target.authenticated_api()?;
                if target.can_self_verify(&mut api)? {
                    workflow.set_phase("preflighting certificate-only self-SSH");
                    let prepared = target.prepare_preflight_assets(&mut api, &workflow)?;
                    preflight_local_enable(&prepared, prepared.host())?;
                    workflow.set_phase("enabling lockdown and verifying reconnect");
                    enable_local_and_verify(&prepared, prepared.host(), &workflow)?;
                } else {
                    ui::warn(
                        "local machine auth cannot issue a self-SSH certificate; enabling inbound lockdown without self-SSH preflight.",
                    );
                    workflow.set_phase("validating and enabling lockdown without self-SSH");
                    enable_local_without_self_ssh(target.host(), &workflow)?;
                }
                Result::<()>::Ok(())
            })();
            match result {
                Ok(()) => workflow.finish("Aegis lockdown enabled and verified"),
                Err(error) => {
                    workflow.abandon(
                        "Lockdown enable did not complete; rescue disable was attempted where required",
                    );
                    return Err(error);
                }
            }
        }
        LockdownCommands::Disable => {
            if let Some(code) = system::LocalRoot::reexec_if_needed()? {
                return Ok(code);
            }
            let workflow = ui::task(TaskOptions {
                label: "Disabling local Aegis SSH lockdown".to_string(),
                visibility: TaskVisibility::Immediate,
                ..TaskOptions::default()
            })?;
            apply_local_disable()?;
            workflow.finish("Aegis lockdown disabled");
        }
        LockdownCommands::Status => {
            let task = ui::task(TaskOptions {
                label: "Inspecting local Aegis SSH lockdown".to_string(),
                ..TaskOptions::default()
            })?;
            let status = current_status()?;
            task.finish_and_clear();
            println!("{}", status.label());
            match status {
                Status::Disabled => ui::detail("aegis lockdown is disabled."),
                Status::EnabledManaged {
                    wireguard_ipv4,
                    wireguard_ipv6,
                } => ui::detail(&format!(
                    "aegis lockdown is enabled for the WireGuard addresses {wireguard_ipv4}{}.",
                    wireguard_ipv6
                        .as_deref()
                        .map(|wireguard_ipv6| format!(", {wireguard_ipv6}"))
                        .unwrap_or_default()
                )),
                Status::EnabledCustom => ui::warn("ssh config drift"),
            }
        }
    }

    Ok(0)
}

struct LocalTarget {
    api_base: String,
    login_principal: Option<String>,
    host: CachedHost,
}

impl LocalTarget {
    fn load(api_base_override: Option<&str>, login_principal: Option<String>) -> Result<Self> {
        let managed_state = local_state::ManagedHostStateStore::load()?.ok_or_else(|| {
            anyhow!("no aegis-managed host state found; run `aegis advanced install` first")
        })?;
        let identity = local_state::RuntimeWireGuardIdentity::read()?;
        let api_base = api_base_override
            .unwrap_or(&managed_state.api_base)
            .to_string();
        let host = identity.find_host(list::refresh_host_cache(Some(&api_base))?)?;
        Ok(Self {
            api_base,
            login_principal,
            host,
        })
    }

    fn host(&self) -> &CachedHost {
        &self.host
    }

    fn authenticated_api(&self) -> Result<crate::api::AuthenticatedApiClient> {
        install::load_authenticated_api(&self.api_base)
    }

    fn can_self_verify(&self, api: &mut crate::api::AuthenticatedApiClient) -> Result<bool> {
        let _ = api.claims()?;
        Ok(true)
    }

    fn prepare_preflight_assets(
        &self,
        api: &mut crate::api::AuthenticatedApiClient,
        workflow: &ui::Task,
    ) -> Result<PreparedConnect> {
        connect::AssetPreparer::new(
            DEFAULT_AEGIS_NETWORK,
            &self.host,
            host::resolve_connect_host(&self.host)?,
            self.login_principal.clone(),
            false,
        )
        .prepare_with_status(api, workflow)
    }
}

fn enable_local_without_self_ssh(host: &CachedHost, workflow: &ui::Task) -> Result<()> {
    workflow.set_phase("preflighting lockdown safety");
    validate_local_enable(host)?;
    workflow.set_phase("enabling local lockdown");
    apply_local_enable(host)
}

fn validate_local_enable(host: &CachedHost) -> Result<()> {
    system::LocalRoot::run_script(&validation_script(host, true))
        .context("the future lockdown SSH configuration is invalid")
}

fn preflight_local_enable(prepared: &PreparedConnect, host: &CachedHost) -> Result<()> {
    prepared
        .run_remote_command("true")
        .context("the future certificate-backed WireGuard SSH path is not working")?;
    let validation_script = validation_script(host, true);
    system::LocalRoot::run_script(&validation_script)
        .context("the future lockdown SSH configuration is invalid")?;
    Ok(())
}

fn validation_script(host: &CachedHost, use_sudo: bool) -> String {
    let lockdown_content = dropin_contents(
        &allowed_addresses(host).expect("lockdown host should have WireGuard addresses"),
    );
    let as_root = if use_sudo { "sudo " } else { "" };
    format!(
        "set -euo pipefail\n\
         candidate=\"$(mktemp)\"\n\
         backup=\"\"\n\
         cleanup() {{\n\
           if [[ -n \"$backup\" && -f \"$backup\" ]]; then\n\
             {as_root}cp \"$backup\" {AEGIS_LOCKDOWN_DROPIN}\n\
             rm -f \"$backup\"\n\
           else\n\
             {as_root}rm -f {AEGIS_LOCKDOWN_DROPIN}\n\
           fi\n\
           rm -f \"$candidate\"\n\
         }}\n\
         trap cleanup EXIT\n\
         printf '%s' {quoted_content} >\"$candidate\"\n\
         if {as_root}test -f {AEGIS_LOCKDOWN_DROPIN}; then\n\
           backup=\"$(mktemp)\"\n\
           {as_root}cp {AEGIS_LOCKDOWN_DROPIN} \"$backup\"\n\
         fi\n\
         {as_root}install -d -m 755 /etc/ssh/sshd_config.d\n\
         {as_root}cp \"$candidate\" {AEGIS_LOCKDOWN_DROPIN}\n\
         {as_root}install -d -m 755 /run/sshd\n\
         {as_root}chmod 755 /run/sshd\n\
         {as_root}/usr/sbin/sshd -t\n",
        quoted_content = sh_quote(&lockdown_content),
    )
}

fn current_status() -> Result<Status> {
    if !Path::new(AEGIS_LOCKDOWN_DROPIN).exists() {
        return Ok(Status::Disabled);
    }

    let current = fs::read_to_string(AEGIS_LOCKDOWN_DROPIN)
        .with_context(|| format!("failed to read {AEGIS_LOCKDOWN_DROPIN}"))?;
    let (wireguard_ipv4, wireguard_ipv6) = wireguard::interface_addresses()?;
    if current == dropin_contents(&local_allowed_addresses()?) {
        Ok(Status::EnabledManaged {
            wireguard_ipv4,
            wireguard_ipv6,
        })
    } else {
        Ok(Status::EnabledCustom)
    }
}

pub(crate) struct HostReport {
    pub(crate) enabled: bool,
    pub(crate) warning: Option<AegisHostMessage>,
}

pub(crate) fn host_report() -> HostReport {
    match current_status() {
        Ok(Status::Disabled) => HostReport {
            enabled: false,
            warning: None,
        },
        Ok(Status::EnabledManaged { .. }) => HostReport {
            enabled: true,
            warning: None,
        },
        Ok(Status::EnabledCustom) => HostReport {
            enabled: true,
            warning: Some(AegisHostMessage {
                level: AegisHostMessageLevel::Warning,
                value: "ssh config drift".to_string(),
            }),
        },
        Err(error) => HostReport {
            enabled: Path::new(AEGIS_LOCKDOWN_DROPIN).exists(),
            warning: Some(AegisHostMessage {
                level: AegisHostMessageLevel::Warning,
                value: format!("ssh config check failed: {error:#}"),
            }),
        },
    }
}

pub(crate) fn reconcile_enabled() -> Result<bool> {
    if !Path::new(AEGIS_LOCKDOWN_DROPIN).exists() {
        return Ok(false);
    }
    let desired = dropin_contents(&local_allowed_addresses()?);
    if fs::read_to_string(AEGIS_LOCKDOWN_DROPIN)
        .with_context(|| format!("failed to read {AEGIS_LOCKDOWN_DROPIN}"))?
        == desired
    {
        return Ok(false);
    }
    system::Sshd::write_dropin(Path::new(AEGIS_LOCKDOWN_DROPIN), &desired)?;
    system::Sshd::reload()?;
    Ok(true)
}

fn apply_local_enable(host: &CachedHost) -> Result<()> {
    system::Sshd::write_dropin(
        Path::new(AEGIS_LOCKDOWN_DROPIN),
        &dropin_contents(&allowed_addresses(host)?),
    )?;
    system::Sshd::reload()
}

pub(super) fn apply_local_disable() -> Result<()> {
    if !system::LocalRoot::is_running() {
        return system::LocalRoot::run_script(&remote_apply_disable_script());
    }
    system::Sshd::remove_dropin(Path::new(AEGIS_LOCKDOWN_DROPIN))?;
    system::Sshd::reload()
}

fn remote_apply_disable_script() -> String {
    format!(
        "set -euo pipefail\n\
         sudo -v\n\
         sudo rm -f {AEGIS_LOCKDOWN_DROPIN}\n\
         sudo install -d -m 755 /run/sshd\n\
         sudo chmod 755 /run/sshd\n\
         if command -v sshd >/dev/null 2>&1; then\n\
           sudo sshd -t\n\
         else\n\
           sudo /usr/sbin/sshd -t\n\
         fi\n\
         if sudo systemctl is-active --quiet ssh.service; then\n\
           sudo systemctl reload ssh.service\n\
         elif sudo systemctl is-active --quiet sshd.service; then\n\
           sudo systemctl reload sshd.service\n\
         else\n\
           echo 'SSH service is not active; refusing to leave the host without a validated reload' >&2\n\
           exit 1\n\
         fi\n"
    )
}

pub(super) fn enable_local_and_verify(
    prepared: &PreparedConnect,
    host: &CachedHost,
    workflow: &ui::Task,
) -> Result<()> {
    workflow.set_phase("enabling local lockdown");
    apply_local_enable(host)?;

    workflow.set_phase("verifying reconnect after lockdown");
    if let Err(error) = prepared.run_remote_command("printf 'aegis-post-lockdown-ok\\n'") {
        ui::warn(&format!(
            "post-lockdown reconnect failed; attempting local rescue disable: {error}"
        ));
        let _ = apply_local_disable();
        return Err(error);
    }
    Ok(())
}

pub(super) fn disable_remote(
    rescue: &dyn remote::RemoteBootstrapSession,
    workflow: &ui::Task,
) -> Result<()> {
    workflow.set_phase("disabling remote lockdown");
    let privileged = |script: &str| run_privileged_remote(rescue, script);
    disable_remote_with(&privileged)
}

fn disable_remote_with(privileged: &dyn Fn(&str) -> Result<()>) -> Result<()> {
    privileged(&remote_apply_disable_script()).context("failed to disable remote lockdown")
}

fn run_privileged_remote(rescue: &dyn remote::RemoteBootstrapSession, script: &str) -> Result<()> {
    ui::suspend(|| {
        rescue.run_private_shell_streaming_with_tty(&remote::SudoScript::new(script).render())
    })
}

pub(super) fn dropin_contents(allowed_local_addresses: &[String]) -> String {
    let mut match_line = "Match LocalAddress *".to_string();
    for address in allowed_local_addresses {
        match_line.push_str(&format!(",!{address}"));
    }
    format!(
        "# Managed by aegis. Restricts SSH to certificate-backed publickey auth on WireGuard only.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nGSSAPIAuthentication no\nHostbasedAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nAuthorizedKeysFile none\n{match_line}\n  PubkeyAuthentication no\n"
    )
}

pub(super) fn allowed_addresses(host: &CachedHost) -> Result<Vec<String>> {
    let mut addresses = BTreeSet::from([host
        .wireguard_ipv4()
        .ok_or_else(|| anyhow!("host has no wireguard ipv4"))?
        .to_string()]);
    if let Some(wireguard_ipv6) = host.wireguard_ipv6() {
        addresses.insert(wireguard_ipv6.to_string());
    }
    if let Some(internal_ipv4) = host.internal_ipv4() {
        addresses.insert(internal_ipv4.to_string());
    }
    if let Some(internal_ipv6) = host.internal_ipv6() {
        addresses.insert(internal_ipv6.to_string());
    }
    Ok(addresses.into_iter().collect())
}

fn local_allowed_addresses() -> Result<Vec<String>> {
    let (wireguard_ipv4, wireguard_ipv6) = wireguard::interface_addresses()?;
    let mut addresses = BTreeSet::from([wireguard_ipv4]);
    if let Some(wireguard_ipv6) = wireguard_ipv6 {
        addresses.insert(wireguard_ipv6);
    }
    addresses.extend(
        system::LoopbackInterface::addresses()?
            .into_iter()
            .filter(|address| address != "127.0.0.1" && address != "::1"),
    );
    let wireguard_directory = Path::new(aegis_dto::layout::WIREGUARD_DIRECTORY);
    if wireguard_directory.exists() {
        for entry in fs::read_dir(wireguard_directory)
            .with_context(|| format!("failed to read {}", wireguard_directory.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("conf") {
                continue;
            }
            let config = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            if let Ok((ipv4, ipv6)) = wireguard::parse_interface_addresses(&config) {
                addresses.insert(ipv4);
                addresses.extend(ipv6);
            }
        }
    }
    Ok(addresses.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockdown_host_reports_separate_state_from_warnings() {
        let disabled = HostReport {
            enabled: false,
            warning: None,
        };
        assert!(!disabled.enabled);
        assert!(disabled.warning.is_none());

        let drift = AegisHostMessage {
            level: AegisHostMessageLevel::Warning,
            value: "ssh config drift".to_string(),
        };
        assert_eq!(drift.value, "ssh config drift");
    }
}
