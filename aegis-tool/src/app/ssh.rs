use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::thread;

use aegis_types::{
    DEFAULT_AEGIS_NETWORK, HostId,
    v1::{AegisDirectClientCertRequest, AegisDirectTarget},
};
use anyhow::{Context, Result, bail};
use dialoguer::{Select, theme::ColorfulTheme};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};

use crate::api::AuthenticatedApiClient;
use crate::cli::SshArgs;
use crate::command::run_status;
use crate::config::{CachedHost, ensure_client_dirs};
use crate::ui::{self, Task, TaskOptions, TaskVisibility};

use super::{connect, host, known_hosts_target, list, local_agent, mesh_route};

pub(super) fn run(api_base_override: Option<&str>, args: &SshArgs) -> Result<i32> {
    let mut args = args.clone();
    if args.host.is_none() {
        args.host = Some(select_normal_target(api_base_override, &args)?);
    }
    let handoff = SshHandoff::new(&args);
    let result = run_with_handoff(api_base_override, &args, &handoff);
    if result.is_err() {
        handoff.fail("SSH session preparation failed");
    }
    result
}

fn select_normal_target(api_base_override: Option<&str>, args: &SshArgs) -> Result<String> {
    let mut hosts = if args.refresh || !crate::api::uses_local_agent(api_base_override)? {
        list::refresh_host_cache_for_network(api_base_override, &args.network)?
    } else {
        crate::config::load_all_hosts_for_network(
            std::path::Path::new(crate::config::SHARED_CACHE_PATH),
            &args.network,
        )?
    }
    .into_iter()
    .filter(|host| (args.allow_pending || !host.pending) && host.ssh.is_some())
    .collect::<Vec<_>>();
    let history = SshHistory::load()?;
    hosts.sort_by(|left, right| {
        let left_hub = left.mode == aegis_types::AegisHostMode::Hub;
        let right_hub = right.mode == aegis_types::AegisHostMode::Hub;
        left_hub
            .cmp(&right_hub)
            .then_with(|| {
                history
                    .accessed_unix(&args.network, &right.host_id)
                    .cmp(&history.accessed_unix(&args.network, &left.host_id))
            })
            .then_with(|| left.alias().cmp(right.alias()))
    });
    let choices = hosts
        .iter()
        .map(|host| HostChoice {
            label: format!(
                "{:<24}  {:<4}  {}",
                host.alias(),
                match host.mode {
                    aegis_types::AegisHostMode::Hub => "hub",
                    aegis_types::AegisHostMode::Leaf => "leaf",
                },
                host.host_label()
            ),
            endpoint: list::SshReachabilityTarget::from_host(host),
        })
        .collect::<Vec<_>>();
    let index = ui::screen(|screen| choose_host(screen, choices))?;
    Ok(hosts[index].alias().to_string())
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SshHistory {
    accessed: BTreeMap<String, BTreeMap<HostId, i64>>,
}

impl SshHistory {
    fn path() -> Result<std::path::PathBuf> {
        Ok(crate::config::app_dir()?.join("ssh-history.json"))
    }

    fn load() -> Result<Self> {
        let path = Self::path()?;
        match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    fn accessed_unix(&self, network: &str, host_id: &HostId) -> i64 {
        self.accessed
            .get(network)
            .and_then(|hosts| hosts.get(host_id))
            .copied()
            .unwrap_or_default()
    }

    fn record(network: &str, host_id: HostId) -> Result<()> {
        let mut history = Self::load()?;
        history
            .accessed
            .entry(network.to_string())
            .or_default()
            .insert(host_id, crate::config::now_unix());
        let path = Self::path()?;
        capulus::store::ensure_directory(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("SSH history path has no parent"))?,
            Some(0o700),
        )?;
        let raw = serde_json::to_string_pretty(&history).context("failed to encode SSH recency")?;
        super::system::TextFile::new(Path::new(&path)).write_atomic(&raw, 0o600)
    }
}

pub(super) fn run_direct_endpoint() -> Result<i32> {
    if std::env::var("SSH_ORIGINAL_COMMAND").is_ok_and(|command| !command.trim().is_empty()) {
        bail!("paired satellite sessions do not accept remote commands");
    }
    let mut session = ui::screen(prepare_direct_endpoint)?;
    eprintln!("{}", session.summary);
    ui::suspend(|| run_status(&mut session.command))
}

fn prepare_direct_endpoint(screen: &ui::Screen) -> Result<PreparedDirectSession> {
    let loading = ui::task(TaskOptions {
        label: "Loading SSH targets".into(),
        ..TaskOptions::default()
    })?;
    let mut targets = local_agent::direct_targets()?
        .ok_or_else(|| anyhow::anyhow!("the local agent did not authorize a direct SSH session"))?
        .targets;
    loading.finish_and_clear();
    let choices = targets
        .iter()
        .map(|target| HostChoice {
            label: format!(
                "{:<24}  {:<4}  {}",
                target.aliases.primary(),
                match target.mode {
                    aegis_types::AegisHostMode::Hub => "hub",
                    aegis_types::AegisHostMode::Leaf => "leaf",
                },
                target.wireguard_ipv4
            ),
            endpoint: list::SshReachabilityTarget {
                ipv4: Some(target.wireguard_ipv4.clone()),
                ipv6: Some(target.wireguard_ipv6.clone()),
                port: Some(target.ssh_port),
            },
        })
        .collect::<Vec<_>>();
    let index = choose_host(screen, choices)?;
    let target = targets.swap_remove(index);
    screen.clear()?;
    let login_principal = select_direct_login_principal(&target, None)?;
    let task = ui::task(TaskOptions {
        label: format!(
            "Preparing direct SSH session to {}",
            target.aliases.primary()
        ),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    match prepare_direct_session(&target, &login_principal, &task) {
        Ok(session) => {
            task.finish_and_clear();
            Ok(session)
        }
        Err(error) => {
            task.fail("Direct SSH session preparation failed");
            Err(error)
        }
    }
}

struct PreparedDirectSession {
    _temporary: tempfile::TempDir,
    command: Command,
    summary: String,
}

fn prepare_direct_session(
    target: &AegisDirectTarget,
    login_principal: &str,
    task: &Task,
) -> Result<PreparedDirectSession> {
    task.set_phase("Generating an ephemeral SSH key");
    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .context("failed to generate ephemeral direct-session SSH key")?;
    let public_key = private_key
        .public_key()
        .to_openssh()
        .context("failed to encode ephemeral direct-session SSH public key")?;
    task.set_phase("Requesting a short-lived client certificate from the hub");
    let certificate = local_agent::request_direct_client_cert(&AegisDirectClientCertRequest {
        target_host_id: target.host_id,
        login_principal: login_principal.to_string(),
        ed25519_public_key: public_key,
    })?;
    if certificate.target.host_id != target.host_id
        || certificate.login_principal != login_principal
    {
        bail!(
            "hub broker returned credentials for {}@{} instead of {login_principal}@{}",
            certificate.login_principal,
            certificate.target.aliases.primary(),
            target.aliases.primary()
        );
    }

    task.set_phase("Writing isolated SSH credentials");
    let temporary = tempfile::tempdir().context("failed to create direct-session key directory")?;
    let private_key_path = temporary.path().join("identity");
    let certificate_path = temporary.path().join("identity-cert.pub");
    let known_hosts_path = temporary.path().join("known_hosts");
    private_key
        .write_openssh_file(&private_key_path, LineEnding::LF)
        .with_context(|| format!("failed to write {}", private_key_path.display()))?;
    fs::write(
        &certificate_path,
        format!("{}\n", certificate.certificate.trim()),
    )
    .with_context(|| format!("failed to write {}", certificate_path.display()))?;
    let connect_host = certificate.target.wireguard_ipv4.clone();
    fs::write(
        &known_hosts_path,
        format!(
            "@cert-authority {} {}\n",
            known_hosts_target(&connect_host, certificate.target.ssh_port),
            certificate.server_ca_public_key.trim()
        ),
    )
    .with_context(|| format!("failed to write {}", known_hosts_path.display()))?;

    let mut command = Command::new("ssh");
    command
        .args(["-F", "/dev/null"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "PreferredAuthentications=publickey"])
        .args(["-o", "PubkeyAuthentication=yes"])
        .args(["-o", "PasswordAuthentication=no"])
        .args(["-o", "KbdInteractiveAuthentication=no"])
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-o", "ForwardAgent=no"])
        .args(["-o", "StrictHostKeyChecking=yes"])
        .args(["-o", "GlobalKnownHostsFile=/dev/null"])
        .args(["-o", "UpdateHostKeys=no"])
        .args(["-o", "HostbasedAuthentication=no"])
        .args(["-o", "VerifyHostKeyDNS=no"])
        .args(["-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts_path.display()))
        .arg("-i")
        .arg(&private_key_path)
        .arg("-o")
        .arg(format!("CertificateFile={}", certificate_path.display()))
        .arg("-p")
        .arg(certificate.target.ssh_port.to_string())
        .arg(format!("{login_principal}@{connect_host}"));
    Ok(PreparedDirectSession {
        _temporary: temporary,
        command,
        summary: format!(
            "aegis ssh {} · {}@{} · via hub broker",
            certificate.target.aliases.primary(),
            login_principal,
            connect_host
        ),
    })
}

fn select_direct_login_principal(
    target: &AegisDirectTarget,
    requested: Option<&str>,
) -> Result<String> {
    let mut principals = target.login_principals.clone();
    principals.sort();
    principals.dedup();
    if let Some(requested) = requested {
        if principals.iter().any(|principal| principal == requested) {
            return Ok(requested.to_string());
        }
        bail!(
            "Unix principal `{requested}` is not available on host `{}`",
            target.aliases.primary()
        );
    }
    if principals.len() == 1 {
        return Ok(principals.remove(0));
    }
    let index = choose("Login", &principals)?;
    Ok(principals.swap_remove(index))
}

struct HostChoice {
    label: String,
    endpoint: list::SshReachabilityTarget,
}

fn choose_host(screen: &ui::Screen, choices: Vec<HostChoice>) -> Result<usize> {
    let options = ui::SelectOptions {
        prompt: "Connect to".into(),
        choices: choices
            .iter()
            .map(|choice| ui::Choice {
                label: choice.label.clone(),
                status: ui::ChoiceStatus::Checking,
            })
            .collect(),
    };
    ui::select_live(screen, options, |tx| {
        for (index, choice) in choices.into_iter().enumerate() {
            let tx = tx.clone();
            // Detached, bounded probes never hold up selection or touch the terminal.
            thread::Builder::new()
                .name("ssh-selector-probe".into())
                .spawn(move || {
                    let state = choice
                        .endpoint
                        .probe()
                        .map(|probe| probe.state)
                        .unwrap_or(list::ReachabilityState::Unreachable);
                    let note = state.note();
                    let _ = tx.send(ui::ChoiceUpdate {
                        index,
                        status: ui::ChoiceStatus::Ready {
                            text: note.text,
                            color: note.color,
                        },
                    });
                })
                .context("failed to start SSH reachability check")?;
        }
        Ok(())
    })
}

fn choose(label: &str, choices: &[String]) -> Result<usize> {
    if choices.is_empty() {
        bail!("no available {}s", label.to_ascii_lowercase());
    }
    if choices.len() == 1 {
        return Ok(0);
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!(
            "multiple {}s are available; specify one explicitly",
            label.to_ascii_lowercase()
        );
    }
    ui::suspend(|| {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt(label)
            .items(choices)
            .default(0)
            .interact_opt()
    })?
    .ok_or_else(|| capulus::Cancelled.into())
}

fn run_with_handoff(
    api_base_override: Option<&str>,
    args: &SshArgs,
    handoff: &SshHandoff,
) -> Result<i32> {
    let mut session = PreparedSshSession::prepare(api_base_override, args, handoff)?;
    handoff.clear();
    if let Err(error) = SshHistory::record(&args.network, session.prepared.host().host_id) {
        crate::ui::warn(&format!("failed to update SSH recency: {error:#}"));
    }
    HostMessagesBanner::new(session.prepared.host()).print();
    handoff.print_session_panel(&session.prepared, &session.display_destination);
    ui::suspend(|| run_status(&mut session.command))
}

struct PreparedSshSession {
    prepared: connect::PreparedConnect,
    display_destination: String,
    command: Command,
}

impl PreparedSshSession {
    fn prepare(
        api_base_override: Option<&str>,
        args: &SshArgs,
        handoff: &SshHandoff,
    ) -> Result<Self> {
        let _system_lock = crate::locks::local_system_lock()?;
        ensure_client_dirs()?;
        let requested_host = args.host.as_deref().ok_or_else(|| {
            anyhow::anyhow!("an SSH host must be selected before preparing the session")
        })?;
        let mut api = AuthenticatedApiClient::load(api_base_override)?;
        handoff.update(&format!(
            "Resolving host inventory   {}/{}",
            args.network, requested_host
        ));
        let host = host::AvailableHostLookup::new(
            api_base_override,
            &args.network,
            requested_host,
            args.allow_pending,
        )
        .refresh(args.refresh)
        .load()?;
        let network = host::load_network_config(&mut api, &args.network)?;
        mesh_route::TargetRouteWait::new(
            host.alias().as_str(),
            host::ssh_mesh_route_targets(&host, args)?,
        )
        .wait(false, Some(handoff))?;
        handoff.update(&format!("Resolving mesh target     {}", host.alias()));
        let connect_host = host::resolve_ssh_connect_host(&host, args)?;
        let display_host =
            host::logical_dns_host(host.alias().as_str(), network.host_dns_suffix.as_deref())
                .unwrap_or_else(|| connect_host.clone());
        let prepared = connect::AssetPreparer::new(
            &args.network,
            &host,
            connect_host,
            args.user.clone(),
            args.no_server_cert,
        )
        .with_presentation_host(display_host.clone())
        .prepare_with_status(&mut api, handoff)?;
        let display_destination =
            connect::SshDestination::new(prepared.ssh_user(), &display_host, prepared.ssh_port())
                .label();
        handoff.update(&format!("Opening SSH session       {display_destination}"));
        let command = prepared.ssh_command(&args.ssh_args, args.command.as_deref(), None, false);
        Ok(Self {
            prepared,
            display_destination,
            command,
        })
    }
}

struct SshHandoff {
    task: Mutex<Option<Task>>,
    route: String,
}

impl SshHandoff {
    fn new(args: &SshArgs) -> Self {
        Self {
            task: Mutex::new(Some(
                ui::task(TaskOptions {
                    label: "Preparing SSH session".to_string(),
                    visibility: TaskVisibility::Immediate,
                    ..TaskOptions::default()
                })
                .expect("static SSH preparation task is valid"),
            )),
            route: route_label(args),
        }
    }

    fn update(&self, message: &str) {
        if let Some(task) = self.task.lock().expect("SSH handoff task lock").as_ref() {
            task.set_phase(message);
        }
    }

    fn clear(&self) {
        if let Some(task) = self.task.lock().expect("SSH handoff task lock").take() {
            task.finish_and_clear();
        }
    }

    fn fail(&self, message: &str) {
        if let Some(task) = self.task.lock().expect("SSH handoff task lock").take() {
            task.fail(message);
        }
    }

    fn print_session_panel(&self, prepared: &connect::PreparedConnect, display_destination: &str) {
        self.clear();
        if ui::current().is_interactive() {
            let destination = panel_destination(display_destination);
            let line = format!(
                "{}  {}  {}",
                prepared.host().alias(),
                destination.visible,
                self.route
            );
            eprintln!(
                "{}",
                render_panel(
                    "aegis ssh",
                    &line,
                    Some(PanelParts {
                        host: prepared.host().alias().as_str(),
                        destination: &destination,
                        route: &self.route,
                    }),
                    ui::current().color_is_enabled(),
                )
            );
            eprintln!();
        } else {
            eprintln!(
                "aegis ssh {} · {} · {}",
                prepared.host().alias(),
                display_destination,
                self.route
            );
        }
    }
}

impl connect::ConnectStatus for SshHandoff {
    fn set_status(&self, message: &str) {
        self.update(message);
    }
}

fn route_label(args: &SshArgs) -> String {
    if args.use_endpoint {
        "via published endpoint".to_string()
    } else if args.network == DEFAULT_AEGIS_NETWORK {
        "via local mesh".to_string()
    } else {
        format!("via {} mesh", args.network)
    }
}

pub(super) struct HostMessagesBanner<'a> {
    host: &'a CachedHost,
}

impl<'a> HostMessagesBanner<'a> {
    pub(super) fn new(host: &'a CachedHost) -> Self {
        Self { host }
    }

    pub(super) fn render(&self) -> Option<String> {
        self.render_with(
            ui::current().is_interactive(),
            ui::current().color_is_enabled(),
        )
    }

    #[cfg(test)]
    pub(super) fn render_for(&self, interactive: bool) -> Option<String> {
        self.render_with(interactive, interactive)
    }

    fn render_with(&self, interactive: bool, color: bool) -> Option<String> {
        let messages = self
            .host
            .messages
            .iter()
            .filter(|message| !message.value.trim().is_empty())
            .collect::<Vec<_>>();
        if messages.is_empty() {
            return None;
        }
        let body = messages
            .into_iter()
            .map(|message| format!("{}: {}", message.level.as_str(), message.value.trim()))
            .collect::<Vec<_>>()
            .join("\n");
        if !interactive {
            return Some(format!("Aegis warnings for {}\n{body}", self.host.alias()));
        }
        Some(render_panel(
            &format!("aegis warnings {}", self.host.alias()),
            &body,
            None,
            color,
        ))
    }

    fn print(&self) {
        if let Some(banner) = self.render() {
            eprintln!("{banner}");
        }
    }
}

struct PanelDestination {
    visible: String,
    rendered: String,
}

struct PanelParts<'a> {
    host: &'a str,
    destination: &'a PanelDestination,
    route: &'a str,
}

fn panel_destination(destination: &str) -> PanelDestination {
    render_panel_destination(destination, ui::current().color_is_enabled())
}

fn render_panel_destination(destination: &str, enabled: bool) -> PanelDestination {
    if let Some((user, path)) = destination.split_once('@') {
        let path = render_panel_destination_path(path, enabled);
        return PanelDestination {
            visible: format!("{user}@{}", path.visible),
            rendered: format!(
                "{}{}{}",
                paint(enabled, ANSI_YELLOW, user),
                paint(enabled, ANSI_BOLD_CYAN, "@"),
                path.rendered
            ),
        };
    }
    render_panel_destination_path(destination, enabled)
}

fn render_panel_destination_path(path: &str, enabled: bool) -> PanelDestination {
    PanelDestination {
        visible: path.to_string(),
        rendered: paint(enabled, ANSI_GREEN, path),
    }
}

fn render_panel(
    title: &str,
    line: &str,
    styled_parts: Option<PanelParts<'_>>,
    enabled: bool,
) -> String {
    let inner_width = line
        .lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or_default()
        .max(title.chars().count() + 2);
    let title_dash_count = inner_width.saturating_sub(title.chars().count() + 1);
    let title = paint(enabled, ANSI_BOLD_CYAN, title);
    let border = paint(enabled, ANSI_DIM, &"─".repeat(title_dash_count));
    let bottom = paint(enabled, ANSI_DIM, &"─".repeat(inner_width + 2));
    let mut lines = Vec::new();
    lines.push(format!(
        "{}─ {title} {border}{}",
        paint(enabled, ANSI_DIM, "╭"),
        paint(enabled, ANSI_DIM, "╮")
    ));
    match styled_parts {
        Some(parts) => lines.push(render_panel_line(
            inner_width,
            &format!(
                "{}  {}  {}",
                paint(enabled, ANSI_BOLD_WHITE, parts.host),
                parts.destination.rendered,
                paint(enabled, ANSI_DIM, parts.route)
            ),
            line.chars().count(),
            enabled,
        )),
        None => {
            for body_line in line.lines() {
                lines.push(render_panel_line(
                    inner_width,
                    &paint(enabled, ANSI_YELLOW, body_line),
                    body_line.chars().count(),
                    enabled,
                ));
            }
        }
    }
    lines.push(format!(
        "{}{bottom}{}",
        paint(enabled, ANSI_DIM, "╰"),
        paint(enabled, ANSI_DIM, "╯")
    ));
    lines.join("\n")
}

fn render_panel_line(
    inner_width: usize,
    rendered_line: &str,
    visible_width: usize,
    enabled: bool,
) -> String {
    format!(
        "{} {rendered_line}{} {}",
        paint(enabled, ANSI_DIM, "│"),
        " ".repeat(inner_width.saturating_sub(visible_width)),
        paint(enabled, ANSI_DIM, "│")
    )
}

fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("{code}{text}{ANSI_RESET}")
    } else {
        text.to_string()
    }
}

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD_CYAN: &str = "\x1b[1;36m";
const ANSI_BOLD_WHITE: &str = "\x1b[1;37m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_YELLOW: &str = "\x1b[33m";

#[cfg(test)]
mod tests {
    use super::{
        ANSI_BOLD_CYAN, ANSI_GREEN, ANSI_RESET, ANSI_YELLOW, connect, host,
        render_panel_destination,
    };

    #[test]
    fn ssh_ui_uses_the_network_dns_name_as_its_logical_destination() {
        let logical_host = host::logical_dns_host("alpha", Some(".aegis.x.hoek.io."))
            .expect("network DNS suffix should produce a logical host");
        let destination = connect::SshDestination::new("ubuntu", &logical_host, 22).label();

        assert_eq!("ubuntu@alpha.aegis.x.hoek.io", destination);
    }

    #[test]
    fn panel_destination_styles_user_at_and_host_separately() {
        let destination = render_panel_destination("ubuntu@alpha.x.hoek.io", true);

        assert_eq!("ubuntu@alpha.x.hoek.io", destination.visible);
        assert_eq!(
            format!(
                "{ANSI_YELLOW}ubuntu{ANSI_RESET}{ANSI_BOLD_CYAN}@{ANSI_RESET}\
                 {ANSI_GREEN}alpha.x.hoek.io{ANSI_RESET}"
            ),
            destination.rendered
        );
    }
}
