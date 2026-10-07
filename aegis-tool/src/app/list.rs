use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use aegis_dto::HostId;
use anyhow::{Context, Result, anyhow, bail};

use crate::agent::{AEGIS_AGENT_VERSION_PATH, AgentTunnelStatus};
use crate::api::AuthenticatedApiClient;
use crate::cli::ListArgs;
use crate::command::run_capture;
use crate::config::{
    AEGIS_AGENT_SOCKET_PATH, CachedHost, SHARED_CACHE_PATH, load_all_hosts_for_network,
};
use crate::ui;

use super::{
    agent_version, command_output_full_failure_detail, connect::PreparedConnect, full_error, host,
    host_list, local_agent, progress_list, sh_quote,
};

const STALE_CACHE_WARNING_AGE: Duration = Duration::from_secs(120);
const RECENT_AGENT_RECONCILE_AGE: Duration = Duration::from_secs(180);
const LOCAL_TUNNEL_STATUS_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostCacheRefreshSource {
    LocalAgent,
    DirectApi,
}

struct HostCacheRefresh {
    hosts: Vec<CachedHost>,
    warning: Option<String>,
    source: HostCacheRefreshSource,
}

#[derive(Clone, Copy)]
enum ProgressFooterOutcome<'a> {
    Success(&'a str),
    Abandoned(&'a str),
}

impl<'a> ProgressFooterOutcome<'a> {
    fn complete(self, list: &progress_list::HostProgressList, elapsed: Duration) {
        if ui::current().is_interactive() {
            list.clear_footer();
            let message = format!("{} · {}", self.message(), ui::format_duration(elapsed));
            match self {
                Self::Success(_) => ui::completed_line(&message),
                Self::Abandoned(_) => ui::abandoned_line(&message),
            }
            return;
        }
        match self {
            Self::Success(message) => list.finish_footer(message),
            Self::Abandoned(message) => list.abandon_footer(message),
        }
    }

    fn message(self) -> &'a str {
        match self {
            Self::Success(message) | Self::Abandoned(message) => message,
        }
    }
}

pub(super) fn refresh_host_cache(api_base_override: Option<&str>) -> Result<Vec<CachedHost>> {
    refresh_host_cache_for_network(api_base_override, aegis_dto::DEFAULT_AEGIS_NETWORK)
}

pub(super) fn refresh_host_cache_for_network(
    api_base_override: Option<&str>,
    network: &str,
) -> Result<Vec<CachedHost>> {
    let task = ui::task(ui::TaskOptions {
        label: format!("Refreshing `{network}` host inventory"),
        ..ui::TaskOptions::default()
    })?;
    let refreshed = match refresh_host_inventory(api_base_override, network) {
        Ok(refreshed) => refreshed,
        Err(error) => {
            task.fail(format!("Failed to refresh `{network}` host inventory"));
            return Err(error);
        }
    };
    let hosts = refreshed.hosts;
    let pending_count = hosts.iter().filter(|host| host.pending).count();
    match refreshed.source {
        HostCacheRefreshSource::LocalAgent if refreshed.warning.is_some() => {
            task.finish(format!(
                "Using cached `{network}` host inventory ({} active, {} pending).",
                hosts.len().saturating_sub(pending_count),
                pending_count
            ));
            if let Some(warning) = refreshed.warning.as_deref() {
                ui::warn(warning);
            }
        }
        HostCacheRefreshSource::DirectApi => {
            task.finish(format!(
                "Fetched {} `{network}` hosts directly from the API ({} active, {} pending).",
                hosts.len(),
                hosts.len().saturating_sub(pending_count),
                pending_count
            ));
            ui::success(&format!(
                "Synced {} `{network}` hosts from the aegis API.",
                hosts.len()
            ));
            if let Some(warning) = refreshed.warning.as_deref() {
                ui::warn(warning);
            }
        }
        HostCacheRefreshSource::LocalAgent => {
            task.finish(format!(
                "Fetched {} `{network}` hosts ({} active, {} pending).",
                hosts.len(),
                hosts.len().saturating_sub(pending_count),
                pending_count
            ));
            ui::success(&format!(
                "Synced {} `{network}` hosts from the local aegis-agent.",
                hosts.len(),
            ));
        }
    }
    Ok(hosts)
}

fn refresh_host_inventory(
    api_base_override: Option<&str>,
    network: &str,
) -> Result<HostCacheRefresh> {
    if !crate::api::uses_local_agent(api_base_override)? {
        return Ok(HostCacheRefresh {
            hosts: refresh_host_cache_from_api(api_base_override, network)?,
            warning: None,
            source: HostCacheRefreshSource::DirectApi,
        });
    }
    match local_agent::refresh_host_cache_for_network(network) {
        Ok(refreshed) => Ok(HostCacheRefresh {
            hosts: refreshed.hosts,
            warning: refreshed.warning,
            source: HostCacheRefreshSource::LocalAgent,
        }),
        Err(agent_error) => match refresh_host_cache_from_api(api_base_override, network) {
            Ok(hosts) => Ok(HostCacheRefresh {
                hosts,
                warning: Some(format!(
                    "local aegis-agent refresh failed; fetched fresh inventory directly from the API but did not update the shared agent cache: {agent_error}"
                )),
                source: HostCacheRefreshSource::DirectApi,
            }),
            Err(api_error) => Err(api_error).with_context(|| {
                format!(
                    "local aegis-agent refresh failed before direct API fallback: {agent_error}"
                )
            }),
        },
    }
}

fn refresh_host_cache_from_api(
    api_base_override: Option<&str>,
    network: &str,
) -> Result<Vec<CachedHost>> {
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    let networks = api.get_networks()?.networks;
    if !networks.contains_key(network) {
        bail!("unknown aegis network `{network}`");
    }
    super::cached_network_members_from_response(api.get_hosts()?, api.get_network_members(network)?)
}

pub(super) fn run(api_base_override: Option<&str>, args: &ListArgs) -> Result<i32> {
    Command {
        api_base_override,
        args,
    }
    .run()
}

struct Command<'a> {
    api_base_override: Option<&'a str>,
    args: &'a ListArgs,
}

struct ProgressRowsUpdate<'a> {
    list: &'a progress_list::HostProgressList,
    tx: &'a mpsc::Sender<ListEvent>,
    rows: &'a mut HashMap<HostId, ui::LiveRow>,
    row_states: &'a mut HashMap<HostId, ProgressHostRowState>,
    layout: &'a mut host_list::HostListLayout,
    hosts: Vec<CachedHost>,
    pending_probes: &'a mut usize,
    cached_fallback: bool,
}

fn listed_hosts_with_reachability(hosts: &[CachedHost]) -> Vec<host_list::ListedHost> {
    let reachability = reachability_by_host_id(hosts);
    hosts
        .iter()
        .map(|host| {
            let mut listed = host_list::listed_host(host);
            if let Some(state) = reachability.get(&host.host_id) {
                apply_reachability_to_listed_host(&mut listed, (*state).clone());
            }
            listed
        })
        .collect()
}

fn reachability_by_host_id(hosts: &[CachedHost]) -> BTreeMap<HostId, ProgressReachabilityState> {
    thread::scope(|scope| {
        let handles = hosts
            .iter()
            .cloned()
            .map(|host| {
                scope.spawn(move || {
                    let state = probe_ssh_reachability(&host)
                        .map(|probe| probe.state.into())
                        .unwrap_or(ProgressReachabilityState::Unreachable);
                    (host.host_id, state)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("reachability probe panicked"))
            .collect()
    })
}

fn probe_cached_hosts_with_progress(hosts: &[CachedHost], show_tunnel_status: bool) -> Result<()> {
    let list = progress_list::HostProgressList::new("Checking cached host reachability...");
    let mut layout = host_list::HostListLayout::default();
    for host in hosts {
        layout.include(&host_list::listed_host(host));
    }
    let (tx, rx) = mpsc::channel();
    let mut rows = HashMap::with_capacity(hosts.len());
    let mut row_states = HashMap::with_capacity(hosts.len());
    let mut pending_probes = 0usize;
    let started = Instant::now();
    for host in hosts {
        let host_id = host.host_id;
        let state = ProgressHostRowState::new(host.clone());
        let row = list.insert_aligned_host(&state.listed_host(), &layout);
        pending_probes += spawn_host_probe(tx.clone(), state.host.clone(), state.probe_generation);
        rows.insert(host_id, row);
        row_states.insert(host_id, state);
    }

    let cancellation = ui::current().cancellation();
    while pending_probes > 0 && !cancellation.is_requested() {
        match rx.recv_timeout(Duration::from_millis(90)) {
            Ok(ListEvent::ProbeReachability {
                host_id,
                generation,
                reachability,
            }) => {
                if let Some(state) = row_states.get_mut(&host_id)
                    && generation == state.probe_generation
                {
                    state.reachability = reachability.into();
                    if let Some(row) = rows.get(&host_id) {
                        list.update_aligned_host(row, &state.listed_host(), &layout);
                    }
                }
            }
            Ok(ListEvent::ProbeDone) => pending_probes = pending_probes.saturating_sub(1),
            Ok(ListEvent::RefreshOk(_) | ListEvent::RefreshErr(_)) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                for (host_id, state) in &mut row_states {
                    if state.tick()
                        && let Some(row) = rows.get(host_id)
                    {
                        list.update_aligned_host_silently(row, &state.listed_host(), &layout);
                    }
                }
                list.set_footer(format!(
                    "Checking cached host reachability ({} elapsed)",
                    host_list::elapsed_duration_text(started.elapsed())
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let host_ids = sorted_progress_host_ids(&row_states);
    for host_id in &host_ids {
        if let Some(row) = rows.get(host_id) {
            list.clear_host(row);
        }
    }
    render_then_complete(
        || {
            print_progress_listed_hosts(&row_states);
            if show_tunnel_status {
                print_local_tunnel_status();
            }
            std::io::stdout()
                .flush()
                .context("failed to flush the Aegis host list")
        },
        || {
            let outcome = if cancellation.is_requested() {
                ProgressFooterOutcome::Abandoned("Cached host reachability check interrupted")
            } else {
                ProgressFooterOutcome::Success("Checked cached host reachability")
            };
            outcome.complete(&list, started.elapsed());
        },
    )
}

impl Command<'_> {
    fn run(&self) -> Result<i32> {
        if !crate::api::uses_local_agent(self.api_base_override)? {
            let hosts = refresh_host_cache_for_network(self.api_base_override, &self.args.network)?;
            let visible = host::filter_visible_hosts(hosts, self.args.allow_pending);
            if ui::current().progress_is_enabled() {
                probe_cached_hosts_with_progress(&visible, false)?;
            } else {
                print_listed_hosts(&listed_hosts_with_reachability(&visible));
            }
            return Ok(0);
        }
        if !self.args.refresh {
            self.run_cached()
        } else if ui::current().progress_is_enabled() {
            self.run_with_progress()
        } else {
            self.run_without_progress()
        }
    }

    fn run_cached(&self) -> Result<i32> {
        warn_if_cache_stale()?;
        let cached = load_all_hosts_for_network(Path::new(SHARED_CACHE_PATH), &self.args.network)?;
        let visible_cached = host::filter_visible_hosts(cached.clone(), self.args.allow_pending);
        if visible_cached.is_empty() {
            if cached.iter().any(|host| host.pending) && !self.args.allow_pending {
                ui::detail(
                    "No active cached hosts. Re-run with `--allow-pending` to include pending entries.",
                );
            } else {
                ui::detail(
                    "No cached hosts yet. Run `aegis list --refresh` to sync host inventory.",
                );
            }
            self.print_local_tunnel_status();
        } else if ui::current().progress_is_enabled() {
            probe_cached_hosts_with_progress(
                &visible_cached,
                self.args.network == aegis_dto::DEFAULT_AEGIS_NETWORK,
            )?;
        } else {
            let rendered = listed_hosts_with_reachability(&visible_cached);
            print_listed_hosts(&rendered);
            self.print_local_tunnel_status();
        }
        ui::check_cancelled()?;
        Ok(0)
    }

    fn run_without_progress(&self) -> Result<i32> {
        let cached = load_all_hosts_for_network(Path::new(SHARED_CACHE_PATH), &self.args.network)?;
        match refresh_host_cache_for_network(self.api_base_override, &self.args.network) {
            Ok(refreshed) => {
                let visible_refreshed =
                    host::filter_visible_hosts(refreshed, self.args.allow_pending);
                if visible_refreshed.is_empty() {
                    if !self.args.allow_pending {
                        ui::detail(
                            "No active hosts are currently available. Re-run with `--allow-pending` to inspect pending entries.",
                        );
                    } else {
                        ui::detail("No hosts are currently available.");
                    }
                } else {
                    let rendered = listed_hosts_with_reachability(&visible_refreshed);
                    print_listed_hosts(&rendered);
                }
                self.print_local_tunnel_status();
                Ok(0)
            }
            Err(error) if !cached.is_empty() => {
                let visible_cached = host::filter_visible_hosts(cached, self.args.allow_pending);
                if visible_cached.is_empty() {
                    ui::detail(
                        "No active cached hosts. Re-run with `--allow-pending` to include pending entries.",
                    );
                } else {
                    let rendered = listed_hosts_with_reachability(&visible_cached);
                    print_listed_hosts(&rendered);
                }
                self.print_local_tunnel_status();
                ui::warn(&format!(
                    "refresh failed; showing cached hosts only: {error}"
                ));
                Ok(0)
            }
            Err(error) => Err(error),
        }
    }

    fn run_with_progress(&self) -> Result<i32> {
        let cached = load_all_hosts_for_network(Path::new(SHARED_CACHE_PATH), &self.args.network)?;
        let visible_cached = host::filter_visible_hosts(cached.clone(), self.args.allow_pending);
        let list = progress_list::HostProgressList::new("Refreshing host inventory...");
        let (tx, rx) = mpsc::channel();
        let mut rows = HashMap::with_capacity(visible_cached.len());
        let mut row_states = HashMap::with_capacity(visible_cached.len());
        let mut layout = host_list::HostListLayout::default();
        for cached_host in &visible_cached {
            layout.include(&host_list::listed_host(cached_host));
        }
        let refresh_tx = tx.clone();
        let api_base_override = self.api_base_override.map(str::to_string);
        let network = self.args.network.clone();
        thread::spawn(move || {
            match refresh_host_inventory(api_base_override.as_deref(), &network) {
                Ok(refreshed) => {
                    let _ = refresh_tx.send(ListEvent::RefreshOk(refreshed));
                }
                Err(error) => {
                    let _ = refresh_tx.send(ListEvent::RefreshErr(error.to_string()));
                }
            }
        });

        let mut pending_probes = 0usize;
        for cached_host in visible_cached {
            let host_id = cached_host.host_id;
            let state = ProgressHostRowState::new(cached_host);
            let row = list.insert_aligned_host(&state.listed_host(), &layout);
            pending_probes += spawn_host_probe(tx.clone(), state.host.clone(), 0);
            rows.insert(host_id, row);
            row_states.insert(host_id, state);
        }

        let mut refresh_done = false;
        let mut refresh_error = None;
        let mut refresh_warning = None;
        let started = Instant::now();
        let cancellation = ui::current().cancellation();
        while (!refresh_done || pending_probes > 0) && !cancellation.is_requested() {
            match rx.recv_timeout(Duration::from_millis(90)) {
                Ok(ListEvent::RefreshOk(refreshed)) => {
                    refresh_done = true;
                    let cached_fallback = refreshed.source == HostCacheRefreshSource::LocalAgent
                        && refreshed.warning.is_some();
                    if let Some(warning) = refreshed.warning {
                        refresh_warning = Some(warning);
                    }
                    let seen = self.update_progress_rows(ProgressRowsUpdate {
                        list: &list,
                        tx: &tx,
                        rows: &mut rows,
                        row_states: &mut row_states,
                        layout: &mut layout,
                        hosts: host::filter_visible_hosts(refreshed.hosts, self.args.allow_pending),
                        pending_probes: &mut pending_probes,
                        cached_fallback,
                    });
                    mark_missing_remote_hosts(&list, &rows, &mut row_states, &layout, &seen);
                    if pending_probes > 0 {
                        list.set_footer("Checking host reachability...");
                    }
                }
                Ok(ListEvent::RefreshErr(error)) => {
                    refresh_done = true;
                    refresh_error = Some(error);
                    for (host_id, state) in &mut row_states {
                        state.status_note = Some(host_list::HostListNote {
                            prefix: None,
                            text: "refresh failed; cached".to_string(),
                            color: Some(ui::Color::Yellow),
                        });
                        if let Some(row) = rows.get(host_id) {
                            list.update_aligned_host(row, &state.listed_host(), &layout);
                        }
                    }
                    if pending_probes > 0 {
                        list.set_footer("Checking cached host reachability...");
                    }
                }
                Ok(ListEvent::ProbeReachability {
                    host_id,
                    generation,
                    reachability,
                }) => {
                    if let Some(state) = row_states.get_mut(&host_id)
                        && generation == state.probe_generation
                    {
                        state.reachability = reachability.into();
                        if let Some(row) = rows.get(&host_id) {
                            list.update_aligned_host(row, &state.listed_host(), &layout);
                        }
                    }
                }
                Ok(ListEvent::ProbeDone) => {
                    pending_probes = pending_probes.saturating_sub(1);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    for (host_id, state) in &mut row_states {
                        if state.tick()
                            && let Some(row) = rows.get(host_id)
                        {
                            list.update_aligned_host_silently(row, &state.listed_host(), &layout);
                        }
                    }
                    list.set_footer(format!(
                        "Refreshing host inventory ({} elapsed)",
                        host_list::elapsed_duration_text(started.elapsed())
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        let host_ids = sorted_progress_host_ids(&row_states);
        for host_id in &host_ids {
            if let Some(row) = rows.get(host_id) {
                list.clear_host(row);
            }
        }
        if row_states.is_empty() {
            ui::detail(empty_hosts_message(
                cached.iter().any(|host| host.pending),
                self.args.allow_pending,
            ));
        }
        if let Some(warning) = refresh_warning.as_deref() {
            ui::warn(warning);
        }
        if let Some(error) = refresh_error.as_deref()
            && !cached.is_empty()
        {
            ui::warn(&format!(
                "refresh failed; showing cached hosts only: {error}"
            ));
        }
        let interrupted = cancellation.is_requested();
        render_then_complete(
            || {
                if !row_states.is_empty() {
                    print_progress_listed_hosts(&row_states);
                }
                self.print_local_tunnel_status();
                std::io::stdout()
                    .flush()
                    .context("failed to flush the Aegis host list")?;
                Ok(())
            },
            || {
                let outcome = if interrupted {
                    ProgressFooterOutcome::Abandoned("Host inventory refresh interrupted")
                } else if refresh_error.is_some() {
                    ProgressFooterOutcome::Abandoned(
                        "Host inventory refresh failed; retained cached results",
                    )
                } else {
                    ProgressFooterOutcome::Success(
                        "Host inventory and reachability checks completed",
                    )
                };
                outcome.complete(&list, started.elapsed());
            },
        )?;

        ui::check_cancelled()?;

        if let Some(error) = refresh_error {
            if !cached.is_empty() {
                Ok(0)
            } else {
                Err(anyhow!(error))
            }
        } else {
            Ok(0)
        }
    }

    fn print_local_tunnel_status(&self) {
        if self.args.network == aegis_dto::DEFAULT_AEGIS_NETWORK {
            print_local_tunnel_status();
        }
    }

    fn update_progress_rows(&self, update: ProgressRowsUpdate<'_>) -> HashSet<HostId> {
        let seen = update
            .hosts
            .iter()
            .map(|host| host.host_id)
            .collect::<HashSet<_>>();
        for refreshed_host in update.hosts {
            let host_id = refreshed_host.host_id;
            if let Some(state) = update.row_states.get_mut(&host_id) {
                let reprobe = state.refresh_host(refreshed_host);
                if update.cached_fallback {
                    state.mark_cached();
                }
                if reprobe {
                    *update.pending_probes += spawn_host_probe(
                        update.tx.clone(),
                        state.host.clone(),
                        state.probe_generation,
                    );
                }
                if let Some(row) = update.rows.get(&host_id) {
                    update
                        .list
                        .update_aligned_host(row, &state.listed_host(), update.layout);
                }
            } else {
                let mut state = ProgressHostRowState::new(refreshed_host);
                if update.cached_fallback {
                    state.mark_cached();
                }
                update.layout.include(&state.listed_host());
                let row = update
                    .list
                    .insert_aligned_host(&state.listed_host(), update.layout);
                *update.pending_probes += spawn_host_probe(
                    update.tx.clone(),
                    state.host.clone(),
                    state.probe_generation,
                );
                update.rows.insert(host_id, row);
                update.row_states.insert(host_id, state);
            }
        }
        *update.layout = progress_host_list_layout(update.row_states);
        update_all_progress_rows(update.list, update.rows, update.row_states, update.layout);
        seen
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgressReachabilityState {
    Connecting(usize),
    NoSsh,
    Available,
    Ipv4Unreachable,
    Ipv6Unreachable,
    Unreachable,
}

impl From<ReachabilityState> for ProgressReachabilityState {
    fn from(state: ReachabilityState) -> Self {
        match state {
            ReachabilityState::NoSsh => Self::NoSsh,
            ReachabilityState::Available => Self::Available,
            ReachabilityState::Ipv4Unreachable => Self::Ipv4Unreachable,
            ReachabilityState::Ipv6Unreachable => Self::Ipv6Unreachable,
            ReachabilityState::Unreachable => Self::Unreachable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostProbeKey {
    ipv4: Option<String>,
    ipv6: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Clone)]
struct ProgressHostRowState {
    host: CachedHost,
    probe_key: HostProbeKey,
    probe_generation: u64,
    reachability: ProgressReachabilityState,
    status_note: Option<host_list::HostListNote>,
    text_effect: ui::TextEffect,
}

impl ProgressHostRowState {
    fn new(host: CachedHost) -> Self {
        Self {
            probe_key: host_probe_key(&host),
            reachability: initial_reachability(&host),
            host,
            probe_generation: 0,
            status_note: None,
            text_effect: ui::TextEffect::None,
        }
    }

    fn listed_host(&self) -> host_list::ListedHost {
        let mut listed = host_list::listed_host(&self.host);
        listed.status_note = self.status_note.clone();
        apply_reachability_to_listed_host(&mut listed, self.reachability.clone());
        listed.text_effect = self.text_effect;
        listed
    }

    fn refresh_host(&mut self, host: CachedHost) -> bool {
        let probe_key = host_probe_key(&host);
        let reprobe = self.probe_key != probe_key;
        self.host = host;
        self.status_note = None;
        self.text_effect = ui::TextEffect::None;
        if reprobe {
            self.probe_key = probe_key;
            self.probe_generation = self.probe_generation.wrapping_add(1);
            self.reachability = initial_reachability(&self.host);
        }
        reprobe
    }

    fn mark_cached(&mut self) {
        self.status_note = Some(host_list::HostListNote {
            prefix: None,
            text: "cached".to_string(),
            color: Some(ui::Color::Yellow),
        });
    }

    fn tick(&mut self) -> bool {
        if let ProgressReachabilityState::Connecting(frame) = &mut self.reachability {
            *frame = frame.wrapping_add(1);
            true
        } else {
            false
        }
    }
}

fn apply_reachability_to_listed_host(
    listed: &mut host_list::ListedHost,
    reachability: ProgressReachabilityState,
) {
    listed.availability_note = Some(reachability_note(&reachability));
    if reachability == ProgressReachabilityState::Unreachable {
        listed.host_label_color = Some(ui::Color::Red);
        listed.host_label_effect = ui::TextEffect::Strikethrough;
    }
    listed.marker_warning |= matches!(
        reachability,
        ProgressReachabilityState::Ipv4Unreachable
            | ProgressReachabilityState::Ipv6Unreachable
            | ProgressReachabilityState::Unreachable
    );
}

fn reachability_note(reachability: &ProgressReachabilityState) -> host_list::HostListNote {
    match reachability {
        ProgressReachabilityState::Connecting(frame) => host_list::HostListNote {
            prefix: Some((
                progress_list::CONTACT_TICKS[frame % progress_list::CONTACT_TICKS.len()]
                    .to_string(),
                Some(ui::Color::Blue),
            )),
            text: "connecting...".to_string(),
            color: Some(ui::Color::Yellow),
        },
        ProgressReachabilityState::NoSsh => host_list::HostListNote {
            prefix: None,
            text: "no ssh".to_string(),
            color: Some(ui::Color::Yellow),
        },
        ProgressReachabilityState::Available => host_list::HostListNote {
            prefix: None,
            text: "available".to_string(),
            color: Some(ui::Color::Green),
        },
        ProgressReachabilityState::Ipv4Unreachable => host_list::HostListNote {
            prefix: None,
            text: "ipv4-unreachable".to_string(),
            color: Some(ui::Color::Red),
        },
        ProgressReachabilityState::Ipv6Unreachable => host_list::HostListNote {
            prefix: None,
            text: "ipv6-unreachable".to_string(),
            color: Some(ui::Color::Red),
        },
        ProgressReachabilityState::Unreachable => host_list::HostListNote {
            prefix: None,
            text: "unreachable".to_string(),
            color: Some(ui::Color::Red),
        },
    }
}

enum ListEvent {
    RefreshOk(HostCacheRefresh),
    RefreshErr(String),
    ProbeReachability {
        host_id: HostId,
        generation: u64,
        reachability: ReachabilityState,
    },
    ProbeDone,
}

fn initial_reachability(host: &CachedHost) -> ProgressReachabilityState {
    if host::host_registration_ssh_port(host).is_some() {
        ProgressReachabilityState::Connecting(0)
    } else {
        ProgressReachabilityState::NoSsh
    }
}

fn host_probe_key(host: &CachedHost) -> HostProbeKey {
    HostProbeKey {
        ipv4: host::mesh_ipv4_connect_host(host),
        ipv6: host::mesh_ipv6_connect_host(host),
        port: host::host_registration_ssh_port(host),
    }
}

fn spawn_host_probe(tx: mpsc::Sender<ListEvent>, host: CachedHost, generation: u64) -> usize {
    if host::host_registration_ssh_port(&host).is_none() {
        return 0;
    }
    let host_id = host.host_id;
    thread::spawn(move || {
        let reachability = probe_ssh_reachability(&host).unwrap_or(ReachabilityProbe {
            state: ReachabilityState::Unreachable,
            connect_host: None,
        });
        let _ = tx.send(ListEvent::ProbeReachability {
            host_id,
            generation,
            reachability: reachability.state,
        });
        let _ = tx.send(ListEvent::ProbeDone);
    });
    1
}

fn mark_missing_remote_hosts(
    list: &progress_list::HostProgressList,
    rows: &HashMap<HostId, ui::LiveRow>,
    row_states: &mut HashMap<HostId, ProgressHostRowState>,
    layout: &host_list::HostListLayout,
    refreshed_host_ids: &HashSet<HostId>,
) {
    for (host_id, state) in row_states {
        if refreshed_host_ids.contains(host_id) {
            continue;
        }
        state.status_note = Some(host_list::HostListNote {
            prefix: None,
            text: "missing remotely".to_string(),
            color: Some(ui::Color::Red),
        });
        state.text_effect = ui::TextEffect::Strikethrough;
        if let Some(row) = rows.get(host_id) {
            list.update_aligned_host(row, &state.listed_host(), layout);
        }
    }
}

fn progress_host_list_layout(
    row_states: &HashMap<HostId, ProgressHostRowState>,
) -> host_list::HostListLayout {
    let mut layout = host_list::HostListLayout::default();
    for state in row_states.values() {
        layout.include(&state.listed_host());
    }
    layout
}

fn update_all_progress_rows(
    list: &progress_list::HostProgressList,
    rows: &HashMap<HostId, ui::LiveRow>,
    row_states: &HashMap<HostId, ProgressHostRowState>,
    layout: &host_list::HostListLayout,
) {
    for (host_id, state) in row_states {
        if let Some(row) = rows.get(host_id) {
            list.update_aligned_host(row, &state.listed_host(), layout);
        }
    }
}

fn print_progress_listed_hosts(row_states: &HashMap<HostId, ProgressHostRowState>) {
    let hosts = sorted_progress_host_ids(row_states)
        .into_iter()
        .filter_map(|host_id| {
            row_states
                .get(&host_id)
                .map(ProgressHostRowState::listed_host)
        })
        .collect::<Vec<_>>();
    print_listed_hosts(&hosts);
}

fn sorted_progress_host_ids(row_states: &HashMap<HostId, ProgressHostRowState>) -> Vec<HostId> {
    let mut hosts = row_states
        .values()
        .map(|state| state.host.clone())
        .collect::<Vec<_>>();
    host::sort_hosts_for_list(&mut hosts);
    hosts.into_iter().map(|host| host.host_id).collect()
}

fn empty_hosts_message(cached_had_pending_hosts: bool, allow_pending: bool) -> &'static str {
    if cached_had_pending_hosts && !allow_pending {
        "No active hosts are currently available. Re-run with `--allow-pending` to inspect pending entries."
    } else {
        "No hosts are currently available."
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReachabilityState {
    NoSsh,
    Available,
    Ipv4Unreachable,
    Ipv6Unreachable,
    Unreachable,
}

impl ReachabilityState {
    pub(super) fn note(self) -> host_list::HostListNote {
        reachability_note(&self.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReachabilityProbe {
    pub(super) state: ReachabilityState,
    pub(super) connect_host: Option<String>,
}

pub(super) fn probe_ssh_reachability(host: &CachedHost) -> Result<ReachabilityProbe> {
    SshReachabilityTarget::from_host(host).probe()
}

pub(super) struct SshReachabilityTarget {
    pub(super) ipv4: Option<String>,
    pub(super) ipv6: Option<String>,
    pub(super) port: Option<u16>,
}

impl SshReachabilityTarget {
    pub(super) fn from_host(host: &CachedHost) -> Self {
        Self {
            ipv4: host::mesh_ipv4_connect_host(host),
            ipv6: host::mesh_ipv6_connect_host(host),
            port: host::host_registration_ssh_port(host),
        }
    }

    pub(super) fn probe(self) -> Result<ReachabilityProbe> {
        let Some(port) = self.port else {
            return Ok(ReachabilityProbe {
                state: ReachabilityState::NoSsh,
                connect_host: None,
            });
        };
        let ipv4 = self.ipv4;
        let ipv6 = self.ipv6;
        if ipv4.is_none() && ipv6.is_none() {
            bail!("host has no mesh ssh endpoint");
        }
        let (ipv4_ok, ipv6_ok) = thread::scope(|scope| {
            let ipv4_handle = ipv4
                .as_ref()
                .map(|address| scope.spawn(move || probe_ssh_endpoint(address, port)));
            let ipv6_handle = ipv6
                .as_ref()
                .map(|address| scope.spawn(move || probe_ssh_endpoint(address, port)));
            (
                ipv4_handle
                    .map(|handle| handle.join().expect("ipv4 reachability probe panicked"))
                    .transpose(),
                ipv6_handle
                    .map(|handle| handle.join().expect("ipv6 reachability probe panicked"))
                    .transpose(),
            )
        });
        let ipv4_ok = ipv4_ok?;
        let ipv6_ok = ipv6_ok?;
        Ok(match (ipv4_ok, ipv6_ok) {
            (Some(true), Some(true)) => ReachabilityProbe {
                state: ReachabilityState::Available,
                connect_host: ipv4,
            },
            (Some(true), Some(false)) => ReachabilityProbe {
                state: ReachabilityState::Ipv6Unreachable,
                connect_host: ipv4,
            },
            (Some(false), Some(true)) => ReachabilityProbe {
                state: ReachabilityState::Ipv4Unreachable,
                connect_host: ipv6,
            },
            (Some(false), Some(false)) => ReachabilityProbe {
                state: ReachabilityState::Unreachable,
                connect_host: None,
            },
            (Some(true), None) => ReachabilityProbe {
                state: ReachabilityState::Available,
                connect_host: ipv4,
            },
            (Some(false), None) => ReachabilityProbe {
                state: ReachabilityState::Unreachable,
                connect_host: None,
            },
            (None, Some(true)) => ReachabilityProbe {
                state: ReachabilityState::Available,
                connect_host: ipv6,
            },
            (None, Some(false)) => ReachabilityProbe {
                state: ReachabilityState::Unreachable,
                connect_host: None,
            },
            (None, None) => unreachable!("checked for at least one mesh ssh endpoint"),
        })
    }
}

fn probe_ssh_endpoint(connect_host: &str, port: u16) -> Result<bool> {
    let address = SocketAddr::new(
        connect_host
            .parse::<IpAddr>()
            .with_context(|| format!("invalid mesh SSH address `{connect_host}`"))?,
        port,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let Ok(mut stream) =
        TcpStream::connect_timeout(&address, deadline.saturating_duration_since(Instant::now()))
    else {
        return Ok(false);
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(false);
    }
    stream
        .set_read_timeout(Some(remaining))
        .context("failed to configure ssh reachability timeout")?;
    let mut prefix = [0u8; 4];
    // Read the complete prefix, including when TCP splits it into packets.
    for byte in &mut prefix {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        stream.set_read_timeout(Some(remaining))?;
        if stream.read_exact(std::slice::from_mut(byte)).is_err() {
            return Ok(false);
        }
    }
    Ok(&prefix == b"SSH-")
}

pub(super) fn probe_agent_version_with_prepared_detail(
    prepared: &PreparedConnect,
    target: &semver::Version,
) -> agent_version::ProbeResult {
    let mut command = prepared.timed_ssh_command(
        &[
            "-n".to_string(),
            "-o".to_string(),
            "ConnectTimeout=5".to_string(),
        ],
        Some(&remote_agent_version_probe_command()),
        None,
        false,
        Duration::from_secs(20),
    );
    match run_capture(&mut command) {
        Ok(output) if output.status.success() => agent_version::from_json(&output.stdout, target),
        Ok(output) => agent_version::ProbeResult::unknown(format!(
            "ssh agent version probe failed: {}",
            command_output_full_failure_detail(&output)
        )),
        Err(error) => agent_version::ProbeResult::unknown(format!(
            "ssh agent version probe failed: {}",
            full_error(&error)
        )),
    }
}

pub(super) fn remote_agent_version_probe_command() -> String {
    format!(
        "curl -fsS --max-time 5 --unix-socket {} {}",
        sh_quote(AEGIS_AGENT_SOCKET_PATH),
        sh_quote(&format!("http://aegis.local{AEGIS_AGENT_VERSION_PATH}"))
    )
}

fn warn_if_cache_stale() -> Result<()> {
    let Some(age) = cache_age(Path::new(SHARED_CACHE_PATH))? else {
        return Ok(());
    };
    if age <= STALE_CACHE_WARNING_AGE {
        return Ok(());
    }
    if let Ok(client) = local_agent::http_client(Duration::from_secs(2))
        && let Ok(Some(status)) = local_agent::status(&client)
    {
        if let Some(warning) = status.last_reconcile_warning.as_deref() {
            ui::warn(&format!(
                "local aegis-agent is using cached host inventory (cache {} old): {warning}",
                cache_age_text(age)
            ));
            return Ok(());
        }
        if let Some(error) = status
            .last_reconcile_error
            .as_deref()
            .or(status.babel.last_error.as_deref())
        {
            ui::warn(&format!(
                "local aegis-agent has not refreshed host inventory (cache {} old): {error}",
                cache_age_text(age)
            ));
            return Ok(());
        }
        if let Some(last_reconcile_unix) = status.last_reconcile_unix {
            let now_unix = crate::config::now_unix().max(0) as u64;
            let agent_age = Duration::from_secs(now_unix.saturating_sub(last_reconcile_unix));
            if agent_age <= RECENT_AGENT_RECONCILE_AGE {
                ui::warn(&format!(
                    "cached host inventory file is {} old even though the local aegis-agent reconciled {} ago; check {} permissions",
                    cache_age_text(age),
                    cache_age_text(agent_age),
                    SHARED_CACHE_PATH
                ));
                return Ok(());
            }
            ui::warn(&format!(
                "cached host inventory is stale ({} old); local aegis-agent last reconciled {} ago",
                cache_age_text(age),
                cache_age_text(agent_age)
            ));
            return Ok(());
        }
        ui::warn(&format!(
            "cached host inventory is stale ({} old); local aegis-agent has not completed its first reconcile",
            cache_age_text(age)
        ));
        return Ok(());
    }
    Ok(())
}

fn cache_age(path: &Path) -> Result<Option<Duration>> {
    if !path.exists() {
        return Ok(None);
    }
    let modified = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .modified()
        .with_context(|| format!("failed to read modification time for {}", path.display()))?;
    Ok(SystemTime::now().duration_since(modified).ok())
}

fn cache_age_text(age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 120 {
        format!("{seconds}s")
    } else if seconds < 7200 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / 3600)
    }
}

fn print_listed_hosts(hosts: &[host_list::ListedHost]) {
    print_listed_hosts_to(hosts, &ui::stdout_render_target(), |rendered| {
        println!("{rendered}");
    });
}

fn print_listed_hosts_to(
    hosts: &[host_list::ListedHost],
    target: &impl host_list::RenderTarget,
    mut print: impl FnMut(String),
) {
    let mut layout = host_list::HostListLayout::default();
    for host in hosts {
        layout.include(host);
    }
    for host in hosts {
        print(host_list::render_aligned_listed_host(host, target, &layout));
    }
}

fn render_then_complete(
    render: impl FnOnce() -> Result<()>,
    complete: impl FnOnce(),
) -> Result<()> {
    render_then_complete_with(render, ui::suspend, complete)
}

fn render_then_complete_with<R, S>(render: R, suspend: S, complete: impl FnOnce()) -> Result<()>
where
    R: FnOnce() -> Result<()>,
    S: FnOnce(R) -> Result<()>,
{
    suspend(render)?;
    complete();
    Ok(())
}

fn print_local_tunnel_status() {
    let Ok(client) = local_agent::http_client(LOCAL_TUNNEL_STATUS_TIMEOUT) else {
        return;
    };
    let Ok(Some(status)) = local_agent::status(&client) else {
        return;
    };
    if let Some(line) = tunnel_status_line(&status.tunnel) {
        println!("{line}");
    }
}

fn tunnel_status_line(status: &AgentTunnelStatus) -> Option<String> {
    match status {
        AgentTunnelStatus::Unknown
        | AgentTunnelStatus::Disabled
        | AgentTunnelStatus::Unsupported => None,
        AgentTunnelStatus::Enabled { via } => Some(format!("↳ tunnel · via {via}")),
        AgentTunnelStatus::Reconciling {
            active_via: None,
            desired_via: Some(desired),
        } => Some(format!("↳ tunnel · enabling via {desired}")),
        AgentTunnelStatus::Reconciling {
            active_via: Some(active),
            desired_via: Some(desired),
        } if active != desired => Some(format!("↳ tunnel · switching from {active} to {desired}")),
        AgentTunnelStatus::Reconciling {
            active_via: Some(active),
            desired_via: Some(_),
        } => Some(format!("↳ tunnel · via {active} · reconciling")),
        AgentTunnelStatus::Reconciling {
            active_via: Some(active),
            desired_via: None,
        } => Some(format!("↳ tunnel · disabling · currently via {active}")),
        AgentTunnelStatus::Reconciling {
            active_via: None,
            desired_via: None,
        } => Some("↳ tunnel · disabling · reconciling".to_string()),
    }
}

#[cfg(test)]
mod reachability_tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn fragmented_ssh_banner_is_available() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"SSH-" {
                stream.write_all(&[*byte]).unwrap();
                thread::sleep(Duration::from_millis(5));
            }
        });
        let result = SshReachabilityTarget {
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            port: Some(port),
        }
        .probe()
        .unwrap();
        assert_eq!(result.state, ReachabilityState::Available);
        assert_eq!(result.connect_host.as_deref(), Some("127.0.0.1"));
        server.join().unwrap();
    }

    #[test]
    fn a_tcp_service_without_an_ssh_banner_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"HTTP").unwrap();
        });
        let result = SshReachabilityTarget {
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            port: Some(port),
        }
        .probe()
        .unwrap();
        assert_eq!(result.state, ReachabilityState::Unreachable);
        assert_eq!(result.connect_host, None);
        server.join().unwrap();
    }
}

#[cfg(test)]
mod tunnel_status_tests {
    use std::cell::RefCell;

    use super::{AgentTunnelStatus, render_then_complete_with, tunnel_status_line};

    #[test]
    fn final_list_payload_is_suspended_before_progress_completion() {
        let events = RefCell::new(Vec::new());
        render_then_complete_with(
            || {
                events.borrow_mut().push("host rows");
                events.borrow_mut().push("tunnel row");
                Ok(())
            },
            |render| {
                events.borrow_mut().push("suspend start");
                render()?;
                events.borrow_mut().push("suspend end");
                Ok(())
            },
            || events.borrow_mut().push("completion"),
        )
        .expect("list rendering succeeds");
        assert_eq!(
            vec![
                "suspend start",
                "host rows",
                "tunnel row",
                "suspend end",
                "completion"
            ],
            events.into_inner()
        );
    }

    #[test]
    fn enabled_tunnel_is_a_separate_list_line() {
        assert_eq!(
            Some("↳ tunnel · via hub-a".to_string()),
            tunnel_status_line(&AgentTunnelStatus::Enabled {
                via: "hub-a".to_string(),
            })
        );
        assert_eq!(None, tunnel_status_line(&AgentTunnelStatus::Disabled));
        assert_eq!(None, tunnel_status_line(&AgentTunnelStatus::Unknown));
    }

    #[test]
    fn reconciling_tunnel_describes_the_active_transition() {
        assert_eq!(
            Some("↳ tunnel · enabling via hub-a".to_string()),
            tunnel_status_line(&AgentTunnelStatus::Reconciling {
                active_via: None,
                desired_via: Some("hub-a".to_string()),
            })
        );
        assert_eq!(
            Some("↳ tunnel · switching from hub-a to hub-b".to_string()),
            tunnel_status_line(&AgentTunnelStatus::Reconciling {
                active_via: Some("hub-a".to_string()),
                desired_via: Some("hub-b".to_string()),
            })
        );
        assert_eq!(
            Some("↳ tunnel · disabling · currently via hub-a".to_string()),
            tunnel_status_line(&AgentTunnelStatus::Reconciling {
                active_via: Some("hub-a".to_string()),
                desired_via: None,
            })
        );
    }
}
