use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aegis_dto::{DEFAULT_AEGIS_NETWORK, HostId};
use anyhow::{Context, Result, bail};

use crate::api::AuthenticatedApiClient;
use crate::cli::{FleetArgs, FleetCommands, FleetRedeployArgs};
use crate::config::CachedHost;
use crate::redeploy_version::{RedeployTarget, RedeployVersion};
use crate::ui;

use super::redeploy_job::{RedeployJob, RedeployJobState};
use super::{
    FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT, agent_version, command_output_full_failure_detail,
    compact_line,
    connect::{AssetPreparer, PreparedConnect},
    full_error, host, host_list, list, local_agent, local_state, maintenance,
    probe_local_agent_version_detail, progress_list,
};

pub(super) const FLEET_REDEPLOY_NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub(super) const FLEET_REDEPLOY_HARD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
pub(super) const FLEET_REDEPLOY_REMOTE_SSH_ASSET_REFRESH_INTERVAL: Duration =
    Duration::from_secs(30);
const FLEET_REDEPLOY_JOB_PROBE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    NoSsh,
    ProbingSsh,
    PreparingSsh,
    SchedulingLocal,
    Installing,
    WaitingForAgent,
    Current,
    Redeployed,
    Unreachable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Status {
    Queued,
    NoSsh,
    ProbingSsh(usize),
    PreparingSsh(usize),
    SchedulingLocal(usize),
    Installing(usize),
    WaitingForAgent {
        frame: usize,
        detail: Option<String>,
    },
    Current,
    Redeployed,
    Unreachable,
    Failed {
        detail: String,
    },
}

impl Status {
    fn phase(&self) -> Phase {
        match self {
            Self::Queued => Phase::Queued,
            Self::NoSsh => Phase::NoSsh,
            Self::ProbingSsh(_) => Phase::ProbingSsh,
            Self::PreparingSsh(_) => Phase::PreparingSsh,
            Self::SchedulingLocal(_) => Phase::SchedulingLocal,
            Self::Installing(_) => Phase::Installing,
            Self::WaitingForAgent { .. } => Phase::WaitingForAgent,
            Self::Current => Phase::Current,
            Self::Redeployed => Phase::Redeployed,
            Self::Unreachable => Phase::Unreachable,
            Self::Failed { .. } => Phase::Failed,
        }
    }

    fn tick(&mut self) -> bool {
        match self {
            Self::ProbingSsh(frame)
            | Self::PreparingSsh(frame)
            | Self::SchedulingLocal(frame)
            | Self::Installing(frame) => {
                *frame = frame.wrapping_add(1);
                true
            }
            Self::WaitingForAgent { frame, .. } => {
                *frame = frame.wrapping_add(1);
                true
            }
            Self::Queued
            | Self::NoSsh
            | Self::Redeployed
            | Self::Unreachable
            | Self::Failed { .. } => false,
            Self::Current => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct RowState {
    pub(super) host: CachedHost,
    target_version: RedeployVersion,
    status: Status,
    status_since: Instant,
    version: agent_version::State,
}

impl RowState {
    pub(super) fn new(
        host: CachedHost,
        target_version: RedeployVersion,
        locally_reachable: bool,
    ) -> Self {
        Self {
            status: if host::host_offers_ssh(&host) || locally_reachable {
                Status::Queued
            } else {
                Status::NoSsh
            },
            status_since: Instant::now(),
            host,
            target_version,
            version: agent_version::State::Unknown,
        }
    }

    pub(super) fn set_status(&mut self, status: Status) -> bool {
        let changed = self.status.phase() != status.phase();
        if changed {
            self.status_since = Instant::now();
        }
        self.status = status;
        changed
    }

    fn tick(&mut self) -> bool {
        self.status.tick()
    }

    fn status_elapsed_text(&self) -> String {
        host_list::elapsed_duration_text(self.status_since.elapsed())
    }

    fn active_note(&self, frame: usize, text: String, color: ui::Color) -> host_list::HostListNote {
        host_list::HostListNote {
            prefix: Some((
                progress_list::CONTACT_TICKS[frame % progress_list::CONTACT_TICKS.len()]
                    .to_string(),
                Some(ui::Color::Blue),
            )),
            text,
            color: Some(color),
        }
    }

    pub(super) fn status_text(&self) -> String {
        match &self.status {
            Status::Queued => "queued".to_string(),
            Status::NoSsh => "no ssh".to_string(),
            Status::ProbingSsh(_) => {
                format!("probing ssh ({})", self.status_elapsed_text())
            }
            Status::PreparingSsh(_) => {
                format!("preparing ssh cert ({})", self.status_elapsed_text())
            }
            Status::SchedulingLocal(_) => {
                format!("scheduling local redeploy ({})", self.status_elapsed_text())
            }
            Status::Installing(_) => {
                format!(
                    "installing aegis-tool v{} ({})",
                    self.target_version,
                    self.status_elapsed_text()
                )
            }
            Status::WaitingForAgent { detail, .. } => {
                let mut text = format!(
                    "waiting for agent v{} ({})",
                    self.target_version,
                    self.status_elapsed_text()
                );
                if let Some(detail) = detail
                    .as_deref()
                    .map(str::trim)
                    .filter(|detail| !detail.is_empty())
                {
                    text.push_str("; ");
                    text.push_str(&compact_line(detail));
                }
                text
            }
            Status::Current => "already current".to_string(),
            Status::Redeployed => "redeployed".to_string(),
            Status::Unreachable => "unreachable".to_string(),
            Status::Failed { detail } => format!("failed: {}", compact_line(detail)),
        }
    }

    fn listed_host(&self) -> host_list::ListedHost {
        let mut listed = host_list::listed_host(&self.host);
        match &self.status {
            Status::Queued => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "queued".to_string(),
                    color: Some(ui::Color::Yellow),
                });
            }
            Status::NoSsh => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "no ssh".to_string(),
                    color: Some(ui::Color::Yellow),
                });
            }
            Status::ProbingSsh(frame) => {
                listed.availability_note =
                    Some(self.active_note(*frame, self.status_text(), ui::Color::Yellow));
            }
            Status::PreparingSsh(frame)
            | Status::SchedulingLocal(frame)
            | Status::Installing(frame) => {
                listed.availability_note =
                    Some(self.active_note(*frame, self.status_text(), ui::Color::Blue));
            }
            Status::WaitingForAgent { frame, .. } => {
                listed.availability_note =
                    Some(self.active_note(*frame, self.status_text(), ui::Color::Blue));
            }
            Status::Current => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "current".to_string(),
                    color: Some(ui::Color::Green),
                });
            }
            Status::Redeployed => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "redeployed".to_string(),
                    color: Some(ui::Color::Green),
                });
            }
            Status::Unreachable => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "unreachable".to_string(),
                    color: Some(ui::Color::Red),
                });
                listed.marker_warning = true;
                listed.host_label_color = Some(ui::Color::Red);
                listed.host_label_effect = ui::TextEffect::Strikethrough;
            }
            Status::Failed { detail } => {
                listed.availability_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: "failed".to_string(),
                    color: Some(ui::Color::Red),
                });
                listed.status_note = Some(host_list::HostListNote {
                    prefix: None,
                    text: compact_line(detail),
                    color: Some(ui::Color::Red),
                });
                listed.marker_warning = true;
            }
        }
        listed.version_note = match &self.version {
            agent_version::State::Older(version) => Some(host_list::HostListNote {
                prefix: None,
                text: format!("old version v{version}"),
                color: Some(ui::Color::Yellow),
            }),
            _ => None,
        };
        listed
    }
}

enum Event {
    Status {
        host_id: HostId,
        status: Status,
    },
    Version {
        host_id: HostId,
        version: agent_version::State,
    },
    Done,
}

struct Progress {
    list: progress_list::HostProgressList,
    rows: HashMap<HostId, ui::LiveRow>,
    target_version: RedeployVersion,
    started_at: Instant,
}

impl Progress {
    fn new(total_hosts: usize, target_version: RedeployVersion) -> Self {
        let list = progress_list::HostProgressList::new(format!(
            "Preparing fleet redeploy to aegis-tool v{} for {total_hosts} hosts...",
            target_version
        ));
        let now = Instant::now();
        Self {
            list,
            rows: HashMap::with_capacity(total_hosts),
            target_version,
            started_at: now,
        }
    }

    fn insert_host(&mut self, state: &RowState) {
        let row = self.list.insert_host(&state.listed_host());
        self.rows.insert(state.host.host_id, row);
    }

    fn update_host(&mut self, state: &RowState, phase_changed: bool) {
        if let Some(row) = self.rows.get(&state.host.host_id) {
            if phase_changed {
                self.list.update_host(row, &state.listed_host());
            } else {
                self.list.update_host_silently(row, &state.listed_host());
            }
        }
    }

    fn update_footer(&mut self, states: &HashMap<HostId, RowState>) {
        let summary = summary(
            states,
            self.started_at.elapsed(),
            &self.target_version.to_string(),
        );
        self.list.set_footer(summary);
    }

    fn finish(self, states: &HashMap<HostId, RowState>, interrupted: bool) {
        let summary = summary(
            states,
            self.started_at.elapsed(),
            &self.target_version.to_string(),
        );
        for (host_id, row) in &self.rows {
            if let Some(state) = states.get(host_id) {
                match state.status.phase() {
                    Phase::Current | Phase::Redeployed => {
                        self.list.finish_host(row, &state.listed_host());
                    }
                    Phase::Failed => self.list.fail_host(row, &state.listed_host()),
                    Phase::Queued
                    | Phase::NoSsh
                    | Phase::ProbingSsh
                    | Phase::PreparingSsh
                    | Phase::SchedulingLocal
                    | Phase::Installing
                    | Phase::WaitingForAgent
                    | Phase::Unreachable => {
                        self.list.abandon_host(row, &state.listed_host());
                    }
                }
            }
        }
        if interrupted {
            self.list.abandon_footer(summary);
        } else if states
            .values()
            .any(|state| matches!(state.status, Status::Failed { .. }))
        {
            self.list.fail_footer(summary);
        } else {
            self.list.finish_footer(summary);
        }
        print_completion_details(states, interrupted);
    }
}

#[derive(Default)]
struct Counts {
    finished: usize,
    active: usize,
    queued: usize,
    no_ssh: usize,
    current: usize,
    redeployed: usize,
    unreachable: usize,
    failed: usize,
}

pub(super) fn summary(
    states: &HashMap<HostId, RowState>,
    elapsed: Duration,
    target_version: &str,
) -> String {
    let counts = counts(states);
    format!(
        concat!(
            "target v{} | {}/{} finished | {} active | {} queued | ",
            "{} current | {} redeployed | {} unreachable | {} failed | {} no ssh | elapsed {}"
        ),
        target_version,
        counts.finished,
        states.len(),
        counts.active,
        counts.queued,
        counts.current,
        counts.redeployed,
        counts.unreachable,
        counts.failed,
        counts.no_ssh,
        host_list::elapsed_duration_text(elapsed),
    )
}

pub(super) fn completion_details(
    states: &HashMap<HostId, RowState>,
    interrupted: bool,
) -> Vec<String> {
    let mut states = states.values().collect::<Vec<_>>();
    states.sort_by(|left, right| left.host.alias().cmp(right.host.alias()));
    states
        .into_iter()
        .filter_map(|state| match &state.status {
            Status::Failed { detail } => Some(format!("{}: {detail}", state.host.alias())),
            Status::WaitingForAgent {
                detail: Some(detail),
                ..
            } if interrupted => Some(format!(
                "{}: interrupted while {}; last probe: {detail}",
                state.host.alias(),
                state.status_text()
            )),
            status
                if interrupted
                    && matches!(
                        status.phase(),
                        Phase::Queued
                            | Phase::ProbingSsh
                            | Phase::PreparingSsh
                            | Phase::SchedulingLocal
                            | Phase::Installing
                            | Phase::WaitingForAgent
                    ) =>
            {
                Some(format!(
                    "{}: interrupted while {}",
                    state.host.alias(),
                    state.status_text()
                ))
            }
            _ => None,
        })
        .collect()
}

fn print_completion_details(states: &HashMap<HostId, RowState>, interrupted: bool) {
    let details = completion_details(states, interrupted);
    if details.is_empty() {
        return;
    }
    ui::warn(if interrupted {
        "Fleet redeploy interrupted; complete host details follow:"
    } else {
        "Fleet redeploy failure details:"
    });
    for detail in details {
        ui::detail(&detail.replace('\n', "\n    "));
    }
}

fn counts(states: &HashMap<HostId, RowState>) -> Counts {
    let mut counts = Counts::default();
    for state in states.values() {
        match state.status.phase() {
            Phase::Queued => counts.queued += 1,
            Phase::NoSsh => {
                counts.no_ssh += 1;
                counts.finished += 1;
            }
            Phase::ProbingSsh
            | Phase::PreparingSsh
            | Phase::SchedulingLocal
            | Phase::Installing
            | Phase::WaitingForAgent => counts.active += 1,
            Phase::Current => {
                counts.current += 1;
                counts.finished += 1;
            }
            Phase::Redeployed => {
                counts.redeployed += 1;
                counts.finished += 1;
            }
            Phase::Unreachable => {
                counts.unreachable += 1;
                counts.finished += 1;
            }
            Phase::Failed => {
                counts.failed += 1;
                counts.finished += 1;
            }
        }
    }
    counts
}

pub(super) fn run(api_base_override: Option<&str>, args: &FleetArgs) -> Result<i32> {
    match &args.command {
        FleetCommands::Redeploy(args) => match Run::load(api_base_override, args)? {
            Some(run) => run.execute(),
            None => Ok(0),
        },
    }
}

struct Run {
    auth: SharedAuth,
    target_version: RedeployVersion,
    network: String,
    login_principal: Option<String>,
    local_host_id: Option<HostId>,
    row_states: HashMap<HostId, RowState>,
    progress: Progress,
}

impl Run {
    fn load(api_base_override: Option<&str>, args: &FleetRedeployArgs) -> Result<Option<Self>> {
        let target = RedeployTarget::requested(args.version.as_deref())?;
        let auth = SharedAuth::new(api_base_override);
        let target_version = match target {
            RedeployTarget::Latest => {
                ui::detail("Resolving the latest published aegis-tool version...");
                let version = RedeployVersion::latest()?;
                ui::detail(&format!(
                    "Using latest published aegis-tool v{version} for the entire fleet."
                ));
                version
            }
            RedeployTarget::Exact(version) => version,
        };
        let hosts = host::filter_visible_hosts(
            list::refresh_host_cache_for_network(api_base_override, &args.network)?,
            false,
        );
        if hosts.is_empty() {
            ui::detail("No active hosts are currently available.");
            return Ok(None);
        }
        let uses_local_agent = crate::api::uses_local_agent(api_base_override)?;
        if uses_local_agent && args.network == DEFAULT_AEGIS_NETWORK {
            local_agent::MeshReadinessWait::new("Waiting for local mesh routing to settle...")
                .wait()?;
        }
        let local_host_id = if uses_local_agent {
            local_state::LocalHostIdentity::host_id_from_managed_state_or_cache()?
        } else {
            None
        };
        let mut progress = Progress::new(hosts.len(), target_version.clone());
        let mut row_states = HashMap::with_capacity(hosts.len());
        for host in hosts {
            let host_id = host.host_id;
            let state = RowState::new(host, target_version.clone(), local_host_id == Some(host_id));
            progress.insert_host(&state);
            row_states.insert(host_id, state);
        }
        progress.update_footer(&row_states);
        Ok(Some(Self {
            auth,
            target_version,
            network: args.network.clone(),
            login_principal: args.user.clone(),
            local_host_id,
            row_states,
            progress,
        }))
    }

    fn execute(mut self) -> Result<i32> {
        if self.row_states.is_empty() {
            return Ok(0);
        }
        let cancellation = ui::current().cancellation();
        let (tx, rx) = mpsc::channel();
        let mut pending = self.spawn_workers(tx);
        while pending > 0 && !cancellation.is_requested() {
            match rx.recv_timeout(Duration::from_millis(90)) {
                Ok(event) => {
                    if self.apply_event(event) {
                        pending = pending.saturating_sub(1);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => self.tick(),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let interrupted = cancellation.is_requested();
        let exit_code = self.exit_code();
        self.progress.finish(&self.row_states, interrupted);
        ui::check_cancelled()?;
        Ok(exit_code)
    }

    fn spawn_workers(&self, tx: mpsc::Sender<Event>) -> usize {
        self.row_states
            .values()
            .map(|state| {
                Worker {
                    tx: tx.clone(),
                    auth: self.auth.clone(),
                    target_version: self.target_version.clone(),
                    network: self.network.clone(),
                    login_principal: self.login_principal.clone(),
                    local_host_id: self.local_host_id,
                    host: state.host.clone(),
                }
                .spawn()
            })
            .sum()
    }

    fn apply_event(&mut self, event: Event) -> bool {
        match event {
            Event::Status { host_id, status } => {
                if let Some(state) = self.row_states.get_mut(&host_id) {
                    let phase_changed = state.set_status(status);
                    self.progress.update_host(state, phase_changed);
                    self.progress.update_footer(&self.row_states);
                }
                false
            }
            Event::Version { host_id, version } => {
                if let Some(state) = self.row_states.get_mut(&host_id) {
                    state.version = version;
                    self.progress.update_host(state, false);
                    self.progress.update_footer(&self.row_states);
                }
                false
            }
            Event::Done => {
                self.progress.update_footer(&self.row_states);
                true
            }
        }
    }

    fn tick(&mut self) {
        for state in self.row_states.values_mut() {
            if state.tick() {
                self.progress.update_host(state, false);
            }
        }
        self.progress.update_footer(&self.row_states);
    }

    fn exit_code(&self) -> i32 {
        i32::from(
            self.row_states
                .values()
                .any(|state| matches!(state.status, Status::Failed { .. })),
        )
    }
}

pub(super) fn agent_wait_timeout_message(
    target_version: &RedeployVersion,
    last_status_detail: Option<&str>,
) -> String {
    let mut message = format!("timed out waiting for v{target_version}");
    if let Some(detail) = last_status_detail
        .map(str::trim)
        .filter(|detail| !detail.is_empty())
    {
        message.push_str("; last status: ");
        message.push_str(detail);
    }
    message
}

struct Worker {
    tx: mpsc::Sender<Event>,
    auth: SharedAuth,
    target_version: RedeployVersion,
    network: String,
    login_principal: Option<String>,
    local_host_id: Option<HostId>,
    host: CachedHost,
}

impl Worker {
    fn spawn(self) -> usize {
        if !host::host_offers_ssh(&self.host) && self.local_host_id != Some(self.host.host_id) {
            return 0;
        }
        thread::spawn(move || self.run());
        1
    }

    fn run(self) {
        let reporter = Reporter::new(self.tx.clone(), self.host.host_id);
        if let Err(error) = self.execute(&reporter) {
            reporter.status(Status::Failed {
                detail: full_error(&error),
            });
        }
        reporter.done();
    }

    fn execute(&self, reporter: &Reporter) -> Result<()> {
        let Some(mut target) = self.prepare_target(reporter)? else {
            return Ok(());
        };
        let system_version = probe_system_version(&mut target, &self.target_version, reporter);
        match system_version {
            agent_version::State::Current => {
                if target.requires_user_update(&self.target_version) {
                    reporter.status(Status::Installing(0));
                    target.update_user(&self.target_version)?;
                }
                reporter.status(Status::Current);
                return Ok(());
            }
            agent_version::State::Newer(_) => {
                reporter.status(Status::Current);
                return Ok(());
            }
            agent_version::State::Unknown | agent_version::State::Older(_) => {}
        }
        let update_user = target.requires_user_update(&self.target_version);
        if update_user && matches!(&target, Target::Local) {
            reporter.status(Status::Installing(0));
            target.update_user(&self.target_version)?;
        }
        target.report_schedule_status(reporter);
        let job = target.schedule_redeploy(&self.target_version, update_user)?;
        reporter.status(waiting_for_agent_status(0, None));
        VersionWait::new().wait(self, &mut target, &job, reporter)
    }

    fn prepare_target(&self, reporter: &Reporter) -> Result<Option<Target>> {
        if self.local_host_id == Some(self.host.host_id) {
            reporter.status(Status::SchedulingLocal(0));
            return Ok(Some(Target::Local));
        }

        reporter.status(Status::ProbingSsh(0));
        let reachability = list::probe_ssh_reachability(&self.host)?;
        let Some(connect_host) = reachability.connect_host else {
            reporter.status(Status::Unreachable);
            return Ok(None);
        };

        reporter.status(Status::PreparingSsh(0));
        let mut api = self.auth.load_api()?;
        let prepared = AssetPreparer::new(
            &self.network,
            &self.host,
            connect_host.clone(),
            self.login_principal.clone(),
            false,
        )
        .prepare_quiet(&mut api)?;
        Ok(Some(Target::Remote(Box::new(RemoteTarget {
            connect_host,
            prepared,
        }))))
    }

    fn refresh_remote_target(&self, target: &mut RemoteTarget) -> Result<()> {
        let mut api = self.auth.load_api()?;
        target.prepared = AssetPreparer::new(
            &self.network,
            &self.host,
            target.connect_host.clone(),
            self.login_principal.clone(),
            false,
        )
        .prepare_quiet(&mut api)?;
        Ok(())
    }
}

#[derive(Clone)]
struct SharedAuth {
    api_base_override: Option<String>,
}

impl SharedAuth {
    fn new(api_base_override: Option<&str>) -> Self {
        Self {
            api_base_override: api_base_override.map(ToString::to_string),
        }
    }

    fn load_api(&self) -> Result<AuthenticatedApiClient> {
        AuthenticatedApiClient::load(self.api_base_override.as_deref())
    }
}

struct Reporter {
    tx: mpsc::Sender<Event>,
    host_id: HostId,
}

impl Reporter {
    fn new(tx: mpsc::Sender<Event>, host_id: HostId) -> Self {
        Self { tx, host_id }
    }

    fn status(&self, status: Status) {
        let _ = self.tx.send(Event::Status {
            host_id: self.host_id,
            status,
        });
    }

    fn version(&self, version: agent_version::State) {
        let _ = self.tx.send(Event::Version {
            host_id: self.host_id,
            version,
        });
    }

    fn done(&self) {
        let _ = self.tx.send(Event::Done);
    }
}

enum Target {
    Local,
    Remote(Box<RemoteTarget>),
}

struct RemoteTarget {
    connect_host: String,
    prepared: PreparedConnect,
}

impl Target {
    fn requires_user_update(&self, target_version: &RedeployVersion) -> bool {
        match self {
            Self::Local => !maintenance::user_program_is_current(target_version),
            Self::Remote(remote) => remote.prepared.ssh_user() != "root",
        }
    }

    fn update_user(&mut self, target_version: &RedeployVersion) -> Result<()> {
        match self {
            Self::Local => maintenance::ensure_user_program(target_version).map(|_| ()),
            Self::Remote(remote) => run_remote_user_update(&remote.prepared, target_version),
        }
    }

    fn report_schedule_status(&self, reporter: &Reporter) {
        match self {
            Self::Local => reporter.status(Status::SchedulingLocal(0)),
            Self::Remote(_) => reporter.status(Status::Installing(0)),
        }
    }

    fn schedule_redeploy(
        &mut self,
        target_version: &RedeployVersion,
        update_remote_user: bool,
    ) -> Result<RedeployJob> {
        let response = match self {
            Self::Local => local_agent::schedule_redeploy(&target_version.to_string())?,
            Self::Remote(remote) => {
                run_remote(&remote.prepared, target_version, update_remote_user)?
            }
        };
        if response.version != target_version.to_string() {
            bail!(
                "redeploy scheduled unexpected version {}; requested {}",
                response.version,
                target_version
            );
        }
        RedeployJob::new(response.unit, response.job)
    }

    fn probe_version(&mut self, target_version: &RedeployVersion) -> agent_version::ProbeResult {
        match self {
            Self::Local => probe_local_agent_version_detail(target_version.semver()),
            Self::Remote(remote) => list::probe_agent_version_with_prepared_detail(
                &remote.prepared,
                target_version.semver(),
            ),
        }
    }

    fn probe_job(&self, job: &RedeployJob) -> RedeployJobState {
        match self {
            Self::Local => job.probe_local(),
            Self::Remote(remote) => {
                let command = job.probe_command();
                let mut remote_command = remote.prepared.timed_ssh_command(
                    &[
                        "-n".to_string(),
                        "-o".to_string(),
                        "ConnectTimeout=5".to_string(),
                    ],
                    Some(&command),
                    None,
                    false,
                    Duration::from_secs(20),
                );
                job.state_from_remote_output(crate::command::run_capture(&mut remote_command))
            }
        }
    }
}

fn probe_system_version(
    target: &mut Target,
    target_version: &RedeployVersion,
    reporter: &Reporter,
) -> agent_version::State {
    let probe = target.probe_version(target_version);
    reporter.version(probe.state.clone());
    probe.state
}

struct VersionWait {
    deadline: Instant,
    hard_deadline: Instant,
    next_job_probe: Instant,
    next_remote_refresh: Instant,
    last_job_state: Option<RedeployJobState>,
    last_probe_detail: Option<String>,
}

impl VersionWait {
    fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn new_at(now: Instant) -> Self {
        Self {
            deadline: now + FLEET_REDEPLOY_NO_PROGRESS_TIMEOUT,
            hard_deadline: now + FLEET_REDEPLOY_HARD_TIMEOUT,
            next_job_probe: now,
            next_remote_refresh: now,
            last_job_state: None,
            last_probe_detail: None,
        }
    }

    fn wait(
        mut self,
        worker: &Worker,
        target: &mut Target,
        job: &RedeployJob,
        reporter: &Reporter,
    ) -> Result<()> {
        loop {
            let refresh_detail = self.refresh_remote_target_if_due(worker, target);
            if Instant::now() >= self.next_job_probe {
                let now = Instant::now();
                self.next_job_probe = now + FLEET_REDEPLOY_JOB_PROBE_INTERVAL;
                self.observe_job_state(now, target.probe_job(job));
            }
            if let Some(RedeployJobState::Failed(detail)) = &self.last_job_state {
                reporter.status(Status::Failed {
                    detail: detail.clone(),
                });
                return Ok(());
            }
            let probe = target.probe_version(&worker.target_version);
            if let Some(detail) = combined_probe_detail(refresh_detail, probe.detail) {
                self.last_probe_detail = Some(detail);
            }
            let version = probe.state;
            reporter.version(version.clone());
            if redeploy_is_complete(self.last_job_state.as_ref(), &version) {
                reporter.status(Status::Redeployed);
                return Ok(());
            }
            reporter.status(waiting_for_agent_status(
                0,
                combined_wait_detail(
                    self.last_job_state.as_ref(),
                    self.last_probe_detail.as_deref(),
                )
                .as_deref(),
            ));
            if Instant::now() >= self.deadline {
                let detail = combined_wait_detail(
                    self.last_job_state.as_ref(),
                    self.last_probe_detail.as_deref(),
                );
                reporter.status(Status::Failed {
                    detail: agent_wait_timeout_message(&worker.target_version, detail.as_deref()),
                });
                return Ok(());
            }
            ui::sleep(Duration::from_secs(3))?;
        }
    }

    fn observe_job_state(&mut self, now: Instant, state: RedeployJobState) {
        let progressed = match (&self.last_job_state, &state) {
            (previous, RedeployJobState::Active(_)) => previous.as_ref() != Some(&state),
            (Some(RedeployJobState::Active(_)), RedeployJobState::Complete(_)) => true,
            _ => false,
        };
        if progressed {
            self.deadline = (now + FLEET_REDEPLOY_NO_PROGRESS_TIMEOUT).min(self.hard_deadline);
        }
        self.last_job_state = Some(state);
    }

    fn refresh_remote_target_if_due(
        &mut self,
        worker: &Worker,
        target: &mut Target,
    ) -> Option<String> {
        if Instant::now() < self.next_remote_refresh {
            return None;
        }
        self.next_remote_refresh =
            Instant::now() + FLEET_REDEPLOY_REMOTE_SSH_ASSET_REFRESH_INTERVAL;
        let Target::Remote(remote) = target else {
            return None;
        };
        if let Err(error) = worker.refresh_remote_target(remote) {
            return Some(format!("ssh asset refresh failed: {}", full_error(&error)));
        }
        None
    }
}

fn redeploy_is_complete(job: Option<&RedeployJobState>, version: &agent_version::State) -> bool {
    matches!(job, Some(RedeployJobState::Complete(_)))
        && matches!(
            version,
            agent_version::State::Current | agent_version::State::Newer(_)
        )
}

fn combined_wait_detail(
    job: Option<&RedeployJobState>,
    agent_probe: Option<&str>,
) -> Option<String> {
    let job = match job {
        Some(RedeployJobState::Active(detail))
        | Some(RedeployJobState::Complete(detail))
        | Some(RedeployJobState::Unknown(detail)) => Some(detail.as_str()),
        Some(RedeployJobState::Failed(_)) | None => None,
    };
    match (job, agent_probe) {
        (Some(job), Some(agent_probe)) => Some(format!("{job}; agent probe: {agent_probe}")),
        (Some(job), None) => Some(job.to_string()),
        (None, Some(agent_probe)) => Some(agent_probe.to_string()),
        (None, None) => None,
    }
}

fn combined_probe_detail(
    refresh_detail: Option<String>,
    probe_detail: Option<String>,
) -> Option<String> {
    match (refresh_detail, probe_detail) {
        (Some(refresh_detail), Some(probe_detail)) => {
            Some(format!("{refresh_detail}; {probe_detail}"))
        }
        (Some(refresh_detail), None) => Some(refresh_detail),
        (None, Some(probe_detail)) => Some(probe_detail),
        (None, None) => None,
    }
}

fn waiting_for_agent_status(frame: usize, detail: Option<&str>) -> Status {
    Status::WaitingForAgent {
        frame,
        detail: detail
            .map(str::trim)
            .filter(|detail| !detail.is_empty())
            .map(ToString::to_string),
    }
}

fn run_remote(
    prepared: &PreparedConnect,
    target_version: &RedeployVersion,
    update_user: bool,
) -> Result<local_agent::RedeployResponse> {
    let remote_command = remote_redeploy_command(target_version, update_user);
    let mut command = prepared.timed_ssh_command(
        &[],
        Some(&remote_command),
        None,
        false,
        FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT,
    );
    let output = crate::command::run_capture(&mut command)?;
    if output.status.success() {
        return serde_json::from_str(output.stdout.trim())
            .context("remote aegis-agent returned an invalid redeploy response");
    }
    if output.status.code() == Some(124) {
        bail!(
            "remote fleet redeploy timed out after {}",
            host_list::elapsed_duration_text(FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT)
        );
    }
    bail!(
        "remote fleet redeploy failed: {}",
        command_output_full_failure_detail(&output)
    );
}

fn run_remote_user_update(
    prepared: &PreparedConnect,
    target_version: &RedeployVersion,
) -> Result<()> {
    let remote_command = remote_user_update_command(target_version);
    let mut command = prepared.timed_ssh_command(
        &[],
        Some(&remote_command),
        None,
        false,
        FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT,
    );
    let output = crate::command::run_capture(&mut command)?;
    if output.status.success() {
        return Ok(());
    }
    if output.status.code() == Some(124) {
        bail!(
            "remote user CLI update timed out after {}",
            host_list::elapsed_duration_text(FLEET_REDEPLOY_REMOTE_INSTALL_TIMEOUT)
        );
    }
    bail!(
        "remote user CLI update failed: {}",
        command_output_full_failure_detail(&output)
    )
}

pub(super) fn remote_redeploy_command(
    target_version: &RedeployVersion,
    update_user: bool,
) -> String {
    let target_version = super::sh_quote(&target_version.to_string());
    let update_user = if update_user {
        format!(
            "if ! /usr/local/bin/aegis advanced update-user --version {target_version} --json >/dev/null; then\n  echo 'remote user CLI update failed; system redeploy was not scheduled' >&2\n  exit 1\nfi\n\
             echo 'remote user CLI update completed; scheduling system redeploy' >&2\n"
        )
    } else {
        String::new()
    };
    format!(
        "if ! test -S {}; then\n  echo 'the remote Capulus management socket is unavailable' >&2\n  exit 1\nfi\n\
         {update_user}\
         if test \"$(id -u)\" -eq 0; then\n  aegis_program={}\nelse\n  aegis_program=\"$HOME/{}\"\nfi\n\
         exec \"$aegis_program\" advanced redeploy --version {target_version} --json\n",
        super::sh_quote(crate::managed::MANAGEMENT_SOCKET_PATH),
        super::sh_quote(aegis_dto::layout::SYSTEM_BINARY_PATH),
        aegis_dto::layout::USER_BINARY_RELATIVE_PATH,
    )
}

fn remote_user_update_command(target_version: &RedeployVersion) -> String {
    format!(
        "exec /usr/local/bin/aegis advanced update-user --version {} --json\n",
        super::sh_quote(&target_version.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_wait_refreshes_remote_ssh_assets_before_first_probe() {
        let wait = VersionWait::new();

        assert!(wait.next_remote_refresh <= Instant::now());
    }

    #[test]
    fn version_wait_reports_refresh_and_probe_failures_together() {
        assert_eq!(
            Some("ssh asset refresh failed: oauth expired; ssh agent version probe failed: Permission denied".to_string()),
            combined_probe_detail(
                Some("ssh asset refresh failed: oauth expired".to_string()),
                Some("ssh agent version probe failed: Permission denied".to_string()),
            ),
        );
    }

    #[test]
    fn version_wait_extends_only_for_real_job_progress_and_never_past_hard_deadline() {
        let started = Instant::now();
        let mut wait = VersionWait::new_at(started);
        let compiling = RedeployJobState::Active("compiling dependency".to_string());

        wait.observe_job_state(started + Duration::from_secs(29 * 60), compiling.clone());
        assert_eq!(started + Duration::from_secs(59 * 60), wait.deadline);

        wait.observe_job_state(started + Duration::from_secs(40 * 60), compiling);
        assert_eq!(
            started + Duration::from_secs(59 * 60),
            wait.deadline,
            "an unchanged status must not extend the deadline"
        );

        wait.observe_job_state(
            started + Duration::from_secs(115 * 60),
            RedeployJobState::Active("linking aegis-tool".to_string()),
        );
        assert_eq!(wait.hard_deadline, wait.deadline);
    }

    #[test]
    fn version_wait_allows_agent_startup_after_job_completion() {
        let started = Instant::now();
        let mut wait = VersionWait::new_at(started);
        wait.observe_job_state(
            started,
            RedeployJobState::Active("installing agent".to_string()),
        );
        wait.observe_job_state(
            started + Duration::from_secs(25 * 60),
            RedeployJobState::Complete("redeploy: complete".to_string()),
        );

        assert_eq!(started + Duration::from_secs(55 * 60), wait.deadline);
    }

    #[test]
    fn current_system_agent_cannot_hide_a_failed_redeploy_job() {
        let current = agent_version::State::Current;
        assert!(!redeploy_is_complete(None, &current));

        let post_commit = RedeployJobState::Unknown("system_committed=true".to_string());

        assert!(!redeploy_is_complete(Some(&post_commit), &current));

        let failed = RedeployJobState::Failed("system_committed=true".to_string());
        assert!(!redeploy_is_complete(Some(&failed), &current));
        assert!(redeploy_is_complete(
            Some(&RedeployJobState::Complete(
                "system_committed=true".to_string()
            )),
            &current
        ));
    }

    #[test]
    fn remote_user_update_uses_the_root_owned_program_without_sudo() {
        let command = remote_user_update_command(&RedeployVersion::explicit("0.1.190").unwrap());
        assert!(command.contains("/usr/local/bin/aegis advanced update-user"));
        assert!(!command.contains("sudo"));
    }

    #[test]
    fn remote_redeploy_updates_the_user_and_schedules_in_one_ssh_session() {
        let command = remote_redeploy_command(&RedeployVersion::explicit("0.1.175").unwrap(), true);

        assert!(command.contains("test -S /run/aegis/capulus.sock"));
        let update = command
            .find("/usr/local/bin/aegis advanced update-user --version 0.1.175 --json >/dev/null")
            .unwrap();
        let schedule = command
            .find("exec \"$aegis_program\" advanced redeploy --version 0.1.175 --json")
            .unwrap();
        assert!(update < schedule);
        assert!(
            command.contains("remote user CLI update failed; system redeploy was not scheduled")
        );
        assert!(command.contains("remote user CLI update completed; scheduling system redeploy"));
        assert!(command.contains("aegis_program=\"$HOME/.cargo/bin/aegis\""));
        assert!(command.contains("aegis_program=/usr/local/bin/aegis"));
        assert!(command.contains("exec \"$aegis_program\" advanced redeploy"));
        assert!(command.contains("advanced redeploy --version 0.1.175 --json"));
        assert!(!command.contains("exec /usr/local/bin/aegis advanced redeploy"));
        assert!(!command.contains("manage login"));
        assert!(!command.contains("/run/aegis/agent.sock"));
        assert!(!command.contains("/etc/hosts"));
        assert!(!command.contains("cargo install"));
        assert!(!command.contains("curl"));
        assert!(!command.contains("sudo"));
    }

    #[test]
    fn root_remote_redeploy_skips_the_user_update() {
        let command =
            remote_redeploy_command(&RedeployVersion::explicit("0.1.175").unwrap(), false);

        assert!(!command.contains("advanced update-user"));
        assert!(command.contains("advanced redeploy --version 0.1.175 --json"));
    }
}
