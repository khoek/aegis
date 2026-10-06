use std::time::Duration;

use aegis_dto::{
    AegisHostMode,
    protocol::{AegisHostMessage, AegisHostMessageLevel},
};
use semver::Version;

use crate::config::{CachedHost, now_unix};
use crate::ui;

const HOST_FIELD_SEPARATOR: &str = " · ";
const STALE_AGENT_REPORT_SECONDS: i64 = 180;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostListNote {
    pub(super) prefix: Option<(String, Option<ui::Color>)>,
    pub(super) text: String,
    pub(super) color: Option<ui::Color>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListedHost {
    pub(super) marker: &'static str,
    pub(super) alias: String,
    pub(super) state: String,
    pub(super) lockdown_indicator: bool,
    pub(super) color: ui::Color,
    pub(super) marker_warning: bool,
    pub(super) pending: bool,
    pub(super) host_label: String,
    pub(super) wireguard_label: Option<String>,
    pub(super) status_note: Option<HostListNote>,
    pub(super) messages_note: Option<HostListNote>,
    pub(super) availability_note: Option<HostListNote>,
    pub(super) version_note: Option<HostListNote>,
    pub(super) host_label_color: Option<ui::Color>,
    pub(super) host_label_effect: ui::TextEffect,
    pub(super) text_effect: ui::TextEffect,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct HostListLayout {
    alias_width: usize,
    state_width: usize,
    host_label_width: usize,
    wireguard_label_width: usize,
    availability_width: usize,
}

impl HostListLayout {
    pub(super) fn include(&mut self, host: &ListedHost) {
        self.alias_width = self.alias_width.max(host.alias.len());
        self.state_width = self.state_width.max(rendered_state_width(host));
        self.host_label_width = self.host_label_width.max(host.host_label.len());
        self.wireguard_label_width = self.wireguard_label_width.max(
            host.wireguard_label
                .as_deref()
                .map(str::len)
                .unwrap_or_default(),
        );
        self.availability_width = self.availability_width.max(
            host.availability_note
                .as_ref()
                .map(host_list_note_width)
                .unwrap_or_default(),
        );
    }
}

fn rendered_state_width(host: &ListedHost) -> usize {
    host.state.chars().count() + if host.lockdown_indicator { 2 } else { 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ListHostKind {
    Hub,
    Leaf,
}

impl ListHostKind {
    const fn marker(self) -> &'static str {
        match self {
            Self::Hub => "◆",
            Self::Leaf => "●",
        }
    }

    const fn state(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Leaf => "leaf",
        }
    }

    const fn color(self) -> ui::Color {
        match self {
            Self::Hub => ui::Color::Cyan,
            Self::Leaf => ui::Color::Green,
        }
    }
}

fn host_messages_note(messages: &[AegisHostMessage]) -> Option<HostListNote> {
    let values = messages
        .iter()
        .map(|message| message.value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| HostListNote {
        prefix: None,
        text: values.join("; "),
        color: if messages
            .iter()
            .any(|message| message.level == AegisHostMessageLevel::Error)
        {
            Some(ui::Color::Red)
        } else if messages
            .iter()
            .any(|message| message.level == AegisHostMessageLevel::Warning)
        {
            Some(ui::Color::Yellow)
        } else {
            None
        },
    })
}

pub(super) fn listed_host(host: &CachedHost) -> ListedHost {
    let kind = list_host_kind(host);

    let version_note = agent_version_note(host);
    ListedHost {
        marker: kind.marker(),
        alias: host.alias().to_string(),
        state: kind.state().to_string(),
        lockdown_indicator: host.host.ssh_lockdown_enabled,
        color: if host.pending {
            ui::Color::Yellow
        } else {
            kind.color()
        },
        marker_warning: version_note.is_some(),
        pending: host.pending,
        host_label: host.host_label(),
        wireguard_label: host
            .wireguard_ipv4()
            .map(|wireguard_ipv4| format!("wg {wireguard_ipv4}")),
        status_note: None,
        messages_note: host_messages_note(&host.messages),
        availability_note: None,
        version_note,
        host_label_color: host_is_leaf_without_configured_port(host).then_some(ui::Color::Yellow),
        host_label_effect: ui::TextEffect::None,
        text_effect: ui::TextEffect::None,
    }
}

fn agent_version_note(host: &CachedHost) -> Option<HostListNote> {
    let should_report_agent = !host.pending && !host.transient;
    if !should_report_agent {
        return None;
    }
    let Some(agent) = host.agent.as_ref() else {
        return Some(warning_note("agent version unknown"));
    };
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("aegis-tool package version must be valid semver");
    let reported = match Version::parse(&agent.version) {
        Ok(reported) => reported,
        Err(_) => {
            return Some(warning_note(&format!(
                "invalid agent version {}",
                agent.version
            )));
        }
    };
    let age_seconds = now_unix().saturating_sub(agent.reported_unix);
    let is_stale = age_seconds > STALE_AGENT_REPORT_SECONDS;
    let unhealthy = agent.health.last_reconcile_error.is_some();
    let text = if reported < current {
        let mut text = format!("old agent v{reported} (want v{current})");
        if is_stale {
            text.push_str(&format!(
                ", report {} old",
                elapsed_duration_text(Duration::from_secs(age_seconds as u64))
            ));
        }
        text
    } else if is_stale {
        format!(
            "agent v{reported} report {} old",
            elapsed_duration_text(Duration::from_secs(age_seconds as u64))
        )
    } else if unhealthy {
        format!("agent v{reported} unhealthy")
    } else {
        return None;
    };
    Some(warning_note(&text))
}

fn warning_note(text: &str) -> HostListNote {
    HostListNote {
        prefix: None,
        text: text.to_string(),
        color: Some(ui::Color::Yellow),
    }
}

pub(super) fn list_host_kind(host: &CachedHost) -> ListHostKind {
    match host.mode {
        AegisHostMode::Hub => ListHostKind::Hub,
        AegisHostMode::Leaf => ListHostKind::Leaf,
    }
}

fn host_is_leaf_without_configured_port(host: &CachedHost) -> bool {
    list_host_kind(host) == ListHostKind::Leaf
        && host.ssh.as_ref().is_some_and(|ssh| ssh.port.is_none())
}

pub(super) trait RenderTarget {
    fn style(&self, text: &str, color: Option<ui::Color>, effect: ui::TextEffect) -> String;

    fn paint(&self, text: &str, color: ui::Color) -> String {
        self.style(text, Some(color), ui::TextEffect::None)
    }

    fn effect(&self, text: &str, effect: ui::TextEffect) -> String {
        self.style(text, None, effect)
    }
}

impl RenderTarget for ui::StdoutRenderTarget {
    fn style(&self, text: &str, color: Option<ui::Color>, effect: ui::TextEffect) -> String {
        ui::RenderTarget::style(self, text, color, effect)
    }
}

impl RenderTarget for ui::StderrRenderTarget {
    fn style(&self, text: &str, color: Option<ui::Color>, effect: ui::TextEffect) -> String {
        ui::RenderTarget::style(self, text, color, effect)
    }
}

impl RenderTarget for ui::ConfiguredRenderTarget {
    fn style(&self, text: &str, color: Option<ui::Color>, effect: ui::TextEffect) -> String {
        ui::RenderTarget::style(self, text, color, effect)
    }
}

#[cfg(test)]
pub(super) struct PlainRenderTarget;

#[cfg(test)]
impl RenderTarget for PlainRenderTarget {
    fn style(&self, text: &str, _color: Option<ui::Color>, _effect: ui::TextEffect) -> String {
        text.to_string()
    }
}

pub(super) fn render_listed_host(host: &ListedHost, target: &impl RenderTarget) -> String {
    render_listed_host_with_optional_layout(host, target, None)
}

pub(super) fn render_aligned_listed_host(
    host: &ListedHost,
    target: &impl RenderTarget,
    layout: &HostListLayout,
) -> String {
    render_listed_host_with_optional_layout(host, target, Some(layout))
}

fn render_listed_host_with_optional_layout(
    host: &ListedHost,
    target: &impl RenderTarget,
    layout: Option<&HostListLayout>,
) -> String {
    let row_is_struck = host.text_effect == ui::TextEffect::Strikethrough;
    let bullet = if host.marker_warning && !row_is_struck {
        render_warning_marker(target, host.marker)
    } else {
        target.style(
            host.marker,
            (!row_is_struck).then_some(host.color),
            host.text_effect,
        )
    };
    let mut rendered_state = target.style(
        &host.state,
        (!row_is_struck).then_some(host.color),
        host.text_effect,
    );
    if host.lockdown_indicator {
        rendered_state.push(' ');
        rendered_state.push_str(&target.style(
            "▣",
            (!row_is_struck).then_some(host.color),
            host.text_effect,
        ));
    }
    let state = pad_rendered_column(
        rendered_state,
        rendered_state_width(host),
        layout.map_or_else(|| rendered_state_width(host), |layout| layout.state_width),
    );
    let mut parts = Vec::with_capacity(
        5 + usize::from(host.messages_note.is_some()) + usize::from(host.status_note.is_some()) + 1,
    );
    parts.push(pad_rendered_column(
        target.effect(&host.alias, host.text_effect),
        host.alias.len(),
        layout.map_or(host.alias.len(), |layout| layout.alias_width),
    ));
    parts.push(state);
    let host_label_effect = if host.host_label_effect == ui::TextEffect::Strikethrough {
        ui::TextEffect::Strikethrough
    } else {
        host.text_effect
    };
    parts.push(pad_rendered_column(
        target.style(&host.host_label, host.host_label_color, host_label_effect),
        host.host_label.len(),
        layout.map_or(host.host_label.len(), |layout| layout.host_label_width),
    ));
    let wireguard_width = layout.map_or_else(
        || {
            host.wireguard_label
                .as_deref()
                .map(str::len)
                .unwrap_or_default()
        },
        |layout| layout.wireguard_label_width,
    );
    if wireguard_width > 0 {
        let wireguard_label = host.wireguard_label.as_deref().unwrap_or_default();
        parts.push(pad_rendered_column(
            target.effect(wireguard_label, host.text_effect),
            wireguard_label.len(),
            wireguard_width,
        ));
    }
    if host.pending {
        parts.push(target.effect("pending", host.text_effect));
    }
    if let Some(note) = render_host_probe_note(host, target, row_is_struck, layout) {
        parts.push(note);
    }
    if let Some(note) = &host.messages_note {
        parts.push(render_host_list_note(
            note,
            target,
            row_is_struck,
            host.text_effect,
        ));
    }
    if let Some(note) = &host.version_note {
        parts.push(render_host_list_note(
            note,
            target,
            row_is_struck,
            host.text_effect,
        ));
    }
    if let Some(note) = &host.status_note {
        parts.push(render_host_list_note(
            note,
            target,
            row_is_struck,
            host.text_effect,
        ));
    }

    format!("{bullet} {}", parts.join(HOST_FIELD_SEPARATOR))
}

fn pad_rendered_column(mut rendered: String, content_width: usize, column_width: usize) -> String {
    rendered.extend(std::iter::repeat_n(
        ' ',
        column_width.saturating_sub(content_width),
    ));
    rendered
}

fn render_host_probe_note(
    host: &ListedHost,
    target: &impl RenderTarget,
    row_is_struck: bool,
    layout: Option<&HostListLayout>,
) -> Option<String> {
    host.availability_note.as_ref().map(|note| {
        let width = host_list_note_width(note);
        pad_rendered_column(
            render_host_list_note(note, target, row_is_struck, host.text_effect),
            width,
            layout.map_or(width, |layout| layout.availability_width),
        )
    })
}

fn host_list_note_width(note: &HostListNote) -> usize {
    note.text.len()
        + note
            .prefix
            .as_ref()
            .map(|(prefix, _)| prefix.len() + 1)
            .unwrap_or_default()
}

fn render_host_list_note(
    note: &HostListNote,
    target: &impl RenderTarget,
    row_is_struck: bool,
    effect: ui::TextEffect,
) -> String {
    let prefix = note
        .prefix
        .as_ref()
        .map(|(text, color)| target.style(text, color.filter(|_| !row_is_struck), effect));
    let text = target.style(&note.text, note.color.filter(|_| !row_is_struck), effect);
    match prefix {
        Some(prefix) => format!("{prefix} {text}"),
        None => text,
    }
}

fn render_warning_marker(target: &impl RenderTarget, text: &str) -> String {
    target.paint(text, ui::Color::Yellow)
}

pub(super) fn elapsed_duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m{}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h{}m", seconds / 3_600, (seconds % 3_600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_listed_host(
        marker: &'static str,
        alias: &str,
        state: &str,
        host_label: &str,
        wireguard_label: Option<&str>,
        pending: bool,
    ) -> ListedHost {
        ListedHost {
            marker,
            alias: alias.to_string(),
            state: state.to_string(),
            lockdown_indicator: false,
            color: ui::Color::Green,
            marker_warning: false,
            pending,
            host_label: host_label.to_string(),
            wireguard_label: wireguard_label.map(str::to_string),
            status_note: None,
            messages_note: None,
            availability_note: Some(HostListNote {
                prefix: None,
                text: "available".to_string(),
                color: Some(ui::Color::Green),
            }),
            version_note: None,
            host_label_color: None,
            host_label_effect: ui::TextEffect::None,
            text_effect: ui::TextEffect::None,
        }
    }

    fn layout_for(hosts: &[ListedHost]) -> HostListLayout {
        let mut layout = HostListLayout::default();
        for host in hosts {
            layout.include(host);
        }
        layout
    }

    fn separator_offsets(rendered: &str) -> Vec<usize> {
        rendered
            .match_indices(HOST_FIELD_SEPARATOR)
            .map(|(offset, _)| rendered[..offset].chars().count())
            .collect()
    }

    #[test]
    fn aligned_rows_share_name_kind_and_ip_column_boundaries() {
        let hosts = [
            sample_listed_host(
                "◆",
                "hub-a",
                "hub",
                "10.75.0.9",
                Some("wg 10.75.1.9"),
                false,
            ),
            sample_listed_host(
                "●",
                "considerably-longer-leaf",
                "leaf",
                "10.75.0.100",
                Some("wg 10.75.1.100"),
                false,
            ),
        ];
        let layout = layout_for(&hosts);
        let rendered = hosts
            .iter()
            .map(|host| render_aligned_listed_host(host, &PlainRenderTarget, &layout))
            .collect::<Vec<_>>();

        assert_eq!(
            separator_offsets(&rendered[0]),
            separator_offsets(&rendered[1])
        );
        assert_eq!(rendered[0].find("available"), rendered[1].find("available"));
    }

    #[test]
    fn lockdown_marker_preserves_kind_column_alignment() {
        let mut locked = sample_listed_host(
            "●",
            "locked",
            "leaf",
            "10.75.0.7",
            Some("wg 10.75.1.7"),
            false,
        );
        locked.lockdown_indicator = true;
        let unlocked = sample_listed_host(
            "●",
            "unlocked",
            "leaf",
            "10.75.0.8",
            Some("wg 10.75.1.8"),
            false,
        );
        let layout = layout_for(&[locked.clone(), unlocked.clone()]);

        let locked = render_aligned_listed_host(&locked, &PlainRenderTarget, &layout);
        let unlocked = render_aligned_listed_host(&unlocked, &PlainRenderTarget, &layout);

        assert!(locked.contains("leaf ▣ ·"));
        assert!(unlocked.contains("leaf   ·"));
        assert_eq!(separator_offsets(&locked), separator_offsets(&unlocked));
    }

    #[test]
    fn pending_note_does_not_shift_the_core_host_columns() {
        let hosts = [
            sample_listed_host(
                "●",
                "active",
                "leaf",
                "10.75.0.9",
                Some("wg 10.75.1.9"),
                false,
            ),
            sample_listed_host(
                "◆",
                "pending-hub",
                "hub",
                "10.75.0.100",
                Some("wg 10.75.1.100"),
                true,
            ),
        ];
        let layout = layout_for(&hosts);
        let active = render_aligned_listed_host(&hosts[0], &PlainRenderTarget, &layout);
        let pending = render_aligned_listed_host(&hosts[1], &PlainRenderTarget, &layout);
        let active_offsets = separator_offsets(&active);
        let pending_offsets = separator_offsets(&pending);

        assert_eq!(active_offsets, pending_offsets[..active_offsets.len()]);
        assert!(pending.rfind("pending").unwrap() > pending.find("wg 10.75.1.100").unwrap());
    }

    #[test]
    fn missing_wireguard_address_keeps_following_status_aligned() {
        let hosts = [
            sample_listed_host(
                "●",
                "with-wg",
                "leaf",
                "10.75.0.9",
                Some("wg 10.75.1.9"),
                false,
            ),
            sample_listed_host("●", "without-wg", "leaf", "10.75.0.10", None, false),
        ];
        let layout = layout_for(&hosts);
        let rendered = hosts
            .iter()
            .map(|host| render_aligned_listed_host(host, &PlainRenderTarget, &layout))
            .collect::<Vec<_>>();

        assert_eq!(rendered[0].find("available"), rendered[1].find("available"));
        assert_eq!(
            separator_offsets(&rendered[0]),
            separator_offsets(&rendered[1])
        );
    }

    #[test]
    fn reachability_column_is_padded_before_following_notes() {
        let mut available = sample_listed_host(
            "●",
            "alpha",
            "leaf",
            "10.75.0.9",
            Some("wg 10.75.1.9"),
            false,
        );
        let mut unreachable = sample_listed_host(
            "●",
            "beta",
            "leaf",
            "10.75.0.10",
            Some("wg 10.75.1.10"),
            false,
        );
        unreachable.availability_note.as_mut().expect("note").text = "ipv6-unreachable".to_string();
        for host in [&mut available, &mut unreachable] {
            host.status_note = Some(HostListNote {
                prefix: None,
                text: "warning".to_string(),
                color: Some(ui::Color::Yellow),
            });
        }
        let hosts = [available, unreachable];
        let layout = layout_for(&hosts);
        let rendered = hosts
            .iter()
            .map(|host| render_aligned_listed_host(host, &PlainRenderTarget, &layout))
            .collect::<Vec<_>>();

        assert_eq!(rendered[0].find("warning"), rendered[1].find("warning"));
    }
}
