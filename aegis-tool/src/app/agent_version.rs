use semver::Version;

use super::local_agent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum State {
    Unknown,
    Current,
    Older(String),
    Newer(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeResult {
    pub(super) state: State,
    pub(super) detail: Option<String>,
}

impl ProbeResult {
    pub(super) fn state(state: State) -> Self {
        Self {
            state,
            detail: None,
        }
    }

    pub(super) fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: State::Unknown,
            detail: Some(detail.into()),
        }
    }
}

#[cfg(test)]
pub(super) fn current() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("aegis-tool package version must be semver")
}

pub(super) fn from_json(payload: &str, target: &Version) -> ProbeResult {
    let payload = payload.trim();
    if payload.is_empty() {
        return ProbeResult::unknown("agent version probe returned no output");
    }
    match serde_json::from_str::<local_agent::AgentVersionResponse>(payload) {
        Ok(response) => from_text(&response.version, target),
        Err(error) => ProbeResult::unknown(format!(
            "agent version probe returned invalid JSON: {error}: {payload}"
        )),
    }
}

pub(super) fn from_text(version: &str, target: &Version) -> ProbeResult {
    let version = version.trim();
    match state(version, target) {
        State::Unknown if version.is_empty() => {
            ProbeResult::unknown("agent version probe returned no output")
        }
        State::Unknown => ProbeResult::unknown(format!("agent version probe returned `{version}`")),
        State::Older(version) => ProbeResult {
            state: State::Older(version.clone()),
            detail: Some(format!("agent still reported v{version}")),
        },
        state => ProbeResult::state(state),
    }
}

fn state(remote_version: &str, target: &Version) -> State {
    let remote_version = remote_version.trim().trim_start_matches('v');
    if remote_version.is_empty() {
        return State::Unknown;
    }
    let Ok(remote) = Version::parse(remote_version) else {
        return State::Unknown;
    };
    match remote.cmp(target) {
        std::cmp::Ordering::Less => State::Older(remote_version.to_string()),
        std::cmp::Ordering::Equal => State::Current,
        std::cmp::Ordering::Greater => State::Newer(remote_version.to_string()),
    }
}
