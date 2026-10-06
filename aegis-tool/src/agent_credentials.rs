use aegis_dto::protocol::{AegisHostMessage, AegisHostMessageLevel};
use anyhow::{Result, bail};

use crate::api::AgentAccessState;

/// All accesses, exchanges and persistence attempts are serialized by the agent.
pub(crate) struct AgentCredentials {
    refresh_token: String,
    access: Option<AgentAccessState>,
    persistence_error: Option<String>,
}

impl AgentCredentials {
    pub(crate) fn new(refresh_token: String) -> Self {
        Self {
            refresh_token,
            access: None,
            persistence_error: None,
        }
    }

    pub(crate) fn alert(&self) -> Option<AegisHostMessage> {
        self.persistence_error.as_ref().map(|error| AegisHostMessage {
            level: AegisHostMessageLevel::Error,
            value: format!("Cannot save agent refresh token: {error}. Replacement retained in memory; retrying. Repair storage before restarting this agent."),
        })
    }

    pub(crate) fn accept(
        &mut self,
        access: AgentAccessState,
        persist: impl FnOnce(&str) -> Result<()>,
    ) {
        self.refresh_token.clone_from(&access.refresh_token);
        self.access = Some(access);
        self.save(persist);
    }

    fn save(&mut self, persist: impl FnOnce(&str) -> Result<()>) {
        let was_failing = self.persistence_error.is_some();
        self.persistence_error = persist(&self.refresh_token)
            .err()
            .map(|error| format!("{error:#}"));
        if !was_failing && let Some(alert) = self.alert() {
            eprintln!("aegis-agent: {}", alert.value);
        }
    }

    pub(crate) fn access_token(
        &mut self,
        now: i64,
        force: bool,
        exchange: impl FnOnce(&str) -> Result<AgentAccessState>,
        persist: impl Fn(&str) -> Result<()>,
    ) -> Result<String> {
        if self.persistence_error.is_some() {
            self.save(&persist);
        }
        if let Some(access) = &self.access {
            // While saving is failing, use the already-issued token until actual expiry
            // so the host can continue publishing its storage alert.
            let skew = if self.persistence_error.is_some() {
                0
            } else {
                30
            };
            if (!force || self.persistence_error.is_some())
                && !access.access_needs_refresh(now, skew)
            {
                return Ok(access.access_token.clone());
            }
        }
        if let Some(alert) = self.alert() {
            bail!("{}", alert.value);
        }
        let access = exchange(&self.refresh_token)?;
        self.accept(access, persist);
        Ok(self
            .access
            .as_ref()
            .expect("accepted access token")
            .access_token
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn access(refresh_token: &str) -> AgentAccessState {
        AgentAccessState {
            host_id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
            credential_kind: aegis_dto::protocol::AegisCredentialKind::Agent,
            refresh_token: refresh_token.into(),
            access_token: "access".into(),
            access_expires_at_unix: 300,
        }
    }

    #[test]
    fn failed_save_retains_replacement_reports_alert_and_retries_before_rotation() {
        let mut credentials = AgentCredentials::new("old".into());
        let exchanged = RefCell::new(Vec::new());
        let exchange = |token: &str| {
            exchanged.borrow_mut().push(token.to_string());
            Ok(access("replacement"))
        };
        let no_space = |_: &str| Err(std::io::Error::from_raw_os_error(28).into());
        assert_eq!(
            "access",
            credentials
                .access_token(0, false, exchange, no_space)
                .unwrap()
        );
        let alert = credentials.alert().unwrap();
        assert_eq!(AegisHostMessageLevel::Error, alert.level);
        assert!(alert.value.contains("No space left on device"));
        assert!(!alert.value.contains("replacement"));
        assert_eq!(
            "access",
            credentials
                .access_token(290, false, exchange, no_space)
                .unwrap()
        );
        assert!(
            credentials
                .access_token(301, true, exchange, no_space)
                .is_err()
        );
        assert_eq!(&["old"], exchanged.borrow().as_slice());
        let saved = RefCell::new(Vec::new());
        credentials
            .access_token(301, false, exchange, |token| {
                saved.borrow_mut().push(token.to_string());
                Ok(())
            })
            .unwrap();
        assert_eq!(&["old", "replacement"], exchanged.borrow().as_slice());
        assert_eq!(&["replacement", "replacement"], saved.borrow().as_slice());
        assert!(credentials.alert().is_none());
    }
}
