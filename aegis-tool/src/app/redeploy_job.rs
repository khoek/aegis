use anyhow::{Result, bail};

use super::{command_output_full_failure_detail, full_error};

pub(super) struct RedeployJob {
    unit: String,
    job: capulus::managed::JobId,
}

impl RedeployJob {
    pub(super) fn new(unit: String, job: String) -> Result<Self> {
        let job = capulus::managed::JobId::parse(&job)?;
        if unit != format!("aegis-redeploy-{job}.service") {
            bail!("Capulus returned invalid redeploy unit \u{60}{unit}\u{60}");
        }
        Ok(Self { unit, job })
    }

    pub(super) fn unit(&self) -> &str {
        &self.unit
    }

    pub(super) fn probe_command(&self) -> String {
        format!(
            "/usr/local/bin/aegis advanced redeploy-status {} --json\n",
            super::sh_quote(&self.job.to_string())
        )
    }

    pub(super) fn probe_local(&self) -> RedeployJobState {
        match crate::managed::status(self.job) {
            Ok(status) => capulus_job_state(status),
            Err(error) => {
                RedeployJobState::Unknown(format!("managed redeploy status probe failed: {error}"))
            }
        }
    }

    pub(super) fn state_from_remote_output(
        &self,
        output: Result<crate::command::CommandOutput>,
    ) -> RedeployJobState {
        match output {
            Ok(output) if output.status.success() => {
                match serde_json::from_str::<capulus::managed::RedeployJob>(output.stdout.trim()) {
                    Ok(status) if status.job == self.job && status.product == "aegis" => {
                        capulus_job_state(status)
                    }
                    Ok(_) => RedeployJobState::Unknown(
                        "managed redeploy status returned the wrong job identity".to_string(),
                    ),
                    Err(error) => RedeployJobState::Unknown(format!(
                        "managed redeploy status returned invalid JSON: {error}"
                    )),
                }
            }
            Ok(output) => RedeployJobState::Unknown(format!(
                "managed redeploy status probe failed: {}",
                command_output_full_failure_detail(&output)
            )),
            Err(error) => RedeployJobState::Unknown(format!(
                "managed redeploy status probe failed: {}",
                full_error(&error)
            )),
        }
    }
}

fn capulus_job_state(status: capulus::managed::RedeployJob) -> RedeployJobState {
    let detail = format!("redeploy: {:?}: {}", status.phase, status.detail);
    match status.phase {
        capulus::managed::JobPhase::Complete => RedeployJobState::Complete(detail),
        capulus::managed::JobPhase::Failed => {
            let rollback = status
                .rollback_succeeded
                .map(|succeeded| {
                    if succeeded {
                        "; rollback succeeded"
                    } else {
                        "; rollback failed"
                    }
                })
                .unwrap_or_default();
            RedeployJobState::Failed(format!("{detail}{rollback}"))
        }
        _ => RedeployJobState::Active(detail),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RedeployJobState {
    Active(String),
    Complete(String),
    Failed(String),
    Unknown(String),
}

impl RedeployJobState {
    pub(super) fn detail(&self) -> &str {
        match self {
            Self::Active(detail)
            | Self::Complete(detail)
            | Self::Failed(detail)
            | Self::Unknown(detail) => detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RedeployJob;

    #[test]
    fn jobs_require_the_exact_capulus_transient_unit() {
        let job = "0123456789abcdef0123456789abcdef";
        let managed =
            RedeployJob::new(format!("aegis-redeploy-{job}.service"), job.to_string()).unwrap();

        assert_eq!(
            format!("/usr/local/bin/aegis advanced redeploy-status {job} --json\n"),
            managed.probe_command()
        );
        assert!(
            RedeployJob::new("aegis-redeploy-other.service".to_string(), job.to_string()).is_err()
        );
        assert!(
            RedeployJob::new(
                format!("aegis-redeploy-{job}.service"),
                "../../etc/passwd".to_string()
            )
            .is_err()
        );
    }
}
