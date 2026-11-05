use aegis_dto::platform::{HostPlatform, OperatingSystem};
use anyhow::{Result, bail};

use super::{command_output_full_failure_detail, full_error};

pub(super) struct RedeployJob {
    platform: HostPlatform,
    unit: String,
    job: capulus::managed::JobId,
}

impl RedeployJob {
    pub(super) fn new(platform: HostPlatform, unit: String, job: String) -> Result<Self> {
        let job = capulus::managed::JobId::parse(&job)?;
        let extension = match platform.operating_system {
            OperatingSystem::MacOs => "plist",
            OperatingSystem::Ubuntu | OperatingSystem::ArchLinux => "service",
        };
        if unit != format!("aegis-redeploy-{job}.{extension}") {
            bail!(
                "Capulus returned invalid redeploy unit `{unit}` for job {job} on {}; the managed job may continue independently",
                platform.operating_system
            );
        }
        Ok(Self {
            platform,
            unit,
            job,
        })
    }

    pub(super) fn unit(&self) -> &str {
        &self.unit
    }

    pub(super) fn probe_command(&self) -> String {
        format!(
            "{} advanced redeploy-status {} --json\n",
            super::sh_quote(crate::platform::system_binary_path(self.platform)),
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
                    Ok(status)
                        if status.job == self.job
                            && status.product == "aegis"
                            && status.unit == self.unit =>
                    {
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
    use std::os::unix::process::ExitStatusExt;

    use aegis_dto::platform::{Architecture, HostPlatform, OperatingSystem};

    use super::{RedeployJob, RedeployJobState};

    fn platform(operating_system: OperatingSystem) -> HostPlatform {
        HostPlatform {
            operating_system,
            architecture: Architecture::X86_64,
        }
    }

    #[test]
    fn macos_redeploy_accepts_the_launchd_job_and_uses_the_native_status_binary() {
        let job = "0123456789abcdef0123456789abcdef";
        let managed = RedeployJob::new(
            platform(OperatingSystem::MacOs),
            format!("aegis-redeploy-{job}.plist"),
            job.to_string(),
        )
        .unwrap();
        assert_eq!(
            format!("/Library/PrivilegedHelperTools/aegis advanced redeploy-status {job} --json\n"),
            managed.probe_command()
        );
    }

    #[test]
    fn jobs_require_the_exact_capulus_transient_unit() {
        let job = "0123456789abcdef0123456789abcdef";
        for (os, extension, wrong_extension) in [
            (OperatingSystem::Ubuntu, "service", "plist"),
            (OperatingSystem::ArchLinux, "service", "plist"),
            (OperatingSystem::MacOs, "plist", "service"),
        ] {
            let platform = platform(os);
            let unit = format!("aegis-redeploy-{job}.{extension}");
            let managed = RedeployJob::new(platform, unit.clone(), job.to_string()).unwrap();
            if os != OperatingSystem::MacOs {
                assert_eq!(
                    format!("/usr/local/bin/aegis advanced redeploy-status {job} --json\n"),
                    managed.probe_command()
                );
            }
            assert!(
                RedeployJob::new(
                    platform,
                    format!("aegis-redeploy-{job}.{wrong_extension}"),
                    job.to_string()
                )
                .is_err()
            );
            assert!(
                RedeployJob::new(
                    platform,
                    format!("aegis-redeploy-other.{extension}"),
                    job.to_string()
                )
                .is_err()
            );
            assert!(RedeployJob::new(platform, unit, "../../etc/passwd".to_string()).is_err());
        }
    }

    #[test]
    fn status_validation_keeps_native_job_identity_and_completion() {
        let job = "0123456789abcdef0123456789abcdef";
        for (os, extension) in [
            (OperatingSystem::MacOs, "plist"),
            (OperatingSystem::Ubuntu, "service"),
        ] {
            let managed = RedeployJob::new(
                platform(os),
                format!("aegis-redeploy-{job}.{extension}"),
                job.to_string(),
            )
            .unwrap();
            let mut status = capulus::managed::RedeployJob {
                job: capulus::managed::JobId::parse(job).unwrap(),
                product: "aegis".to_string(),
                version: "0.5.5".to_string(),
                unit: managed.unit().to_string(),
                phase: capulus::managed::JobPhase::Complete,
                detail: "system_committed=true".to_string(),
                system_committed: true,
                rollback_succeeded: None,
            };
            let output = |status: &capulus::managed::RedeployJob| {
                Ok(crate::command::CommandOutput {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: serde_json::to_string(status).unwrap(),
                    stderr: String::new(),
                })
            };
            assert!(matches!(
                managed.state_from_remote_output(output(&status)),
                RedeployJobState::Complete(_)
            ));
            status.phase = capulus::managed::JobPhase::Failed;
            status.rollback_succeeded = Some(true);
            assert!(
                matches!(managed.state_from_remote_output(output(&status)), RedeployJobState::Failed(detail) if detail.contains("rollback succeeded"))
            );
            status.unit = "another-job.service".to_string();
            assert!(matches!(
                managed.state_from_remote_output(output(&status)),
                RedeployJobState::Unknown(_)
            ));
        }
    }
}
