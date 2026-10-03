use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{process::Command, time::Duration};

#[derive(Clone)]
pub(super) struct Gcloud {
    pub project: String,
}

impl Gcloud {
    pub fn new(project: String) -> Result<Self> {
        ensure!(
            project.len() >= 6
                && project.len() <= 30
                && project.as_bytes()[0].is_ascii_lowercase()
                && !project.ends_with('-')
                && project
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid GCP project id"
        );
        Ok(Self { project })
    }

    pub fn json(&self, args: &[&str]) -> Result<Value> {
        let output = self.run(args, None, Duration::from_secs(20 * 60))?;
        if output.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&output).context("gcloud returned invalid JSON")
    }

    pub fn run(&self, args: &[&str], input: Option<&[u8]>, timeout: Duration) -> Result<String> {
        let phase = args.iter().take(3).copied().collect::<Vec<_>>().join(" ");
        let task = aegis_tool::ui::task(aegis_tool::ui::TaskOptions {
            label: format!("GCP: {phase}"),
            deadline: Some(timeout),
            ..Default::default()
        })?;
        let mut command = Command::new("gcloud");
        command
            .args(args)
            .args(["--project", &self.project, "--quiet", "--format=json"]);
        let output = capulus::process::CaptureOptions {
            timeout,
            cancellation: aegis_tool::ui::current().cancellation(),
            ..Default::default()
        }
        .validate()?
        .run(&mut command, input)?;
        ensure!(
            output.status.success(),
            "gcloud {phase} failed: {}",
            output.stderr.trim()
        );
        task.finish_and_clear();
        Ok(output.stdout)
    }

    pub fn token(&self) -> Result<String> {
        let value = self.run(
            &["auth", "print-access-token"],
            None,
            Duration::from_secs(30),
        )?;
        let token = value.trim().trim_matches('"').to_owned();
        ensure!(
            !token.is_empty(),
            "gcloud returned no credentials; run gcloud auth login"
        );
        Ok(token)
    }

    pub fn stream(&self, args: &[&str], input: &[u8], timeout: Duration) -> Result<()> {
        let mut command = Command::new("gcloud");
        command
            .args(args)
            .args(["--project", &self.project, "--quiet"]);
        let output = aegis_tool::ui::suspend(|| {
            capulus::process::CaptureOptions {
                timeout,
                cancellation: aegis_tool::ui::current().cancellation(),
                ..Default::default()
            }
            .validate()?
            .run_streaming(&mut command, Some(input))
        })?;
        ensure!(
            output.status.success(),
            "gcloud child operation failed: {}",
            output.stderr.trim()
        );
        Ok(())
    }

    pub fn active_project() -> Result<Option<String>> {
        let output = capulus::process::CaptureOptions {
            timeout: Duration::from_secs(30),
            cancellation: aegis_tool::ui::current().cancellation(),
            ..Default::default()
        }
        .validate()?
        .run(
            Command::new("gcloud").args(["config", "get", "project", "--quiet"]),
            None,
        )?;
        ensure!(
            output.status.success(),
            "cannot read gcloud configuration: {}",
            output.stderr.trim()
        );
        let value = output.stdout.trim();
        Ok((!value.is_empty() && value != "(unset)").then(|| value.to_owned()))
    }
}
