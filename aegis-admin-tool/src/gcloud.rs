use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    process::Command,
    time::{Duration, Instant},
};

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
        decode(&self.run(args, None, Duration::from_secs(20 * 60))?)
    }

    pub fn global_json(args: &[&str]) -> Result<Value> {
        decode(&execute(
            Command::new("gcloud")
                .args(args)
                .args(["--quiet", "--format=json"]),
            None,
            Duration::from_secs(30),
        )?)
    }

    /// Wait for a newly enabled API's serving frontend to observe activation.
    pub fn ready_json(&self, args: &[&str]) -> Result<Value> {
        let timeout = Duration::from_secs(180);
        let deadline = Instant::now() + timeout;
        let task = aegis_tool::ui::task(aegis_tool::ui::TaskOptions {
            label: format!(
                "Waiting for GCP API: {}",
                args.iter().take(3).copied().collect::<Vec<_>>().join(" ")
            ),
            deadline: Some(timeout),
            ..Default::default()
        })?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(
                !remaining.is_zero(),
                "GCP API activation exceeded its three-minute deadline; resources are retained, rerun setup"
            );
            match self.run(args, None, remaining.min(Duration::from_secs(30))) {
                Ok(output) => {
                    task.finish_and_clear();
                    return serde_json::from_str(&output).context("gcloud returned invalid JSON");
                }
                Err(error)
                    if !capulus::error_is_cancelled(&error)
                        && error.to_string().contains("reason: SERVICE_DISABLED") =>
                {
                    task.set_phase("Activation requested; GCP still reports SERVICE_DISABLED");
                    aegis_tool::ui::sleep(
                        Duration::from_secs(3)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn run(&self, args: &[&str], input: Option<&[u8]>, timeout: Duration) -> Result<String> {
        execute(
            Command::new("gcloud").args(args).args([
                "--project",
                &self.project,
                "--quiet",
                "--format=json",
            ]),
            input,
            timeout,
        )
    }

    pub fn token(&self) -> Result<String> {
        self.token_as(None, Duration::from_secs(30))
    }

    pub fn token_as(&self, account: Option<&str>, timeout: Duration) -> Result<String> {
        let mut args = vec!["auth", "print-access-token"];
        if let Some(account) = account {
            args.extend(["--impersonate-service-account", account]);
        }
        let value: Value = serde_json::from_str(&self.run(&args, None, timeout)?)
            .context("gcloud returned invalid access-token JSON")?;
        let token = value["token"]
            .as_str()
            .context("gcloud returned no access token; run gcloud auth login")?;
        ensure!(
            !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "gcloud returned an invalid access token; run gcloud auth login"
        );
        Ok(token.into())
    }

    pub fn operator_account(&self) -> Result<String> {
        let accounts = self.json(&["auth", "list", "--filter=status:ACTIVE"])?;
        let account = accounts
            .as_array()
            .and_then(|accounts| accounts.first())
            .and_then(|account| account["account"].as_str())
            .context("No active gcloud account; run gcloud auth login")?;
        Ok(account.into())
    }

    pub fn user_account(&self) -> Result<String> {
        let account = self.operator_account()?;
        ensure!(
            !account.ends_with(".gserviceaccount.com"),
            "browser OAuth setup requires a gcloud user account"
        );
        Ok(account)
    }

    pub fn operator_member(&self) -> Result<String> {
        let account = self.operator_account()?;
        let kind = if account.ends_with(".gserviceaccount.com") {
            "serviceAccount"
        } else {
            "user"
        };
        Ok(format!("{kind}:{account}"))
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
        let output = execute(
            Command::new("gcloud").args(["config", "get", "project", "--quiet"]),
            None,
            Duration::from_secs(30),
        )?;
        let value = output.trim();
        Ok((!value.is_empty() && value != "(unset)").then(|| value.to_owned()))
    }
}

fn decode(output: &str) -> Result<Value> {
    if output.trim().is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_str(output).context("gcloud returned invalid JSON")
    }
}

fn execute(command: &mut Command, input: Option<&[u8]>, timeout: Duration) -> Result<String> {
    let phase = command
        .get_args()
        .take(3)
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let task = aegis_tool::ui::task(aegis_tool::ui::TaskOptions {
        label: format!("GCP: {phase}"),
        deadline: Some(timeout),
        ..Default::default()
    })?;
    let output = capulus::process::CaptureOptions {
        timeout,
        cancellation: aegis_tool::ui::current().cancellation(),
        ..Default::default()
    }
    .validate()?
    .run(command, input)?;
    task.finish_and_clear();
    ensure!(
        output.status.success(),
        "gcloud {phase} failed: {}",
        output.stderr.trim()
    );
    Ok(output.stdout)
}
