use std::time::{Duration, Instant};

use aegis_tool::ui;
use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::gcloud::Gcloud;

const OPERATOR_WAIT: Duration = Duration::from_secs(15 * 60);

pub(super) fn prepare(project: Option<String>, interactive: bool) -> Result<Gcloud> {
    if let Some(project) = &project {
        Gcloud::new(project.clone())?;
    }
    Gcloud::global_json(&["version"]).map_err(|error| {
        if error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        }) {
            error.context(
                "Install the Google Cloud CLI: https://cloud.google.com/sdk/docs/install\n\
                 Open a new terminal so `gcloud` is on PATH, then rerun `aegis-admin setup`",
            )
        } else {
            error
        }
    })?;
    let mut account = active_account()?;
    if account.is_none() {
        ui::stage("Sign in to Google Cloud: run `gcloud auth login` in another terminal.");
        wait_for(
            "Google Cloud sign-in",
            "No active gcloud account",
            interactive,
            |_| {
                account = active_account()?;
                Ok(account.is_some())
            },
        )?;
    }
    let account = account.context("gcloud sign-in completed without an active account")?;
    ui::detail(&format!("GCP account: {account}"));
    Gcloud::global_json(&["auth", "print-access-token"]).context(
        "Could not use the active GCP credential. If sign-in has expired, run `gcloud auth login`, then rerun setup",
    )?;
    let project = match project {
        Some(project) => project,
        None => match Gcloud::active_project()? {
            Some(project) => project,
            None => {
                let project = select_project(&account, interactive)?;
                Gcloud::new(project.clone())?;
                Gcloud::global_json(&["config", "set", "project", &project])?;
                ui::detail(&format!("Saved GCP project: {project}"));
                project
            }
        },
    };
    Gcloud::new(project)
}

pub(super) fn check_project(cloud: &Gcloud, interactive: bool) -> Result<()> {
    ui::stage("Preparing GCP management APIs");
    let activation = cloud.json(&[
        "services",
        "enable",
        "serviceusage.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "cloudbilling.googleapis.com",
        "iamcredentials.googleapis.com",
    ]);
    if activation.as_ref().is_err_and(capulus::error_is_cancelled) {
        ui::warn(
            "GCP API activation was interrupted and may be partially applied. No Aegis resources were created in this run; rerun setup to verify and continue.",
        );
    }
    activation.with_context(|| format!(
        "Use a GCP account with provisioning access to project {}. Review access at https://console.cloud.google.com/iam-admin/iam?project={}. API activation may be partially applied; no Aegis resources were created in this run",
        cloud.project, cloud.project,
    ))?;
    let billing = check_billing(cloud, interactive);
    let retained = "GCP management APIs remain enabled; no Aegis resources were created in this run. Any billing changes are retained. Rerun `aegis-admin setup` to continue";
    if billing.as_ref().is_err_and(capulus::error_is_cancelled) {
        ui::warn(retained);
    }
    billing.context(retained)
}

fn active_account() -> Result<Option<String>> {
    let accounts = Gcloud::global_json(&["auth", "list", "--filter=status:ACTIVE"])?;
    let accounts = accounts
        .as_array()
        .context("gcloud returned an invalid account list")?;
    accounts
        .first()
        .map(|account| {
            account["account"]
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .context("gcloud returned an invalid active account")
        })
        .transpose()
}

fn select_project(account: &str, interactive: bool) -> Result<String> {
    require_interactive(
        interactive,
        "Choose a GCP project with `--project PROJECT_ID`, or run `gcloud config set project PROJECT_ID`, then rerun setup",
    )?;
    let projects = Gcloud::global_json(&["projects", "list", "--sort-by=projectId"])?;
    let projects = projects
        .as_array()
        .context("gcloud returned an invalid project list")?;
    let ids = projects
        .iter()
        .map(|project| {
            project["projectId"]
                .as_str()
                .context("gcloud returned a project without its ID")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut choices = ids.clone();
    choices.push("Create a project / enter a project ID");
    let selected = ui::suspend(|| {
        dialoguer::Select::new()
            .with_prompt("GCP project")
            .items(&choices)
            .default(0)
            .max_length(10)
            .interact()
    })?;
    if let Some(project) = ids.get(selected) {
        return Ok((*project).into());
    }
    ui::stage(&format!(
        "Create a project at https://console.cloud.google.com/projectcreate using {account}, or enter an existing project ID."
    ));
    ui::suspend(|| {
        dialoguer::Input::<String>::new()
            .with_prompt("GCP project ID")
            .validate_with(|value: &String| Gcloud::new(value.clone()).map(|_| ()))
            .interact_text()
            .map_err(Into::into)
    })
}

fn check_billing(cloud: &Gcloud, interactive: bool) -> Result<()> {
    let args = ["billing", "projects", "describe", &cloud.project];
    if billing_enabled(&cloud.ready_json(&args)?)? {
        return Ok(());
    }
    let url = format!(
        "https://console.cloud.google.com/billing/linkedaccount?project={}",
        cloud.project
    );
    ui::stage(&format!(
        "Enable billing for {}: {url}\nLink a billing account in the Cloud Console. GCP charges this account for the API and hub VMs.",
        cloud.project,
    ));
    require_interactive(
        interactive,
        "Enable project billing at the URL above, then rerun `aegis-admin setup`",
    )?;
    ui::maybe_open_browser(&url);
    wait_for(
        "Project billing",
        "Billing is not enabled",
        interactive,
        |remaining| {
            billing_enabled(&serde_json::from_str(&cloud.run(
                &args,
                None,
                remaining.min(Duration::from_secs(30)),
            )?)?)
        },
    )
}

fn billing_enabled(value: &Value) -> Result<bool> {
    value["billingEnabled"]
        .as_bool()
        .context("gcloud returned no billing status")
}

fn require_interactive(interactive: bool, message: &str) -> Result<()> {
    ensure!(interactive, "{message}");
    ui::require_interactive(message)
}

fn wait_for(
    label: &str,
    state: &str,
    interactive: bool,
    mut check: impl FnMut(Duration) -> Result<bool>,
) -> Result<()> {
    require_interactive(
        interactive,
        "Complete the step above, then rerun `aegis-admin setup` in a terminal",
    )?;
    let task = ui::task(ui::TaskOptions {
        label: format!("Waiting for {label}"),
        deadline: Some(OPERATOR_WAIT),
        ..Default::default()
    })?;
    task.set_phase(state);
    let deadline = Instant::now() + OPERATOR_WAIT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "{label} was not completed within 15 minutes; finish the step above and rerun setup"
        );
        ui::check_cancelled()?;
        if check(remaining)? {
            task.finish_and_clear();
            return Ok(());
        }
        ui::sleep(Duration::from_secs(3).min(deadline.saturating_duration_since(Instant::now())))?;
    }
}
