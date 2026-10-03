use std::collections::HashMap;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::command::run_capture;
use crate::config::CachedHost;
use crate::ui::{self, LiveRow};

use super::{
    SYSTEM_AEGIS_BIN, command_output_failure_detail, host, local_agent, local_state,
    single_line_error,
};

const REMOTE_REFRESH_TIMEOUT: Duration = Duration::from_secs(75);

pub(super) fn refresh_after_topology_change(api_base_override: Option<&str>) {
    if let Err(error) = RefreshFanout::new(api_base_override).run() {
        ui::warn(&format!(
            "topology changed, but fleet mesh refresh did not fully complete: {error}"
        ));
    }
}

struct RefreshFanout<'a> {
    api_base_override: Option<&'a str>,
}

impl<'a> RefreshFanout<'a> {
    fn new(api_base_override: Option<&'a str>) -> Self {
        Self { api_base_override }
    }

    fn run(&self) -> Result<()> {
        if !crate::api::uses_local_agent(self.api_base_override)?
            || crate::config::load_user_auth_state()?.is_none()
        {
            ui::detail("Agents will discover topology changes on their next synchronization.");
            return Ok(());
        }
        let refreshed = local_agent::refresh_host_cache()?;
        let targets = host::filter_visible_hosts(refreshed.hosts, false)
            .into_iter()
            .filter(host::host_offers_ssh)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(());
        }

        let group = ui::live_group(format!(
            "Triggering mesh refresh on {} SSH-capable hosts",
            targets.len()
        ))?;
        let local_host_id = local_state::LocalHostIdentity::host_id_from_managed_state_or_cache()?;
        let (tx, rx) = mpsc::channel();
        let mut rows = HashMap::<String, LiveRow>::with_capacity(targets.len());
        for target in targets {
            let tx = tx.clone();
            let api_base_override = self.api_base_override.map(str::to_string);
            let local = local_host_id == Some(target.host_id);
            let alias = target.alias().to_string();
            rows.insert(alias.clone(), group.row(&alias, "queued")?);
            thread::spawn(move || {
                let result = if local {
                    refresh_local()
                } else {
                    trigger_remote_reconcile(api_base_override.as_deref(), &target)
                };
                let _ = tx.send((alias, result));
            });
        }
        drop(tx);

        let mut failures = Vec::new();
        let mut remaining = rows.len();
        while remaining > 0 {
            if let Err(error) = ui::check_cancelled() {
                for row in rows.values() {
                    row.abandon("interrupted");
                }
                group.abandon("Fleet mesh refresh interrupted");
                return Err(error);
            }
            let (alias, result) = match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    group.fail("Fleet mesh refresh workers stopped unexpectedly");
                    bail!("fleet mesh refresh workers stopped before reporting every host");
                }
            };
            remaining -= 1;
            if let Err(error) = result {
                let detail = single_line_error(&error);
                if let Some(row) = rows.get(&alias) {
                    row.fail(detail.clone());
                }
                failures.push(format!("{alias}: {detail}"));
            } else if let Some(row) = rows.get(&alias) {
                row.finish("refresh triggered");
            }
        }
        if failures.is_empty() {
            group.finish("Fleet mesh refresh triggered");
            return Ok(());
        }
        failures.sort();
        group.fail(format!(
            "Fleet mesh refresh completed with {} failure(s)",
            failures.len()
        ));
        bail!("{}", failures.join("; "))
    }
}

fn refresh_local() -> Result<()> {
    local_agent::refresh_host_cache().map(|_| ())
}

pub(super) fn trigger_remote_reconcile(
    api_base_override: Option<&str>,
    target: &CachedHost,
) -> Result<()> {
    let product = crate::managed::product()?;
    let exe = product
        .program()
        .trusted_installed_path()
        .context("failed to locate system Aegis for fleet reconciliation")?;
    let mut command = Command::new("timeout");
    command.arg(format!("{}s", REMOTE_REFRESH_TIMEOUT.as_secs()));
    command.arg(exe);
    if let Some(api_base_override) = api_base_override {
        command.args(["--api-base", api_base_override]);
    }
    command.args([
        "ssh",
        target.alias().as_str(),
        "--command",
        &format!("{SYSTEM_AEGIS_BIN} advanced reconcile"),
    ]);
    capulus::configure_child_command(&mut command);
    let output = run_capture(&mut command)?;
    if output.status.success() {
        return Ok(());
    }
    if output.status.code() == Some(124) {
        bail!(
            "remote Aegis reconcile timed out after {}s",
            REMOTE_REFRESH_TIMEOUT.as_secs()
        );
    }
    bail!(
        "remote Aegis reconcile failed: {}",
        command_output_failure_detail(&output)
    )
}
