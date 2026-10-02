use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::command::run_capture;
use crate::ui;

use super::connect::ConnectStatus;
use super::local_agent;

const TARGET_ROUTE_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
const TARGET_ROUTE_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(super) struct TargetRouteWait<'a> {
    host_alias: &'a str,
    targets: Vec<IpAddr>,
}

impl<'a> TargetRouteWait<'a> {
    pub(super) fn new(host_alias: &'a str, targets: Vec<IpAddr>) -> Self {
        Self {
            host_alias,
            targets,
        }
    }

    pub(super) fn wait(&self, emit_ui: bool, status: Option<&dyn ConnectStatus>) -> Result<()> {
        if self.targets.is_empty() || self.has_route()? {
            return Ok(());
        }

        let started = Instant::now();
        set_status(
            status,
            &format!("Refreshing mesh route    {}", self.host_alias),
        );
        let task = (emit_ui && status.is_none())
            .then(|| {
                ui::task(ui::TaskOptions {
                    label: format!("Refreshing mesh route for {}", self.host_alias),
                    deadline: Some(TARGET_ROUTE_WAIT_TIMEOUT),
                    ..ui::TaskOptions::default()
                })
            })
            .transpose()?;
        let refresh_detail = match local_agent::refresh_host_cache() {
            Ok(refresh) => refresh.warning,
            Err(error) => Some(format!("{error:#}")),
        };

        loop {
            if self.has_route()? {
                if let Some(task) = task {
                    task.finish(format!("Mesh route to {} is ready.", self.host_alias));
                }
                return Ok(());
            }
            if started.elapsed() >= TARGET_ROUTE_WAIT_TIMEOUT {
                if let Some(task) = task {
                    task.fail(format!(
                        "Mesh route to {} did not become ready.",
                        self.host_alias
                    ));
                }
                let addresses = self
                    .targets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let refresh_detail = refresh_detail
                    .as_deref()
                    .unwrap_or("local agent reconcile completed without an error");
                bail!(
                    "no exact Aegis mesh route to `{}` ({addresses}) appeared within {}s after a local agent reconcile; reconcile result: {refresh_detail}",
                    self.host_alias,
                    TARGET_ROUTE_WAIT_TIMEOUT.as_secs()
                );
            }

            let message = format!(
                "Waiting for mesh route     {} ({}s)",
                self.host_alias,
                started.elapsed().as_secs()
            );
            set_status(status, &message);
            if let Some(task) = task.as_ref() {
                task.set_phase(message);
            }
            ui::sleep(
                TARGET_ROUTE_POLL_INTERVAL
                    .min(TARGET_ROUTE_WAIT_TIMEOUT.saturating_sub(started.elapsed())),
            )?;
        }
    }

    fn has_route(&self) -> Result<bool> {
        self.targets.iter().try_fold(false, |found, target| {
            Ok(found || exact_route_exists(*target)?)
        })
    }
}

fn set_status(status: Option<&dyn ConnectStatus>, message: &str) {
    if let Some(status) = status {
        status.set_status(message);
    }
}

fn exact_route_exists(target: IpAddr) -> Result<bool> {
    let mut command = Command::new("ip");
    if target.is_ipv6() {
        command.arg("-6");
    }
    command.args([
        "-j",
        "route",
        "show",
        "table",
        "all",
        "exact",
        &host_prefix(target),
    ]);
    let output = run_capture(&mut command).context("failed to inspect local mesh routes")?;
    if !output.status.success() {
        bail!(
            "failed to inspect exact route to {target}: {}",
            output.stderr.trim()
        );
    }
    let routes: Vec<serde_json::Value> = serde_json::from_str(&output.stdout)
        .with_context(|| format!("failed to parse route query for {target}"))?;
    Ok(!routes.is_empty())
}

fn host_prefix(target: IpAddr) -> String {
    match target {
        IpAddr::V4(_) => format!("{target}/32"),
        IpAddr::V6(_) => format!("{target}/128"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::host_prefix;

    #[test]
    fn exact_route_queries_use_host_prefixes() {
        assert_eq!(
            "10.75.0.7/32",
            host_prefix(IpAddr::V4(Ipv4Addr::new(10, 75, 0, 7)))
        );
        assert_eq!(
            "fd75::7/128",
            host_prefix(IpAddr::V6("fd75::7".parse::<Ipv6Addr>().expect("IPv6")))
        );
    }
}
