use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use capulus::shell::shell_quote as sh_quote;

use crate::api::AuthenticatedApiClient;
use crate::cli::TransferArgs;
use crate::command::{run_capture, run_status};
use crate::config::ensure_client_dirs;
use crate::ui::{self, Task, TaskOptions, TaskVisibility};

use super::{
    connect::{AssetPreparer, PreparedConnect},
    host, mesh_route,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Direction {
    Push,
    Pull,
}

const REMOTE_DESTINATION_EXISTS_EXIT: i32 = 73;

pub(super) struct PreparedTransfer {
    command: Command,
    connection: PreparedConnect,
}

impl PreparedTransfer {
    pub(super) fn new(
        connection: PreparedConnect,
        direction: Direction,
        sources: &[String],
        destination: &str,
        args: &TransferArgs,
        show_progress: bool,
    ) -> Result<Self> {
        let command = build_rsync_command(
            &connection,
            direction,
            sources,
            destination,
            args,
            show_progress,
        )?;
        Ok(Self {
            command,
            connection,
        })
    }

    fn destination_label(&self) -> String {
        self.connection.destination_label()
    }

    fn run(&mut self) -> Result<i32> {
        run_status(&mut self.command)
    }

    #[cfg(test)]
    pub(super) fn command(&self) -> &Command {
        &self.command
    }
}

impl Direction {
    const fn noun(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }

    const fn stage_verb(self) -> &'static str {
        match self {
            Self::Push => "Pushing to",
            Self::Pull => "Pulling from",
        }
    }
}

pub(super) fn run(
    api_base_override: Option<&str>,
    args: &TransferArgs,
    direction: Direction,
) -> Result<i32> {
    let (sources, destination) = sources_and_destination(&args.paths)?;
    validate_transfer_args(args, direction)?;
    let task = ui::task(TaskOptions {
        label: format!("Preparing {} transfer to {}", direction.noun(), args.host),
        visibility: TaskVisibility::Immediate,
        ..TaskOptions::default()
    })?;
    let result = prepare_transfer(
        api_base_override,
        args,
        direction,
        &sources,
        &destination,
        &task,
    );
    let mut prepared = match result {
        Ok(prepared) => prepared,
        Err(error) => {
            task.fail("Transfer preparation failed");
            return Err(error);
        }
    };
    task.finish_and_clear();
    ui::stage(&format!(
        "{} {}",
        direction.stage_verb(),
        prepared.destination_label()
    ));
    let exit_code = ui::suspend(|| prepared.run())?;
    if exit_code == 0 {
        ui::success("Transfer completed.");
    } else {
        ui::warn(&format!("rsync exited with status {exit_code}."));
    }
    Ok(exit_code)
}

fn prepare_transfer(
    api_base_override: Option<&str>,
    args: &TransferArgs,
    direction: Direction,
    sources: &[String],
    destination: &str,
    task: &Task,
) -> Result<PreparedTransfer> {
    task.set_phase("Resolving the host and preparing SSH credentials");
    let prepared = prepare_session(api_base_override, args, task)?;
    if direction == Direction::Push && args.fail_if_exists {
        task.set_phase("Checking the remote destination");
        fail_if_remote_destination_exists(&prepared, destination)?;
    }
    task.set_phase("Checking transfer tools");
    validate_rsync(
        &run_capture(Command::new(rsync_program(crate::platform::detect()?)).arg("--version"))
            .context("rsync is missing; install rsync 3.2 or newer (macOS: brew install rsync)")?,
        "local machine",
    )?;
    let remote_program = rsync_program(prepared.host().platform);
    validate_rsync(
        &run_capture(&mut prepared.ssh_command(
            &[],
            Some(&format!("{} --version", sh_quote(remote_program))),
            None,
            false,
        ))?,
        &prepared.destination_label(),
    )?;
    task.set_phase("Building the rsync handoff");
    PreparedTransfer::new(
        prepared,
        direction,
        sources,
        destination,
        args,
        ui::current().progress_is_enabled(),
    )
}

fn validate_transfer_args(args: &TransferArgs, direction: Direction) -> Result<()> {
    if direction == Direction::Pull && args.fail_if_exists {
        bail!("`--fail-if-exists` is only valid for `aegis push`");
    }
    if args.fail_if_exists && args.paths.len() < 2 {
        bail!("`aegis push --fail-if-exists` requires an explicit remote destination path");
    }
    Ok(())
}

fn prepare_session(
    api_base_override: Option<&str>,
    args: &TransferArgs,
    task: &Task,
) -> Result<PreparedConnect> {
    let _system_lock = crate::locks::local_system_lock()?;
    ensure_client_dirs()?;
    let mut api = AuthenticatedApiClient::load(api_base_override)?;
    let host = host::AvailableHostLookup::new(
        api_base_override,
        &args.network,
        &args.host,
        args.allow_pending,
    )
    .load()?;
    mesh_route::TargetRouteWait::new(
        host.alias().as_str(),
        host::transfer_mesh_route_targets(&host, args)?,
    )
    .wait(true, None)?;
    AssetPreparer::new(
        &args.network,
        &host,
        host::resolve_transfer_connect_host(&host, args)?,
        args.user.clone(),
        args.no_server_cert,
    )
    .prepare_with_status(&mut api, task)
}

fn fail_if_remote_destination_exists(prepared: &PreparedConnect, destination: &str) -> Result<()> {
    let remote_command = format!(
        "if test -e {}; then exit {REMOTE_DESTINATION_EXISTS_EXIT}; fi",
        sh_quote(destination)
    );
    let mut command = prepared.ssh_command(&[], Some(&remote_command), None, false);
    let output = run_capture(&mut command)?;
    if output.status.success() {
        return Ok(());
    }
    if output.status.code() == Some(REMOTE_DESTINATION_EXISTS_EXIT) {
        bail!(
            "remote destination `{destination}` already exists on {}",
            prepared.destination_label()
        );
    }
    let detail = output
        .stderr
        .trim()
        .lines()
        .next()
        .or_else(|| output.stdout.trim().lines().next())
        .unwrap_or("remote destination preflight failed")
        .trim();
    bail!(
        "failed to check remote destination `{destination}` on {}: {detail}",
        prepared.destination_label()
    )
}

pub(super) fn sources_and_destination(paths: &[String]) -> Result<(Vec<String>, String)> {
    if paths.is_empty() {
        bail!("transfer requires at least one source path");
    }
    if paths.iter().any(|path| path.is_empty()) {
        bail!("transfer paths must not be empty");
    }
    if paths.len() == 1 {
        return Ok((vec![paths[0].clone()], ".".to_string()));
    }
    Ok((
        paths[..paths.len() - 1].to_vec(),
        paths[paths.len() - 1].clone(),
    ))
}

fn build_rsync_command(
    prepared: &PreparedConnect,
    direction: Direction,
    sources: &[String],
    destination: &str,
    args: &TransferArgs,
    show_progress: bool,
) -> Result<Command> {
    if sources.is_empty() {
        bail!("transfer requires at least one source path");
    }

    let mut command = Command::new(rsync_program(crate::platform::detect()?));
    command.args(default_rsync_args(args, show_progress));
    command.arg(format!(
        "--rsync-path={}",
        sh_quote(rsync_program(prepared.host().platform))
    ));
    command.arg("-e");
    command.arg(strict_ssh_remote_shell(prepared, &[]));

    match direction {
        Direction::Push => {
            command.args(sources);
            command.arg(rsync_remote_path(prepared, destination));
        }
        Direction::Pull => {
            for source in sources {
                command.arg(rsync_remote_path(prepared, source));
            }
            command.arg(destination);
        }
    }

    Ok(command)
}

pub(super) fn default_rsync_args(args: &TransferArgs, show_progress: bool) -> Vec<String> {
    let mut rsync_args = vec![
        "--archive".to_string(),
        "--partial".to_string(),
        "--human-readable".to_string(),
        "--protect-args".to_string(),
    ];
    if !args.no_checksum {
        rsync_args.push("--checksum".to_string());
    }
    if !args.no_compress {
        rsync_args.push("--compress".to_string());
    }
    if args.delete {
        rsync_args.push("--delete".to_string());
    }
    if args.dry_run {
        rsync_args.push("--dry-run".to_string());
    }
    if show_progress {
        rsync_args.push("--info=progress2,stats1".to_string());
    } else {
        rsync_args.push("--info=stats1".to_string());
    }
    rsync_args.extend(args.rsync_args.iter().cloned());
    rsync_args
}

fn strict_ssh_remote_shell(prepared: &PreparedConnect, extra_ssh_args: &[String]) -> String {
    let mut parts = Vec::new();
    parts.push(sh_quote("ssh"));
    parts.extend(
        prepared
            .ssh_transport_args(extra_ssh_args, None, false)
            .into_iter()
            .map(|arg| sh_quote(&arg)),
    );
    parts.join(" ")
}

fn rsync_remote_path(prepared: &PreparedConnect, path: &str) -> String {
    format!(
        "{}@{}:{}",
        prepared.ssh_user(),
        rsync_remote_host(prepared.connect_host()),
        path
    )
}

fn rsync_remote_host(host: &str) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn rsync_program(platform: aegis_dto::platform::HostPlatform) -> &'static str {
    use aegis_dto::platform::{Architecture, OperatingSystem};
    match (platform.operating_system, platform.architecture) {
        (OperatingSystem::MacOs, Architecture::X86_64) => "/usr/local/bin/rsync",
        (OperatingSystem::MacOs, Architecture::Aarch64) => "/opt/homebrew/bin/rsync",
        _ => "rsync",
    }
}

fn validate_rsync(output: &crate::command::CommandOutput, location: &str) -> Result<()> {
    let version = output
        .stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .and_then(|value| semver::Version::parse(value).ok());
    ensure!(
        output.status.success()
            && version.is_some_and(|version| version >= semver::Version::new(3, 2, 0)),
        "{location} needs rsync 3.2 or newer; install the rsync package (macOS: brew install rsync)"
    );
    Ok(())
}
