use std::process::Command;

use anyhow::Result;

pub use capulus::process::{CommandOutput, run_status_streaming};

pub fn run_capture(command: &mut Command) -> Result<CommandOutput> {
    authorize_privileged_child(command)?;
    if crate::tunnel_operation::active() {
        crate::tunnel_operation::run_command(command, None)
    } else {
        capture(std::time::Duration::from_secs(120))?.run(command, None)
    }
}

pub fn require_success(action: &str, command: &mut Command) -> Result<CommandOutput> {
    let output = run_capture(command)?;
    check_output(action, command, output)
}

pub fn require_success_with_input(
    action: &str,
    command: &mut Command,
    input: &[u8],
) -> Result<CommandOutput> {
    authorize_privileged_child(command)?;
    let output = if crate::tunnel_operation::active() {
        crate::tunnel_operation::run_command(command, Some(input))?
    } else {
        capture(std::time::Duration::from_secs(120))?.run(command, Some(input))?
    };
    check_output(action, command, output)
}

pub(crate) fn run_install(command: &mut Command, input: Option<&[u8]>) -> Result<()> {
    authorize_privileged_child(command)?;
    crate::ui::stage("Running installation; child output follows (90-minute deadline)");
    let output = crate::ui::suspend(|| {
        capture(std::time::Duration::from_secs(90 * 60))?.run_streaming(command, input)
    })?;
    check_output("install system components", command, output).map(|_| ())
}

fn capture(timeout: std::time::Duration) -> Result<capulus::process::CaptureConfig> {
    capulus::process::CaptureOptions {
        timeout,
        cancellation: crate::ui::cancellation(),
        ..Default::default()
    }
    .validate()
}

fn authorize_privileged_child(command: &Command) -> Result<()> {
    if std::path::Path::new(command.get_program()).file_name() != Some(std::ffi::OsStr::new("sudo"))
    {
        return Ok(());
    }
    let probe = capture(std::time::Duration::from_secs(10))?
        .run(Command::new("/usr/bin/sudo").args(["-n", "-v"]), None)?;
    if probe.status.success() {
        return Ok(());
    }
    crate::ui::stage(&format!(
        "Waiting for sudo authorization (started {} UTC)",
        time::OffsetDateTime::now_utc()
    ));
    let mut authorize = Command::new("/usr/bin/sudo");
    if std::env::var_os("SUDO_ASKPASS").is_some() {
        authorize.arg("-A");
    }
    let status = crate::ui::suspend(|| authorize.arg("-v").status())?;
    crate::ui::check_cancelled()?;
    anyhow::ensure!(status.success(), "sudo authorization failed");
    Ok(())
}

fn check_output(action: &str, command: &Command, output: CommandOutput) -> Result<CommandOutput> {
    if output.status.success() {
        return Ok(output);
    }
    anyhow::bail!(
        "Failed to {action} while running `{}`: {}",
        capulus::process::render_command(command),
        if output.stderr.trim().is_empty() {
            output.stdout.trim()
        } else {
            output.stderr.trim()
        }
    );
}

pub fn run_status(command: &mut Command) -> Result<i32> {
    capulus::process::run_status_code(command)
}

#[cfg(test)]
mod tests {
    use super::require_success;
    use capulus::process::{render_command, run_with_input};
    use std::process::Command;

    #[test]
    fn render_command_quotes_args_with_whitespace() {
        let mut command = Command::new("ssh");
        command.args(["user@example.com", "echo hello world"]);

        assert_eq!(
            "ssh 'user@example.com' 'echo hello world'",
            render_command(&command)
        );
    }

    #[test]
    fn run_with_input_pipes_stdin_to_child() {
        let mut command = Command::new("cat");
        let output = run_with_input(&mut command, b"abc\n").expect("cat should succeed");

        assert!(output.status.success());
        assert_eq!("abc\n", output.stdout);
    }

    #[test]
    fn require_success_reports_stdout_when_stderr_is_empty() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'stdout-only'; exit 2"]);

        let error =
            require_success("run failing command", &mut command).expect_err("command should fail");
        let text = error.to_string();
        assert!(text.contains("Failed to run failing command"));
        assert!(text.contains("stdout-only"));
    }
}
