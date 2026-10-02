use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::{Context, Result, anyhow, bail};
use capulus::shell::shell_quote as sh_quote;
use tempfile::{TempDir, TempPath};

use crate::command::{
    CommandOutput, require_success, require_success_with_input, run_capture, run_status_streaming,
};
use crate::ui;

use super::{
    REMOTE_HOST_KEY_PATH, REMOTE_SUDO_PASSWORD_HELPER_PATH, RemoteTarget, SYSTEM_AEGIS_BIN,
    WIREGUARD_PUBLIC_KEY_PATH,
};

pub(super) trait RemoteBootstrapSession {
    fn run_shell_capture(&self, shell_body: &str) -> Result<CommandOutput>;

    fn run_shell_capture_with_input(&self, shell_body: &str, input: &[u8])
    -> Result<CommandOutput>;

    fn run_shell_streaming_with_tty(&self, shell_body: &str) -> Result<()>;

    fn cleanup(&self) -> Result<()>;

    fn load_enroll_state(&self, publish_ssh: bool) -> Result<EnrollState> {
        let host_public_key = if publish_ssh {
            format!(
                "HOST_PUBLIC_KEY=\"$(cat {REMOTE_HOST_KEY_PATH}.pub)\"\n\
                 printf 'HOST_PUBLIC_KEY=%s\\n' \"$HOST_PUBLIC_KEY\"\n"
            )
        } else {
            String::new()
        };
        let output = self.run_shell_capture(&format!(
            "WIREGUARD_PUBLIC_KEY=\"$(cat {WIREGUARD_PUBLIC_KEY_PATH})\"\n\
             printf 'WIREGUARD_PUBLIC_KEY=%s\\n' \"$WIREGUARD_PUBLIC_KEY\"\n\
             {host_public_key}"
        ))?;
        EnrollState::parse(&output.stdout, publish_ssh)
    }

    fn run_private_shell_streaming_with_tty(&self, shell_body: &str) -> Result<()> {
        let output = self.run_shell_capture(
            "install -d -m 700 \"$HOME/.cache/aegis\"\n\
             mktemp \"$HOME/.cache/aegis/remote-command.XXXXXX.sh\"\n",
        )?;
        let remote_path = output.stdout.trim().to_string();
        if remote_path.is_empty() {
            bail!("remote private script path was empty");
        }
        let upload = format!(
            "path={}\n\
             install -d -m 700 \"$(dirname \"$path\")\"\n\
             cat > \"$path\"\n\
             chmod 700 \"$path\"\n",
            sh_quote(&remote_path),
        );
        self.run_shell_capture_with_input(&upload, shell_body.as_bytes())
            .context("failed to upload remote private script")?;
        let result = self.run_shell_streaming_with_tty(&format!("bash {}", sh_quote(&remote_path)));
        let cleanup = self.run_shell_capture(&format!("rm -f {}\n", sh_quote(&remote_path)));
        match (result, cleanup) {
            (Ok(()), Ok(_)) => Ok(()),
            (Ok(()), Err(error)) => Err(error).context("failed to remove remote private script"),
            (Err(error), Ok(_)) => Err(error),
            (Err(error), Err(cleanup_error)) => {
                ui::warn(&format!(
                    "failed to remove remote private script after command failure: {cleanup_error}"
                ));
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct BootstrapSession<'a> {
    target: &'a RemoteTarget,
    _control_dir: TempDir,
    control_socket: PathBuf,
    _local_askpass: TempPath,
}

impl<'a> BootstrapSession<'a> {
    pub(super) fn open(
        target: &'a RemoteTarget,
        socket_name: &str,
        prompt: PasswordPrompt<'_>,
    ) -> Result<Self> {
        let task = ui::task(ui::TaskOptions {
            label: format!(
                "Opening bootstrap session to {}@{}",
                target.user, target.host
            ),
            visibility: ui::TaskVisibility::Immediate,
            ..ui::TaskOptions::default()
        })?;
        let result = (|| {
            task.set_phase("waiting for the remote machine password");
            let password = ui::suspend(|| prompt.read(target))?;
            let local_askpass = LocalAskpassScript::new(&password).write()?;
            let control_dir =
                tempfile::tempdir().context("failed to create temporary control socket dir")?;
            let control_socket = control_dir.path().join(socket_name);

            task.set_phase("opening the public SSH control connection");
            ui::suspend(|| {
                target.open_password_control_master(&control_socket, local_askpass.as_ref())
            })?;
            task.set_phase("installing the remote sudo password helper");
            target.install_sudo_password_helper(&control_socket, &password)?;

            Ok(Self {
                target,
                _control_dir: control_dir,
                control_socket,
                _local_askpass: local_askpass,
            })
        })();
        match result {
            Ok(session) => {
                task.finish("Bootstrap SSH control connection is ready");
                Ok(session)
            }
            Err(error) => {
                task.fail("Bootstrap SSH connection failed");
                Err(error)
            }
        }
    }

    pub(super) fn run_shell_capture(&self, shell_body: &str) -> Result<CommandOutput> {
        self.target
            .run_shell_capture(&self.control_socket, shell_body)
    }

    fn run_shell_capture_with_input(
        &self,
        shell_body: &str,
        input: &[u8],
    ) -> Result<CommandOutput> {
        self.target
            .run_shell_capture_with_input(&self.control_socket, shell_body, input)
    }

    pub(super) fn run_shell_streaming_with_tty(&self, shell_body: &str) -> Result<()> {
        self.target
            .run_shell_streaming_with_tty(&self.control_socket, shell_body)
    }

    pub(super) fn has_trusted_system_aegis(&self) -> Result<bool> {
        let output = self.run_shell_capture(&format!(
            "if test -f {installed} && test ! -L {installed} && test -x {installed} && \\\n               test \"$(stat -c '%u:%g' {installed})\" = '0:0' && \\\n               test \"$(stat -c '%a' {installed})\" = '755'; then\n\
               printf 'trusted\\n'\n\
             fi\n",
            installed = sh_quote(SYSTEM_AEGIS_BIN),
        ))?;
        Ok(output.stdout.trim() == "trusted")
    }

    pub(super) fn run_aegis_unenroll(&self, api_base: &str, host_alias: &str) -> Result<()> {
        let remote_command = SudoScript::new(&format!(
            "sudo -v\n\
             sudo -- {} --api-base {} manage unenroll {} --local --skip-api-delete\n",
            sh_quote(SYSTEM_AEGIS_BIN),
            sh_quote(api_base),
            sh_quote(host_alias),
        ))
        .render();
        let mut command = self.target.ambient_ssh_command(
            Some(&remote_command),
            Some(&self.control_socket),
            TtyMode::Force,
            ControlMasterMode::Disabled,
        );
        run_status_streaming(&mut command, "run remote aegis unenroll")
    }

    pub(super) fn cleanup(&self) -> Result<()> {
        let helper = self
            .target
            .remove_sudo_password_helper(&self.control_socket);
        let control = self.target.close_control_master(&self.control_socket);
        helper.and(control)
    }
}

impl RemoteBootstrapSession for BootstrapSession<'_> {
    fn run_shell_capture(&self, shell_body: &str) -> Result<CommandOutput> {
        Self::run_shell_capture(self, shell_body)
    }

    fn run_shell_capture_with_input(
        &self,
        shell_body: &str,
        input: &[u8],
    ) -> Result<CommandOutput> {
        Self::run_shell_capture_with_input(self, shell_body, input)
    }

    fn run_shell_streaming_with_tty(&self, shell_body: &str) -> Result<()> {
        Self::run_shell_streaming_with_tty(self, shell_body)
    }

    fn cleanup(&self) -> Result<()> {
        Self::cleanup(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PasswordPrompt<'a> {
    text: &'a str,
}

impl<'a> PasswordPrompt<'a> {
    pub(super) fn new(text: &'a str) -> Self {
        Self { text }
    }

    fn read(&self, target: &RemoteTarget) -> Result<String> {
        if let Some(password) = env::var("AEGIS_REMOTE_PASSWORD")
            .ok()
            .filter(|password| !password.is_empty())
        {
            return Ok(password);
        }

        if !io::stdin().is_terminal() {
            bail!(
                "remote password prompt for {}@{} requires an interactive terminal; set AEGIS_REMOTE_PASSWORD for automation",
                target.user,
                target.host
            );
        }

        eprintln!("{}", self.text);
        eprint!("Password for {}@{}: ", target.user, target.host);
        io::stderr()
            .flush()
            .context("failed to flush password prompt")?;

        let _echo_guard = TerminalEchoGuard::disable(libc::STDIN_FILENO)?;
        let mut password = String::new();
        io::stdin()
            .read_line(&mut password)
            .context("failed to read remote machine password")?;
        drop(_echo_guard);
        eprintln!();

        let password = password.trim_end_matches(['\r', '\n']).to_string();
        if password.is_empty() {
            bail!(
                "the supplied password for {}@{} was empty",
                target.user,
                target.host
            );
        }
        Ok(password)
    }
}

struct TerminalEchoGuard {
    fd: libc::c_int,
    original: libc::termios,
    restored: bool,
}

impl TerminalEchoGuard {
    fn disable(fd: libc::c_int) -> Result<Self> {
        let original = unsafe {
            let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(fd, original.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error())
                    .context("failed to read terminal echo settings");
            }
            original.assume_init()
        };
        let mut without_echo = original;
        without_echo.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &without_echo) } != 0 {
            return Err(io::Error::last_os_error()).context("failed to disable terminal echo");
        }
        Ok(Self {
            fd,
            original,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(super) struct SudoScript<'a> {
    body: &'a str,
}

impl<'a> SudoScript<'a> {
    pub(super) fn new(body: &'a str) -> Self {
        Self { body }
    }

    pub(super) fn render(&self) -> String {
        let body = self
            .body
            .strip_prefix("set -euo pipefail\n")
            .unwrap_or(self.body);
        format!(
            "set -euo pipefail\n{sudo_defs}{body}",
            sudo_defs = SudoPasswordScript::function_definition(),
        )
    }
}

pub(super) struct ShellCommand<'a> {
    body: &'a str,
}

impl<'a> ShellCommand<'a> {
    pub(super) fn new(body: &'a str) -> Self {
        Self { body }
    }

    pub(super) fn render(&self) -> String {
        format!("bash --noprofile --norc -ceu {}", sh_quote(self.body))
    }
}

#[derive(Debug, Clone)]
pub(super) struct EnrollState {
    pub(super) wireguard_public_key: String,
    pub(super) host_public_key: Option<String>,
}

impl EnrollState {
    fn parse(content: &str, publish_ssh: bool) -> Result<Self> {
        let mut wireguard_public_key = None;
        let mut host_public_key = None;
        for line in content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid remote enroll state line `{line}`"))?;
            match name {
                "WIREGUARD_PUBLIC_KEY" => wireguard_public_key = Some(value.to_string()),
                "HOST_PUBLIC_KEY" => host_public_key = Some(value.to_string()),
                _ => bail!("unexpected remote enroll state field `{name}`"),
            }
        }

        Ok(Self {
            wireguard_public_key: wireguard_public_key
                .ok_or_else(|| anyhow!("remote enroll state is missing WIREGUARD_PUBLIC_KEY"))?,
            host_public_key: match (publish_ssh, host_public_key) {
                (true, None) => {
                    return Err(anyhow!("remote enroll state is missing HOST_PUBLIC_KEY"));
                }
                (false, Some(_)) => {
                    return Err(anyhow!(
                        "remote enroll state unexpectedly contains HOST_PUBLIC_KEY"
                    ));
                }
                (_, host_public_key) => host_public_key,
            },
        })
    }
}

impl RemoteTarget {
    fn ambient_ssh_command(
        &self,
        remote_command: Option<&str>,
        control_socket: Option<&Path>,
        tty: TtyMode,
        control_master: ControlMasterMode,
    ) -> Command {
        let mut command = Command::new("ssh");
        command.arg(tty.arg());
        command.args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
        ]);
        command.arg("-p");
        command.arg(self.port.to_string());
        if let Some(control_socket) = control_socket {
            command.arg("-S");
            command.arg(control_socket.display().to_string());
        }
        match control_master {
            ControlMasterMode::Default => {}
            ControlMasterMode::Disabled => {
                command.args(["-o", "ControlMaster=no"]);
            }
            ControlMasterMode::Background => {
                command.args(["-M", "-N", "-f", "-o", "ControlPersist=600"]);
            }
        };
        command.arg(format!("{}@{}", self.user, self.host));
        if let Some(remote_command) = remote_command {
            command.arg(remote_command);
        }
        command
    }

    fn password_ambient_ssh_command(
        &self,
        remote_command: Option<&str>,
        control_socket: Option<&Path>,
        tty: TtyMode,
        control_master: ControlMasterMode,
        askpass_path: &Path,
    ) -> Command {
        let mut command =
            self.ambient_ssh_command(remote_command, control_socket, tty, control_master);
        command.env("SSH_ASKPASS", askpass_path);
        command.env("SSH_ASKPASS_REQUIRE", "force");
        if env::var_os("DISPLAY").is_none() {
            command.env("DISPLAY", ":0");
        }
        if let Some(value) = env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            command.env("DBUS_SESSION_BUS_ADDRESS", value);
        }
        if let Some(value) = env::var_os("WAYLAND_DISPLAY") {
            command.env("WAYLAND_DISPLAY", value);
        }
        if let Some(value) = env::var_os("XDG_RUNTIME_DIR") {
            command.env("XDG_RUNTIME_DIR", value);
        }
        command.stdin(Stdio::null());
        command.args([
            "-o",
            "BatchMode=no",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "ConnectTimeout=10",
        ]);
        command
    }

    fn open_password_control_master(
        &self,
        control_socket: &Path,
        askpass_path: &Path,
    ) -> Result<()> {
        if control_socket.exists() {
            let _ = fs::remove_file(control_socket);
        }
        if let Some(parent) = control_socket.parent() {
            capulus::store::ensure_directory(parent, Some(0o700))?;
        }

        let mut command = self.password_ambient_ssh_command(
            None,
            Some(control_socket),
            TtyMode::None,
            ControlMasterMode::Background,
            askpass_path,
        );
        run_status_streaming(&mut command, "open ambient ssh control master")?;

        let deadline = Instant::now() + Duration::from_secs(5);
        while !control_socket.exists() {
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for ssh control socket {}",
                    control_socket.display()
                );
            }
            ui::sleep(Duration::from_millis(100))?;
        }
        Ok(())
    }

    fn close_control_master(&self, control_socket: &Path) -> Result<()> {
        let mut command = Command::new("ssh");
        command.arg("-S");
        command.arg(control_socket.display().to_string());
        command.arg("-O");
        command.arg("exit");
        command.arg("-p");
        command.arg(self.port.to_string());
        command.arg(format!("{}@{}", self.user, self.host));
        let _ = run_capture(&mut command)?;
        Ok(())
    }

    fn run_shell_capture(&self, control_socket: &Path, shell_body: &str) -> Result<CommandOutput> {
        let mut command = self.ambient_ssh_command(
            Some(&ShellCommand::new(shell_body).render()),
            Some(control_socket),
            TtyMode::None,
            ControlMasterMode::Default,
        );
        require_success("run remote ssh command", &mut command)
    }

    fn run_shell_capture_with_input(
        &self,
        control_socket: &Path,
        shell_body: &str,
        input: &[u8],
    ) -> Result<CommandOutput> {
        let mut command = self.ambient_ssh_command(
            Some(&ShellCommand::new(shell_body).render()),
            Some(control_socket),
            TtyMode::None,
            ControlMasterMode::Default,
        );
        require_success_with_input("run remote ssh command", &mut command, input)
    }

    fn run_shell_streaming_with_tty(&self, control_socket: &Path, shell_body: &str) -> Result<()> {
        let mut command = self.ambient_ssh_command(
            Some(&ShellCommand::new(shell_body).render()),
            Some(control_socket),
            TtyMode::Force,
            ControlMasterMode::Default,
        );
        crate::command::run_install(&mut command, None)
    }

    fn upload_file(
        &self,
        control_socket: &Path,
        remote_path_shell: &str,
        content: &[u8],
        mode: u32,
    ) -> Result<()> {
        let remote_command = ShellCommand::new(&format!(
            "path=\"{remote_path_shell}\"\n\
             install -d -m 700 \"$(dirname \"$path\")\"\n\
             cat > \"$path\"\n\
             chmod {mode:o} \"$path\"\n",
        ))
        .render();
        let mut command = self.ambient_ssh_command(
            Some(&remote_command),
            Some(control_socket),
            TtyMode::None,
            ControlMasterMode::Default,
        );
        require_success_with_input("upload remote file", &mut command, content)?;
        Ok(())
    }

    fn remove_file(&self, control_socket: &Path, remote_path_shell: &str) -> Result<()> {
        self.run_shell_capture(
            control_socket,
            &format!(
                "path=\"{remote_path_shell}\"\n\
                 rm -f \"$path\"\n",
            ),
        )?;
        Ok(())
    }

    fn install_sudo_password_helper(&self, control_socket: &Path, password: &str) -> Result<()> {
        self.upload_file(
            control_socket,
            REMOTE_SUDO_PASSWORD_HELPER_PATH,
            SudoPasswordScript::new(password).render().as_bytes(),
            0o700,
        )
    }

    fn remove_sudo_password_helper(&self, control_socket: &Path) -> Result<()> {
        self.remove_file(control_socket, REMOTE_SUDO_PASSWORD_HELPER_PATH)
    }
}

#[derive(Debug, Clone, Copy)]
enum ControlMasterMode {
    Default,
    Disabled,
    Background,
}

#[derive(Debug, Clone, Copy)]
enum TtyMode {
    None,
    Force,
}

impl TtyMode {
    const fn arg(self) -> &'static str {
        match self {
            Self::None => "-T",
            Self::Force => "-tt",
        }
    }
}

struct LocalAskpassScript<'a> {
    password: &'a str,
}

impl<'a> LocalAskpassScript<'a> {
    fn new(password: &'a str) -> Self {
        Self { password }
    }

    fn write(&self) -> Result<TempPath> {
        let mut file =
            tempfile::NamedTempFile::new().context("failed to create local SSH askpass helper")?;
        file.write_all(self.render().as_bytes())
            .context("failed to write local SSH askpass helper")?;
        #[cfg(unix)]
        fs::set_permissions(file.path(), Permissions::from_mode(0o700))
            .context("failed to chmod local SSH askpass helper")?;
        Ok(file.into_temp_path())
    }

    fn render(&self) -> String {
        format!("#!/bin/sh\nprintf '%s' {}\n", sh_quote(self.password))
    }
}

struct SudoPasswordScript<'a> {
    password: &'a str,
}

impl<'a> SudoPasswordScript<'a> {
    fn new(password: &'a str) -> Self {
        Self { password }
    }

    fn render(&self) -> String {
        format!("#!/bin/sh\nprintf '%s' {}\n", sh_quote(self.password))
    }

    fn function_definition() -> String {
        format!(
            concat!(
                "sudo() {{\n",
                "  command sudo -n -v 2>/dev/null || ",
                "\"{REMOTE_SUDO_PASSWORD_HELPER_PATH}\" | command sudo -S -p '' -v\n",
                "  command sudo \"$@\"\n",
                "}}\n",
            ),
            REMOTE_SUDO_PASSWORD_HELPER_PATH = REMOTE_SUDO_PASSWORD_HELPER_PATH,
        )
    }
}
