use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::{Context, Result, anyhow, bail};
use capulus::shell::shell_quote as sh_quote;

use crate::cli::InstallArgs;
use crate::command::{require_success, require_success_with_input, run_capture};
use crate::config::agent_refresh_token_env_value;
use crate::ui;

use super::{
    AEGIS_AGENT_REFRESH_TOKEN_ENV, REMOTE_HOST_CERT_PATH, WIREGUARD_DIR,
    WIREGUARD_PRIVATE_KEY_PATH, WIREGUARD_PUBLIC_KEY_PATH,
};

pub(super) struct LocalRoot;

impl LocalRoot {
    pub(super) fn reexec_if_needed() -> Result<Option<i32>> {
        #[cfg(unix)]
        {
            if !Self::is_running() {
                crate::locks::prepare_user_auth_lock_for_privileged_reexec()?;
                let mut command = Self::sudo_command();
                command.arg(trusted_system_aegis()?);
                command.args(env::args_os().skip(1));
                let status = ui::suspend(|| command.status()).context("failed to invoke sudo")?;
                return Ok(Some(status.code().unwrap_or(1)));
            }
        }

        Ok(None)
    }

    pub(super) fn reinstall_requires_explicit_user(args: &InstallArgs) -> bool {
        DirectRootReinstall::new(Self::is_direct(), args.reinstall, args.user.as_deref())
            .requires_explicit_user()
    }

    pub(super) fn is_direct() -> bool {
        Self::is_running() && env::var_os("SUDO_USER").is_none()
    }

    pub(super) fn is_running() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub(super) fn sudo_command() -> Command {
        let mut command = Command::new("/usr/bin/sudo");
        capulus::configure_privileged_child_command(&mut command, "sudo");
        if env::var_os("SUDO_ASKPASS").is_some() {
            command.arg("-A");
        }
        command.arg(
            "--preserve-env=HOME,USER,SUDO_USER,SUDO_ASKPASS,DISPLAY,DBUS_SESSION_BUS_ADDRESS,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,AEGIS_AGENT_REFRESH_TOKEN_B64",
        );
        command
    }

    pub(super) fn run_script(script: &str) -> Result<()> {
        let mut command = Self::sudo_command();
        command.arg("bash");
        command.arg("-seuo");
        command.arg("pipefail");
        crate::command::run_install(&mut command, Some(script.as_bytes()))
    }

    pub(super) fn require_ubuntu() -> Result<()> {
        let os_release =
            fs::read_to_string("/etc/os-release").context("failed to read /etc/os-release")?;
        if os_release
            .lines()
            .any(|line| matches!(line.trim(), "ID=ubuntu" | "ID=\"ubuntu\""))
        {
            Ok(())
        } else {
            bail!("only Ubuntu is supported")
        }
    }

    pub(super) fn install_ubuntu_packages(packages: &[&str]) -> Result<()> {
        Self::run_script(&format!(
            "{}retry env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {}\n",
            Bird3Repository::without_sudo().setup_script(),
            packages.join(" "),
        ))
    }

    pub(super) fn install_ubuntu_packages_without_sudo(packages: &[&str]) -> Result<()> {
        let mut command = Command::new("sh");
        command.args([
            "-ceu",
            &format!(
                "{}retry env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {}\n",
                Bird3Repository::without_sudo().setup_script(),
                packages.join(" "),
            ),
        ]);
        crate::command::run_install(&mut command, None)
    }

    pub(super) fn read_file_trimmed(path: &str) -> Result<String> {
        let mut command = Self::sudo_command();
        command.args(["cat", path]);
        Ok(require_success("read local root-owned file", &mut command)?
            .stdout
            .trim()
            .to_string())
    }

    pub(super) fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
        let path = sh_quote(&path.display().to_string());
        let mut command = Self::sudo_command();
        command.args([
            "sh",
            "-ceu",
            &format!("cat > {path} && chmod {mode:o} {path}"),
        ]);
        require_success_with_input("write local root-owned file", &mut command, content)?;
        Ok(())
    }

    pub(super) fn install_server_certificate(content: &[u8]) -> Result<()> {
        Self::write_file(Path::new(REMOTE_HOST_CERT_PATH), content, 0o644)
    }

    pub(super) fn run_aegis_command(
        api_base: &str,
        args: &[String],
        agent_token: &str,
    ) -> Result<()> {
        let mut command = Self::sudo_command();
        command.env(
            AEGIS_AGENT_REFRESH_TOKEN_ENV,
            agent_refresh_token_env_value(agent_token),
        );
        command.arg(trusted_system_aegis()?);
        command.arg("--api-base");
        command.arg(api_base);
        command.args(args);
        crate::command::run_install(&mut command, None)
    }
}

fn trusted_system_aegis() -> Result<PathBuf> {
    crate::managed::product()?
        .program()
        .trusted_installed_path()
        .map(Path::to_path_buf)
        .context(
            "trusted system Aegis is unavailable; bootstrap the published aegis-tool release before requesting a privileged Aegis operation",
        )
}

pub(super) struct DirectRootReinstall<'a> {
    running_as_direct_root: bool,
    reinstall: bool,
    user: Option<&'a str>,
}

impl<'a> DirectRootReinstall<'a> {
    pub(super) fn new(
        running_as_direct_root: bool,
        reinstall: bool,
        user: Option<&'a str>,
    ) -> Self {
        Self {
            running_as_direct_root,
            reinstall,
            user,
        }
    }

    pub(super) fn requires_explicit_user(&self) -> bool {
        self.running_as_direct_root && self.reinstall && self.user.is_none()
    }
}

pub(super) struct LoginPrincipal;

impl LoginPrincipal {
    pub(super) fn current() -> Result<String> {
        env::var("SUDO_USER")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                env::var("USER")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            })
            .ok_or_else(|| anyhow!("failed to determine the local login principal"))
    }
}

pub(super) struct Systemd;

impl Systemd {
    pub(super) fn daemon_reload() -> Result<()> {
        require_success(
            "reload systemd daemon",
            Command::new("systemctl").args(["daemon-reload"]),
        )?;
        Ok(())
    }
}

pub(super) struct SystemdUnit {
    name: String,
}

impl SystemdUnit {
    pub(super) fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub(super) fn enable_now(&self) -> Result<()> {
        require_success(
            &format!("enable {}", self.name),
            Command::new("systemctl").args(self.enable_args()),
        )?;
        self.restart()
    }

    fn enable_args(&self) -> [&str; 2] {
        ["enable", &self.name]
    }

    pub(super) fn restart(&self) -> Result<()> {
        let _ = run_capture(Command::new("systemctl").args(["reset-failed", &self.name]));
        require_success(
            &format!("restart {}", self.name),
            Command::new("systemctl").args(["restart", &self.name]),
        )?;
        Ok(())
    }

    pub(super) fn disable_now(&self) -> Result<()> {
        let mut disable = Command::new("systemctl");
        disable.args(["disable", "--now", &self.name]);
        if let Ok(output) = run_capture(&mut disable)
            && output.status.success()
        {
            return Ok(());
        }
        let mut stop = Command::new("systemctl");
        stop.args(["stop", &self.name]);
        if let Ok(output) = run_capture(&mut stop)
            && output.status.success()
        {
            return Ok(());
        }
        Ok(())
    }

    fn is_active(&self) -> bool {
        let mut command = Command::new("systemctl");
        command.args(["is-active", "--quiet", &self.name]);
        run_capture(&mut command)
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

pub(super) struct TextFile<'a> {
    path: &'a Path,
}

impl<'a> TextFile<'a> {
    pub(super) fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub(super) fn write_atomic(&self, content: &str, mode: u32) -> Result<()> {
        capulus::store::atomic_write(self.path, content.as_bytes(), Some(mode), Some(0o755))
    }

    pub(super) fn remove_if_exists(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_file(self.path)
                .with_context(|| format!("failed to remove {}", self.path.display()))?;
        }
        Ok(())
    }
}

pub(super) struct Sshd;

impl Sshd {
    pub(super) fn write_dropin(path: &Path, content: &str) -> Result<()> {
        let previous = if path.exists() {
            Some(
                fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
            )
        } else {
            None
        };

        TextFile::new(path).write_atomic(content, 0o644)?;
        if let Err(error) = Self::validate_config() {
            match previous {
                Some(previous) => TextFile::new(path).write_atomic(&previous, 0o644)?,
                None => {
                    let _ = fs::remove_file(path);
                }
            }
            let _ = Self::validate_config();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn remove_dropin(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let previous = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
        if let Err(error) = Self::validate_config() {
            TextFile::new(path).write_atomic(&previous, 0o644)?;
            let _ = Self::validate_config();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn reload() -> Result<()> {
        for unit in ["ssh.service", "sshd.service"] {
            if SystemdUnit::new(unit).is_active() {
                for args in [["reload", unit], ["restart", unit]] {
                    let mut command = Command::new("systemctl");
                    command.args(args);
                    if let Ok(output) = run_capture(&mut command)
                        && output.status.success()
                    {
                        return Ok(());
                    }
                }
            }
        }

        for args in [
            ["ssh", "reload"],
            ["sshd", "reload"],
            ["ssh", "restart"],
            ["sshd", "restart"],
        ] {
            let mut command = Command::new("service");
            command.args(args);
            if let Ok(output) = run_capture(&mut command)
                && output.status.success()
            {
                return Ok(());
            }
        }

        if ["ssh.socket", "sshd.socket"]
            .into_iter()
            .any(|unit| SystemdUnit::new(unit).is_active())
        {
            return Ok(());
        }

        bail!("failed to reload sshd using systemctl/service")
    }

    fn validate_config() -> Result<()> {
        let _ = fs::create_dir_all("/run/sshd");
        #[cfg(unix)]
        let _ = fs::set_permissions("/run/sshd", Permissions::from_mode(0o755));
        let mut saw_binary = false;
        for program in ["sshd", "/usr/sbin/sshd"] {
            let mut command = Command::new(program);
            command.arg("-t");
            if let Ok(output) = run_capture(&mut command) {
                saw_binary = true;
                if output.status.success() {
                    return Ok(());
                }
            }
        }
        if saw_binary {
            bail!("sshd configuration test failed");
        } else {
            bail!("could not find sshd to validate configuration");
        }
    }
}

pub(super) struct LoopbackInterface;

impl LoopbackInterface {
    pub(super) fn addresses() -> Result<Vec<String>> {
        let output = require_success(
            "list loopback interface addresses",
            Command::new("ip").args(["-o", "address", "show", "dev", "lo"]),
        )?;
        let mut addresses = BTreeSet::new();
        for line in output.stdout.lines() {
            let mut fields = line.split_whitespace();
            let Some(family) = fields.nth(2) else {
                continue;
            };
            if family != "inet" && family != "inet6" {
                continue;
            }
            let Some(address) = fields.next() else {
                continue;
            };
            if let Some((ip, _)) = address.split_once('/') {
                addresses.insert(ip.to_string());
            }
        }
        Ok(addresses.into_iter().collect())
    }
}

pub(super) struct Bird3Repository {
    command_prefix: CommandPrefix,
}

impl Bird3Repository {
    pub(super) fn without_sudo() -> Self {
        Self {
            command_prefix: CommandPrefix::None,
        }
    }

    pub(super) fn with_sudo() -> Self {
        Self {
            command_prefix: CommandPrefix::Sudo,
        }
    }

    pub(super) fn setup_script(&self) -> String {
        let prefix = self.command_prefix.shell_prefix();
        let curl_retry_args =
            "--retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 --max-time 60 -fsSL";
        let install_sources = match self.command_prefix {
            CommandPrefix::None => "install -d -m 755 /usr/share/keyrings /etc/apt/sources.list.d",
            CommandPrefix::Sudo => {
                "sudo install -d -m 755 /usr/share/keyrings /etc/apt/sources.list.d"
            }
        };
        format!(
            "{prefix}rm -f /etc/apt/sources.list.d/cznic-bird3.list /etc/apt/sources.list.d/cznic-bird3.sources\n\
             retry() {{\n\
               attempts=0\n\
               until \"$@\"; do\n\
                 attempts=$((attempts + 1))\n\
                 if [ \"$attempts\" -ge 5 ]; then\n\
                   return 1\n\
                 fi\n\
                 sleep \"$attempts\"\n\
               done\n\
             }}\n\
             retry {prefix}apt-get -o Acquire::Retries=5 -o Acquire::Languages=none update\n\
             retry {prefix}env DEBIAN_FRONTEND=noninteractive apt-get install -y \\\n\
               --no-install-recommends ca-certificates curl gnupg\n\
             . /etc/os-release\n\
             repo_index=\"$(retry curl {curl_retry_args} https://pkg.labs.nic.cz/bird3/dists/)\"\n\
             has_suite() {{ printf '%s\n' \"$repo_index\" | grep -q \">${{1}}/<\"; }}\n\
             bird_suite=\"${{VERSION_CODENAME}}\"\n\
             if ! has_suite \"$bird_suite\"; then\n\
               case \"${{ID:-}}\" in\n\
                 ubuntu)\n\
                   for candidate in questing plucky noble jammy focal bionic; do\n\
                     if has_suite \"$candidate\"; then\n\
                       bird_suite=\"$candidate\"\n\
                       break\n\
                     fi\n\
                   done\n\
                   ;;\n\
                 debian)\n\
                   for candidate in trixie bookworm bullseye buster; do\n\
                     if has_suite \"$candidate\"; then\n\
                       bird_suite=\"$candidate\"\n\
                       break\n\
                     fi\n\
                   done\n\
                   ;;\n\
                 *)\n\
                   echo \"unsupported distro for bird3 repo: ${{ID:-unknown}}\" >&2\n\
                   exit 1\n\
                   ;;\n\
               esac\n\
             fi\n\
             if ! has_suite \"$bird_suite\"; then\n\
               echo \"no supported bird3 suite found for ${{ID:-unknown}}/${{VERSION_CODENAME:-unknown}}\" >&2\n\
               exit 1\n\
             fi\n\
             bird_arch=\"$(dpkg --print-architecture)\"\n\
             bird_suite_release_url=\"https://pkg.labs.nic.cz/bird3/dists/$bird_suite/InRelease\"\n\
             suite_release=\"$(retry curl {curl_retry_args} \"$bird_suite_release_url\")\"\n\
             repo_arches=\"$(printf '%s\n' \"$suite_release\" | sed -n 's/^Architectures: //p')\"\n\
             case \" $repo_arches \" in\n\
               *\" $bird_arch \"*)\n\
                 ;;\n\
               *)\n\
                 echo \"bird3 repo does not support architecture $bird_arch for suite $bird_suite\" >&2\n\
                 exit 1\n\
                 ;;\n\
             esac\n\
             {install_sources}\n\
             tmp_gnupg=\"$(mktemp -d)\"\n\
             chmod 700 \"$tmp_gnupg\"\n\
             gpg_key_file=\"$(mktemp)\"\n\
             gpg_keyring_file=\"$(mktemp)\"\n\
             source_file=\"$(mktemp)\"\n\
             trap 'rm -rf \"$tmp_gnupg\"; rm -f \"$gpg_key_file\" \"$gpg_keyring_file\" \"$source_file\"' EXIT\n\
             retry curl {curl_retry_args} -o \"$gpg_key_file\" https://pkg.labs.nic.cz/gpg\n\
             env GNUPGHOME=\"$tmp_gnupg\" gpg --batch --yes --dearmor \\\n\
               -o \"$gpg_keyring_file\" \"$gpg_key_file\"\n\
             printf 'Types: deb\\nURIs: https://pkg.labs.nic.cz/bird3\\nSuites: %s\\nComponents: main\\nArchitectures: %s\\nSigned-By: /usr/share/keyrings/cznic-labs-bird3.gpg\\n' \"$bird_suite\" \"$bird_arch\" > \"$source_file\"\n\
             {prefix}install -o root -g root -m 0644 \"$gpg_keyring_file\" /usr/share/keyrings/cznic-labs-bird3.gpg\n\
             {prefix}install -o root -g root -m 0644 \"$source_file\" /etc/apt/sources.list.d/cznic-bird3.sources\n\
             retry {prefix}apt-get -o Acquire::Retries=5 -o Acquire::Languages=none update\n",
            curl_retry_args = curl_retry_args,
        )
    }
}

enum CommandPrefix {
    None,
    Sudo,
}

impl CommandPrefix {
    fn shell_prefix(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Sudo => "sudo ",
        }
    }
}

pub(super) struct WireGuardKeypairInstallScript;

impl WireGuardKeypairInstallScript {
    pub(super) fn render() -> String {
        format!(
            "set -euo pipefail\n\
             install -d -m 700 {WIREGUARD_DIR}\n\
             if ! test -f {WIREGUARD_PRIVATE_KEY_PATH}; then\n\
               sh -ceu 'umask 077; wg genkey > {WIREGUARD_PRIVATE_KEY_PATH}'\n\
             fi\n\
             if ! test -f {WIREGUARD_PUBLIC_KEY_PATH}; then\n\
               sh -ceu 'wg pubkey < {WIREGUARD_PRIVATE_KEY_PATH} > {WIREGUARD_PUBLIC_KEY_PATH}'\n\
             fi\n\
             chmod 600 {WIREGUARD_PRIVATE_KEY_PATH}\n\
             chmod 644 {WIREGUARD_PUBLIC_KEY_PATH}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SystemdUnit;

    #[test]
    fn enabling_a_unit_does_not_start_it_before_the_single_restart() {
        assert_eq!(
            SystemdUnit::new("aegis-agent.service").enable_args(),
            ["enable", "aegis-agent.service"]
        );
    }
}
