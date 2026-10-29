use std::{fs, os::unix::fs::PermissionsExt, process::Command};

use aegis_dto::platform::OperatingSystem;
#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::{Result, ensure};

use crate::command::{require_success, run_capture};

fn linux_unit(system: OperatingSystem) -> &'static str {
    match system {
        OperatingSystem::Ubuntu => "ssh.service",
        OperatingSystem::ArchLinux => "sshd.service",
        OperatingSystem::MacOs => unreachable!("macOS uses socket-activated sshd"),
    }
}

pub(crate) fn active() -> Result<bool> {
    let system = crate::platform::detect()?.operating_system;
    if system == OperatingSystem::MacOs {
        let output =
            run_capture(Command::new("/bin/launchctl").args(["print", "system/com.openssh.sshd"]))?;
        return Ok(output.status.success());
    }
    let service =
        run_capture(Command::new("systemctl").args(["is-active", "--quiet", linux_unit(system)]))?;
    if service.status.success() {
        return Ok(true);
    }
    if system == OperatingSystem::Ubuntu {
        return Ok(run_capture(Command::new("systemctl").args([
            "is-active",
            "--quiet",
            "ssh.socket",
        ]))?
        .status
        .success());
    }
    Ok(false)
}

pub(crate) fn prepare_inbound() -> Result<()> {
    let system = crate::platform::detect()?.operating_system;
    if system == OperatingSystem::MacOs {
        if active()? {
            return Ok(());
        }
        crate::ui::require_interactive(
            "Enable Remote Login in macOS Sharing settings, then rerun enrollment",
        )?;
        crate::ui::stage("Waiting for Remote Login to be enabled in macOS Sharing settings");
        let started = std::time::Instant::now();
        loop {
            crate::ui::check_cancelled()?;
            if active()? {
                return Ok(());
            }
            crate::ui::detail(&format!(
                "Remote Login is still disabled; waiting {}s. Press Ctrl-C to stop.",
                started.elapsed().as_secs()
            ));
            crate::ui::sleep(std::time::Duration::from_secs(10))?;
        }
    }
    if !active()? {
        require_success(
            "enable inbound SSH",
            Command::new("systemctl").args(["enable", "--now", linux_unit(system)]),
        )?;
    }
    Ok(())
}

pub(crate) fn validate() -> Result<()> {
    let system = crate::platform::detect()?.operating_system;
    if system != OperatingSystem::MacOs {
        fs::create_dir_all("/run/sshd")?;
        fs::set_permissions("/run/sshd", fs::Permissions::from_mode(0o755))?;
    }
    require_success(
        "validate SSH server configuration",
        Command::new("/usr/sbin/sshd").arg("-t"),
    )?;
    Ok(())
}

pub(crate) fn reload() -> Result<()> {
    validate()?;
    let system = crate::platform::detect()?.operating_system;
    if system == OperatingSystem::MacOs {
        // launchd starts a fresh sshd for each connection; existing sessions need no restart.
        ensure!(
            active()?,
            "Remote Login is disabled; enable it in macOS Sharing settings"
        );
        return Ok(());
    }
    let unit = linux_unit(system);
    if run_capture(Command::new("systemctl").args(["is-active", "--quiet", unit]))?
        .status
        .success()
    {
        require_success(
            "reload SSH server configuration",
            Command::new("systemctl").args(["reload", unit]),
        )?;
    } else {
        ensure!(active()?, "SSH service is not active");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const OWNED_INCLUDE: &str = "# BEGIN Aegis certificate authentication\nInclude /etc/ssh/sshd_config.d/90-aegis.conf\n# END Aegis certificate authentication\n";

#[cfg(target_os = "macos")]
const OWNED_INLINE_BEGIN: &str = "# BEGIN Aegis certificate authentication (inline)\n";

#[cfg(target_os = "macos")]
const OWNED_INLINE_END: &str = "# END Aegis certificate authentication (inline)\n";

#[cfg(target_os = "macos")]
pub(crate) fn ensure_certificate_integration() -> Result<()> {
    use std::path::Path;
    let dropin = Path::new(crate::app::AEGIS_SSHD_DROPIN);
    let desired = fs::read_to_string(dropin)?;
    let path = Path::new("/etc/ssh/sshd_config");
    let previous = fs::read_to_string(path)?;
    let include_supported = sshd_supports_include()?;
    if effective_configuration_contains(&desired)? {
        return Ok(());
    }
    ensure!(
        !previous.contains("# BEGIN Aegis certificate authentication"),
        "the owned aegis SSH integration is present but ineffective; repair conflicting SSH policy"
    );
    let owned = if include_supported {
        OWNED_INCLUDE.to_string()
    } else {
        format!("{OWNED_INLINE_BEGIN}{desired}{OWNED_INLINE_END}")
    };
    capulus::store::atomic_write(
        path,
        format!("{owned}{previous}").as_bytes(),
        Some(0o644),
        None,
    )?;
    let result = validate().and_then(|()| {
        ensure!(
            effective_configuration_contains(&desired)?,
            "Aegis certificate authentication is overridden by SSH policy"
        );
        Ok(())
    });
    if let Err(error) = result {
        capulus::store::atomic_write(path, previous.as_bytes(), Some(0o644), None).map_err(
            |restore| {
                anyhow::anyhow!(
                    "SSH integration failed: {error:#}; restoring sshd_config failed: {restore:#}"
                )
            },
        )?;
        return Err(error.context("SSH integration rejected; previous sshd_config restored"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn sshd_supports_include() -> Result<bool> {
    let output = run_capture(Command::new("/usr/sbin/sshd").arg("-V"))?;
    let version = output
        .stderr
        .lines()
        .chain(output.stdout.lines())
        .flat_map(str::split_whitespace)
        .find_map(|word| word.strip_prefix("OpenSSH_"))
        .context("sshd -V did not report an OpenSSH version")?;
    let mut components = version.split('.');
    let major = components
        .next()
        .context("OpenSSH version omitted its major component")?
        .parse::<u32>()?;
    let minor = components
        .next()
        .context("OpenSSH version omitted its minor component")?
        .trim_end_matches(|character: char| !character.is_ascii_digit())
        .parse::<u32>()?;
    Ok((major, minor) >= (8, 2))
}

#[cfg(target_os = "macos")]
fn effective_configuration_contains(desired: &str) -> Result<bool> {
    let output = require_success(
        "inspect effective SSH server configuration",
        Command::new("/usr/sbin/sshd").arg("-T"),
    )?;
    let effective = output
        .stdout
        .lines()
        .map(|line| line.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    Ok(desired
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .all(|line| effective.contains(&line.trim().to_ascii_lowercase())))
}

#[cfg(target_os = "macos")]
pub(crate) fn remove_certificate_integration() -> Result<()> {
    use std::io::ErrorKind;

    let path = std::path::Path::new("/etc/ssh/sshd_config");
    let previous = fs::read_to_string(path)?;
    let restored = if previous.starts_with(OWNED_INCLUDE) {
        &previous.as_bytes()[OWNED_INCLUDE.len()..]
    } else if previous.starts_with(OWNED_INLINE_BEGIN) {
        let end = previous
            .find(OWNED_INLINE_END)
            .map(|index| index + OWNED_INLINE_END.len())
            .context("owned inline SSH integration is truncated")?;
        &previous.as_bytes()[end..]
    } else {
        ensure!(
            !previous.contains("# BEGIN Aegis certificate authentication"),
            "owned SSH integration was edited; retained for explicit repair"
        );
        &[]
    };
    if previous.starts_with(OWNED_INCLUDE) || previous.starts_with(OWNED_INLINE_BEGIN) {
        capulus::store::atomic_write(path, restored, Some(0o644), None)?;
    }
    if let Err(error) = validate() {
        capulus::store::atomic_write(path, previous.as_bytes(), Some(0o644), None)?;
        return Err(error.context("SSH include removal rejected; previous sshd_config restored"));
    }
    match fs::remove_file(crate::app::AEGIS_SSHD_DROPIN) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
