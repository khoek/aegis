use std::fs;

#[cfg(target_os = "macos")]
use std::process::Command;

use aegis_dto::platform::{Architecture, HostPlatform, OperatingSystem};
use anyhow::{Context, Result, bail, ensure};

pub(crate) fn detect() -> Result<HostPlatform> {
    identify(
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(target_os = "linux") {
            Some(fs::read_to_string("/etc/os-release").context("read operating system identity")?)
        } else {
            None
        }
        .as_deref(),
    )
}

pub(crate) fn identify(
    kernel: &str,
    architecture: &str,
    os_release: Option<&str>,
) -> Result<HostPlatform> {
    let operating_system = match kernel {
        "macos" | "Darwin" => OperatingSystem::MacOs,
        "linux" | "Linux" => match os_release.and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("ID=")
                    .map(|id| id.trim_matches(['\"', '\'']))
            })
        }) {
            Some("ubuntu") => OperatingSystem::Ubuntu,
            Some("arch") => OperatingSystem::ArchLinux,
            _ => bail!(
                "Aegis supports Ubuntu, Arch Linux, and macOS; this Linux distribution is unsupported"
            ),
        },
        _ => bail!("unsupported operating system `{kernel}`"),
    };
    let architecture = match architecture {
        "x86_64" => Architecture::X86_64,
        "aarch64" | "arm64" => Architecture::Aarch64,
        _ => bail!("unsupported architecture `{architecture}`"),
    };
    HostPlatform {
        operating_system,
        architecture,
    }
    .validate()
}

pub(crate) const IDENTIFICATION_SCRIPT: &str = r#"
printf 'PLATFORM_KERNEL=%s\n' "$(uname -s)"
printf 'PLATFORM_ARCH=%s\n' "$(uname -m)"
if [ "$(uname -s)" = Linux ]; then
    . /etc/os-release
    printf 'PLATFORM_DISTRO=%s\n' "$ID"
fi
"#;

pub(crate) fn parse_identification(output: &str) -> Result<HostPlatform> {
    let fields = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    identify(
        fields
            .get("PLATFORM_KERNEL")
            .context("platform probe omitted kernel")?,
        fields
            .get("PLATFORM_ARCH")
            .context("platform probe omitted architecture")?,
        fields
            .get("PLATFORM_DISTRO")
            .map(|distro| format!("ID={distro}"))
            .as_deref(),
    )
}

pub(crate) fn boot_id() -> Result<String> {
    #[cfg(target_os = "linux")]
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("failed to read kernel boot ID")?;
    #[cfg(target_os = "macos")]
    let value = {
        let output = crate::command::run_capture(
            Command::new("/usr/sbin/sysctl").args(["-n", "kern.bootsessionuuid"]),
        )?;
        ensure!(
            output.status.success(),
            "failed to read kernel boot ID: {}",
            output.stderr.trim()
        );
        output.stdout
    };
    let value = value.trim();
    ensure!(
        uuid::Uuid::parse_str(value).is_ok(),
        "kernel boot ID is not a UUID"
    );
    Ok(value.to_owned())
}

pub(crate) fn bird_config_path(platform: HostPlatform) -> Result<&'static str> {
    match platform.operating_system {
        OperatingSystem::Ubuntu => Ok("/etc/bird/bird.conf"),
        OperatingSystem::ArchLinux => Ok("/etc/bird.conf"),
        OperatingSystem::MacOs => bail!("BIRD configuration is only used on Linux"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) const SYSTEM_BINARY_PATH: &str = "/usr/local/bin/aegis";
#[cfg(target_os = "macos")]
pub(crate) const SYSTEM_BINARY_PATH: &str = "/Library/PrivilegedHelperTools/aegis";

pub(crate) const fn system_binary_path(platform: HostPlatform) -> &'static str {
    match platform.operating_system {
        OperatingSystem::MacOs => "/Library/PrivilegedHelperTools/aegis",
        OperatingSystem::Ubuntu | OperatingSystem::ArchLinux => "/usr/local/bin/aegis",
    }
}

pub(crate) const BINARY_SHELL_ASSIGNMENT: &str = "case $(uname -s) in Darwin) system_aegis=/Library/PrivilegedHelperTools/aegis ;; Linux) system_aegis=/usr/local/bin/aegis ;; *) exit 1 ;; esac";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_native_targets_without_guessing_derivatives() {
        assert_eq!(
            identify("Linux", "x86_64", Some("ID=arch\n"))
                .unwrap()
                .operating_system,
            OperatingSystem::ArchLinux
        );
        assert_eq!(
            identify("Darwin", "arm64", None).unwrap().architecture,
            Architecture::Aarch64
        );
        assert!(identify("Linux", "x86_64", Some("ID=manjaro\nID_LIKE=arch\n")).is_err());
        assert!(identify("Darwin", "i386", None).is_err());
    }
}
