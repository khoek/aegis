use std::{fs, io::ErrorKind, os::unix::fs::PermissionsExt, path::Path, process::Command};

use aegis_types::layout::{
    APPARMOR_WG_QUICK_AEGIS_RULES_PATH, APPARMOR_WG_QUICK_LOCAL_PATH,
    APPARMOR_WG_QUICK_PROFILE_PATH, WIREGUARD_DIRECTORY,
};
use anyhow::{Context, Result, anyhow};
use capulus::shell::shell_quote;

use crate::command::require_success;

const APPARMOR_PARSER_PATH: &str = "/usr/sbin/apparmor_parser";
const WG_QUICK_AEGIS_INCLUDE: &str = "include if exists <local/aegis-wg-quick>";

pub(crate) fn ensure_wireguard_access() -> Result<()> {
    replace_wireguard_access(true)
}

pub(crate) fn remove_wireguard_access() -> Result<()> {
    replace_wireguard_access(false)?;
    replace_optional_text(Path::new(APPARMOR_WG_QUICK_AEGIS_RULES_PATH), None, 0o644)?;
    Ok(())
}

fn replace_wireguard_access(enabled: bool) -> Result<()> {
    for (profile, local) in [
        (APPARMOR_WG_QUICK_PROFILE_PATH, APPARMOR_WG_QUICK_LOCAL_PATH),
        ("/etc/apparmor.d/wg", "/etc/apparmor.d/local/wg"),
    ] {
        if Path::new(profile).exists() {
            replace_profile_access(profile, local, enabled)?;
        }
    }
    Ok(())
}

fn replace_profile_access(profile: &str, local: &str, enabled: bool) -> Result<()> {
    let profile_path = Path::new(profile);
    let local_path = Path::new(local);
    let rules_path = Path::new(APPARMOR_WG_QUICK_AEGIS_RULES_PATH);
    let previous_local = read_optional_text(local_path)?;
    let previous_rules = read_optional_text(rules_path)?;
    let desired_local = apparmor_local_contents(previous_local.as_deref(), enabled);
    let desired_rules = Some(wireguard_rules_contents());

    let local_changed = replace_optional_text(local_path, desired_local.as_deref(), 0o644)?;
    let rules_changed = replace_optional_text(rules_path, desired_rules.as_deref(), 0o644)?;
    if !local_changed && !rules_changed {
        return Ok(());
    }
    if !profile_path.exists() {
        return Ok(());
    }

    if let Err(change_error) = reload_profile(profile) {
        let restore_result = replace_optional_text(local_path, previous_local.as_deref(), 0o644)
            .and_then(|_| {
                replace_optional_text(rules_path, previous_rules.as_deref(), 0o644).map(|_| ())
            })
            .and_then(|()| reload_profile(profile));
        return match restore_result {
            Ok(()) => Err(change_error).context(
                "failed to activate Aegis WireGuard AppArmor access; restored the previous policy",
            ),
            Err(restore_error) => Err(anyhow!(
                "failed to activate Aegis WireGuard AppArmor access: {change_error:#}; restoring the previous policy also failed: {restore_error:#}"
            )),
        };
    }
    Ok(())
}

fn apparmor_local_contents(existing: Option<&str>, enabled: bool) -> Option<String> {
    let existing = existing.unwrap_or_default();
    let has_include = existing
        .lines()
        .any(|line| line.trim() == WG_QUICK_AEGIS_INCLUDE);
    if enabled {
        if has_include {
            return Some(existing.to_string());
        }
        let mut output = existing.to_string();
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(WG_QUICK_AEGIS_INCLUDE);
        output.push('\n');
        return Some(output);
    }

    if !has_include {
        return (!existing.is_empty()).then(|| existing.to_string());
    }
    let output = existing
        .split_inclusive('\n')
        .filter(|line| line.trim() != WG_QUICK_AEGIS_INCLUDE)
        .collect::<String>();
    (!output.trim().is_empty()).then_some(output)
}

fn wireguard_rules_contents() -> String {
    format!("# Managed by aegis.\n{WIREGUARD_DIRECTORY}/{{,**}} r,\n")
}

fn read_optional_text(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn replace_optional_text(path: &Path, content: Option<&str>, mode: u32) -> Result<bool> {
    let current = read_optional_text(path)?;
    if current.as_deref() == content {
        if content.is_some() {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to chmod {}", path.display()))?;
        }
        return Ok(false);
    }
    match content {
        Some(content) => {
            let parent = path
                .parent()
                .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            let temporary = path.with_extension("tmp");
            fs::write(&temporary, content)
                .with_context(|| format!("failed to write {}", temporary.display()))?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to chmod {}", temporary.display()))?;
            fs::rename(&temporary, path)
                .with_context(|| format!("failed to update {}", path.display()))?;
        }
        None => match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to remove {}", path.display()));
            }
        },
    }
    Ok(true)
}

fn reload_profile(profile: &str) -> Result<()> {
    require_success(
        "reload the WireGuard AppArmor profile",
        Command::new("/usr/bin/timeout").args(["10s", APPARMOR_PARSER_PATH, "-r", profile]),
    )?;
    Ok(())
}

pub(crate) fn wireguard_access_install_shell() -> String {
    [
        (APPARMOR_WG_QUICK_PROFILE_PATH, APPARMOR_WG_QUICK_LOCAL_PATH),
        ("/etc/apparmor.d/wg", "/etc/apparmor.d/local/wg"),
    ]
    .into_iter()
    .map(|(profile, local)| {
        format!(
            "if sudo test -f {profile}; then\n\
           sudo install -d -m 755 /etc/apparmor.d/local\n\
           cat <<'EOF_AEGIS_APPARMOR_RULES' | sudo tee {rules} >/dev/null\n\
{contents}\
EOF_AEGIS_APPARMOR_RULES\n\
           sudo chmod 644 {rules}\n\
           if ! sudo grep -Fqx {include} {local} 2>/dev/null; then\n\
             printf '\\n%s\\n' {include} | sudo tee -a {local} >/dev/null\n\
           fi\n\
           sudo chmod 644 {local}\n\
           sudo /usr/bin/timeout 10s {parser} -r {profile}\n\
         fi\n",
            profile = shell_quote(profile),
            local = shell_quote(local),
            rules = shell_quote(APPARMOR_WG_QUICK_AEGIS_RULES_PATH),
            include = shell_quote(WG_QUICK_AEGIS_INCLUDE),
            parser = shell_quote(APPARMOR_PARSER_PATH),
            contents = wireguard_rules_contents(),
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        WG_QUICK_AEGIS_INCLUDE, apparmor_local_contents, wireguard_access_install_shell,
        wireguard_rules_contents,
    };

    #[test]
    fn apparmor_include_is_added_and_removed_without_losing_local_rules() {
        let existing = "# operator rule\n/etc/operator/** r,\n";
        let installed = apparmor_local_contents(Some(existing), true).expect("installed policy");
        assert!(installed.starts_with(existing));
        assert_eq!(
            1,
            installed
                .lines()
                .filter(|line| line.trim() == WG_QUICK_AEGIS_INCLUDE)
                .count()
        );
        assert_eq!(
            Some(existing.to_string()),
            apparmor_local_contents(Some(&installed), false)
        );
    }

    #[test]
    fn apparmor_policy_is_narrow_and_shell_paths_match() {
        let rules = wireguard_rules_contents();
        assert_eq!(
            "# Managed by aegis.\n/etc/aegis/wireguard/{,**} r,\n",
            rules
        );
        let install = wireguard_access_install_shell();
        assert!(install.contains("/etc/apparmor.d/local/aegis-wg-quick"));
        assert!(install.contains("apparmor_parser"));
    }
}
