use std::fs::OpenOptions;
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aegis_types::HostId;
use anyhow::{Context, Result};
use capulus::paths::home_dir;
use capulus::store::ensure_directory;
use capulus::{InvocationLock, acquire_in_with_ui, acquire_named_in_with_ui};
use sha2::{Digest, Sha256};

use crate::config::locks_dir;

const LOCAL_SYSTEM_LOCK_NAME: &str = "aegis-system";
const USER_AUTH_LOCK_NAME: &str = "aegis-user-auth";

pub fn local_system_lock() -> Result<InvocationLock> {
    acquire_user_scoped_lock(LOCAL_SYSTEM_LOCK_NAME)
}

pub(crate) fn deployment_lock(project: &str) -> Result<InvocationLock> {
    acquire_user_scoped_lock(&format!(
        "aegis-deployment-{}",
        lock_hash(project.as_bytes())
    ))
}

pub fn host_shell_assets_lock(host_id: &HostId) -> Result<InvocationLock> {
    let name = format!("aegis-shell-assets-{}", lock_hash(host_id.as_bytes()));
    let (root, path) = prepare_user_scoped_lock_file(&name)?;
    let lock = acquire_named_in_with_ui(&root, &name, true, crate::ui::current())?;
    preserve_home_owner(&root, &path)?;
    Ok(lock)
}

pub fn user_auth_lock() -> Result<InvocationLock> {
    acquire_user_scoped_lock(USER_AUTH_LOCK_NAME)
}

pub fn prepare_user_auth_lock_for_privileged_reexec() -> Result<()> {
    prepare_user_scoped_lock_file(USER_AUTH_LOCK_NAME).map(|_| ())
}

fn prepare_user_scoped_lock_file(name: &str) -> Result<(PathBuf, PathBuf)> {
    let root = locks_dir()?;
    ensure_directory(&root, Some(0o700))?;
    let path = root.join(format!("{name}.lock"));
    if !path.exists() {
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to prepare {}", path.display()));
            }
        }
    }
    preserve_home_owner(&root, &path)?;
    secure_lock_permissions(&root, &path)?;
    Ok((root, path))
}

fn acquire_user_scoped_lock(name: &str) -> Result<InvocationLock> {
    let (root, path) = prepare_user_scoped_lock_file(name)?;
    let lock = if name == LOCAL_SYSTEM_LOCK_NAME {
        acquire_in_with_ui(&root, name, true, crate::ui::current())?
    } else {
        acquire_named_in_with_ui(&root, name, true, crate::ui::current())?
    };
    preserve_home_owner(&root, &path)?;
    Ok(lock)
}

#[cfg(unix)]
fn preserve_home_owner(root: &Path, path: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let home = home_dir()?;
    let home_metadata = std::fs::metadata(&home)
        .with_context(|| format!("failed to inspect {}", home.display()))?;
    let owner = (home_metadata.uid(), home_metadata.gid());
    for candidate in [root, path] {
        let metadata = std::fs::metadata(candidate)
            .with_context(|| format!("failed to inspect {}", candidate.display()))?;
        if (metadata.uid(), metadata.gid()) != owner {
            std::os::unix::fs::chown(candidate, Some(owner.0), Some(owner.1)).with_context(
                || format!("failed to preserve ownership of {}", candidate.display()),
            )?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn preserve_home_owner(_root: &Path, _path: &Path) -> Result<()> {
    Ok(())
}

fn secure_lock_permissions(root: &Path, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::set_permissions(root, Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {}", root.display()))?;
        std::fs::set_permissions(path, Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (root, path);
    }
    Ok(())
}

fn lock_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::secure_lock_permissions;

    #[test]
    fn administration_locks_do_not_claim_the_system_child_bypass() {
        use std::process::Command;
        const MARKER: &str = "AEGIS_TEST_LOCK_CHILD";
        if let Ok(stage) = std::env::var(MARKER) {
            if stage == "parent" {
                drop(super::user_auth_lock().unwrap());
                let _deployment = super::deployment_lock("example-project").unwrap();
                let _system = super::local_system_lock().unwrap();
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        "locks::tests::administration_locks_do_not_claim_the_system_child_bypass",
                    ])
                    .env(MARKER, "child");
                capulus::configure_child_command(&mut command);
                let output = capulus::process::CaptureOptions {
                    timeout: std::time::Duration::from_secs(3),
                    ..Default::default()
                }
                .validate()
                .unwrap()
                .run(&mut command, None)
                .unwrap();
                assert!(output.status.success(), "{}", output.stderr);
            } else {
                let _lock = super::local_system_lock().unwrap();
            }
            return;
        }
        let home = tempdir().unwrap();
        let output = capulus::process::CaptureOptions::default()
            .validate()
            .unwrap()
            .run(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "locks::tests::administration_locks_do_not_claim_the_system_child_bypass",
                    ])
                    .env(MARKER, "parent")
                    .env("HOME", home.path())
                    .env_remove("SUDO_USER")
                    .env_remove("CAPULUS_SINGLE_INSTANCE_BYPASS"),
                None,
            )
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            output.stdout,
            output.stderr
        );
    }

    #[test]
    fn user_scoped_lock_paths_are_private() {
        let temp = tempdir().expect("temporary directory");
        let root = temp.path().join("locks");
        fs::create_dir(&root).expect("lock directory");
        let path = root.join("aegis-system.lock");
        fs::write(&path, b"").expect("lock file");

        secure_lock_permissions(&root, &path).expect("secure lock paths");

        assert_eq!(
            0o700,
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777
        );
        assert_eq!(
            0o600,
            fs::metadata(&path)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777
        );
    }
}
