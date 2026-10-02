use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use capulus::managed::UnixAccount;

use crate::command::{require_success, run_capture};

pub(crate) struct ManagementOperatorSetup {
    principal: String,
    group_existed: bool,
}

impl ManagementOperatorSetup {
    pub(crate) fn prepare(principal: &str, managed_install_present: bool) -> Result<Self> {
        let account = UnixAccount::by_name(principal)?
            .ok_or_else(|| anyhow!("login principal `{principal}` has no NSS account"))?;
        account.validate_interactive()?;
        let group_existed = management_group_exists()?;
        if group_existed && !managed_install_present {
            bail!(
                "refusing to adopt pre-existing unmanaged Unix group `{}`",
                crate::managed::ACCESS_GROUP
            );
        }
        Ok(Self {
            principal: principal.to_string(),
            group_existed,
        })
    }

    pub(crate) fn apply(self) -> Result<()> {
        if self.group_existed != management_group_exists()? {
            bail!("Aegis management-group state changed while installation was prepared");
        }
        if !self.group_existed {
            let mut command = bounded_command("/usr/sbin/groupadd");
            command.args(["--system", crate::managed::ACCESS_GROUP]);
            require_success("create the Aegis management group", &mut command)?;
        }
        let mut command = bounded_command("/usr/sbin/usermod");
        command.args([
            "--append",
            "--groups",
            crate::managed::ACCESS_GROUP,
            &self.principal,
        ]);
        require_success("authorize the Aegis management operator", &mut command)?;
        Ok(())
    }
}

pub(crate) fn remove_management_group() -> Result<()> {
    if management_group_exists()? {
        let mut command = bounded_command("/usr/sbin/groupdel");
        command.arg(crate::managed::ACCESS_GROUP);
        require_success("remove the Aegis management group", &mut command)?;
    }
    Ok(())
}

fn management_group_exists() -> Result<bool> {
    let mut command = bounded_command("/usr/bin/getent");
    command.args(["group", crate::managed::ACCESS_GROUP]);
    let output =
        run_capture(&mut command).context("failed to inspect the Aegis management group")?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        status => bail!(
            "getent failed while inspecting the Aegis management group with status {}: {}",
            status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            output.stderr.trim()
        ),
    }
}

fn bounded_command(program: &str) -> Command {
    let mut command = Command::new("/usr/bin/timeout");
    command.args(["--signal=TERM", "--kill-after=2s", "15s", program]);
    command
}
