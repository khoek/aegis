use std::process::Command;

use anyhow::{Result, anyhow, bail};
use capulus::managed::UnixAccount;

use crate::command::require_success;

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
        if cfg!(target_os = "macos") {
            if !self.group_existed {
                require_success(
                    "create the Aegis management group",
                    Command::new("/usr/sbin/dseditgroup").args([
                        "-o",
                        "create",
                        "-q",
                        crate::managed::ACCESS_GROUP,
                    ]),
                )?;
            }
            require_success(
                "authorize the Aegis management operator",
                Command::new("/usr/sbin/dseditgroup").args([
                    "-o",
                    "edit",
                    "-a",
                    &self.principal,
                    "-t",
                    "user",
                    crate::managed::ACCESS_GROUP,
                ]),
            )?;
        } else {
            if !self.group_existed {
                require_success(
                    "create the Aegis management group",
                    Command::new("/usr/sbin/groupadd")
                        .args(["--system", crate::managed::ACCESS_GROUP]),
                )?;
            }
            require_success(
                "authorize the Aegis management operator",
                Command::new("/usr/sbin/usermod").args([
                    "--append",
                    "--groups",
                    crate::managed::ACCESS_GROUP,
                    &self.principal,
                ]),
            )?;
        }
        Ok(())
    }
}

pub(crate) fn remove_management_group() -> Result<()> {
    if management_group_exists()? {
        let mut command = if cfg!(target_os = "macos") {
            let mut command = Command::new("/usr/sbin/dseditgroup");
            command.args(["-o", "delete"]);
            command
        } else {
            Command::new("/usr/sbin/groupdel")
        };
        require_success(
            "remove the Aegis management group",
            command.arg(crate::managed::ACCESS_GROUP),
        )?;
    }
    Ok(())
}

fn management_group_exists() -> Result<bool> {
    let output = if cfg!(target_os = "macos") {
        require_success(
            "inspect the Aegis management group",
            Command::new("/usr/bin/dscl").args([
                ".",
                "-read",
                &format!("/Groups/{}", crate::managed::ACCESS_GROUP),
            ]),
        )
    } else {
        require_success(
            "inspect the Aegis management group",
            Command::new("/usr/bin/getent").args(["group", crate::managed::ACCESS_GROUP]),
        )
    };
    Ok(output.is_ok())
}
