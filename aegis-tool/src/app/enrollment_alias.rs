use std::{ffi::CStr, io::ErrorKind};

use aegis_dto::HostAlias;
use anyhow::{Context, Result};

use crate::ui;

pub(super) fn select(hostname: &CStr) -> Result<HostAlias> {
    let default = hostname
        .to_str()
        .context("system hostname is not UTF-8")
        .and_then(|hostname| {
            HostAlias::parse(hostname.split('.').next().unwrap_or(hostname))
                .context("system hostname is not a valid Aegis alias")
        });
    match default {
        Ok(alias) => return Ok(alias),
        Err(error) => ui::warn(&format!("{error:#}")),
    }
    ui::require_interactive(
        "Choose a host alias with --name ALIAS, or rerun in an interactive terminal",
    )?;
    ui::check_cancelled()?;
    let result = ui::suspend(|| {
        dialoguer::Input::<HostAlias>::new()
            .with_prompt("Host alias for this computer")
            .interact_text()
    });
    ui::check_cancelled()?;
    match result {
        Err(dialoguer::Error::IO(error)) if error.kind() == ErrorKind::Interrupted => {
            Err(capulus::Cancelled.into())
        }
        result => result.map_err(Into::into),
    }
}

#[cfg(test)]
mod tests;
