use std::{
    ffi::CStr,
    io::{self, ErrorKind},
};

use aegis_dto::HostAlias;
use anyhow::{Context, Result};
use rustix::termios::{self, LocalModes, OptionalActions, SpecialCodeIndex, Termios};

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
    let result = ui::suspend(|| -> Result<HostAlias> {
        // Queue an early Ctrl-C as input before rendering the prompt. Otherwise
        // the signal can be handled before dialoguer starts its blocking read.
        let mut input = PromptInput::prepare()?;
        ui::check_cancelled()?;
        let result = dialoguer::Input::<HostAlias>::new()
            .with_prompt("Host alias for this computer")
            .interact_text();
        input.restore()?;
        match result {
            Err(dialoguer::Error::IO(error)) if error.kind() == ErrorKind::Interrupted => {
                Err(capulus::Cancelled.into())
            }
            result => result.map_err(Into::into),
        }
    });
    ui::check_cancelled()?;
    result
}

struct PromptInput {
    stdin: io::Stdin,
    original: Option<Termios>,
}

impl PromptInput {
    fn prepare() -> Result<Self> {
        let stdin = io::stdin();
        let original = termios::tcgetattr(&stdin).context("read prompt input settings")?;
        let mut input = original.clone();
        input
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG);
        input.special_codes[SpecialCodeIndex::VMIN] = 1;
        input.special_codes[SpecialCodeIndex::VTIME] = 0;
        // Preserve output processing so dialoguer's validation messages retain
        // normal line endings. Do not flush input that the user already typed.
        termios::tcsetattr(&stdin, OptionalActions::Now, &input).context("prepare prompt input")?;
        Ok(Self {
            stdin,
            original: Some(original),
        })
    }

    fn restore(&mut self) -> Result<()> {
        if let Some(original) = &self.original {
            termios::tcsetattr(&self.stdin, OptionalActions::Now, original)
                .context("restore prompt input settings")?;
            self.original = None;
        }
        Ok(())
    }
}

impl Drop for PromptInput {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests;
