use std::sync::OnceLock;

use anyhow::{Result, anyhow};

pub use capulus::ui::{
    Color, ConfiguredRenderTarget, LiveGroup, LiveRow, RenderTarget, StderrRenderTarget,
    StdoutRenderTarget, Task, TaskKind, TaskOptions, TaskVisibility, TextEffect, format_duration,
};
use capulus::ui::{Ui, UiOptions};

mod selector;
pub(crate) use selector::{
    Choice, ChoiceStatus, ChoiceUpdate, Screen, SelectOptions, screen, select_live,
};

static UI: OnceLock<Ui> = OnceLock::new();

pub fn init(options: UiOptions) -> Result<()> {
    let ui = Ui::from_options(options)?;
    UI.set(ui)
        .map_err(|_| anyhow!("Aegis UI was initialized more than once"))
}

pub fn current() -> &'static Ui {
    #[cfg(test)]
    {
        UI.get_or_init(|| {
            Ui::from_options(UiOptions {
                progress: capulus::ui::ProgressMode::Off,
                color: capulus::ui::ColorMode::Never,
                ..UiOptions::default()
            })
            .expect("test UI options are valid")
        })
    }
    #[cfg(not(test))]
    {
        UI.get().expect("Aegis UI must be initialized before use")
    }
}

pub(crate) fn cancellation() -> capulus::Cancellation {
    UI.get()
        .map(Ui::cancellation)
        .unwrap_or_else(capulus::Cancellation::passive)
}

pub fn task(options: TaskOptions) -> Result<Task> {
    current().task(options)
}

pub fn live_group(label: impl Into<String>) -> Result<LiveGroup> {
    current().live_group(label)
}

pub fn render_target() -> ConfiguredRenderTarget {
    current().render_target()
}

pub fn stdout_render_target() -> ConfiguredRenderTarget {
    current().stdout_render_target()
}

pub fn check_cancelled() -> Result<()> {
    current().check_cancelled()?;
    Ok(())
}

pub fn sleep(duration: std::time::Duration) -> Result<()> {
    current().sleep(duration)?;
    Ok(())
}

pub fn suspend<T>(operation: impl FnOnce() -> T) -> T {
    current().suspend(operation)
}

pub fn require_interactive(message: &str) -> Result<()> {
    capulus::ui::require_interactive(message)
}

pub fn maybe_open_browser(url: &str) {
    current().suspend(|| capulus::ui::maybe_open_browser(url));
}

pub fn stage(message: &str) {
    current().info(message);
}

pub fn detail(message: &str) {
    current().detail(message);
}

pub fn success(message: &str) {
    current().success(message);
}

pub fn warn(message: &str) {
    current().warn(message);
}

pub fn error(message: &str) {
    current().error(message);
}

pub fn completed_line(message: &str) {
    outcome_line("✓", Color::Green, message);
}

pub fn abandoned_line(message: &str) {
    outcome_line("!", Color::Yellow, message);
}

fn outcome_line(glyph: &str, color: Color, message: &str) {
    let ui = current();
    ui.suspend(|| {
        eprintln!("{} {message}", ui.render_target().paint(glyph, color));
    });
}
