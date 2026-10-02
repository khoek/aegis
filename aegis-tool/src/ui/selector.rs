use std::io::{self, IsTerminal, Write};
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::Print,
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use dialoguer::console::{measure_text_width, truncate_str};

use super::{Color, RenderTarget};

const TICK: Duration = Duration::from_millis(100);
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub(crate) enum ChoiceStatus {
    Checking,
    Ready { text: String, color: Option<Color> },
}

pub(crate) struct Choice {
    pub label: String,
    pub status: ChoiceStatus,
}

pub(crate) struct ChoiceUpdate {
    pub index: usize,
    pub status: ChoiceStatus,
}

pub(crate) struct SelectOptions {
    pub prompt: String,
    pub choices: Vec<Choice>,
}

struct Selection {
    options: SelectOptions,
    selected: usize,
}

impl Selection {
    fn update(&mut self, update: ChoiceUpdate) -> Result<()> {
        let choice = self
            .options
            .choices
            .get_mut(update.index)
            .ok_or_else(|| anyhow::anyhow!("selector update refers to an unknown choice"))?;
        choice.status = update.status;
        Ok(())
    }

    fn key(&mut self, key: KeyEvent, page_size: usize) -> Result<Option<usize>> {
        if key.kind == KeyEventKind::Release {
            return Ok(None);
        }
        if key.code == KeyCode::Esc
            || key.code == KeyCode::Char('q')
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return Err(capulus::Cancelled.into());
        }
        let count = self.options.choices.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = (self.selected + count - 1) % count,
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.selected = (self.selected + 1) % count
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = count - 1,
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(page_size),
            KeyCode::PageDown => self.selected = (self.selected + page_size).min(count - 1),
            KeyCode::Enter | KeyCode::Char(' ') => return Ok(Some(self.selected)),
            _ => {}
        }
        Ok(None)
    }

    fn visible_range(&self, page_size: usize) -> std::ops::Range<usize> {
        let start = (self.selected / page_size) * page_size;
        start..(start + page_size).min(self.options.choices.len())
    }

    fn render(&self, size: (u16, u16), elapsed: Duration) -> Result<()> {
        let target = super::render_target();
        let width = usize::from(size.0.saturating_sub(1));
        let mut output = Vec::new();
        let mut line = |row: u16, text: &str| -> Result<()> {
            queue!(
                output,
                MoveTo(0, row),
                Print(truncate_str(text, width, "…")),
                Clear(ClearType::UntilNewLine)
            )?;
            Ok(())
        };
        line(0, &target.paint(&self.options.prompt, Color::Cyan))?;
        let mut row = 1;
        for index in self.visible_range(page_size(size)) {
            let choice = &self.options.choices[index];
            let (status, color) = match &choice.status {
                ChoiceStatus::Checking => (
                    format!(
                        "{} checking…",
                        SPINNER[(elapsed.as_millis() / TICK.as_millis()) as usize % SPINNER.len()]
                    ),
                    Some(Color::Yellow),
                ),
                ChoiceStatus::Ready { text, color } => (text.clone(), *color),
            };
            // Keep status visible on phone terminals; shorten the address/label first.
            let status_width = 16.min(width / 2);
            let label_width = width.saturating_sub(status_width + 4);
            let label = truncate_str(&choice.label, label_width, "…");
            let padding = " ".repeat(label_width.saturating_sub(measure_text_width(&label)));
            let marker = if index == self.selected { ">" } else { " " };
            let label = if index == self.selected {
                target.paint(&label, Color::Cyan)
            } else {
                label.into_owned()
            };
            let status = target.style(
                &truncate_str(&status, status_width, "…"),
                color,
                super::TextEffect::None,
            );
            line(row, &format!("{marker} {label}{padding}  {status}"))?;
            row += 1;
        }
        let checked = self
            .options
            .choices
            .iter()
            .filter(|choice| matches!(choice.status, ChoiceStatus::Ready { .. }))
            .count();
        line(row, "↑/↓ move · Enter select · Esc cancel")?;
        line(
            row + 1,
            &format!(
                "{checked}/{} checked · {} elapsed",
                self.options.choices.len(),
                super::format_duration(elapsed)
            ),
        )?;
        queue!(output, Clear(ClearType::FromCursorDown))?;
        let mut stderr = io::stderr().lock();
        stderr.write_all(&output)?;
        stderr.flush()?;
        Ok(())
    }
}

fn page_size(size: (u16, u16)) -> usize {
    usize::from(size.1.saturating_sub(4)).max(1)
}

pub(crate) struct Screen {
    active: bool,
}

impl Screen {
    pub(crate) fn clear(&self) -> Result<()> {
        if self.active {
            super::suspend(|| execute!(io::stderr(), MoveTo(0, 0), Clear(ClearType::All)))?;
        }
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.active {
            super::suspend(|| {
                let _ = execute!(io::stderr(), Clear(ClearType::All), LeaveAlternateScreen);
            });
        }
    }
}

/// Own the transient display until the complete operation hands off to SSH.
/// Wrapped progress frames must never become part of the shell's scrollback.
pub(crate) fn screen<T>(operation: impl FnOnce(&Screen) -> Result<T>) -> Result<T> {
    let screen = Screen {
        active: io::stdin().is_terminal() && io::stderr().is_terminal(),
    };
    if screen.active {
        super::suspend(|| execute!(io::stderr(), EnterAlternateScreen))?;
        screen.clear()?;
    }
    operation(&screen)
}

struct RawInput;

impl RawInput {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stderr(), Hide)?;
        Ok(guard)
    }
}

impl Drop for RawInput {
    fn drop(&mut self) {
        let _ = execute!(io::stderr(), Show);
        let _ = terminal::disable_raw_mode();
    }
}

/// Background workers only send row updates. All terminal input stays on this
/// thread, so accepting a choice never waits for a probe or leaves a reader
/// consuming keystrokes intended for the following prompt/SSH session.
pub(crate) fn select_live(
    screen: &Screen,
    options: SelectOptions,
    start_checks: impl FnOnce(Sender<ChoiceUpdate>) -> Result<()>,
) -> Result<usize> {
    ensure!(
        !options.prompt.trim().is_empty(),
        "selector prompt is empty"
    );
    ensure!(!options.choices.is_empty(), "no available targets");
    if options.choices.len() == 1 {
        return Ok(0);
    }
    if !screen.active {
        bail!("multiple targets are available; select one from an interactive terminal");
    }
    super::suspend(|| {
        let _terminal = RawInput::enter()?;
        let mut selection = Selection {
            options,
            selected: 0,
        };
        let started = Instant::now();
        let mut size = terminal::size()?;
        selection.render(size, started.elapsed())?;
        let (tx, rx) = mpsc::channel();
        start_checks(tx)?;
        let mut rendered_seconds = 0;
        // This is an intentional wait for a person; each network check has its
        // own deadline, and the footer shows elapsed time and completed checks.
        loop {
            super::check_cancelled()?;
            let mut changed = false;
            for update in rx.try_iter() {
                selection.update(update)?;
                changed = true;
            }
            if event::poll(TICK)? {
                match event::read()? {
                    Event::Key(key) => {
                        if let Some(index) = selection.key(key, page_size(size))? {
                            return Ok(index);
                        }
                        changed = true;
                    }
                    Event::Resize(columns, rows) => {
                        size = (columns, rows);
                        changed = true;
                    }
                    _ => {}
                }
            }
            let elapsed = started.elapsed();
            if changed
                || elapsed.as_secs() != rendered_seconds
                || selection
                    .options
                    .choices
                    .iter()
                    .any(|choice| matches!(choice.status, ChoiceStatus::Checking))
            {
                selection.render(size, elapsed)?;
                rendered_seconds = elapsed.as_secs();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> Selection {
        Selection {
            options: SelectOptions {
                prompt: "Connect to".into(),
                choices: (0..13)
                    .map(|index| Choice {
                        label: format!("host-{index}"),
                        status: ChoiceStatus::Checking,
                    })
                    .collect(),
            },
            selected: 0,
        }
    }

    #[test]
    fn navigation_and_acceptance_do_not_wait_for_checks() {
        let mut state = selection();
        state.key(KeyCode::Down.into(), 5).unwrap();
        assert_eq!(state.key(KeyCode::Enter.into(), 5).unwrap(), Some(1));
        assert!(
            state
                .options
                .choices
                .iter()
                .all(|choice| matches!(choice.status, ChoiceStatus::Checking))
        );
    }

    #[test]
    fn out_of_order_updates_preserve_selected_host_and_allow_unreachable_choice() {
        let mut state = selection();
        state.key(KeyCode::Down.into(), 5).unwrap();
        for index in [7, 1, 0] {
            state
                .update(ChoiceUpdate {
                    index,
                    status: ChoiceStatus::Ready {
                        text: "unreachable".into(),
                        color: Some(Color::Red),
                    },
                })
                .unwrap();
        }
        assert_eq!(state.key(KeyCode::Enter.into(), 5).unwrap(), Some(1));
        assert_eq!(state.options.choices[1].label, "host-1");
    }

    #[test]
    fn scrolling_and_resizing_keep_selection_visible() {
        let mut state = selection();
        state.key(KeyCode::End.into(), 5).unwrap();
        assert_eq!(state.visible_range(5), 10..13);
        assert!(state.visible_range(2).contains(&state.selected));
        state.key(KeyCode::Down.into(), 2).unwrap();
        assert_eq!(state.selected, 0);
        state.key(KeyCode::Up.into(), 2).unwrap();
        assert_eq!(state.selected, 12);
    }

    #[test]
    fn cancellation_is_typed() {
        for key in [
            KeyCode::Esc.into(),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            assert!(capulus::error_is_cancelled(
                &selection().key(key, 5).unwrap_err()
            ));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod terminal_tests;
