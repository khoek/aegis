use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::ui;

const FIXTURE: &str = "AEGIS_SELECTOR_TEST_CHILD";

#[test]
fn terminal_fixture() {
    if std::env::var_os(FIXTURE).is_none() {
        return;
    }
    ui::init(capulus::ui::UiOptions {
        cancellation: capulus::ui::CancellationMode::Passive,
        ..Default::default()
    })
    .unwrap();
    eprintln!("BEFORE_MENU");
    let result = screen(|screen| {
        let selected = select_live(
            screen,
            SelectOptions {
                prompt: "Connect to".into(),
                choices: (0..13)
                    .map(|index| Choice {
                        label: format!("host-{index}"),
                        status: ChoiceStatus::Checking,
                    })
                    .collect(),
            },
            |_| Ok(()),
        )?;
        assert_eq!(selected, 1);
        screen.clear()?;
        let task = ui::task(ui::TaskOptions {
            label: "Preparing direct SSH session to host-1".into(),
            visibility: ui::TaskVisibility::Immediate,
            ..Default::default()
        })?;
        task.set_phase("Requesting a short-lived client certificate from the hub");
        thread::sleep(Duration::from_millis(400));
        task.finish_and_clear();
        Ok(())
    });
    if let Err(error) = result {
        assert!(capulus::error_is_cancelled(&error));
        eprintln!("CANCELLED");
    } else {
        eprintln!("SHELL_STARTED");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        assert_eq!(input.trim(), "shell input");
        eprintln!("INPUT_RESTORED");
    }
}

struct TerminalChild {
    process: Child,
    master: File,
}

impl TerminalChild {
    fn start() -> Self {
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 20,
            ws_col: 40,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // openpty initializes both descriptors on success; each File takes ownership once.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &size,
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "ui::selector::terminal_tests::terminal_fixture",
                "--exact",
                "--nocapture",
            ])
            .env(FIXTURE, "1")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // Establish a controlling terminal in the isolated test child before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            process: command.spawn().unwrap(),
            master,
        }
    }

    fn read(&mut self, parser: &mut vt100::Parser) {
        let mut poll = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Poll borrows one initialized descriptor and has a bounded wait.
        if unsafe { libc::poll(&mut poll, 1, 50) } > 0 {
            let mut buffer = [0; 8192];
            let size = self.master.read(&mut buffer).unwrap();
            parser.process(&buffer[..size]);
        }
    }
}

impl Drop for TerminalChild {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn resized_handoff_and_cancellation_preserve_the_main_screen_and_input() {
    for cancel in [false, true] {
        let mut child = TerminalChild::start();
        let mut parser = vt100::Parser::new(20, 40, 1000);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut selected = false;
        let mut resized = false;
        let mut handoff = false;
        loop {
            assert!(
                Instant::now() < deadline,
                "terminal child timed out: {}",
                parser.screen().contents()
            );
            child.read(&mut parser);
            let contents = parser.screen().contents();
            if !selected && contents.contains("0/13 checked") {
                child
                    .master
                    .write_all(if cancel { b"\x03" } else { b"\x1b[B\r" })
                    .unwrap();
                selected = true;
            }
            if !resized && contents.contains("Preparing direct SSH") {
                assert!(
                    parser.screen().alternate_screen(),
                    "preparation escaped the transient screen"
                );
                // The phone changes width before the resize notification reaches the hub.
                parser.screen_mut().set_size(20, 30);
                resized = true;
            }
            if !handoff && contents.contains(if cancel { "CANCELLED" } else { "SHELL_STARTED" }) {
                assert!(!parser.screen().alternate_screen());
                assert!(contents.contains("BEFORE_MENU"));
                assert!(!contents.contains("Preparing"));
                assert!(!contents.contains("checking"));
                assert!(
                    !contents
                        .chars()
                        .any(|c| ('\u{2800}'..='\u{28ff}').contains(&c))
                );
                if cancel {
                    break;
                }
                assert!(resized);
                child.master.write_all(b"shell input\r").unwrap();
                handoff = true;
            }
            if contents.contains("INPUT_RESTORED") {
                break;
            }
        }
    }
}
