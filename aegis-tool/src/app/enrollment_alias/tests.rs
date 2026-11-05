use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use super::*;

const HOSTNAME: &str = "AEGIS_ALIAS_TEST_HOSTNAME";
const FIXTURE: &str = "app::enrollment_alias::tests::alias_prompt_fixture";

#[test]
fn valid_short_hostname_is_used_without_a_prompt() {
    for (hostname, expected) in [("laptop", "laptop"), ("laptop.example.com", "laptop")] {
        assert_eq!(
            select(&CString::new(hostname).unwrap()).unwrap().as_str(),
            expected
        );
    }
}

#[test]
fn alias_prompt_fixture() {
    let Some(hostname) = std::env::var_os(HOSTNAME) else {
        return;
    };
    ui::init(capulus::ui::UiOptions {
        progress: capulus::ui::ProgressMode::Plain,
        cancellation: capulus::ui::CancellationMode::Signal,
        ..Default::default()
    })
    .unwrap();
    use std::os::unix::ffi::OsStrExt;
    match select(&CString::new(hostname.as_bytes()).unwrap()) {
        Ok(alias) => eprintln!("SELECTED={alias}"),
        Err(error) if capulus::error_is_cancelled(&error) => eprintln!("CANCELLED"),
        Err(error) => eprintln!("FAILED={error:#}"),
    }
}

fn fixture_command(hostname: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([FIXTURE, "--exact", "--nocapture"])
        .env(HOSTNAME, hostname)
        .env("TERM", "xterm-256color");
    command
}

#[test]
fn invalid_hostnames_without_a_terminal_request_an_explicit_name() {
    use std::os::unix::ffi::OsStrExt;
    for hostname in [
        b"Zoes-MacBook.local".as_slice(),
        b"",
        b"a9b0c1d2-0000-4000-8000-000000000000",
        b"non-utf8-\xff",
    ] {
        let output = capulus::process::CaptureOptions::default()
            .validate()
            .unwrap()
            .run(
                fixture_command(std::ffi::OsStr::from_bytes(hostname)).stdin(Stdio::null()),
                None,
            )
            .unwrap();
        assert!(output.status.success(), "{}", output.stderr);
        assert!(output.stderr.contains("FAILED="), "{}", output.stderr);
        assert!(output.stderr.contains("--name ALIAS"), "{}", output.stderr);
        assert!(!output.stdout.contains("Host alias"));
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
        // openpty initializes both descriptors; each File takes ownership once.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let mut command = fixture_command("Zoes-MacBook.local");
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(slave));
        // Give the isolated child its own controlling terminal before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
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

    fn read_until(&mut self, expected: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = Vec::new();
        loop {
            let text = String::from_utf8_lossy(&output);
            if text.contains(expected) {
                return text.into_owned();
            }
            assert!(Instant::now() < deadline, "waiting for {expected}: {text}");
            let mut poll = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // Poll borrows an initialized descriptor and has a bounded wait.
            if unsafe { libc::poll(&mut poll, 1, 50) } > 0 {
                let mut buffer = [0; 4096];
                let size = self
                    .master
                    .read(&mut buffer)
                    .expect("reading test terminal");
                output.extend_from_slice(&buffer[..size]);
            }
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
fn invalid_hostname_prompts_and_rejects_invalid_answers() {
    let mut child = TerminalChild::start();
    child.read_until("Host alias for this computer");
    child.master.write_all(b"Still Invalid\r").unwrap();
    child.read_until("host alias must use lowercase");
    child.master.write_all(b"zoes-macbook\r").unwrap();
    child.read_until("SELECTED=zoes-macbook");
}

#[test]
fn interrupting_the_alias_prompt_preserves_typed_cancellation() {
    let mut child = TerminalChild::start();
    child.read_until("Host alias for this computer");
    child.master.write_all(b"\x03").unwrap();
    child.read_until("CANCELLED");
}
