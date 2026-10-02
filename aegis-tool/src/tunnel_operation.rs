//! One bounded source-side operation, shared by the agent, CLI and command runner.
use std::{
    cell::RefCell,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::process::CommandExt,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use aegis_types::HostAlias;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(crate) struct Unauthorized;
impl std::fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel authorization expired")
    }
}
impl std::error::Error for Unauthorized {}

pub(crate) const TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const PATH: &str = "/aegis-agent/egress/operation";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub via: Option<HostAlias>,
    pub isolated: bool,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.isolated || self.via.is_some(),
            "isolated mode requires a gateway"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum State {
    Running {
        phase: String,
    },
    Succeeded {
        message: String,
    },
    Failed {
        message: String,
        interrupted: bool,
        unauthorized: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub id: u64,
    pub elapsed_ms: u64,
    pub remaining_ms: u64,
    pub state: State,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    pub source: aegis_types::HostId,
    pub central: Option<aegis_types::v1::AegisEgressStatus>,
    pub central_error: Option<String>,
    pub local: crate::agent::AgentTunnelStatus,
    pub aliases: std::collections::BTreeMap<aegis_types::HostId, String>,
    pub operation: Option<Snapshot>,
    pub recovery_pending: bool,
}

pub(crate) struct Operation {
    pub id: u64,
    pub owner: u32,
    started: Instant,
    deadline: Mutex<Instant>,
    cancelled: AtomicBool,
    state: Mutex<State>,
    last_poll: Mutex<Instant>,
}

impl Operation {
    pub fn new(id: u64, owner: u32) -> Arc<Self> {
        Arc::new(Self {
            id,
            owner,
            started: Instant::now(),
            deadline: Mutex::new(Instant::now() + TIMEOUT),
            cancelled: AtomicBool::new(false),
            state: Mutex::new(State::Running {
                phase: "Loading gateway".into(),
            }),
            last_poll: Mutex::new(Instant::now()),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            id: self.id,
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            remaining_ms: self
                .deadline
                .lock()
                .expect("operation deadline")
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
            state: self.state.lock().expect("operation state").clone(),
        }
    }

    pub fn running(&self) -> bool {
        matches!(
            *self.state.lock().expect("operation state"),
            State::Running { .. }
        )
    }

    pub fn heartbeat(&self) {
        *self.last_poll.lock().expect("operation lease") = Instant::now();
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn finish(&self, result: Result<String>) {
        *self.state.lock().expect("operation state") = match result {
            Ok(message) => State::Succeeded { message },
            Err(error) => State::Failed {
                interrupted: capulus::error_is_cancelled(&error),
                unauthorized: error
                    .downcast_ref::<crate::api::ApiClientError>()
                    .is_some_and(|error| error.is_unauthorized()),
                message: format!("{error:#}"),
            },
        };
    }

    pub fn run<T>(self: &Arc<Self>, work: impl FnOnce() -> Result<T>) -> Result<T> {
        scoped(
            ContextState {
                deadline: self.started + TIMEOUT,
                operation: Some(Arc::clone(self)),
            },
            work,
        )
    }
}

#[derive(Clone)]
struct ContextState {
    deadline: Instant,
    operation: Option<Arc<Operation>>,
}

thread_local! { static CURRENT: RefCell<Option<ContextState>> = const { RefCell::new(None) }; }

fn scoped<T>(context: ContextState, work: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Restore(Option<ContextState>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(CURRENT.with(|slot| slot.borrow_mut().replace(context)));
    work()
}

pub(crate) fn recover<T>(phase: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    CURRENT.with(|slot| {
        if let Some(operation) = slot
            .borrow()
            .as_ref()
            .and_then(|context| context.operation.as_ref())
        {
            *operation.state.lock().expect("operation state") = State::Running {
                phase: phase.into(),
            };
            *operation.deadline.lock().expect("operation deadline") = deadline;
        }
    });
    scoped(
        ContextState {
            deadline,
            operation: None,
        },
        work,
    )
}

pub(crate) fn bounded<T>(timeout: Duration, work: impl FnOnce() -> Result<T>) -> Result<T> {
    scoped(
        ContextState {
            deadline: Instant::now() + timeout,
            operation: None,
        },
        work,
    )
}

pub(crate) fn check() -> Result<()> {
    CURRENT.with(|slot| {
        if let Some(context) = slot.borrow().as_ref() {
            if context
                .operation
                .as_ref()
                .is_some_and(|op| op.cancelled.load(Ordering::SeqCst))
            {
                return Err(capulus::Cancelled.into());
            }
            if context.operation.as_ref().is_some_and(|op| {
                op.last_poll.lock().expect("operation lease").elapsed() > Duration::from_secs(4)
            }) {
                return Err(
                    anyhow::Error::new(capulus::Cancelled).context("tunnel client disconnected")
                );
            }
            ensure!(
                Instant::now() < context.deadline,
                "tunnel operation timed out"
            );
        }
        Ok(())
    })
}

pub(crate) fn phase(phase: &str) -> Result<()> {
    check()?;
    CURRENT.with(|slot| {
        if let Some(operation) = slot
            .borrow()
            .as_ref()
            .and_then(|context| context.operation.as_ref())
        {
            *operation.state.lock().expect("operation state") = State::Running {
                phase: phase.into(),
            };
        }
    });
    Ok(())
}

pub(crate) fn request_timeout(maximum: Duration) -> Result<Duration> {
    check()?;
    Ok(CURRENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|context| maximum.min(context.deadline.saturating_duration_since(Instant::now())))
            .unwrap_or(maximum)
    }))
}

pub(crate) fn active() -> bool {
    CURRENT.with(|slot| slot.borrow().is_some())
}

/// Keep the existing route while another operation or enrollment update owns the interface.
pub(crate) fn lock<T>(lock: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    let deadline = Instant::now() + request_timeout(Duration::from_secs(3))?;
    loop {
        check()?;
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => bail!("tunnel state lock is poisoned"),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        ensure!(
            Instant::now() < deadline,
            "tunnel configuration is busy; previous route retained"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn run_command(
    command: &mut Command,
    input: Option<&[u8]>,
) -> Result<capulus::process::CommandOutput> {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
    check()?;
    let deadline = Instant::now() + request_timeout(Duration::from_secs(10))?;
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = Child(
        command
            .stdin(std::process::Stdio::piped())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .process_group(0)
            .spawn()
            .context("failed to start tunnel command")?,
    );
    let mut stdin = child.0.stdin.take().expect("piped stdin");
    let input = input.unwrap_or_default().to_vec();
    // Keep /dev/stdin a pipe: AppArmor may deny reopening an inherited temporary file.
    // Killing the process group closes its readers, so this writer also exits on cancellation.
    let writer = thread::spawn(move || stdin.write_all(&input));
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        check().and_then(|()| {
            ensure!(Instant::now() < deadline, "tunnel command timed out");
            Ok(())
        })?;
        thread::sleep(Duration::from_millis(10));
    };
    drop(child);
    let written = writer
        .join()
        .map_err(|_| anyhow::anyhow!("tunnel input writer stopped"))?;
    if status.success() {
        written.context("failed to write tunnel command input")?;
    }
    let mut out = String::new();
    let mut err = String::new();
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    stdout.read_to_string(&mut out)?;
    stderr.read_to_string(&mut err)?;
    Ok(capulus::process::CommandOutput {
        status,
        stdout: out,
        stderr: err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_command_is_reaped_and_recovery_ignores_cancellation() {
        let operation = Operation::new(1, 1);
        let cancel = Arc::clone(&operation);
        let timer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(70));
            cancel.cancel();
        });
        let started = Instant::now();
        let error = operation
            .run(|| run_command(Command::new("sh").args(["-c", "sleep 30"]), None))
            .unwrap_err();
        timer.join().unwrap();
        assert!(capulus::error_is_cancelled(&error));
        assert!(started.elapsed() < Duration::from_secs(2));
        operation.run(|| recover("Restoring previous route", || {
            check()?;
            assert!(matches!(operation.snapshot().state, State::Running { phase } if phase == "Restoring previous route"));
            Ok(())
        })).unwrap();
        operation.finish(Err(error.context("previous route restored")));
        assert!(matches!(
            operation.snapshot().state,
            State::Failed {
                interrupted: true,
                ..
            }
        ));
    }

    #[test]
    fn abandoned_client_and_expired_deadline_stop_before_work() {
        let operation = Operation::new(1, 1);
        *operation.last_poll.lock().unwrap() = Instant::now() - Duration::from_secs(5);
        assert!(capulus::error_is_cancelled(
            &operation.run(check).unwrap_err()
        ));
        operation.heartbeat();
        operation.run(check).unwrap();
        let error = bounded(Duration::ZERO, || {
            run_command(Command::new("true").arg("unused"), None)
        })
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(!active(), "deadline context must be restored after errors");
    }

    #[test]
    fn command_input_is_a_pipe_and_large_writes_have_a_deadline() {
        let input = vec![b'x'; 128 * 1024];
        let output = bounded(Duration::from_secs(2), || {
            run_command(&mut Command::new("cat"), Some(&input))
        })
        .unwrap();
        assert_eq!(output.stdout.as_bytes(), input);
        let output = bounded(Duration::from_secs(2), || {
            run_command(Command::new("readlink").arg("/dev/stdin"), None)
        })
        .unwrap();
        assert_eq!(output.stdout.trim(), "/proc/self/fd/0");
        let started = Instant::now();
        assert!(
            bounded(Duration::from_millis(80), || run_command(
                Command::new("sleep").arg("30"),
                Some(&input)
            ))
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn wrapped_api_cancellation_preserves_type() {
        let error = anyhow::Error::new(crate::api::ApiClientError::Transport(
            capulus::Cancelled.into(),
        ));
        assert!(capulus::error_is_cancelled(&error));
    }
}
