//! Runtime detection for process tracing and a Linux ptrace sentinel.
//!
//! This layer is detection and friction, not a boundary against a privileged,
//! targeted attacker.  In particular, direct `/proc/<pid>/mem` access does not
//! necessarily establish a ptrace relationship that appears in `TracerPid`.

const SENTINEL_ARG: &str = "--memory-sentinel";
#[cfg(target_os = "linux")]
const PR_SET_PTRACER: libc::c_int = 0x5961_6d61;
const WATCHDOG_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);

#[derive(Clone, Default)]
pub struct MemoryGuard {
    #[cfg(target_os = "linux")]
    expected_tracer: Option<u32>,
}

impl MemoryGuard {
    #[cfg(target_os = "linux")]
    fn check(&self) -> anyhow::Result<()> {
        self.check_observed_tracer(tracer_pid(std::process::id())?)
    }

    #[cfg(target_os = "linux")]
    fn check_observed_tracer(&self, tracer: u32) -> anyhow::Result<()> {
        match self.expected_tracer {
            Some(expected) if tracer == expected => Ok(()),
            None if tracer == 0 => Ok(()),
            Some(expected) => Err(anyhow::anyhow!(
                "rbw-agent ptrace sentinel missing or replaced: expected \
                 TracerPid {expected}, observed {tracer}"
            )),
            None => Err(anyhow::anyhow!(
                "rbw-agent is unexpectedly traced by pid {tracer}"
            )),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn check(&self) -> anyhow::Result<()> {
        // macOS already uses PT_DENY_ATTACH in debugger::disable_tracing().
        // Other supported non-Linux systems have no /proc TracerPid analogue;
        // keep the guard fail-open rather than clearing a valid session.
        Ok(())
    }

    /// Check tracing state before serving a request and clear all key material
    /// if the expected state has changed.
    pub async fn enforce(
        &self,
        state: &std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> anyhow::Result<()> {
        if let Err(error) = self.check() {
            state.lock().await.clear();
            warn_and_notify(&error);
            return Err(error);
        }
        Ok(())
    }

    /// Start the five-second periodic tracing check and the immediate sentinel
    /// exit monitor.
    pub fn spawn_watchdogs(
        &self,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
        sentinel_exit: Option<std::sync::mpsc::Receiver<()>>,
    ) {
        let guard = self.clone();
        let periodic_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                interval.tick().await;
                if guard.enforce(&periodic_state).await.is_err() {
                    break;
                }
            }
        });

        if let Some(exit) = sentinel_exit {
            tokio::spawn(async move {
                let exited =
                    tokio::task::spawn_blocking(move || exit.recv()).await;
                if exited.is_ok() {
                    let error = anyhow::anyhow!(
                        "rbw-agent ptrace sentinel exited unexpectedly"
                    );
                    state.lock().await.clear();
                    warn_and_notify(&error);
                }
            });
        }
    }
}

fn warn_and_notify(error: &anyhow::Error) {
    eprintln!("SECURITY WARNING: {error}");
    // HOOK(memory-guard-notification): a future desktop notification can be
    // emitted here without changing the key-clearing behavior.
}

#[cfg(target_os = "linux")]
fn tracer_pid(pid: u32) -> anyhow::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_tracer_pid(&status)
}

fn parse_tracer_pid(status: &str) -> anyhow::Result<u32> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .ok_or_else(|| {
            anyhow::anyhow!("TracerPid missing from proc status")
        })?;
    value
        .trim()
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid TracerPid: {error}"))
}

/// Start a helper process that occupies the Linux ptrace slot.
///
/// The child uses `PTRACE_ATTACH`, resumes the agent after the attach stop, and
/// forwards subsequent signals.  The attach is established before
/// `PR_SET_DUMPABLE(0)` is applied.  `PR_SET_PTRACER` authorizes exactly this
/// child under Yama; no wildcard ptracer exception is installed.
#[cfg(target_os = "linux")]
pub fn start_sentinel(
) -> anyhow::Result<(MemoryGuard, Option<std::sync::mpsc::Receiver<()>>)> {
    use std::io::{BufRead as _, Write as _};

    let parent_pid = std::process::id();
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg(SENTINEL_ARG)
        .arg(parent_pid.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let sentinel_pid = child.id();

    // Linux PR_SET_PTRACER, from linux/prctl.h. This bypasses only the Yama
    // ancestor restriction for the named sentinel.
    // SAFETY: prctl is called with the documented PR_SET_PTRACER operation and
    // a live child pid; trailing variadic arguments are unused and zeroed.
    let allowed = unsafe {
        libc::prctl(
            PR_SET_PTRACER,
            libc::c_ulong::from(sentinel_pid),
            0,
            0,
            0,
        )
    };
    if allowed != 0 {
        let error = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("sentinel stdin unavailable"))?
        .write_all(&[1])?;
    let mut ready = String::new();
    std::io::BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("sentinel stdout unavailable"))?,
    )
    .read_line(&mut ready)?;
    if ready.trim() != "READY" {
        let _ = child.kill();
        let _ = child.wait();
        return Err(anyhow::anyhow!(
            "ptrace sentinel failed to attach: {}",
            ready.trim()
        ));
    }

    let (exit_tx, exit_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("rbw-ptrace-sentinel-monitor".to_string())
        .spawn(move || {
            let _ = child.wait();
            let _ = exit_tx.send(());
        })?;

    Ok((
        MemoryGuard {
            expected_tracer: Some(sentinel_pid),
        },
        Some(exit_rx),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn start_sentinel(
) -> anyhow::Result<(MemoryGuard, Option<std::sync::mpsc::Receiver<()>>)> {
    Ok((MemoryGuard::default(), None))
}

pub fn sentinel_requested() -> bool {
    std::env::args().nth(1).as_deref() == Some(SENTINEL_ARG)
}

#[cfg(target_os = "linux")]
pub fn run_sentinel() -> bool {
    use std::io::{Read as _, Write as _};

    let Some(pid) = std::env::args()
        .nth(2)
        .and_then(|value| value.parse::<libc::pid_t>().ok())
    else {
        println!("ERROR invalid parent pid");
        return false;
    };
    let mut start = [0_u8; 1];
    if std::io::stdin().read_exact(&mut start).is_err() {
        println!("ERROR startup handshake failed");
        return false;
    }

    // SAFETY: pid comes from our parent, and null address/data are required by
    // PTRACE_ATTACH.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } != 0
    {
        println!("ERROR {}", std::io::Error::last_os_error());
        return false;
    }

    let mut status = 0;
    // SAFETY: status is a valid wait status pointer for the traced pid.
    if unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) } < 0 {
        println!("ERROR {}", std::io::Error::last_os_error());
        return false;
    }
    if !libc::WIFSTOPPED(status) {
        println!("ERROR tracee did not stop during attach");
        return false;
    }
    // SAFETY: the process is ptrace-stopped and null address/data are valid for
    // PTRACE_CONT with no delivered signal.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } != 0
    {
        println!("ERROR {}", std::io::Error::last_os_error());
        return false;
    }
    println!("READY");
    let _ = std::io::stdout().flush();

    loop {
        // SAFETY: status remains valid and pid is the tracee.
        let waited =
            unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) };
        if waited < 0 || libc::WIFEXITED(status) || libc::WIFSIGNALED(status)
        {
            break;
        }
        if libc::WIFSTOPPED(status) {
            let signal = libc::WSTOPSIG(status);
            // SAFETY: the process is ptrace-stopped. Deliver the intercepted
            // signal so the sentinel does not alter normal agent semantics.
            if unsafe {
                libc::ptrace(
                    libc::PTRACE_CONT,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    signal,
                )
            } != 0
            {
                break;
            }
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub fn run_sentinel() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracer_pid() {
        assert_eq!(
            parse_tracer_pid("Name:\ttest\nTracerPid:\t42\n").unwrap(),
            42
        );
        assert!(parse_tracer_pid("Name:\ttest\n").is_err());
    }

    #[test]
    fn detects_unexpected_tracer_from_status() {
        let tracer =
            parse_tracer_pid("TracerPid:\t19\n").expect("valid status");
        assert_ne!(tracer, 0);
        assert_ne!(tracer, 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifies_expected_and_unexpected_tracers() {
        assert!(MemoryGuard::default().check_observed_tracer(0).is_ok());
        assert!(MemoryGuard::default().check_observed_tracer(19).is_err());
        let sentinel = MemoryGuard {
            expected_tracer: Some(7),
        };
        assert!(sentinel.check_observed_tracer(7).is_ok());
        assert!(sentinel.check_observed_tracer(0).is_err());
        assert!(sentinel.check_observed_tracer(19).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enforcement_clears_keys_when_tracer_state_changes() {
        let (timeout, _timeout_receiver) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync_timeout_receiver) =
            crate::timeout::Timeout::new();
        let mut material = rbw::locked::Vec::new();
        material.extend(0_u8..64);
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::state::State {
                priv_key: Some(rbw::locked_shatter::ShatteredKeys::seal(
                    &rbw::locked::Keys::new(material),
                )),
                org_keys: Some(std::collections::HashMap::new()),
                clear_generation: tokio::sync::watch::channel(0).0,
                timeout,
                l1_timeout: std::time::Duration::from_secs(60),
                last_bio_success: None,
                pam_gate_required: false,
                ordinary_session: false,
                sync_timeout,
                sync_timeout_duration: std::time::Duration::ZERO,
                notifications_handler: crate::notifications::Handler::new(),
                master_password_reprompt: std::collections::HashSet::new(),
                master_password_reprompt_initialized: false,
                last_environment: rbw::protocol::Environment::default(),
                #[cfg(feature = "clipboard")]
                clipboard: None,
            },
        ));
        let guard = MemoryGuard {
            // No real process can have this PID on Linux.
            expected_tracer: Some(u32::MAX),
        };

        assert!(guard.enforce(&state).await.is_err());
        assert!(state.lock().await.needs_unlock());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attached_process_reports_tracer_pid() {
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("spawn sleep");
        let pid = libc::pid_t::try_from(child.id()).expect("child pid fits");
        // SAFETY: child is owned by this test process and valid for attach.
        let attached = unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        assert_eq!(attached, 0, "{}", std::io::Error::last_os_error());
        let mut status = 0;
        // SAFETY: status is valid and child is ptrace-stopped after attach.
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0) },
            pid
        );
        let tracer = tracer_pid(child.id()).unwrap();
        assert_ne!(tracer, 0);
        assert_ne!(tracer, child.id());
        // SAFETY: the child is ptrace-stopped and can be detached.
        assert_eq!(
            unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            },
            0
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
