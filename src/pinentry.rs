use crate::prelude::*;

use std::convert::TryFrom as _;

use tokio::io::AsyncWriteExt as _;

pub async fn getpin(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<crate::locked::Password> {
    getpin_with_timeout(
        pinentry,
        prompt,
        desc,
        err,
        environment,
        grab,
        std::time::Duration::from_secs(120),
    )
    .await
}

async fn getpin_with_timeout(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
    timeout: std::time::Duration,
) -> Result<crate::locked::Password> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // Do not let a stale inherited tty send curses into an unbounded retry loop.
    // O_NONBLOCK also prevents validation itself from hanging on a bogus path.
    let tty = environment.tty().and_then(|path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .ok()
            .filter(|file| {
                // SAFETY: the descriptor is owned and live for this call.
                unsafe { libc::isatty(file.as_raw_fd()) == 1 }
            })
            .map(|file| (path, file))
    });
    let env_vars = environment.env_vars();
    let has_display = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|name| {
        env_vars
            .get(std::ffi::OsStr::new(name))
            .is_some_and(|value| !value.is_empty())
    });
    if tty.is_none() && !has_display {
        return Err(Error::PinentryUnavailable);
    }

    let mut opts = tokio::process::Command::new(pinentry);
    opts.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true);
    // The protocol I/O deadline below remains authoritative, including helpers
    // that ignore --timeout or hang after returning a password.
    let seconds = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() != 0))
        .max(1);
    let mut args = vec!["--timeout".into(), seconds.to_string().into()];
    if let Some((path, _file)) = &tty {
        args.extend(["--ttyname".into(), (*path).into()]);
    }
    // Some graphical pinentries require DISPLAY in both the argument and env.
    if let Some(display) = env_vars.get(std::ffi::OsStr::new("DISPLAY")) {
        args.extend(["--display".into(), display.clone()]);
    }
    if !grab {
        args.push("--no-global-grab".into());
    }
    opts.args(args);
    for env_var in &*crate::protocol::ENVIRONMENT_VARIABLES_OS {
        if let Some(val) = env_vars.get(env_var) {
            opts.env(env_var, val);
        } else {
            opts.env_remove(env_var);
        }
    }
    opts.envs(env_vars);

    #[cfg(target_os = "linux")]
    {
        // Capture the parent's PID before fork; close the race where it dies
        // just before the child installs its parent-death signal.
        let parent = std::process::id();
        // SAFETY: pre_exec only invokes async-signal-safe libc calls, without
        // allocation, logging or locks inherited from the multithreaded agent.
        unsafe {
            opts.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid().cast_unsigned() != parent {
                    return Err(std::io::Error::from_raw_os_error(
                        libc::ECANCELED,
                    ));
                }
                Ok(())
            });
        }
    }

    let mut child = opts.spawn().map_err(|source| Error::Spawn { source })?;
    let result = tokio::time::timeout(timeout, async {
        // These pipes are present because the command configured them above.
        let mut stdin = child.stdin.take().unwrap();
        let mut ncommands = 1;
        let mut commands =
            format!("SETTITLE rbw\nSETPROMPT {prompt}\nSETDESC {desc}\n");
        ncommands += 3;
        if let Some(err) = err {
            commands.push_str(&format!("SETERROR {err}\n"));
            ncommands += 1;
        }
        commands.push_str("GETPIN\n");
        ncommands += 1;
        stdin
            .write_all(commands.as_bytes())
            .await
            .map_err(|source| Error::WriteStdin { source })?;
        drop(stdin);

        let mut buf = crate::locked::Vec::new();
        buf.zero();
        let len = read_password(
            ncommands,
            buf.data_mut(),
            child.stdout.as_mut().unwrap(),
        )
        .await?;
        buf.truncate(len);
        child
            .wait()
            .await
            .map_err(|source| Error::PinentryWait { source })?;
        Ok(crate::locked::Password::new(buf))
    })
    .await;

    match result {
        Ok(Ok(password)) => Ok(password),
        failure => {
            // Also reap on protocol/write errors, not only on the deadline.
            // kill_on_drop covers cancellation by a shorter enclosing request.
            let _ = child.start_kill();
            child
                .wait()
                .await
                .map_err(|source| Error::PinentryWait { source })?;
            match failure {
                Ok(Err(error)) => Err(error),
                Err(_) => Err(Error::PinentryTimeout),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}

async fn read_password<R>(
    mut ncommands: u8,
    data: &mut [u8],
    mut r: R,
) -> Result<usize>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncReadExt + Unpin + Send,
{
    let mut len = 0;
    loop {
        let nl = data.iter().take(len).position(|c| *c == b'\n');
        if let Some(nl) = nl {
            if data.starts_with(b"OK") {
                if ncommands == 1 {
                    len = 0;
                    break;
                }
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
                ncommands -= 1;
            } else if data.starts_with(b"D ") {
                data.copy_within(2..nl, 0);
                len = nl - 2;
                break;
            } else if data.starts_with(b"S ") {
                data.copy_within((nl + 1).., 0);
                len -= nl + 1;
            } else if data.starts_with(b"ERR ") {
                let line: Vec<u8> = data.iter().take(nl).copied().collect();
                let line = String::from_utf8(line).unwrap();
                let mut split = line.splitn(3, ' ');
                let _ = split.next(); // ERR
                let code = split.next();
                match code {
                    Some("83886179") => {
                        return Err(Error::PinentryCancelled);
                    }
                    Some(code) => {
                        if let Some(error) = split.next() {
                            return Err(Error::PinentryErrorMessage {
                                error: error.to_string(),
                            });
                        }
                        return Err(Error::PinentryErrorMessage {
                            error: format!("unknown error ({code})"),
                        });
                    }
                    None => {
                        return Err(Error::PinentryErrorMessage {
                            error: "unknown error".to_string(),
                        });
                    }
                }
            } else {
                return Err(Error::FailedToParsePinentry {
                    out: String::from_utf8_lossy(data)
                        .trim_end_matches('\0')
                        .to_string(),
                });
            }
        } else {
            let bytes = r
                .read(&mut data[len..])
                .await
                .map_err(|source| Error::PinentryReadOutput { source })?;
            if bytes == 0 {
                return Err(Error::PinentryReadOutput {
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ),
                });
            }
            len += bytes;
        }
    }

    len = percent_decode(&mut data[..len]);

    Ok(len)
}

// not using the percent-encoding crate because it doesn't provide a way to do
// this in-place, and we want the password to always live within the locked
// vec. should really move something like this into the percent-encoding crate
// at some point.
fn percent_decode(buf: &mut [u8]) -> usize {
    let mut read_idx = 0;
    let mut write_idx = 0;
    let len = buf.len();

    while read_idx < len {
        let mut c = buf[read_idx];

        if c == b'%' && read_idx + 2 < len {
            if let Some(h) = char::from(buf[read_idx + 1]).to_digit(16) {
                if let Some(l) = char::from(buf[read_idx + 2]).to_digit(16) {
                    // h and l were parsed from a single hex digit, so they
                    // must be in the range 0-15, so these unwraps are safe
                    c = u8::try_from(h).unwrap() * 0x10
                        + u8::try_from(l).unwrap();
                    read_idx += 2;
                }
            }
        }

        buf[write_idx] = c;
        read_idx += 1;
        write_idx += 1;
    }

    write_idx
}

#[test]
fn test_read_password() {
    let good_inputs = &[
        (0, &b"D super secret password\n"[..]),
        (4, &b"OK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (12, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
        (24, &b"OK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nOK\nD super secret password\nOK\n"[..]),
    ];
    for (ncommands, input) in good_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(*ncommands, &mut buf, &input[..])
                .await
                .unwrap();
            assert_eq!(&buf[0..len], b"super secret password");
        });
    }

    let match_inputs = &[
        (&b"OK\nOK\nOK\nOK\n"[..], &b""[..]),
        (&b"D foo%25bar\n"[..], &b"foo%bar"[..]),
        (&b"D foo%0abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Abar\n"[..], &b"foo\nbar"[..]),
        (&b"D foo%0Gbar\n"[..], &b"foo%0Gbar"[..]),
        (&b"D foo%0\n"[..], &b"foo%0"[..]),
        (&b"D foo%\n"[..], &b"foo%"[..]),
        (&b"D %25foo\n"[..], &b"%foo"[..]),
        (&b"D %25\n"[..], &b"%"[..]),
    ];

    for (input, output) in match_inputs {
        let mut buf = [0; 64];
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let len = read_password(4, &mut buf, &input[..]).await.unwrap();
            assert_eq!(&buf[0..len], &output[..]);
        });
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("pinentry-fixture");
        std::fs::write(&helper, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(
            &helper,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        (dir, helper)
    }

    fn graphical(
        tty: Option<std::ffi::OsString>,
    ) -> crate::protocol::Environment {
        crate::protocol::Environment::new(
            tty,
            [("DISPLAY".into(), ":pinentry-fixture".into())]
                .into_iter()
                .collect(),
        )
    }

    async fn prompt(
        helper: &std::path::Path,
        env: &crate::protocol::Environment,
    ) -> Result<crate::locked::Password> {
        getpin_with_timeout(
            helper.to_str().unwrap(),
            "Test",
            "Fixture only",
            None,
            env,
            true,
            std::time::Duration::from_millis(250),
        )
        .await
    }

    fn assert_reaped(pidfile: &std::path::Path) {
        let pid: i32 = std::fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal zero only probes this fixture's recorded PID.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "fixture still exists (possibly a zombie)"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_tty_does_not_start_pinentry() {
        let (dir, helper) = fixture("printf started > \"$0.started\"");
        let env = crate::protocol::Environment::new(
            Some(dir.path().join("missing-tty").into_os_string()),
            Default::default(),
        );
        assert!(matches!(
            prompt(&helper, &env).await,
            Err(Error::PinentryUnavailable)
        ));
        assert!(!std::path::PathBuf::from(format!(
            "{}.started",
            helper.display()
        ))
        .exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_file_is_not_a_terminal() {
        let (dir, helper) = fixture("printf started > \"$0.started\"");
        let file = dir.path().join("not-a-tty");
        std::fs::write(&file, "").unwrap();
        let env = crate::protocol::Environment::new(
            Some(file.into_os_string()),
            Default::default(),
        );
        assert!(matches!(
            prompt(&helper, &env).await,
            Err(Error::PinentryUnavailable)
        ));
        assert!(!std::path::PathBuf::from(format!(
            "{}.started",
            helper.display()
        ))
        .exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn graphical_prompt_omits_stale_tty_and_has_finite_timeout() {
        let (dir, helper) = fixture(
            "case \" $* \" in *\" --ttyname \"*|*\" --timeout 0 \"*) printf 'ERR 1 invalid arguments\\n'; exit 1;; esac\n\
             while IFS= read -r line; do case \"$line\" in GETPIN) printf 'D fixture-password\\n';; *) printf 'OK\\n';; esac; done"
        );
        let env =
            graphical(Some(dir.path().join("missing-tty").into_os_string()));
        let password = prompt(&helper, &env).await.unwrap();
        assert_eq!(password.password(), b"fixture-password");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn real_terminal_is_accepted_without_a_display() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes these two descriptors; optional pointers are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: each returned descriptor is exclusively owned by one File.
        let (_master, slave) = unsafe {
            (
                std::fs::File::from_raw_fd(master),
                std::fs::File::from_raw_fd(slave),
            )
        };
        let mut name = [0_i8; 256];
        // SAFETY: name is a writable buffer and slave remains open.
        assert_eq!(
            unsafe {
                libc::ttyname_r(
                    slave.as_raw_fd(),
                    name.as_mut_ptr(),
                    name.len(),
                )
            },
            0
        );
        // SAFETY: ttyname_r wrote a nul-terminated path after successful return.
        let path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_str()
            .unwrap();
        let (_dir, helper) = fixture("printf 'D fixture-password\\n'");
        let env =
            crate::protocol::Environment::new(Some(path.into()), Vec::new());
        assert_eq!(
            prompt(&helper, &env).await.unwrap().password(),
            b"fixture-password"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_pinentry_installs_parent_death_signal() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("probe.c");
        let helper = dir.path().join("pinentry-probe");
        // Query in the executable's main thread: libtest creates another
        // thread for each Rust test, whose own PDEATHSIG starts at zero.
        std::fs::write(
            &source,
            r#"
#include <stdio.h>
#include <sys/prctl.h>
int main(void) {
    int signal = 0;
    char line[256];
    if (prctl(PR_GET_PDEATHSIG, &signal) != 0) return 1;
    while (fgets(line, sizeof(line), stdin) != NULL) {}
    printf("D %d\n", signal);
    return 0;
}
"#,
        )
        .unwrap();
        let build = std::process::Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&helper)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let password = getpin_with_timeout(
            helper.to_str().unwrap(),
            "Test",
            "Fixture only",
            None,
            &graphical(None),
            true,
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(password.password(), libc::SIGKILL.to_string().as_bytes());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hung_reader_times_out_and_is_reaped() {
        let (dir, helper) =
            fixture("printf '%s' $$ > \"$0.pid\"; exec sleep 30");
        assert!(matches!(
            prompt(&helper, &graphical(None)).await,
            Err(Error::PinentryTimeout)
        ));
        assert_reaped(&dir.path().join("pinentry-fixture.pid"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn password_then_hung_exit_is_also_bounded() {
        let (dir, helper) = fixture("printf '%s' $$ > \"$0.pid\"; printf 'D fixture-password\\n'; exec sleep 30");
        assert!(matches!(
            prompt(&helper, &graphical(None)).await,
            Err(Error::PinentryTimeout)
        ));
        assert_reaped(&dir.path().join("pinentry-fixture.pid"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_error_also_kills_and_reaps() {
        let (dir, helper) = fixture("printf '%s' $$ > \"$0.pid\"; printf 'ERR 1 fixture-rejected\\n'; exec sleep 30");
        assert!(matches!(
            prompt(&helper, &graphical(None)).await,
            Err(Error::PinentryErrorMessage { .. })
        ));
        assert_reaped(&dir.path().join("pinentry-fixture.pid"));
    }
}
