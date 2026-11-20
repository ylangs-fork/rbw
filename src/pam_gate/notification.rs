use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::process::CommandExt as _;
use std::process::Stdio;

use anyhow::Context as _;

use crate::protocol::Environment;

const BUNDLED_NOTIFY_SEND: &str =
    "/usr/lib/security/rbw-howdy/runtime/bin/notify-send";
const NOTIFICATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);
const AUTHORIZATION_TITLE: &str = "rbw authorization";
const AUTHORIZATION_BODY: &str =
    "Recognizing your face to authorize access to rbw secrets.";

/// Success confirms that the notification daemon accepted a real notification;
/// desktop do-not-disturb settings can still prevent a visible banner.
pub(super) async fn preflight(
    environment: &Environment,
) -> anyhow::Result<()> {
    send(
        environment,
        "rbw face authentication setup",
        "Desktop notifications are available for rbw face authorization.",
    )
    .await
}

pub(super) async fn authorize(
    environment: &Environment,
    title: &str,
    description: &str,
    request_link: Option<&str>,
) -> anyhow::Result<()> {
    let body = authorization_body(title, description);
    if let Some(url) = request_link {
        crate::desktop::notify_request(environment, AUTHORIZATION_TITLE, &body, url).await
    } else {
        send(environment, AUTHORIZATION_TITLE, &body).await
    }
}

fn authorization_body(title: &str, description: &str) -> String {
    // Never forward arbitrary prompt text (vault names, secrets, or markup).
    // Only the existing, strictly validated device-approval metadata is useful
    // on the desktop; even there the UUID itself is unnecessary.
    if title == "Approve device login" {
        if let Some((id, fingerprint)) = description
            .strip_prefix("Approve device login request ")
            .and_then(|value| value.split_once(" with fingerprint "))
        {
            if uuid::Uuid::parse_str(id)
                .is_ok_and(|parsed| parsed.to_string() == id)
                && safe_fingerprint(fingerprint)
            {
                return format!(
                    "Recognizing your face to approve device login. Fingerprint: {fingerprint}"
                );
            }
        }
    }
    AUTHORIZATION_BODY.to_string()
}

fn safe_fingerprint(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let mut count = 0;
    for word in value.split('-') {
        if word.is_empty()
            || !word.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            return false;
        }
        count += 1;
    }
    count == 5
}

pub(super) fn session_bus(
    environment: &Environment,
) -> anyhow::Result<std::ffi::OsString> {
    let variables = environment.env_vars();
    let address = if let Some(address) =
        variables.get(std::ffi::OsStr::new("DBUS_SESSION_BUS_ADDRESS"))
    {
        address.clone()
    } else {
        let runtime = variables
            .get(std::ffi::OsStr::new("XDG_RUNTIME_DIR"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(format!("/run/user/{}", unsafe {
                    libc::geteuid()
                }))
            });
        let metadata = std::fs::symlink_metadata(&runtime)
            .context("desktop notifications require a local user session")?;
        if !runtime.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            anyhow::bail!(
                "desktop notification runtime directory is insecure"
            );
        }
        let mut address = std::ffi::OsString::from("unix:path=");
        address.push(runtime.join("bus"));
        address
    };
    // No TCP, autolaunch, unixexec, or fallback transports: notifications must
    // stay on an existing local session socket owned by this effective user.
    let path = address
        .to_str()
        .and_then(|value| value.strip_prefix("unix:path="))
        .and_then(|value| {
            if let Some((path, guid)) = value.split_once(",guid=") {
                (guid.len() == 32
                    && guid.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then_some(path)
            } else {
                Some(value)
            }
        })
        .filter(|value| {
            !value.is_empty()
                && !value.contains([';', ',', '%'])
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "desktop notifications require a local unix:path session bus"
            )
        })?;
    let path = std::path::Path::new(path);
    let metadata = std::fs::symlink_metadata(path)
        .context("desktop notification session bus is unavailable")?;
    if !path.is_absolute()
        || !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        anyhow::bail!("desktop notification session bus is insecure");
    }
    Ok(address)
}

fn notification_executable() -> anyhow::Result<std::path::PathBuf> {
    let managed = std::path::Path::new("/usr/lib/security/rbw-howdy");
    let path = std::path::Path::new(if managed.try_exists()? {
        BUNDLED_NOTIFY_SEND
    } else {
        "/usr/bin/notify-send"
    });
    let canonical = std::fs::canonicalize(path).context(
        "desktop notification runtime is missing; reinstall the matching precompiled rbw package",
    )?;
    for candidate in [path, canonical.as_path()] {
        for component in candidate.ancestors() {
            let metadata = std::fs::metadata(component)?;
            anyhow::ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "desktop notification runtime path is insecure"
            );
        }
    }
    let metadata = std::fs::metadata(&canonical)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.mode() & 0o111 != 0,
        "desktop notification executable is unavailable"
    );
    Ok(canonical)
}

async fn send(
    environment: &Environment,
    title: &str,
    body: &str,
) -> anyhow::Result<()> {
    let executable = notification_executable()?;
    let environment = environment.with_desktop_fallback();
    let bus = session_bus(&environment)?;
    let mut command = tokio::process::Command::new(executable);
    command
        .args([
            "--app-name=rbw",
            "--urgency=critical",
            "--expire-time=10000",
            "--",
            title,
            body,
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("DBUS_SESSION_BUS_ADDRESS", bus)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    deliver(command, NOTIFICATION_TIMEOUT).await
}

async fn deliver(
    mut command: tokio::process::Command,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    command.kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command
        .spawn()
        .context("failed to start desktop notification")?;
    let mut group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(super::ProcessGroup::new)
        .ok_or_else(|| {
            anyhow::anyhow!("desktop notification process is unavailable")
        })?;
    let status = tokio::time::timeout(timeout, child.wait())
        .await
        .context("desktop notification timed out; authorization denied")?
        .context("desktop notification failed; authorization denied")?;
    group.disarm();
    if !status.success() {
        anyhow::bail!(
            "desktop notification was not accepted; check the user session notification service; authorization denied"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_context_never_enters_notifications() {
        for context in [
            "password=secret",
            "<b>secret</b>",
            "Approve device login request forged with fingerprint a-b-c-d-e",
        ] {
            assert_eq!(
                authorization_body("Approve device login", context),
                AUTHORIZATION_BODY,
            );
        }
    }

    #[test]
    fn only_bounded_plain_device_fingerprints_are_shown() {
        let id = "00000000-0000-0000-0000-000000000000";
        let description = format!(
            "Approve device login request {id} with fingerprint alpha-bravo-charlie-delta-echo"
        );
        let body = authorization_body("Approve device login", &description);
        assert!(body.contains("alpha-bravo-charlie-delta-echo"));
        assert!(!body.contains(id));
        for value in ["a-b-c-d", "<b>-b-c-d-e", "a-b-c-d-e\n", "a-b-c-d-e-f"]
        {
            assert!(!safe_fingerprint(value));
        }
        assert!(!safe_fingerprint(&format!("{}-a-b-c-d", "x".repeat(256))));
        assert_eq!(
            authorization_body("secret vault name", &description),
            AUTHORIZATION_BODY,
        );
    }

    #[test]
    fn remote_or_executable_bus_transports_are_rejected() {
        for address in [
            "tcp:host=example.org,port=1234",
            "unixexec:path=/bin/false",
            "autolaunch:",
            "unix:path=/run/user/1000/bus;tcp:host=example.org",
            "unix:path=/run/user/1000/bus,guid=untrusted",
        ] {
            let environment = Environment::new(
                None,
                vec![("DBUS_SESSION_BUS_ADDRESS".into(), address.into())],
            );
            assert!(session_bus(&environment).is_err());
        }
    }

    #[test]
    fn bus_must_be_an_owned_socket_not_a_file_or_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bus");
        let _listener =
            std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let environment = |path: &std::path::Path| {
            Environment::new(
                None,
                vec![(
                    "DBUS_SESSION_BUS_ADDRESS".into(),
                    format!("unix:path={}", path.display()).into(),
                )],
            )
        };
        assert!(session_bus(&environment(&socket)).is_ok());
        let with_guid = Environment::new(
            None,
            vec![(
                "DBUS_SESSION_BUS_ADDRESS".into(),
                format!(
                    "unix:path={},guid=0123456789abcdef0123456789abcdef",
                    socket.display()
                )
                .into(),
            )],
        );
        assert!(session_bus(&with_guid).is_ok());
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&socket, &alias).unwrap();
        assert!(session_bus(&environment(&alias)).is_err());
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(session_bus(&environment(&file)).is_err());
    }

    // Injection is limited to the process dependency boundary in these tests;
    // production always builds the fixed root-owned native notify-send command.
    #[tokio::test]
    async fn delivery_requires_a_successful_child_exit() {
        assert!(deliver(
            tokio::process::Command::new("/bin/true"),
            NOTIFICATION_TIMEOUT,
        )
        .await
        .is_ok());
        assert!(deliver(
            tokio::process::Command::new("/bin/false"),
            NOTIFICATION_TIMEOUT,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn delivery_timeout_is_fail_closed() {
        let mut command = tokio::process::Command::new("/bin/sleep");
        command.arg("30");
        let error = deliver(command, std::time::Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
