use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use anyhow::Context as _;

const AUTH_REQUEST_DISPLAY_FIELD_MAX: usize = 256;

pub fn auth_request_display_field(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let escaped = character.escape_default().to_string();
        if output.len() + escaped.len() > AUTH_REQUEST_DISPLAY_FIELD_MAX {
            output.truncate(AUTH_REQUEST_DISPLAY_FIELD_MAX.saturating_sub(3));
            output.push_str("...");
            break;
        }
        output.push_str(&escaped);
    }
    output
}

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlock_with_device() -> anyhow::Result<()> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::UnlockWithDevice,
    ))?;
    loop {
        match sock.recv()? {
            rbw::protocol::Response::DeviceAuthPending {
                id,
                fingerprint,
            } => {
                eprintln!("Auth request: {id}");
                eprintln!("Fingerprint: {fingerprint}");
                eprintln!(
                    "Approve this request from another unlocked device."
                );
            }
            rbw::protocol::Response::Ack => return Ok(()),
            rbw::protocol::Response::Error { error } => {
                return Err(anyhow::anyhow!(error));
            }
            response => {
                return Err(anyhow::anyhow!(
                    "unexpected message: {response:?}"
                ));
            }
        }
    }
}

pub fn list_auth_requests(
) -> anyhow::Result<Vec<rbw::protocol::AuthRequestInfo>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::ListAuthRequests,
    ))?;
    match sock.recv()? {
        rbw::protocol::Response::AuthRequests { requests } => Ok(requests),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!(error))
        }
        response => Err(anyhow::anyhow!("unexpected message: {response:?}")),
    }
}

pub fn approve_auth_request(id: &str) -> anyhow::Result<()> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::ApproveAuthRequest { id: id.to_string() },
    ))?;
    loop {
        match sock.recv()? {
            rbw::protocol::Response::AuthRequestApproval { request } => {
                eprintln!(
                    "Request: {}",
                    auth_request_display_field(&request.id)
                );
                eprintln!(
                    "Device: {}",
                    auth_request_display_field(&request.device_type)
                );
                eprintln!(
                    "IP address: {}",
                    auth_request_display_field(&request.ip_address)
                );
                eprintln!(
                    "Fingerprint: {}",
                    auth_request_display_field(&request.fingerprint)
                );
                eprintln!("Complete local system authentication to approve.");
            }
            rbw::protocol::Response::Ack => return Ok(()),
            rbw::protocol::Response::Error { error } => {
                return Err(anyhow::anyhow!(error));
            }
            response => {
                return Err(anyhow::anyhow!(
                    "unexpected message: {response:?}"
                ));
            }
        }
    }
}

pub fn reject_auth_request(id: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::RejectAuthRequest {
        id: id.to_string(),
    })
}

pub fn unlocked() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = sock.recv()?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                anyhow::bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::Quit,
            ))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn decrypt(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Version,
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new(get_environment(), action))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}

#[cfg(test)]
mod auth_request_display_tests {
    use super::*;

    #[test]
    fn auth_request_fields_escape_controls_and_are_bounded() {
        assert_eq!(
            auth_request_display_field("device\n\u{1b}[31m\tname"),
            "device\\n\\u{1b}[31m\\tname"
        );
        let output = auth_request_display_field(&"x".repeat(1024));
        assert_eq!(output.len(), AUTH_REQUEST_DISPLAY_FIELD_MAX);
        assert!(output.ends_with("..."));
        assert!(!output.chars().any(char::is_control));
    }
}
