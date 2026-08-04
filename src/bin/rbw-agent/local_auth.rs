use std::ffi::OsStr;
#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
use std::io::Read as _;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::ffi::{CStr, CString};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::fs::MetadataExt as _;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::process::CommandExt as _;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::process::Stdio;

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
use anyhow::Context as _;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use tokio::io::AsyncWriteExt as _;

const HELPER_ARGUMENT: &str = "--local-auth-helper";
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const PAM_POLICY_PATH: &str = "/etc/pam.d/rbw-device-auth";
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const PAM_SERVICE: &str = "rbw-device-auth";
#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
const MAX_HELPER_INPUT: usize = 64 * 1024;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct HelperInput {
    pinentry: String,
    environment: rbw::protocol::Environment,
    request_id: String,
    fingerprint: String,
}

pub fn helper_requested() -> bool {
    helper_requested_from(std::env::args_os())
}

fn helper_requested_from(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> bool {
    let mut args = args.into_iter();
    let _program = args.next();
    args.next().as_deref() == Some(OsStr::new(HELPER_ARGUMENT))
        && args.next().is_none()
}

/// Run the isolated PAM transaction. The caller deliberately exposes only the
/// process exit status; helper errors and PAM messages never cross into agent
/// logs or the public IPC protocol.
pub fn run_helper() -> bool {
    run_helper_inner().is_ok()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn run_helper_inner() -> anyhow::Result<()> {
    crate::debugger::disable_tracing()
        .context("failed to protect local-auth helper memory")?;
    validate_policy()?;
    let input = read_helper_input()?;
    let description = approval_description(&input)?;
    let username = effective_username()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize local-auth prompt runtime")?;
    let conversation = Conversation {
        username: CString::new(username.as_bytes())
            .context("effective username contains a NUL byte")?,
        pinentry: input.pinentry,
        environment: input.environment,
        description,
        runtime,
    };
    let mut context =
        pam_client2::Context::new(PAM_SERVICE, Some(&username), conversation)
            .context("failed to initialize PAM")?;
    context
        .authenticate(pam_client2::Flag::NONE)
        .context("PAM authentication failed")?;
    context
        .acct_mgmt(pam_client2::Flag::NONE)
        .context("PAM account authorization failed")?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn run_helper_inner() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "local system authentication requires GNU/Linux"
    ))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub async fn authorize(
    environment: &rbw::protocol::Environment,
    request_id: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    validate_approval_context(request_id, fingerprint).map_err(|_| {
        anyhow::anyhow!("local system authentication is unavailable")
    })?;
    let pinentry = rbw::config::Config::load_async()
        .await
        .map_err(|_| {
            anyhow::anyhow!("local system authentication is unavailable")
        })?
        .pinentry;
    let input = serde_json::to_vec(&HelperInput {
        pinentry,
        environment: environment.clone(),
        request_id: request_id.to_string(),
        fingerprint: fingerprint.to_string(),
    })
    .map_err(|_| {
        anyhow::anyhow!("local system authentication is unavailable")
    })?;
    if input.len() > MAX_HELPER_INPUT {
        return Err(anyhow::anyhow!(
            "local system authentication is unavailable"
        ));
    }

    let executable = std::env::current_exe().map_err(|_| {
        anyhow::anyhow!("local system authentication is unavailable")
    })?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg(HELPER_ARGUMENT)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|_| {
        anyhow::anyhow!("local system authentication is unavailable")
    })?;
    let mut process_group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(ProcessGroup::new)
        .ok_or_else(|| {
            anyhow::anyhow!("local system authentication is unavailable")
        })?;

    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            anyhow::anyhow!("local system authentication is unavailable")
        })?;
        stdin.write_all(&input).await.map_err(|_| {
            anyhow::anyhow!("local system authentication is unavailable")
        })?;
        stdin.shutdown().await.map_err(|_| {
            anyhow::anyhow!("local system authentication is unavailable")
        })?;
        drop(stdin);
        child.wait().await.map_err(|_| {
            anyhow::anyhow!("local system authentication is unavailable")
        })
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("local system authentication timed out")
    })??;

    // wait() reaped the helper and released its numeric PID/PGID. Disarm the
    // guard before branching so drop cannot signal a subsequently reused PGID.
    process_group.disarm();
    if !result.success() {
        return Err(anyhow::anyhow!("local system authentication failed"));
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub async fn authorize(
    _environment: &rbw::protocol::Environment,
    _request_id: &str,
    _fingerprint: &str,
) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "local system authentication requires a GNU/Linux build"
    ))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct ProcessGroup(Option<i32>);

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl ProcessGroup {
    const fn new(pgid: i32) -> Self {
        Self(Some(pgid))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }

    const fn signal_target(&self) -> Option<i32> {
        match self.0 {
            Some(pgid) => Some(-pgid),
            None => None,
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // The helper starts a fresh process group. Kill it only while the child
        // is still unreaped, which covers cancellation, timeout, and I/O error.
        if let Some(target) = self.signal_target() {
            let _ = unsafe { libc::kill(target, libc::SIGKILL) };
        }
    }
}

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
fn validate_approval_context(
    request_id: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    let parsed = uuid::Uuid::parse_str(request_id)
        .context("local-auth request ID is invalid")?;
    if parsed.to_string() != request_id {
        return Err(anyhow::anyhow!(
            "local-auth request ID is not canonical"
        ));
    }
    let mut words = fingerprint.split('-');
    for _ in 0..5 {
        let word = words.next().ok_or_else(|| {
            anyhow::anyhow!("local-auth fingerprint is invalid")
        })?;
        if word.is_empty()
            || !word.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            return Err(anyhow::anyhow!("local-auth fingerprint is invalid"));
        }
    }
    if words.next().is_some() {
        return Err(anyhow::anyhow!("local-auth fingerprint is invalid"));
    }
    Ok(())
}

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
fn approval_description(input: &HelperInput) -> anyhow::Result<String> {
    validate_approval_context(&input.request_id, &input.fingerprint)?;
    Ok(format!(
        "Approve device login request {} with fingerprint {}",
        input.request_id, input.fingerprint
    ))
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn validate_policy() -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(PAM_POLICY_PATH)
        .context("dedicated PAM policy is unavailable")?;
    if !policy_metadata_is_secure(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
    ) {
        return Err(anyhow::anyhow!("dedicated PAM policy is insecure"));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const fn policy_metadata_is_secure(
    is_regular: bool,
    uid: u32,
    mode: u32,
) -> bool {
    is_regular && uid == 0 && mode & 0o022 == 0
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn read_helper_input() -> anyhow::Result<HelperInput> {
    read_helper_input_from(std::io::stdin())
}

#[cfg(any(all(target_os = "linux", target_env = "gnu"), test))]
fn read_helper_input_from(
    reader: impl std::io::Read,
) -> anyhow::Result<HelperInput> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(MAX_HELPER_INPUT + 1).unwrap())
        .read_to_end(&mut bytes)
        .context("failed to read local-auth helper input")?;
    if bytes.len() > MAX_HELPER_INPUT {
        return Err(anyhow::anyhow!("local-auth helper input is too large"));
    }
    serde_json::from_slice(&bytes)
        .context("failed to parse local-auth helper input")
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn effective_username() -> anyhow::Result<String> {
    // getpwuid_r is used instead of USER/LOGNAME so the PAM identity is bound
    // to the helper process's effective UID. The buffer and result pointer are
    // valid for each call, and the returned C string is copied before the
    // buffer is dropped.
    let uid = unsafe { libc::geteuid() };
    let configured_size =
        unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if configured_size > 0 {
        usize::try_from(configured_size).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    };
    size = size.clamp(1024, 1024 * 1024);

    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; size];
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE && size < 1024 * 1024 {
            size = (size * 2).min(1024 * 1024);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc))
                .context("failed to resolve effective user");
        }
        if result.is_null() {
            return Err(anyhow::anyhow!("effective user is unknown"));
        }
        let record = unsafe { record.assume_init() };
        if record.pw_name.is_null() {
            return Err(anyhow::anyhow!("effective username is unavailable"));
        }
        let username = unsafe { CStr::from_ptr(record.pw_name) }
            .to_str()
            .context("effective username is not valid UTF-8")?
            .to_owned();
        return Ok(username);
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct Conversation {
    username: CString,
    pinentry: String,
    environment: rbw::protocol::Environment,
    description: String,
    runtime: tokio::runtime::Runtime,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl pam_client2::ConversationHandler for Conversation {
    fn prompt_echo_on(
        &mut self,
        _prompt: &CStr,
    ) -> Result<CString, pam_client2::ErrorCode> {
        Ok(self.username.clone())
    }

    fn prompt_echo_off(
        &mut self,
        _prompt: &CStr,
    ) -> Result<CString, pam_client2::ErrorCode> {
        let password = self
            .runtime
            .block_on(rbw::pinentry::getpin(
                &self.pinentry,
                "Local authentication",
                &self.description,
                None,
                &self.environment,
                false,
            ))
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)?;
        CString::new(password.password())
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn text_info(&mut self, _message: &CStr) {}

    fn error_msg(&mut self, _message: &CStr) {}

    fn radio_prompt(
        &mut self,
        _prompt: &CStr,
    ) -> Result<bool, pam_client2::ErrorCode> {
        Err(pam_client2::ErrorCode::CONV_ERR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    use pam_client2::ConversationHandler as _;

    fn valid_input() -> HelperInput {
        HelperInput {
            pinentry: "/usr/bin/pinentry".to_string(),
            environment: rbw::protocol::Environment::default(),
            request_id: "00000000-0000-0000-0000-000000000000".to_string(),
            fingerprint: "alpha-bravo-charlie-delta-echo".to_string(),
        }
    }

    #[test]
    fn helper_mode_requires_the_exact_hidden_argument() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(helper_requested_from(args(&[
            "rbw-agent",
            "--local-auth-helper",
        ])));
        assert!(!helper_requested_from(args(&["rbw-agent"])));
        assert!(!helper_requested_from(args(&[
            "rbw-agent",
            "--no-daemonize",
        ])));
        assert!(!helper_requested_from(args(&[
            "rbw-agent",
            "--local-auth-helper",
            "extra",
        ])));
    }

    #[test]
    fn helper_input_is_bounded_and_strict_json() {
        let encoded = serde_json::to_vec(&valid_input()).unwrap();
        let parsed = read_helper_input_from(encoded.as_slice()).unwrap();
        assert_eq!(parsed.request_id, "00000000-0000-0000-0000-000000000000");
        assert!(read_helper_input_from(&b"{"[..]).is_err());
        assert!(read_helper_input_from(
            vec![b'x'; MAX_HELPER_INPUT + 1].as_slice()
        )
        .unwrap_err()
        .to_string()
        .contains("too large"));
    }

    #[test]
    fn approval_description_accepts_only_safe_local_context() {
        let input = valid_input();
        let description = approval_description(&input).unwrap();
        assert!(description.contains(&input.request_id));
        assert!(description.contains(&input.fingerprint));
        assert!(!description.chars().any(char::is_control));

        let mut forged = valid_input();
        forged.request_id.push('\n');
        assert!(approval_description(&forged).is_err());
        let mut forged = valid_input();
        forged.fingerprint = "alpha-bravo-charlie-delta-\u{1b}".to_string();
        assert!(approval_description(&forged).is_err());
        let mut forged = valid_input();
        forged.fingerprint =
            "alpha-bravo-charlie-delta-echo-foxtrot".to_string();
        assert!(approval_description(&forged).is_err());
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn pam_policy_metadata_is_fail_closed() {
        assert_eq!(PAM_SERVICE, "rbw-device-auth");
        assert_eq!(PAM_POLICY_PATH, "/etc/pam.d/rbw-device-auth");
        assert!(policy_metadata_is_secure(true, 0, 0o100_644));
        assert!(policy_metadata_is_secure(true, 0, 0o100_600));
        assert!(!policy_metadata_is_secure(false, 0, 0o100_644));
        assert!(!policy_metadata_is_secure(true, 1000, 0o100_644));
        assert!(!policy_metadata_is_secure(true, 0, 0o100_664));
        assert!(!policy_metadata_is_secure(true, 0, 0o100_646));
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn effective_username_is_nonempty() {
        assert!(!effective_username().unwrap().is_empty());
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn echo_on_uses_the_fixed_effective_username() {
        let mut conversation = Conversation {
            username: CString::new("expected-user").unwrap(),
            pinentry: "unused".to_string(),
            environment: rbw::protocol::Environment::default(),
            description: "trusted description".to_string(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        };
        let response = conversation.prompt_echo_on(c"forged prompt").unwrap();
        assert_eq!(response.as_bytes(), b"expected-user");
        assert!(conversation.radio_prompt(c"yes?").is_err());
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn process_group_can_be_disarmed_before_drop() {
        let mut process_group = ProcessGroup::new(1234);
        assert_eq!(process_group.signal_target(), Some(-1234));
        process_group.disarm();
        assert_eq!(process_group.signal_target(), None);
        drop(process_group);
    }
}
