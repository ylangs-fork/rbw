use anyhow::Context as _;

pub use rbw::pam_gate::{helper_requested, run_helper};

/// Authorize release of a User Key for a specific device-login request.
///
/// Device-auth metadata remains validated here; the observable request UI owns
/// the native PAM gate and its lifecycle.
pub async fn authorize(
    environment: &rbw::protocol::Environment,
    request_id: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    validate_approval_context(request_id, fingerprint).map_err(|_| {
        anyhow::anyhow!("local system authentication is unavailable")
    })?;
    crate::request_ui::authorize_device(environment, request_id, fingerprint)
        .await
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_context_accepts_only_canonical_safe_metadata() {
        assert!(validate_approval_context(
            "00000000-0000-0000-0000-000000000000",
            "alpha-bravo-charlie-delta-echo",
        )
        .is_ok());
        assert!(validate_approval_context(
            "00000000-0000-0000-0000-000000000000\n",
            "alpha-bravo-charlie-delta-echo",
        )
        .is_err());
        assert!(validate_approval_context(
            "00000000-0000-0000-0000-000000000000",
            "alpha-bravo-charlie-delta-\u{1b}",
        )
        .is_err());
        assert!(validate_approval_context(
            "00000000-0000-0000-0000-000000000000",
            "alpha-bravo-charlie-delta-echo-foxtrot",
        )
        .is_err());
    }
}
