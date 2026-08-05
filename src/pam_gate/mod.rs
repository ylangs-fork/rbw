// CONTRACT-STUB: replaced by B0 on merge
//! Temporary implementation of the shared PAM gate contract.
//!
//! Dimension B replaces this module with the hardened helper-process PAM
//! implementation. SSH-agent callers intentionally depend only on this API.

#[derive(Clone, Copy, Debug)]
pub struct PamGate;

impl PamGate {
    const POLICY_PATH: &'static str = "/etc/pam.d/rbw-device-auth";

    /// Detect whether the configured PAM service exists.
    ///
    /// B0 replaces this existence check with ownership and mode validation.
    pub fn detect() -> Option<Self> {
        std::path::Path::new(Self::POLICY_PATH)
            .is_file()
            .then_some(Self)
    }

    pub fn new() -> anyhow::Result<Self> {
        Self::detect().ok_or_else(|| {
            anyhow::anyhow!("PAM policy {} is unavailable", Self::POLICY_PATH)
        })
    }

    /// CONTRACT-STUB: B0 performs a fresh PAM conversation here.
    #[allow(clippy::unused_async)] // async is part of the B0 merge contract
    pub async fn authorize(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
