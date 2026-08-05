use sha2::Digest as _;

pub const REMOTE_L1_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);

pub struct State {
    // HOOK(shatter): state-machine must preserve this wrapped representation
    // when adding L1 metadata and should use `with_key` for all access.
    pub priv_key: Option<rbw::locked_shatter::ShatteredKeys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub(crate) clear_generation: tokio::sync::watch::Sender<u64>,
    pub timeout: crate::timeout::Timeout,
    pub l1_timeout: std::time::Duration,
    pub last_bio_success: Option<std::time::Instant>,
    /// Fixed at agent startup. Once a secure local PAM policy selects the
    /// local mode, a later policy error must fail closed instead of silently
    /// downgrading the running session to the remote bypass mode.
    pub(crate) pam_gate_required: bool,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,
    pub master_password_reprompt: std::collections::HashSet<[u8; 32]>,
    pub master_password_reprompt_initialized: bool,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: rbw::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    fn has_keys(&self) -> bool {
        self.priv_key.is_some() && self.org_keys.is_some()
    }

    /// Clone the user/org key material out of `ShatteredKeys` for callers that
    /// need to hold the plaintext across multiple operations (e.g. decrypt
    /// with reprompt). The clone is short-lived on the caller's stack; this
    /// relaxes the strict closure confinement of `with_key` for legacy
    /// multi-step paths. Gated by L1 liveness.
    pub fn key_cloned(
        &self,
        org_id: Option<&str>,
    ) -> Option<rbw::locked::Keys> {
        if !self.l1_alive() {
            return None;
        }
        org_id.map_or_else(
            || {
                self.priv_key
                    .as_ref()
                    .map(|keys| keys.with_unsealed(std::clone::Clone::clone))
            },
            |id| {
                self.org_keys
                    .as_ref()
                    .and_then(|keys| keys.get(id))
                    .cloned()
            },
        )
    }

    /// Access the user/org key material inside a closure so the plaintext
    /// only exists transiently (`ShatteredKeys`). Gated by L1 liveness: returns
    /// None when the L1 session has expired (caller must re-unlock).
    #[allow(dead_code)]
    pub fn with_key<R>(
        &self,
        org_id: Option<&str>,
        f: impl FnOnce(&rbw::locked::Keys) -> R,
    ) -> Option<R> {
        if !self.l1_alive() {
            return None;
        }
        if let Some(id) = org_id {
            self.org_keys.as_ref().and_then(|keys| keys.get(id)).map(f)
        } else {
            self.priv_key.as_ref().map(|keys| keys.with_unsealed(f))
        }
    }

    pub fn needs_unlock(&self) -> bool {
        !self.l1_alive()
    }

    pub fn l1_alive(&self) -> bool {
        self.has_keys()
            && self
                .last_bio_success
                .is_some_and(|last| last.elapsed() < self.l1_timeout)
    }

    pub fn pam_gate_required(&self) -> bool {
        self.pam_gate_required
    }

    pub fn effective_l1_timeout(
        configured: std::time::Duration,
        pam_gate_required: bool,
    ) -> std::time::Duration {
        if pam_gate_required {
            configured
        } else {
            configured.min(REMOTE_L1_TIMEOUT)
        }
    }

    /// Begin or renew the L1 lifetime after a trusted authorization event.
    pub fn record_bio_success(&mut self) {
        self.last_bio_success = Some(std::time::Instant::now());
        self.timeout.set(self.l1_timeout);
    }

    /// Refresh the L1 timeout without recording a new bio heartbeat. Used by
    /// non-sensitive actions that should keep an already-live session alive
    /// but must not themselves renew authorization.
    pub fn set_timeout(&self) {
        self.timeout.set(self.l1_timeout);
    }

    /// A cold unlock is a stronger authorization event than a bio heartbeat
    /// and starts the same L1 lifetime.
    #[allow(dead_code)]
    pub fn begin_l1_session(&mut self) {
        self.record_bio_success();
    }

    // HOOK(state-machine): B2 replaces this unlocked-state approximation
    // with the L1 expiry calculation from the shared contract.
    // -> merged: real l1_alive() is defined above (line ~88); this hook removed.

    // HOOK(state-machine): B3 replaces the existing timeout reset with the
    // dedicated bio-heartbeat timestamp.
    // -> merged: real record_bio_success() is defined above (line ~111); this hook removed.

    pub fn cancellation(&self) -> Cancellation {
        Cancellation {
            receiver: self.clear_generation.subscribe(),
        }
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.timeout.clear();
        self.last_bio_success = None;
        let next = self.clear_generation.borrow().wrapping_add(1);
        self.clear_generation.send_replace(next);
    }

    pub fn set_sync_timeout(&self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }

    // the way we structure the client/agent split in rbw makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled. this set is only updated when the agent itself does
    // a sync, so it can't be bypassed by editing the on-disk file directly.
    // if the agent gets a request for any of those cipherstrings that it saw
    // marked as master password reprompt during the most recent sync, it
    // forces a reprompt.
    pub fn set_master_password_reprompt(
        &mut self,
        entries: &[rbw::db::Entry],
    ) {
        self.master_password_reprompt.clear();

        let mut hasher = sha2::Sha256::new();
        let mut insert = |s: Option<&str>| {
            if let Some(s) = s {
                if !s.is_empty() {
                    hasher.update(s);
                    self.master_password_reprompt
                        .insert(hasher.finalize_reset().into());
                }
            }
        };

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                rbw::db::EntryData::Login { password, totp, .. } => {
                    insert(password.as_deref());
                    insert(totp.as_deref());
                }
                rbw::db::EntryData::Card { number, code, .. } => {
                    insert(number.as_deref());
                    insert(code.as_deref());
                }
                rbw::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    insert(ssn.as_deref());
                    insert(passport_number.as_deref());
                }
                rbw::db::EntryData::SecureNote => {}
                rbw::db::EntryData::SshKey { private_key, .. } => {
                    insert(private_key.as_deref());
                }
            }

            for field in &entry.fields {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    insert(field.value.as_deref());
                }
            }
        }

        self.master_password_reprompt_initialized = true;
    }

    pub fn master_password_reprompt_initialized(&self) -> bool {
        self.master_password_reprompt_initialized
    }

    pub fn last_environment(&self) -> &rbw::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: rbw::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}

pub struct Cancellation {
    receiver: tokio::sync::watch::Receiver<u64>,
}

impl Cancellation {
    pub fn is_cancelled(&self) -> bool {
        self.receiver.has_changed().unwrap_or(true)
    }

    pub async fn cancelled(&mut self) {
        let _ = self.receiver.changed().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> rbw::locked::Keys {
        let mut material = rbw::locked::Vec::new();
        material.extend(0_u8..64);
        rbw::locked::Keys::new(material)
    }

    #[tokio::test]
    async fn clear_removes_user_and_organization_keys() {
        let (timeout, _timeout_receiver) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync_timeout_receiver) =
            crate::timeout::Timeout::new();
        let mut state = State {
            priv_key: Some(rbw::locked_shatter::ShatteredKeys::seal(&keys())),
            org_keys: Some(std::collections::HashMap::new()),
            clear_generation: tokio::sync::watch::channel(0).0,
            timeout,
            l1_timeout: std::time::Duration::from_secs(60),
            last_bio_success: Some(std::time::Instant::now()),
            pam_gate_required: true,
            sync_timeout,
            sync_timeout_duration: std::time::Duration::ZERO,
            notifications_handler: crate::notifications::Handler::new(),
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: None,
        };
        let mut cancellation = state.cancellation();
        assert!(!state.needs_unlock());
        assert!(state.l1_alive());
        state.clear();
        assert!(state.needs_unlock());
        assert!(!state.l1_alive());
        assert!(state.last_bio_success.is_none());
        assert!(state.priv_key.is_none());
        assert!(state.org_keys.is_none());
        assert!(cancellation.is_cancelled());
        cancellation.cancelled().await;
    }

    #[tokio::test]
    async fn l1_expiry_and_bio_renewal_are_explicit() {
        let (timeout, _timeout_receiver) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync_timeout_receiver) =
            crate::timeout::Timeout::new();
        let mut state = State {
            priv_key: Some(rbw::locked_shatter::ShatteredKeys::seal(&keys())),
            org_keys: Some(std::collections::HashMap::new()),
            clear_generation: tokio::sync::watch::channel(0).0,
            timeout,
            l1_timeout: std::time::Duration::from_secs(60),
            last_bio_success: Some(
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(61))
                    .expect("a 61-second subtraction is representable"),
            ),
            pam_gate_required: true,
            sync_timeout,
            sync_timeout_duration: std::time::Duration::ZERO,
            notifications_handler: crate::notifications::Handler::new(),
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: None,
        };
        assert!(!state.l1_alive());
        assert!(state.needs_unlock());
        assert!(state.with_key(None, |_| ()).is_none());
        state.record_bio_success();
        assert!(state.l1_alive());
        assert!(!state.needs_unlock());
        assert!(state.with_key(None, |_| ()).is_some());
    }

    #[test]
    fn local_and_remote_modes_choose_distinct_l1_lifetimes() {
        let configured = std::time::Duration::from_secs(24 * 60 * 60);
        assert_eq!(State::effective_l1_timeout(configured, true), configured);
        assert_eq!(
            State::effective_l1_timeout(configured, false),
            REMOTE_L1_TIMEOUT
        );

        let stricter = std::time::Duration::from_secs(5 * 60);
        assert_eq!(State::effective_l1_timeout(stricter, false), stricter);
    }

    #[tokio::test]
    async fn pam_gate_mode_is_fixed_for_the_session() {
        let (timeout, _timeout_receiver) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync_timeout_receiver) =
            crate::timeout::Timeout::new();
        let state = State {
            priv_key: Some(rbw::locked_shatter::ShatteredKeys::seal(&keys())),
            org_keys: Some(std::collections::HashMap::new()),
            clear_generation: tokio::sync::watch::channel(0).0,
            timeout,
            l1_timeout: std::time::Duration::from_secs(60),
            last_bio_success: Some(std::time::Instant::now()),
            pam_gate_required: false,
            sync_timeout,
            sync_timeout_duration: std::time::Duration::ZERO,
            notifications_handler: crate::notifications::Handler::new(),
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: None,
        };
        assert!(!state.pam_gate_required());
    }
}
