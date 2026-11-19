use anyhow::Context as _;
use futures_util::StreamExt as _;

pub struct Agent {
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    memory_guard: crate::memory_guard::MemoryGuard,
}

impl Agent {
    pub fn new(
        timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
        memory_guard: crate::memory_guard::MemoryGuard,
    ) -> Self {
        Self {
            timer_r,
            sync_timer_r,
            state,
            memory_guard,
        }
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        pub enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Timeout(()),
            Sync(()),
        }

        let notifications = self
            .state
            .lock()
            .await
            .notifications_handler
            .get_channel()
            .await;
        let notifications =
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                notifications,
            )
            .map(|message| match message {
                crate::notifications::Message::Logout => Event::Timeout(()),
                crate::notifications::Message::Sync => Event::Sync(()),
            })
            .boxed();

        let mut stream = futures_util::stream::select_all([
            tokio_stream::wrappers::UnixListenerStream::new(listener)
                .map(Event::Request)
                .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.timer_r,
            )
            .map(Event::Timeout)
            .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.sync_timer_r,
            )
            .map(Event::Sync)
            .boxed(),
            notifications,
        ]);
        while let Some(event) = stream.next().await {
            match event {
                Event::Request(res) => {
                    let mut sock = crate::sock::Sock::new(
                        res.context("failed to accept incoming connection")?,
                    );
                    let state = self.state.clone();
                    let memory_guard = self.memory_guard.clone();
                    tokio::spawn(async move {
                        let res = Box::pin(handle_request(
                            &mut sock,
                            state.clone(),
                            &memory_guard,
                        ))
                        .await;
                        if let Err(e) = res {
                            if let Err(error) = sock
                                .send(&rbw::protocol::Response::Error {
                                    error: format!("{e:#}"),
                                })
                                .await
                            {
                                log::debug!(
                                    "client disconnected before agent error response: {error:#}"
                                );
                            }
                        }
                    });
                }
                Event::Timeout(()) => {
                    self.state.lock().await.clear();
                }
                Event::Sync(()) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // this could fail if we aren't logged in, but we
                        // don't care about that
                        if let Err(e) =
                            crate::actions::sync(None, state.clone()).await
                        {
                            eprintln!("failed to sync: {e:#}");
                        }
                    });
                    self.state.lock().await.set_sync_timeout();
                }
            }
        }
        Ok(())
    }
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    memory_guard: &crate::memory_guard::MemoryGuard,
) -> anyhow::Result<()> {
    let req = sock.recv().await?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let (action, environment) = req.into_parts();
    // RAM defense: reject/abort if the agent is being traced (C3/C4).
    // Covers all actions; cost is one small procfs read.
    memory_guard.enforce(&state).await?;
    // Sensitive actions require a fresh bio (re)authorization (B3).
    if sensitive_action(&action) {
        gate_sensitive_action(state.clone(), &environment).await?;
    }
    match &action {
        rbw::protocol::Action::Register => {
            crate::actions::register(sock, &environment).await?;
        }
        rbw::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), &environment).await?;
        }
        rbw::protocol::Action::ReloadSessionConfig => {
            let config = rbw::config::Config::load_async().await?;
            state.lock().await.reload_session_config(&config);
            sock.send(&rbw::protocol::Response::Ack).await?;
        }
        rbw::protocol::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), &environment).await?;
        }
        rbw::protocol::Action::UnlockWithUserKey { key } => {
            crate::actions::unlock_with_user_key(
                sock,
                state.clone(),
                key.as_bytes(),
            )
            .await?;
        }
        rbw::protocol::Action::UnlockWithDevice => {
            Box::pin(crate::actions::unlock_with_device(
                sock,
                state.clone(),
                &environment,
            ))
            .await?;
        }
        rbw::protocol::Action::ListAuthRequests => {
            crate::actions::list_auth_requests(sock).await?;
        }
        rbw::protocol::Action::ApproveAuthRequest { id } => {
            crate::actions::approve_auth_request(
                sock,
                state.clone(),
                id,
                &environment,
            )
            .await?;
        }
        rbw::protocol::Action::RejectAuthRequest { id } => {
            crate::actions::reject_auth_request(sock, id).await?;
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(sock, state.clone()).await?;
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(Some(sock), state.clone()).await?;
        }
        rbw::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
        } => {
            let cipherstring = cipherstring.clone();
            let entry_key = entry_key.clone();
            let org_id = org_id.clone();
            crate::actions::decrypt(
                sock,
                state.clone(),
                &environment,
                &cipherstring,
                entry_key.as_deref(),
                org_id.as_deref(),
            )
            .await?;
        }
        rbw::protocol::Action::Encrypt { plaintext, org_id } => {
            crate::actions::encrypt(
                sock,
                state.clone(),
                plaintext,
                org_id.as_deref(),
            )
            .await?;
        }
        rbw::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(sock, state.clone(), text)
                .await?;
        }
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
        }
    }

    let mut state = state.lock().await;
    state.record_activity();
    state.set_last_environment(environment);

    Ok(())
}

fn sensitive_action(action: &rbw::protocol::Action) -> bool {
    matches!(
        action,
        rbw::protocol::Action::Sync | rbw::protocol::Action::Decrypt { .. }
    )
}

pub async fn gate_sensitive_action(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let (pam_gate_required, mut cancellation) = {
        let mut state = state.lock().await;
        if !state.l1_alive() {
            state.clear();
            return Err(anyhow::anyhow!("agent is locked"));
        }
        (state.pam_gate_required(), state.cancellation())
    };

    if !pam_gate_required {
        return Ok(());
    }

    // The mode was selected at startup. Revalidate the policy for every
    // authorization and fail closed if the local policy disappears or becomes
    // insecure instead of dynamically downgrading to the remote bypass mode.
    let gate = rbw::pam_gate::PamGate::new()?.with_context(
        environment.clone(),
        "Authorize rbw secret access",
        "Confirm that you are present to access rbw secrets",
    )?;
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return Err(anyhow::anyhow!(
                "agent locked during local authentication"
            ));
        }
        result = gate.authorize() => result?,
    }

    let mut state = state.lock().await;
    if cancellation.is_cancelled() {
        return Err(anyhow::anyhow!(
            "agent locked during local authentication"
        ));
    }
    if !state.l1_alive() {
        state.clear();
        return Err(anyhow::anyhow!(
            "agent locked during local authentication"
        ));
    }
    state.record_bio_success();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_secret_read_actions_require_the_general_gate() {
        assert!(sensitive_action(&rbw::protocol::Action::Sync));
        assert!(sensitive_action(&rbw::protocol::Action::Decrypt {
            cipherstring: "cipher".to_string(),
            entry_key: None,
            org_id: None,
        }));
        assert!(!sensitive_action(&rbw::protocol::Action::Encrypt {
            plaintext: "secret".to_string(),
            org_id: None,
        }));
        assert!(!sensitive_action(&rbw::protocol::Action::ClipboardStore {
            text: "secret".to_string(),
        }));
        assert!(!sensitive_action(&rbw::protocol::Action::Unlock));
    }
}
