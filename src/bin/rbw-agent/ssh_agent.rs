use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
use std::os::unix::fs::PermissionsExt as _;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    config: rbw::config::SshAgentConfig,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
        config: rbw::config::SshAgentConfig,
    ) -> Self {
        Self { state, config }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();
        let listener = bind_socket(&socket)?;
        ssh_agent_lib::agent::listen(listener, self).await?;
        Ok(())
    }

    async fn authorize_signing(
        &self,
        public_key: &ssh_agent_lib::ssh_key::PublicKey,
    ) -> anyhow::Result<()> {
        let fingerprint = public_key
            .fingerprint(ssh_agent_lib::ssh_key::HashAlg::Sha256)
            .to_string();
        let (
            l1_alive,
            mut cancellation,
            face_required,
            ordinary,
            environment,
        ) = {
            let state = self.state.lock().await;
            (
                state.l1_alive(),
                state.cancellation(),
                state.pam_gate_required(),
                state.ordinary_session,
                state.last_environment().clone(),
            )
        };
        let policy = match self.config.policy_for(&fingerprint) {
            rbw::config::SshAgentPolicy::L1 if face_required => {
                rbw::config::SshAgentPolicy::Always
            }
            policy => policy,
        };
        let gate = if ordinary {
            None
        } else {
            rbw::pam_gate::PamGate::detect()
        };

        match policy_decision(policy, l1_alive, gate.is_some()) {
            GateDecision::Allow => {
                self.state.lock().await.record_activity();
                Ok(())
            }
            GateDecision::Authorize => {
                // Face authorization cannot establish or revive a cold session.
                if !l1_alive {
                    return Err(anyhow::anyhow!("agent is locked"));
                }
                let gate = gate
                    .ok_or_else(|| anyhow::anyhow!("PAM gate unavailable"))?
                    .with_context(
                        environment,
                        "Authorize rbw SSH signing",
                        "Look at the camera to authorize an SSH signature",
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
                let mut state = self.state.lock().await;
                if cancellation.is_cancelled() || !state.l1_alive() {
                    return Err(anyhow::anyhow!(
                        "agent locked during local authentication"
                    ));
                }
                state.record_bio_success();
                Ok(())
            }
            GateDecision::Deny => Err(anyhow::anyhow!(
                "SSH signing requires authorization, but no local PAM gate is available; remote approval is a later integration phase"
            )),
        }
    }
}

pub fn remove_stale_socket() -> anyhow::Result<()> {
    let socket = rbw::dirs::ssh_agent_socket_file();
    match std::fs::remove_file(&socket) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn bind_socket(
    path: &std::path::Path,
) -> anyhow::Result<tokio::net::UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateDecision {
    Allow,
    Authorize,
    Deny,
}

fn policy_decision(
    policy: rbw::config::SshAgentPolicy,
    l1_alive: bool,
    pam_available: bool,
) -> GateDecision {
    match policy {
        rbw::config::SshAgentPolicy::Never => GateDecision::Allow,
        rbw::config::SshAgentPolicy::L1 if l1_alive => GateDecision::Allow,
        rbw::config::SshAgentPolicy::Always
        | rbw::config::SshAgentPolicy::L1
            if pam_available =>
        {
            GateDecision::Authorize
        }
        rbw::config::SshAgentPolicy::Always
        | rbw::config::SshAgentPolicy::L1 => GateDecision::Deny,
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshAgent {
    async fn request_identities(
        &mut self,
    ) -> Result<
        Vec<ssh_agent_lib::proto::Identity>,
        ssh_agent_lib::error::AgentError,
    > {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|error| {
                ssh_agent_lib::error::AgentError::Other(error.into())
            })?
            .into_iter()
            .map(|public_key| {
                public_key
                    .parse::<ssh_agent_lib::ssh_key::PublicKey>()
                    .map(|key| ssh_agent_lib::proto::Identity {
                        pubkey: key.key_data().clone(),
                        comment: key.comment().to_string(),
                    })
                    .map_err(ssh_agent_lib::error::AgentError::other)
            })
            .collect()
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<
        ssh_agent_lib::ssh_key::Signature,
        ssh_agent_lib::error::AgentError,
    > {
        let public_key =
            ssh_agent_lib::ssh_key::PublicKey::new(request.pubkey, "");

        self.authorize_signing(&public_key).await.map_err(|error| {
            ssh_agent_lib::error::AgentError::Other(error.into())
        })?;

        let private_key = crate::actions::find_ssh_private_key(
            self.state.clone(),
            public_key,
        )
        .await
        .map_err(|error| {
            ssh_agent_lib::error::AgentError::Other(error.into())
        })?;

        let signature =
            sign_with_private_key(&private_key, &request.data, request.flags);
        // ssh-key's private key variants zeroize on Drop; release the parsed
        // signing copy before returning the protocol response.
        drop(private_key);
        signature
    }
}

fn sign_with_private_key(
    private_key: &ssh_agent_lib::ssh_key::PrivateKey,
    data: &[u8],
    flags: u32,
) -> Result<ssh_agent_lib::ssh_key::Signature, ssh_agent_lib::error::AgentError>
{
    match private_key.key_data() {
        ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(key) => key
            .try_sign(data)
            .map_err(ssh_agent_lib::error::AgentError::other),

        ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
            let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
            let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
            let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
            let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                .map_err(ssh_agent_lib::error::AgentError::other)?;

            let mut rng = rand_8::rngs::OsRng;
            let (algorithm, signature) = if flags & SSH_AGENT_RSA_SHA2_512
                != 0
            {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(rsa_key);
                let signature = signing_key
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;
                ("rsa-sha2-512", signature.to_bytes())
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);
                let signature = signing_key
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;
                ("rsa-sha2-256", signature.to_bytes())
            } else {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(
                        rsa_key,
                    );
                let signature = signing_key
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;
                ("ssh-rsa", signature.to_bytes())
            };

            ssh_agent_lib::ssh_key::Signature::new(
                ssh_agent_lib::ssh_key::Algorithm::new(algorithm)
                    .map_err(ssh_agent_lib::error::AgentError::other)?,
                signature,
            )
            .map_err(ssh_agent_lib::error::AgentError::other)
        }

        other => Err(ssh_agent_lib::error::AgentError::Other(
            format!("unsupported key type: {other:?}").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::agent::Session as _;

    #[test]
    fn per_key_policy_decisions_are_fail_closed() {
        use rbw::config::SshAgentPolicy::{Always, Never, L1};
        assert_eq!(policy_decision(Never, false, false), GateDecision::Allow);
        assert_eq!(policy_decision(L1, true, false), GateDecision::Allow);
        assert_eq!(policy_decision(L1, false, true), GateDecision::Authorize);
        assert_eq!(policy_decision(L1, false, false), GateDecision::Deny);
        assert_eq!(
            policy_decision(Always, true, true),
            GateDecision::Authorize
        );
        assert_eq!(policy_decision(Always, true, false), GateDecision::Deny);
    }

    #[tokio::test]
    async fn socket_is_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let listener = bind_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(listener);
    }

    #[tokio::test]
    async fn unsupported_protocol_requests_fail() {
        #[derive(Clone, Copy)]
        struct ReadOnlySession;
        #[ssh_agent_lib::async_trait]
        impl ssh_agent_lib::agent::Session for ReadOnlySession {}

        let error = ReadOnlySession
            .handle(ssh_agent_lib::proto::Request::RemoveAllIdentities)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ssh_agent_lib::error::AgentError::Proto(
                ssh_agent_lib::proto::Error::UnsupportedCommand {
                    command: 19
                }
            )
        ));
    }

    #[tokio::test]
    async fn protocol_frames_list_sign_and_fail() {
        #[derive(Clone)]
        struct TestSession {
            key: std::sync::Arc<ssh_agent_lib::ssh_key::PrivateKey>,
        }

        #[ssh_agent_lib::async_trait]
        impl ssh_agent_lib::agent::Session for TestSession {
            async fn request_identities(
                &mut self,
            ) -> Result<
                Vec<ssh_agent_lib::proto::Identity>,
                ssh_agent_lib::error::AgentError,
            > {
                Ok(vec![ssh_agent_lib::proto::Identity {
                    pubkey: self.key.public_key().key_data().clone(),
                    comment: "fixture".to_string(),
                }])
            }

            async fn sign(
                &mut self,
                request: ssh_agent_lib::proto::SignRequest,
            ) -> Result<
                ssh_agent_lib::ssh_key::Signature,
                ssh_agent_lib::error::AgentError,
            > {
                sign_with_private_key(&self.key, &request.data, request.flags)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("protocol.sock");
        let listener = bind_socket(&path).unwrap();
        let mut rng = rand_8::rngs::OsRng;
        let key = std::sync::Arc::new(
            ssh_agent_lib::ssh_key::PrivateKey::random(
                &mut rng,
                ssh_agent_lib::ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let server = tokio::spawn(ssh_agent_lib::agent::listen(
            listener,
            TestSession { key: key.clone() },
        ));
        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut client = ssh_agent_lib::client::Client::new(stream);

        let identities = client.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment, "fixture");

        let signature = client
            .sign(ssh_agent_lib::proto::SignRequest {
                pubkey: key.public_key().key_data().clone(),
                data: b"protocol payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap();
        signature::Verifier::verify(
            key.public_key(),
            b"protocol payload",
            &signature,
        )
        .unwrap();

        assert!(client.remove_all_identities().await.is_err());
        server.abort();
    }

    #[test]
    fn sign_response_uses_requested_key() {
        let mut rng = rand_8::rngs::OsRng;
        let key = ssh_agent_lib::ssh_key::PrivateKey::random(
            &mut rng,
            ssh_agent_lib::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let signature = sign_with_private_key(&key, b"frame payload", 0)
            .expect("signing succeeds");
        signature::Verifier::verify(
            key.public_key(),
            b"frame payload",
            &signature,
        )
        .expect("signature verifies");
    }
}
