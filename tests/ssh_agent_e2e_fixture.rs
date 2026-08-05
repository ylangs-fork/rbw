//! Docker E2E fixture generator for the rbw SSH agent.
//!
//! This ignored test writes an offline rbw config/database. The Docker test
//! then starts the real rbw-agent binary and exercises it with OpenSSH/Git.

#[test]
#[ignore = "invoked explicitly by the Docker SSH-agent E2E script"]
fn create_ssh_agent_fixture() {
    use rsa::pkcs8::EncodePrivateKey as _;

    let private_key_path = std::env::var_os("RBW_E2E_PRIVATE_KEY")
        .expect("RBW_E2E_PRIVATE_KEY is required");
    let public_key_path = std::env::var_os("RBW_E2E_PUBLIC_KEY")
        .expect("RBW_E2E_PUBLIC_KEY is required");
    let pinentry = std::env::var("RBW_E2E_PINENTRY")
        .expect("RBW_E2E_PINENTRY is required");
    let password = b"rbw-e2e-password";
    let email = "ssh-agent-e2e@example.invalid";

    let private_key = std::fs::read_to_string(private_key_path).unwrap();
    let public_key = std::fs::read_to_string(public_key_path).unwrap();

    let mut password_material = rbw::locked::Vec::new();
    password_material.extend(password.iter().copied());
    let password = rbw::locked::Password::new(password_material);
    let identity = rbw::identity::Identity::new(
        email,
        &password,
        rbw::api::KdfType::Pbkdf2,
        100_000,
        None,
        None,
    )
    .unwrap();

    let user_key_bytes = [0x42_u8; rbw::locked::KEYS_LEN];
    let mut user_key_material = rbw::locked::Vec::new();
    user_key_material.extend(user_key_bytes.iter().copied());
    let user_key = rbw::locked::Keys::new(user_key_material);

    let protected_key = rbw::cipherstring::CipherString::encrypt_symmetric(
        &identity.keys,
        &user_key_bytes,
    )
    .unwrap()
    .to_string();

    let account_private_key =
        rsa::RsaPrivateKey::new(&mut rand_8::rngs::OsRng, 2048).unwrap();
    let account_private_key = account_private_key.to_pkcs8_der().unwrap();
    let protected_private_key =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            &user_key,
            account_private_key.as_bytes(),
        )
        .unwrap()
        .to_string();

    let encrypted_ssh_private =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            &user_key,
            private_key.as_bytes(),
        )
        .unwrap()
        .to_string();
    let encrypted_ssh_public =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            &user_key,
            public_key.as_bytes(),
        )
        .unwrap()
        .to_string();

    let mut config = rbw::config::Config::new();
    config.email = Some(email.to_string());
    config.base_url = Some("http://127.0.0.1:9".to_string());
    config.pinentry = pinentry;
    config.ssh_agent.enabled = true;
    config.ssh_agent.default_policy = rbw::config::SshAgentPolicy::L1;
    config.save().unwrap();

    let mut db = rbw::db::Db::new();
    db.access_token = Some("offline-fixture-access-token".to_string());
    db.refresh_token = Some("offline-fixture-refresh-token".to_string());
    db.kdf = Some(rbw::api::KdfType::Pbkdf2);
    db.iterations = Some(100_000);
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.entries.push(rbw::db::Entry {
        id: "ssh-agent-e2e-key".to_string(),
        org_id: None,
        folder: None,
        folder_id: None,
        name: "SSH agent E2E key".to_string(),
        data: rbw::db::EntryData::SshKey {
            private_key: Some(encrypted_ssh_private),
            public_key: Some(encrypted_ssh_public),
            fingerprint: None,
        },
        fields: Vec::new(),
        notes: None,
        history: Vec::new(),
        key: None,
        master_password_reprompt: rbw::api::CipherRepromptType::None,
    });
    db.save(config.server_name().as_str(), email).unwrap();
}
