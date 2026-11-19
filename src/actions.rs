use crate::prelude::*;

pub async fn register(
    email: &str,
    apikey: crate::locked::ApiKey,
) -> Result<()> {
    let (client, config) = api_client_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

pub async fn login(
    email: &str,
    password: crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, config) = api_client_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            config.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn create_auth_request(
    email: &str,
    public_key: &str,
    access_code: &str,
) -> Result<crate::api::AuthRequest> {
    let (client, config) = api_client_async().await?;
    client
        .create_auth_request(
            email,
            &crate::config::registered_device_id(&config).await?,
            public_key,
            access_code,
        )
        .await
}

pub async fn get_auth_request_response(
    request_id: &str,
    access_code: &str,
) -> Result<crate::api::AuthRequest> {
    let (client, _) = api_client_async().await?;
    client
        .get_auth_request_response(request_id, access_code)
        .await
}

pub async fn login_with_auth_request(
    email: &str,
    access_code: &str,
    request_id: &str,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, config) = api_client_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;
    let (access_token, refresh_token, protected_key) = client
        .login_with_auth_request(
            email,
            &crate::config::registered_device_id(&config).await?,
            access_code,
            request_id,
            two_factor_token,
            two_factor_provider,
        )
        .await?;
    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn pending_auth_requests(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<crate::api::AuthRequest>)> {
    let (client, _) = api_client_async().await?;
    match client.pending_auth_requests(access_token).await {
        Ok(requests) => Ok((None, requests)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let requests =
                client.pending_auth_requests(&access_token).await?;
            Ok((Some(access_token), requests))
        }
        Err(error) => Err(error),
    }
}

pub async fn get_auth_request(
    access_token: &str,
    refresh_token: &str,
    request_id: &str,
) -> Result<(Option<String>, crate::api::AuthRequest)> {
    let (client, _) = api_client_async().await?;
    match client.get_auth_request(access_token, request_id).await {
        Ok(request) => Ok((None, request)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let request =
                client.get_auth_request(&access_token, request_id).await?;
            Ok((Some(access_token), request))
        }
        Err(error) => Err(error),
    }
}

pub async fn update_auth_request(
    access_token: &str,
    refresh_token: &str,
    request_id: &str,
    key: &str,
    approved: bool,
) -> Result<(Option<String>, crate::api::AuthRequest)> {
    let (client, config) = api_client_async().await?;
    let device_id = crate::config::registered_device_id(&config).await?;
    match client
        .update_auth_request(
            access_token,
            request_id,
            &device_id,
            key,
            approved,
        )
        .await
    {
        Ok(request) => Ok((None, request)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let request = client
                .update_auth_request(
                    &access_token,
                    request_id,
                    &device_id,
                    key,
                    approved,
                )
                .await?;
            Ok((Some(access_token), request))
        }
        Err(error) => Err(error),
    }
}

pub async fn send_two_factor_email(
    email: &str,
    sso_email_2fa_session_token: &str,
) -> Result<()> {
    let (client, config) = api_client_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let identity = crate::identity::Identity::new(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    unlock_with_user_key(key, protected_private_key, protected_org_keys)
}

pub fn unlock_with_user_key<S: std::hash::BuildHasher>(
    key: crate::locked::Keys,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key = crate::locked::PrivateKey::new(
        protected_private_key.decrypt_locked_symmetric(&key)?,
    );

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?
                .decrypt_locked_asymmetric_der(&private_key)?;
        org_keys.insert(org_id.clone(), crate::locked::Keys::new(org_key));
    }

    Ok((key, org_keys))
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    ),
)> {
    with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        |access_token| {
            let access_token = access_token.to_string();
            Box::pin(async move { sync_once(&access_token).await })
        },
    )
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(access_token, name, data, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(access_token, name, data, notes, folder_id)?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
        )
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        remove_once(access_token, id)
    })
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove(access_token, id)?;
    Ok(())
}

pub fn list_folders(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client()?;
    client.folders(access_token)
}

pub fn create_folder(
    access_token: &str,
    refresh_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

fn with_exchange_refresh_token<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            let t = f(&access_token)?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_refresh_token_async<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send>,
        > + Send
        + Sync,
    T: Send,
{
    match f(access_token).await {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token(refresh_token)
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token_async(refresh_token).await
}

fn api_client() -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load()?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

async fn api_client_async(
) -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load_async().await?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

#[cfg(test)]
mod device_auth_unlock_tests {
    use rsa::pkcs8::EncodePrivateKey as _;

    use super::*;

    #[test]
    fn unlock_with_user_key_decrypts_organization_key_from_unpadded_der() {
        let mut user_material = crate::locked::Vec::new();
        user_material
            .extend(0_u8..u8::try_from(crate::locked::KEYS_LEN).unwrap());
        let user_key = crate::locked::Keys::new(user_material);

        let private_key =
            rsa::RsaPrivateKey::new(&mut rand_8::rngs::OsRng, 2048)
                .expect("RSA key generation succeeds");
        let private_key_der = private_key
            .to_pkcs8_der()
            .expect("PKCS#8 encoding succeeds");
        let protected_private_key =
            crate::cipherstring::CipherString::encrypt_symmetric(
                &user_key,
                private_key_der.as_bytes(),
            )
            .expect("private-key protection succeeds")
            .to_string();

        let expected_org_key = [0x5a_u8; crate::locked::KEYS_LEN];
        let encrypted_org_key = rsa::RsaPublicKey::from(&private_key)
            .encrypt(
                &mut rand_8::rngs::OsRng,
                rsa::Oaep::new::<sha1::Sha1>(),
                &expected_org_key,
            )
            .expect("organization-key protection succeeds");
        let protected_org_keys = std::collections::HashMap::from([(
            "organization-id".to_string(),
            format!("4.{}", crate::base64::encode(encrypted_org_key)),
        )]);

        let (unlocked_user_key, org_keys) = unlock_with_user_key(
            user_key,
            &protected_private_key,
            &protected_org_keys,
        )
        .expect("organization vault unlock succeeds");

        assert_eq!(
            unlocked_user_key.as_bytes().len(),
            crate::locked::KEYS_LEN
        );
        assert_eq!(org_keys["organization-id"].as_bytes(), expected_org_key);
    }
}
