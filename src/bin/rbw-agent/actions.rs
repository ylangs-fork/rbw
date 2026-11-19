use anyhow::Context as _;
use sha2::Digest as _;
use zeroize::Zeroizing;

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        'attempts: for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::login(&email, password.clone(), None, None)
                .await
            {
                Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                )) => {
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        password,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    rbw::actions::send_two_factor_email(
                                        &email,
                                        &sso_email_2fa_session_token,
                                    )
                                    .await?;
                                }
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = two_factor(
                                environment,
                                &email,
                                password.clone(),
                                provider,
                            )
                            .await?;
                            login_success(
                                state.clone(),
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                password,
                                email,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(anyhow::anyhow!(
                        "unsupported two factor methods: {providers:?}"
                    ));
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn two_factor(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    email: String,
) -> anyhow::Result<()> {
    update_db(true, |db| {
        db.access_token = Some(access_token);
        db.refresh_token = Some(refresh_token);
        db.kdf = Some(kdf);
        db.iterations = Some(iterations);
        db.memory = memory;
        db.parallelism = parallelism;
        db.protected_key = Some(protected_key.clone());
    })
    .await?;

    sync(None, state.clone()).await?;
    let db = load_db_coordinated().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key =
                Some(rbw::locked_shatter::ShatteredKeys::seal(&keys));
            state.org_keys = Some(
                org_keys
                    .iter()
                    .map(|(id, key)| {
                        (
                            id.clone(),
                            rbw::locked_shatter::ShatteredKeys::seal(key),
                        )
                    })
                    .collect(),
            );
            state.record_bio_success();
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

fn auth_request_info(
    request: &rbw::api::AuthRequest,
    email: &str,
) -> anyhow::Result<rbw::protocol::AuthRequestInfo> {
    validate_auth_request_id(&request.id)?;
    let public_key = rbw::base64::decode(&request.public_key)
        .context("auth request contained an invalid public key")?;
    let fingerprint = rbw::device_auth::fingerprint(email, &public_key)
        .context("failed to calculate auth-request fingerprint")?;
    Ok(rbw::protocol::AuthRequestInfo {
        id: request.id.clone(),
        fingerprint,
        device_type: request.request_device_type.clone(),
        ip_address: request.request_ip_address.clone(),
        country_name: request.request_country_name.clone(),
        creation_date: request.creation_date.clone(),
    })
}

async fn cancel_or<T, F>(
    cancellation: &mut crate::state::Cancellation,
    future: F,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            Err(anyhow::anyhow!("device authentication cancelled because the agent was cleared"))
        }
        output = future => Ok(output),
    }
}

fn ensure_not_cancelled(
    cancellation: &crate::state::Cancellation,
) -> anyhow::Result<()> {
    if cancellation.is_cancelled() {
        Err(anyhow::anyhow!(
            "device authentication cancelled because the agent was cleared"
        ))
    } else {
        Ok(())
    }
}

async fn auth_request_tokens() -> anyhow::Result<(String, String)> {
    let db = load_db_coordinated().await?;
    let access_token = db.access_token.ok_or_else(|| {
        anyhow::anyhow!("failed to find access token in db")
    })?;
    let refresh_token = db.refresh_token.ok_or_else(|| {
        anyhow::anyhow!("failed to find refresh token in db")
    })?;
    Ok((access_token, refresh_token))
}

fn auth_request_db_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

type DbFuture<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<T>> + Send + 'a>,
>;

async fn coordinated_db_update_with<L, S, F>(
    load: L,
    save: S,
    update: F,
) -> anyhow::Result<()>
where
    L: FnOnce() -> DbFuture<'static, rbw::db::Db>,
    S: for<'a> FnOnce(&'a rbw::db::Db) -> DbFuture<'a, ()>,
    F: FnOnce(&mut rbw::db::Db),
{
    let _guard = auth_request_db_lock().lock().await;
    let mut db = load().await?;
    update(&mut db);
    save(&db).await
}

async fn update_db<F>(allow_new: bool, update: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut rbw::db::Db),
{
    coordinated_db_update_with(
        move || {
            Box::pin(async move {
                match load_db().await {
                    Ok(db) => Ok(db),
                    Err(_) if allow_new => Ok(rbw::db::Db::new()),
                    Err(error) => Err(error),
                }
            })
        },
        |db| Box::pin(save_db(db)),
        update,
    )
    .await
}

async fn load_db_coordinated() -> anyhow::Result<rbw::db::Db> {
    let _guard = auth_request_db_lock().lock().await;
    load_db().await
}

async fn save_refreshed_access_token(
    access_token: Option<String>,
) -> anyhow::Result<()> {
    if let Some(access_token) = access_token {
        update_db(false, |db| db.access_token = Some(access_token)).await?;
    }
    Ok(())
}

type AuthRequestLogin = (
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
);

fn auth_request_two_factor_provider(
    providers: &[rbw::api::TwoFactorProviderType],
) -> anyhow::Result<rbw::api::TwoFactorProviderType> {
    [
        rbw::api::TwoFactorProviderType::Authenticator,
        rbw::api::TwoFactorProviderType::Yubikey,
        rbw::api::TwoFactorProviderType::Email,
    ]
    .into_iter()
    .find(|provider| providers.contains(provider))
    .ok_or_else(|| {
        anyhow::anyhow!("unsupported two factor methods: {providers:?}")
    })
}

async fn exchange_auth_request_tokens(
    environment: &rbw::protocol::Environment,
    email: &str,
    access_code: &str,
    request_id: &str,
    deadline: tokio::time::Instant,
    cancellation: &mut crate::state::Cancellation,
) -> anyhow::Result<AuthRequestLogin> {
    let first = cancel_or(
        cancellation,
        tokio::time::timeout_at(
            deadline,
            rbw::actions::login_with_auth_request(
                email,
                access_code,
                request_id,
                None,
                None,
            ),
        ),
    )
    .await?
    .map_err(|_| {
        anyhow::anyhow!(
            "auth request expired before token exchange completed"
        )
    })?;
    let (providers, email_session_token) = match first {
        Ok(login) => return Ok(login),
        Err(rbw::error::Error::TwoFactorRequired {
            providers,
            sso_email_2fa_session_token,
        }) => (providers, sso_email_2fa_session_token),
        Err(error) => {
            return Err(error).context(
                "failed to exchange approved auth request for tokens",
            )
        }
    };

    let provider = auth_request_two_factor_provider(&providers)?;
    if provider == rbw::api::TwoFactorProviderType::Email {
        if let Some(email_session_token) = email_session_token {
            cancel_or(
                cancellation,
                tokio::time::timeout_at(
                    deadline,
                    rbw::actions::send_two_factor_email(
                        email,
                        &email_session_token,
                    ),
                ),
            )
            .await?
            .map_err(|_| {
                anyhow::anyhow!(
                    "auth request expired during two factor setup"
                )
            })??;
        }
    }

    let mut err_msg = None;
    for attempt in 1_u8..=3 {
        let err = err_msg
            .as_ref()
            .map(|message| format!("{message} (attempt {attempt}/3)"));
        let pinentry = cancel_or(
            cancellation,
            tokio::time::timeout_at(deadline, config_pinentry()),
        )
        .await?
        .map_err(|_| {
            anyhow::anyhow!(
                "auth request expired while loading pinentry configuration"
            )
        })??;
        let code = cancel_or(
            cancellation,
            tokio::time::timeout_at(
                deadline,
                rbw::pinentry::getpin(
                    &pinentry,
                    provider.header(),
                    provider.message(),
                    err.as_deref(),
                    environment,
                    provider.grab(),
                ),
            ),
        )
        .await?
        .map_err(|_| {
            anyhow::anyhow!("auth request expired during two factor prompt")
        })??;
        let code = std::str::from_utf8(code.password())
            .context("two factor code was not valid utf8")?;
        let login = cancel_or(
            cancellation,
            tokio::time::timeout_at(
                deadline,
                rbw::actions::login_with_auth_request(
                    email,
                    access_code,
                    request_id,
                    Some(code),
                    Some(provider),
                ),
            ),
        )
        .await?
        .map_err(|_| {
            anyhow::anyhow!(
                "auth request expired before token exchange completed"
            )
        })?;
        match login {
            Ok(login) => return Ok(login),
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if attempt == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed auth-request two factor verification");
                }
                err_msg = Some(message);
            }
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if attempt == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed auth-request two factor verification");
                }
                err_msg = Some(message);
            }
            Err(error) => {
                return Err(error)
                    .context("failed auth-request two factor verification")
            }
        }
    }
    unreachable!()
}

pub async fn unlock_with_device(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let mut cancellation = {
        let state = state.lock().await;
        if !state.needs_unlock() {
            return respond_ack(sock).await;
        }
        state.cancellation()
    };

    let email = config_email().await?;
    let deadline =
        tokio::time::Instant::now() + rbw::device_auth::REQUEST_DEADLINE;
    let request_keys = rbw::device_auth::RequestKeyPair::generate()
        .context("failed to generate auth-request key pair")?;
    let request = cancel_or(
        &mut cancellation,
        tokio::time::timeout_at(
            deadline,
            rbw::actions::create_auth_request(
                &email,
                &request_keys.public_key_base64(),
                request_keys.access_code(),
            ),
        ),
    )
    .await?
    .map_err(|_| anyhow::anyhow!("auth request creation timed out"))??;
    validate_auth_request_id(&request.id)?;
    let fingerprint =
        rbw::device_auth::fingerprint(&email, request_keys.public_key())
            .context("failed to calculate auth-request fingerprint")?;
    sock.send(&rbw::protocol::Response::DeviceAuthPending {
        id: request.id.clone(),
        fingerprint,
    })
    .await?;

    let encrypted_user_key = loop {
        let next_poll = std::cmp::min(
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            deadline,
        );
        cancel_or(&mut cancellation, tokio::time::sleep_until(next_poll))
            .await?;
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "auth request timed out after five minutes"
            ));
        }
        let response = cancel_or(
            &mut cancellation,
            tokio::time::timeout_at(
                deadline,
                rbw::actions::get_auth_request_response(
                    &request.id,
                    request_keys.access_code(),
                ),
            ),
        )
        .await?
        .map_err(|_| {
            anyhow::anyhow!("auth request timed out after five minutes")
        })?
        .context("failed to poll auth-request response")?;
        match rbw::device_auth::response_state(&response)
            .context("invalid auth-request response")?
        {
            rbw::device_auth::ResponseState::Pending => {}
            rbw::device_auth::ResponseState::Approved(encrypted_user_key) => {
                break encrypted_user_key.to_string();
            }
        }
    };

    let (
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ) = exchange_auth_request_tokens(
        environment,
        &email,
        request_keys.access_code(),
        &request.id,
        deadline,
        &mut cancellation,
    )
    .await?;

    ensure_not_cancelled(&cancellation)?;
    update_db(true, |db| {
        db.access_token = Some(access_token);
        db.refresh_token = Some(refresh_token);
        db.kdf = Some(kdf);
        db.iterations = Some(iterations);
        db.memory = memory;
        db.parallelism = parallelism;
        db.protected_key = Some(protected_key);
    })
    .await?;
    ensure_not_cancelled(&cancellation)?;

    sync(None, state.clone()).await?;
    ensure_not_cancelled(&cancellation)?;
    let db = cancel_or(&mut cancellation, load_db_coordinated()).await??;
    let protected_private_key =
        db.protected_private_key.ok_or_else(|| {
            anyhow::anyhow!("failed to find protected private key in db")
        })?;
    let user_key = request_keys
        .decrypt_user_key(&encrypted_user_key)
        .context("failed to decrypt approved auth-request key")?;
    let (key, org_keys) = rbw::actions::unlock_with_user_key(
        user_key,
        &protected_private_key,
        &db.protected_org_keys,
    )
    .context("failed to unlock database with approved user key")?;
    {
        let mut state = state.lock().await;
        ensure_not_cancelled(&cancellation)?;
        state.priv_key = Some(rbw::locked_shatter::ShatteredKeys::seal(&key));
        state.org_keys = Some(
            org_keys
                .iter()
                .map(|(id, key)| {
                    (
                        id.clone(),
                        rbw::locked_shatter::ShatteredKeys::seal(key),
                    )
                })
                .collect(),
        );
        // Device-auth approval delivered the User Key -> a full-trust event,
        // start the L1 session just like a cold unlock.
        state.record_bio_success();
    }
    respond_ack(sock).await
}

pub async fn list_auth_requests(
    sock: &mut crate::sock::Sock,
) -> anyhow::Result<()> {
    let email = config_email().await?;
    let (access_token, refresh_token) = auth_request_tokens().await?;
    let (new_access_token, requests) =
        rbw::actions::pending_auth_requests(&access_token, &refresh_token)
            .await
            .context("failed to list pending auth requests")?;
    save_refreshed_access_token(new_access_token).await?;
    let requests = requests
        .iter()
        .map(|request| auth_request_info(request, &email))
        .collect::<anyhow::Result<Vec<_>>>()?;
    sock.send(&rbw::protocol::Response::AuthRequests { requests })
        .await?;
    Ok(())
}

fn validate_auth_request_id(request_id: &str) -> anyhow::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(request_id)
        .context("auth-request ID is not a valid UUID")
}

fn encrypt_approval_user_key(
    state: &crate::state::State,
    cancellation: &crate::state::Cancellation,
    public_key: &str,
) -> anyhow::Result<String> {
    ensure_not_cancelled(cancellation)?;
    let user_key = state.key_cloned(None).ok_or_else(|| {
        anyhow::anyhow!("agent locked during local system authentication")
    })?;
    rbw::device_auth::encrypt_user_key(public_key, &user_key)
        .context("failed to encrypt user key for auth request")
}

pub async fn approve_auth_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_id: &str,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let validated_request_id = validate_auth_request_id(request_id)?;
    let mut cancellation = {
        let state = state.lock().await;
        if state.needs_unlock() {
            return Err(anyhow::anyhow!(
                "agent must be unlocked before approving an auth request"
            ));
        }
        state.cancellation()
    };
    let email = config_email().await?;
    let (access_token, refresh_token) = auth_request_tokens().await?;
    let (new_access_token, request) = cancel_or(
        &mut cancellation,
        rbw::actions::get_auth_request(
            &access_token,
            &refresh_token,
            request_id,
        ),
    )
    .await??;
    if !matches!(
        rbw::device_auth::response_state(&request),
        Ok(rbw::device_auth::ResponseState::Pending)
    ) {
        return Err(anyhow::anyhow!(
            "auth request has already been answered or has invalid state"
        ));
    }
    let active_access_token = new_access_token
        .as_deref()
        .unwrap_or(access_token.as_str())
        .to_string();
    save_refreshed_access_token(new_access_token).await?;
    ensure_not_cancelled(&cancellation)?;
    let request_info = auth_request_info(&request, &email)?;
    let fingerprint = request_info.fingerprint.clone();
    sock.send(&rbw::protocol::Response::AuthRequestApproval {
        request: request_info,
    })
    .await?;

    cancel_or(
        &mut cancellation,
        crate::local_auth::authorize(
            environment,
            &validated_request_id.to_string(),
            &fingerprint,
        ),
    )
    .await??;
    let encrypted_user_key = {
        let state = state.lock().await;
        encrypt_approval_user_key(&state, &cancellation, &request.public_key)?
    };

    let (new_access_token, _) = cancel_or(
        &mut cancellation,
        rbw::actions::update_auth_request(
            &active_access_token,
            &refresh_token,
            request_id,
            &encrypted_user_key,
            true,
        ),
    )
    .await?
    .context("failed to approve auth request")?;
    ensure_not_cancelled(&cancellation)?;
    save_refreshed_access_token(new_access_token).await?;
    ensure_not_cancelled(&cancellation)?;
    respond_ack(sock).await
}

pub async fn reject_auth_request(
    sock: &mut crate::sock::Sock,
    request_id: &str,
) -> anyhow::Result<()> {
    validate_auth_request_id(request_id)?;
    let (access_token, refresh_token) = auth_request_tokens().await?;
    let (new_access_token, _) = rbw::actions::update_auth_request(
        &access_token,
        &refresh_token,
        request_id,
        "",
        false,
    )
    .await
    .context("failed to reject auth request")?;
    save_refreshed_access_token(new_access_token).await?;
    respond_ack(sock).await
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!(
                    "Unlock the local database for '{}'",
                    rbw::dirs::profile()
                ),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

pub async fn unlock_with_user_key(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    user_key: &[u8; rbw::locked::KEYS_LEN],
) -> anyhow::Result<()> {
    if !state.lock().await.needs_unlock() {
        return respond_ack(sock).await;
    }

    let db = load_db().await?;
    let protected_private_key =
        db.protected_private_key.ok_or_else(|| {
            anyhow::anyhow!("failed to find protected private key in db")
        })?;
    let mut material = rbw::locked::Vec::new();
    material.extend(user_key.iter().copied());
    let (keys, org_keys) = rbw::actions::unlock_with_user_key(
        rbw::locked::Keys::new(material),
        &protected_private_key,
        &db.protected_org_keys,
    )
    .context(
        "unlock helper returned a User Key that cannot unlock this vault",
    )?;
    unlock_success(state, keys, org_keys).await?;
    respond_ack(sock).await
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(rbw::locked_shatter::ShatteredKeys::seal(&keys));
    state.org_keys = Some(
        org_keys
            .iter()
            .map(|(id, key)| {
                (id.clone(), rbw::locked_shatter::ShatteredKeys::seal(key))
            })
            .collect(),
    );
    // A cold unlock (master password / TPM helper / device-auth approval) is a
    // full-trust authorization event, stronger than a bio heartbeat, so it
    // starts the L1 session the same way a successful bio gate does.
    // Without this, needs_unlock() (= !l1_alive()) stays true forever because
    // last_bio_success is never set -> L1 deadlock.
    state.record_bio_success();
    Ok(())
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    state.lock().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let db = load_db_coordinated().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(anyhow::anyhow!("failed to find refresh token in db"));
    };
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = rbw::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    state.lock().await.set_master_password_reprompt(&entries);
    update_db(false, |db| {
        if let Some(access_token) = access_token {
            db.access_token = Some(access_token);
        }
        db.protected_key = Some(protected_key);
        db.protected_private_key = Some(protected_private_key);
        db.protected_org_keys = protected_org_keys;
        db.entries = entries;
    })
    .await?;

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

async fn decrypt_cipher_locked(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    authorization: Option<&crate::state::Cancellation>,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<rbw::locked::Vec> {
    let mut state = state.lock().await;
    if let Some(authorization) = authorization {
        anyhow::ensure!(
            !authorization.is_cancelled(),
            "decryption authorization was invalidated"
        );
    }
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key_cloned(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(&keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state
        .master_password_reprompt
        .contains(&master_password_reprompt)
    {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                "Accessing this entry requires the master password",
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok(_) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    cipherstring
        .decrypt_locked_symmetric_with_entry_key(&keys, entry_key.as_ref())
        .context("failed to decrypt encrypted secret")
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    authorization: Option<&crate::state::Cancellation>,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    let plaintext = decrypt_cipher_locked(
        state,
        environment,
        authorization,
        cipherstring,
        entry_key,
        org_id,
    )
    .await?;
    let plaintext = String::from_utf8(plaintext.data().to_vec())
        .context("failed to parse decrypted secret")?;
    Ok(Zeroizing::new(plaintext))
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    authorization: &crate::state::Cancellation,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let plaintext = decrypt_cipher(
        state,
        environment,
        Some(authorization),
        cipherstring,
        entry_key,
        org_id,
    )
    .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key_cloned(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        &keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            anyhow::anyhow!("couldn't store value to clipboard: {e}")
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: Zeroizing<String>,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt {
        plaintext: plaintext.to_string(),
    })
    .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    config.email.map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        Ok,
    )
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        match &entry.data {
            rbw::db::EntryData::SshKey {
                public_key: Some(encrypted),
                ..
            } => {
                let plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    None,
                    encrypted,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;
                pubkeys.push(plaintext.to_string());
            }
            rbw::db::EntryData::SecureNote => {
                let Some(encrypted) = entry.notes.as_deref() else {
                    continue;
                };
                let plaintext = decrypt_cipher_locked(
                    state.clone(),
                    &environment,
                    None,
                    encrypted,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;
                if let Ok(private_key) = private_key_from_locked(&plaintext) {
                    pubkeys.push(
                        private_key
                            .public_key()
                            .to_openssh()
                            .map_err(anyhow::Error::new)?,
                    );
                }
            }
            _ => {}
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                None,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    public_key_plaintext.as_str(),
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_cipher_locked(
                    state.clone(),
                    &environment,
                    None,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;

                return private_key_from_locked(&private_key_plaintext);
            }
        } else if matches!(entry.data, rbw::db::EntryData::SecureNote) {
            let Some(notes) = entry.notes.as_deref() else {
                continue;
            };
            let private_key_plaintext = decrypt_cipher_locked(
                state.clone(),
                &environment,
                None,
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let Ok(private_key) =
                private_key_from_locked(&private_key_plaintext)
            else {
                continue;
            };
            if private_key.public_key().to_bytes() == request_bytes {
                return Ok(private_key);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}

fn private_key_from_locked(
    private_key: &rbw::locked::Vec,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let private_key = std::str::from_utf8(private_key.data())
        .context("failed to parse SSH private key as UTF-8")?;
    ssh_agent_lib::ssh_key::PrivateKey::from_openssh(private_key)
        .map_err(anyhow::Error::new)
}

#[cfg(test)]
mod device_auth_tests {
    use super::*;

    fn test_state(unlocked: bool) -> crate::state::State {
        let (timeout, _timeout_receiver) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync_timeout_receiver) =
            crate::timeout::Timeout::new();
        let (priv_key, org_keys) = if unlocked {
            let mut material = rbw::locked::Vec::new();
            material.extend(0_u8..64);
            (
                Some(rbw::locked_shatter::ShatteredKeys::seal(
                    &rbw::locked::Keys::new(material),
                )),
                Some(std::collections::HashMap::new()),
            )
        } else {
            (None, None)
        };
        crate::state::State {
            priv_key,
            org_keys,
            clear_generation: tokio::sync::watch::channel(0).0,
            timeout,
            l1_timeout: std::time::Duration::from_secs(60),
            last_bio_success: if unlocked {
                Some(std::time::Instant::now())
            } else {
                None
            },
            pam_gate_required: false,
            ordinary_session: false,
            sync_timeout,
            sync_timeout_duration: std::time::Duration::ZERO,
            notifications_handler: crate::notifications::Handler::new(),
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: None,
        }
    }

    #[tokio::test]
    async fn clear_cancels_pending_device_request() {
        let state =
            std::sync::Arc::new(tokio::sync::Mutex::new(test_state(false)));
        let mut cancellation = state.lock().await.cancellation();
        let clear_state = state.clone();
        let clear = async move {
            tokio::task::yield_now().await;
            clear_state.lock().await.clear();
        };
        let wait = cancel_or(&mut cancellation, std::future::pending::<()>());
        let ((), result) = tokio::join!(clear, wait);
        assert!(result.unwrap_err().to_string().contains("cancelled"));
    }

    #[tokio::test]
    async fn clear_prevents_approval_key_release() {
        let mut state = test_state(true);
        let cancellation = state.cancellation();
        let request = rbw::device_auth::RequestKeyPair::generate().unwrap();
        state.clear();
        let error = encrypt_approval_user_key(
            &state,
            &cancellation,
            &request.public_key_base64(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }

    #[test]
    fn auth_request_ids_are_validated_before_url_construction() {
        assert!(validate_auth_request_id(
            "00000000-0000-0000-0000-000000000000"
        )
        .is_ok());
        assert!(validate_auth_request_id("../../not-a-uuid").is_err());
    }

    #[test]
    fn auth_request_two_factor_selects_supported_provider() {
        assert_eq!(
            auth_request_two_factor_provider(&[
                rbw::api::TwoFactorProviderType::Duo,
                rbw::api::TwoFactorProviderType::Email,
            ])
            .unwrap(),
            rbw::api::TwoFactorProviderType::Email,
        );
        assert!(auth_request_two_factor_provider(&[
            rbw::api::TwoFactorProviderType::WebAuthn,
        ])
        .is_err());
    }

    #[tokio::test]
    async fn coordinated_db_update_reloads_and_preserves_unrelated_fields() {
        let stale_snapshot = rbw::db::Db::new();
        let backend = std::sync::Arc::new(std::sync::Mutex::new(
            serde_json::to_string(&stale_snapshot).unwrap(),
        ));

        {
            let mut newest: rbw::db::Db =
                serde_json::from_str(&backend.lock().unwrap()).unwrap();
            newest.protected_private_key =
                Some("newer-unrelated-private-key".to_string());
            *backend.lock().unwrap() =
                serde_json::to_string(&newest).unwrap();
        }

        let load_backend = backend.clone();
        let save_backend = backend.clone();
        coordinated_db_update_with(
            move || {
                let json = load_backend.lock().unwrap().clone();
                Box::pin(async move {
                    serde_json::from_str(&json).map_err(anyhow::Error::new)
                })
            },
            move |db| {
                let json = serde_json::to_string(db).unwrap();
                Box::pin(async move {
                    *save_backend.lock().unwrap() = json;
                    Ok(())
                })
            },
            |db| db.access_token = Some("refreshed-token".to_string()),
        )
        .await
        .unwrap();

        let saved: rbw::db::Db =
            serde_json::from_str(&backend.lock().unwrap()).unwrap();
        assert_eq!(saved.access_token.as_deref(), Some("refreshed-token"));
        assert_eq!(
            saved.protected_private_key.as_deref(),
            Some("newer-unrelated-private-key")
        );
        assert!(stale_snapshot.protected_private_key.is_none());
    }
}
