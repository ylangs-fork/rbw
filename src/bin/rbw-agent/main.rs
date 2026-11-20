use anyhow::Context as _;

mod actions;
mod agent;
mod daemon;
mod debugger;
mod local_auth;
mod memory_guard;
mod notifications;
mod request_ui;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
    memory_guard: crate::memory_guard::MemoryGuard,
    sentinel_exit: Option<std::sync::mpsc::Receiver<()>>,
) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = if rbw::dirs::config_file().try_exists()? {
        rbw::config::Config::load()?
    } else {
        rbw::config::Config::new()
    };
    // Apply enrollment changes without exporting or discarding an unlocked key.
    let session = crate::state::SessionSettings::from_config(&config);
    let sync_timeout_duration =
        std::time::Duration::from_secs(config.sync_interval);
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
    if sync_timeout_duration > std::time::Duration::ZERO {
        sync_timeout.set(sync_timeout_duration);
    }
    let notifications_handler = crate::notifications::Handler::new();
    let state =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::state::State {
            priv_key: None,
            org_keys: None,
            clear_generation: tokio::sync::watch::channel(0).0,
            timeout,
            l1_timeout: session.timeout,
            last_bio_success: None,
            pam_gate_required: session.pam_gate_required,
            ordinary_session: session.ordinary_session,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: arboard::Clipboard::new()
                .inspect_err(|e| {
                    log::warn!("couldn't create clipboard context: {e}");
                })
                .ok(),
        }));

    memory_guard.spawn_watchdogs(state.clone(), sentinel_exit);
    if config.face_auth == Some(true) || session.pam_gate_required {
        if request_ui::start(state.clone(), &rbw::protocol::Environment::default()).await.is_err() {
            log::warn!("rbwBio request panel is unavailable; local authorization will fail closed if observation cannot start");
        }
    }
    let agent = crate::agent::Agent::new(
        timer_r,
        sync_timer_r,
        state.clone(),
        memory_guard,
    );

    if config.ssh_agent.enabled {
        let ssh_agent =
            crate::ssh_agent::SshAgent::new(state.clone(), config.ssh_agent);
        tokio::try_join!(agent.run(listener), ssh_agent.run())?;
    } else {
        crate::ssh_agent::remove_stale_socket()?;
        agent.run(listener).await?;
    }

    Ok(())
}

fn real_main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    rbw::dirs::make_all()?;

    let startup_ack =
        daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    let (memory_guard, sentinel_exit) =
        match crate::memory_guard::start_sentinel() {
            Ok(guard) => guard,
            Err(error) => {
                log::warn!(
                    "failed to start ptrace sentinel; continuing with \
                     TracerPid monitoring only: {error:#}"
                );
                (crate::memory_guard::MemoryGuard::default(), None)
            }
        };

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) =
            tokio_main(startup_ack, memory_guard, sentinel_exit).await
        {
            // this unwrap is fine because it's the only real option here
            w.send(e).unwrap();
        }
    });

    if let Ok(e) = r.recv() {
        return Err(e);
    }

    Ok(())
}

fn main() {
    if std::env::args().len() == 2 {
        match std::env::args().nth(1).as_deref() {
            Some("--version" | "-V") => {
                println!("rbw-agent {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            Some("--help" | "-h") => {
                println!("rbw-agent {}\nUsage: rbw-agent [--no-daemonize]\n\nBackground vault agent. Use `rbw ui` for the desktop request panel.", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {}
        }
    }
    if crate::memory_guard::sentinel_requested() {
        std::process::exit(i32::from(!crate::memory_guard::run_sentinel()));
    }
    if crate::local_auth::helper_requested() {
        std::process::exit(crate::local_auth::run_helper());
    }

    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
