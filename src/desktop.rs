//! Portable session-desktop entry points. Opening a request is never approval.
//!
//! Notifications follow the freedesktop protocol; the tray uses the deployed
//! org.kde.StatusNotifierItem protocol used by KDE, Waybar and AppIndicator.
//! A missing tray host is normal on an unextended GNOME desktop.

use std::{
    collections::HashMap,
    io::Write as _,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, LazyLock,
    },
    time::Duration,
};

use anyhow::Context as _;
use futures_util::StreamExt as _;
use zbus::{object_server::SignalEmitter, Connection, Proxy, Variant};

use crate::protocol::Environment;

const CALL_TIMEOUT: Duration = Duration::from_secs(3);
const NOTIFICATION_LIFETIME: Duration = Duration::from_secs(60);
const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
const ITEM_PATH: &str = "/StatusNotifierItem";
const ITEM_INTERFACE: &str = "org.kde.StatusNotifierItem";
const OWNED_DESKTOP: &str = "X-rbwBio-Managed=true";
const OWNED_ICON: &str = "<!-- rbwBio managed desktop asset -->";

type Pixmap = (i32, i32, Vec<u8>);

fn normal_user() -> anyhow::Result<()> {
    // Never open a browser or install user launchers as root or setuid.
    if unsafe { libc::geteuid() == 0 || libc::geteuid() != libc::getuid() } {
        anyhow::bail!("rbwBio desktop integration requires a normal user session");
    }
    Ok(())
}

fn validate_url(value: &str) -> anyhow::Result<()> {
    let invalid = || anyhow::anyhow!("invalid local rbwBio request URL");
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.as_str() != value
    {
        return Err(invalid());
    }
    let token = url.path().strip_prefix('/').and_then(|path| path.strip_suffix('/'))
        .ok_or_else(invalid)?;
    if token.len() != 43
        || !token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid());
    }
    if let Some(fragment) = url.fragment() {
        let (kind, id) = fragment.split_once('=').ok_or_else(invalid)?;
        if !matches!(kind, "local" | "device")
            || uuid::Uuid::parse_str(id).map_err(|_| invalid())?.to_string() != id
        {
            return Err(invalid());
        }
    }
    Ok(())
}

async fn session_connection(environment: &Environment) -> anyhow::Result<Connection> {
    normal_user()?;
    let environment = environment.with_desktop_fallback();
    let address = crate::pam_gate::desktop_session_bus(&environment)?;
    let address = address.to_str().context("desktop session address is not UTF-8")?;
    tokio::time::timeout(
        CALL_TIMEOUT,
        zbus::connection::Builder::address(address)
            .method_timeout(CALL_TIMEOUT)
            .build(),
    )
    .await
    .context("desktop session bus connection timed out")?
    .context("desktop session bus connection failed")
}

/// Open only a validated local capability URL, without a shell or secret output.
pub async fn open_url(environment: &Environment, url: &str) -> anyhow::Result<()> {
    open_with_activation(environment, url, None).await
}

async fn open_with_activation(
    environment: &Environment,
    url: &str,
    activation: Option<&str>,
) -> anyhow::Result<()> {
    normal_user()?;
    validate_url(url)?;
    let environment = environment.with_desktop_fallback();
    let bus = crate::pam_gate::desktop_session_bus(&environment)?;
    let mut command = tokio::process::Command::new("/usr/bin/xdg-open");
    command.arg(url).env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .envs(environment.env_vars())
        .env("DBUS_SESSION_BUS_ADDRESS", bus)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .kill_on_drop(true);
    // Local process configuration only; never forward arbitrary client env.
    for name in ["HOME", "USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_DATA_DIRS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(token) = activation.filter(|token| valid_activation(token)) {
        command.env("XDG_ACTIVATION_TOKEN", token).env("DESKTOP_STARTUP_ID", token);
    }
    let mut child = command.spawn().context("could not start the desktop browser launcher")?;
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await.context("desktop browser launcher timed out")?
        .context("desktop browser launcher failed")?;
    if !status.success() {
        anyhow::bail!("desktop browser launcher did not accept the request");
    }
    Ok(())
}

fn valid_activation(token: &str) -> bool {
    !token.is_empty() && token.len() <= 4096 && !token.chars().any(char::is_control)
}

fn escaped_body(body: &str) -> String {
    let mut escaped = String::with_capacity(body.len());
    for character in body.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Return only after a real, actionable notification has been accepted by DBus.
/// Desktop do-not-disturb settings can still suppress its visible banner.
pub async fn notify_request(
    environment: &Environment,
    title: &str,
    body: &str,
    url: &str,
) -> anyhow::Result<()> {
    validate_url(url)?;
    let connection = session_connection(environment).await?;
    let proxy = Proxy::new_owned(
        connection, "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications", "org.freedesktop.Notifications",
    ).await.context("desktop notification service is unavailable")?;
    // This first call also allows the session bus to activate the daemon.
    let _: Vec<String> = proxy.call("GetCapabilities", &()).await
        .context("could not query desktop notification capabilities")?;
    // Pin this notification's lifetime to one daemon instance. A replacement
    // daemon can reuse numeric IDs; its unrelated actions must not open this URL.
    let bus = Proxy::new(proxy.connection(), "org.freedesktop.DBus",
        "/org/freedesktop/DBus", "org.freedesktop.DBus").await?;
    let owner: String = bus.call("GetNameOwner", &("org.freedesktop.Notifications",)).await
        .context("desktop notification service disappeared")?;
    let proxy = Proxy::new_owned(proxy.connection().clone(), owner,
        "/org/freedesktop/Notifications", "org.freedesktop.Notifications").await?;
    let capabilities: Vec<String> = proxy.call("GetCapabilities", &()).await
        .context("could not query desktop notification capabilities")?;
    if !capabilities.iter().any(|value| value == "actions") {
        anyhow::bail!("desktop notification service does not support actions; open rbwBio from the application launcher");
    }
    // One ordered subscription, before Notify: ActivationToken must be consumed
    // before ActionInvoked, even if both arrive before the Notify reply.
    let mut signals = proxy.receive_all_signals().await
        .context("could not subscribe to desktop notification actions")?;
    let body = if capabilities.iter().any(|value| value == "body-markup") {
        escaped_body(body)
    } else {
        body.to_owned()
    };
    let hints = HashMap::from([
        ("desktop-entry", Variant::from("rbwbio")),
        ("urgency", Variant::from(1_u8)),
    ]);
    let id: u32 = proxy.call("Notify", &(
        "rbwBio", 0_u32, "rbwbio", title, body.as_str(),
        vec!["default", "Open rbwBio", "open", "Open rbwBio"], hints, 60_000_i32,
    )).await.context("desktop notification was not accepted")?;
    anyhow::ensure!(id != 0, "desktop notification service returned an invalid notification ID");
    let environment = environment.clone();
    let url = url.to_owned();
    tokio::spawn(async move {
        let expires = tokio::time::Instant::now() + NOTIFICATION_LIFETIME;
        // Reserve the last method timeout for withdrawing the notification.
        let action_deadline = expires - CALL_TIMEOUT;
        let deadline = tokio::time::sleep_until(action_deadline);
        tokio::pin!(deadline);
        let mut activation = None;
        let mut closed = false;
        loop {
            let message = tokio::select! {
                () = &mut deadline => break,
                message = signals.next() => match message {
                    Some(message) => message,
                    None => break,
                },
            };
            let header = message.header();
            match header.member().map(|member| member.as_str()) {
                Some("ActivationToken") => {
                    if let Ok((notification, token)) = message.body().deserialize::<(u32, String)>() {
                        if notification == id && valid_activation(&token) {
                            activation = Some(token);
                        }
                    }
                }
                Some("ActionInvoked") => {
                    if let Ok((notification, action)) = message.body().deserialize::<(u32, String)>() {
                        if notification == id && matches!(action.as_str(), "default" | "open") {
                            // Opening details is the only action. It never invokes PAM,
                            // unlocks the vault, or approves a remote device.
                            if !matches!(tokio::time::timeout_at(
                                action_deadline,
                                open_with_activation(&environment, &url, activation.as_deref()),
                            ).await, Ok(Ok(()))) {
                                log::warn!("rbwBio could not open notification details");
                            }
                            break;
                        }
                    }
                }
                Some("NotificationClosed") => {
                    if let Ok((notification, _reason)) = message.body().deserialize::<(u32, u32)>() {
                        if notification == id {
                            closed = true;
                            break;
                        }
                    }
                }
                _ => {},
            }
        }
        if !closed {
            let _ = tokio::time::timeout_at(
                expires, proxy.call::<_, _, ()>("CloseNotification", &(id,)),
            ).await;
        }
        // Dropping the stream and proxy releases this notification's connection.
    });
    Ok(())
}

struct StatusItem {
    environment: Environment,
    url: String,
    pending: Arc<AtomicUsize>,
    activation: std::sync::Mutex<Option<String>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl StatusItem {
    async fn activate(&self, _x: i32, _y: i32) -> zbus::fdo::Result<()> {
        let token = self.activation.lock().map_err(|_| zbus::fdo::Error::Failed("desktop activation unavailable".into()))?.take();
        open_with_activation(&self.environment, &self.url, token.as_deref()).await
            .map_err(|_| zbus::fdo::Error::Failed("could not open rbwBio".into()))
    }

    async fn secondary_activate(&self, x: i32, y: i32) -> zbus::fdo::Result<()> {
        self.activate(x, y).await
    }

    async fn context_menu(&self, x: i32, y: i32) -> zbus::fdo::Result<()> {
        // There is no menu-only UI: a secondary click also opens the inbox.
        self.activate(x, y).await
    }

    fn provide_xdg_activation_token(&self, token: &str) {
        if valid_activation(token) {
            if let Ok(mut activation) = self.activation.lock() {
                *activation = Some(token.to_owned());
            }
        }
    }

    #[zbus(property)]
    fn category(&self) -> &str { "ApplicationStatus" }
    #[zbus(property)]
    fn id(&self) -> &str { "rbwbio" }
    #[zbus(property)]
    fn title(&self) -> &str { "rbwBio" }
    #[zbus(property(emits_changed_signal = "false"))]
    fn status(&self) -> &str { pending_status(self.pending.load(Ordering::Relaxed)) }
    #[zbus(property)]
    fn window_id(&self) -> i32 { 0 }
    #[zbus(property)]
    fn icon_name(&self) -> &str { "rbwbio" }
    #[zbus(property)]
    fn icon_pixmap(&self) -> &[Pixmap] { &ICON_PIXMAP }
    #[zbus(property)]
    fn attention_icon_name(&self) -> &str { "rbwbio" }
    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> &[Pixmap] { &ICON_PIXMAP }
    #[zbus(property)]
    fn overlay_icon_name(&self) -> &str { "" }
    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<Pixmap> { Vec::new() }
    #[zbus(property)]
    fn attention_movie_name(&self) -> &str { "" }
    #[zbus(property)]
    fn icon_theme_path(&self) -> &str { "" }
    #[zbus(property)]
    fn item_is_menu(&self) -> bool { false }
    #[zbus(property)]
    fn menu(&self) -> zbus::ObjectPath<'static> { zbus::ObjectPath::from_static_str_unchecked("/") }
    #[zbus(property(emits_changed_signal = "false"), name = "ToolTip")]
    fn tool_tip(&self) -> (&str, Vec<Pixmap>, &str, String) {
        let count = self.pending.load(Ordering::Relaxed);
        ("rbwbio", Vec::new(), "rbwBio", if count == 0 {
            "Open the request inbox".into()
        } else {
            format!("{count} requests awaiting attention")
        })
    }
}

fn pending_status(count: usize) -> &'static str {
    if count == 0 { "Active" } else { "NeedsAttention" }
}

// A small network-byte-order ARGB shield/face fallback for hosts that cannot
// resolve the installed icon theme name. Built once, not once per property read.
static ICON_PIXMAP: LazyLock<Vec<Pixmap>> = LazyLock::new(|| {
    let mut bytes = vec![0_u8; 32 * 32 * 4];
    for y in 0_usize..32 {
        for x in 0_usize..32 {
            let half_width = if y < 16 { 12 } else { 12_usize.saturating_sub((y - 16) * 3 / 4) };
            let shield = (3..30).contains(&y) && x.abs_diff(16) <= half_width
                && (y >= 7 || x.abs_diff(16) <= (y - 2) * 3);
            if shield {
                let face = ((x == 11 || x == 21) && (11..15).contains(&y))
                    || (x == 16 && (11..18).contains(&y))
                    || ((13..20).contains(&x) && y == 22)
                    || ((x == 12 || x == 20) && y == 21);
                let pixel = if face { [255, 235, 255, 250] } else { [255, 20, 135, 157] };
                bytes[(y * 32 + x) * 4..(y * 32 + x + 1) * 4].copy_from_slice(&pixel);
            }
        }
    }
    vec![(32, 32, bytes)]
});

/// Keep this value alive as long as the inbox is available. Dropping it removes
/// the real bus object and cancels watcher monitoring.
pub struct Tray {
    connection: Connection,
    registered: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
    monitor: tokio::task::JoinHandle<()>,
}

impl Tray {
    /// True only after watcher acceptance and while it reports a real host.
    pub fn is_registered(&self) -> bool {
        self.registered.load(Ordering::Acquire)
    }

    pub async fn set_pending(&self, count: usize) -> anyhow::Result<()> {
        if self.pending.swap(count, Ordering::Relaxed) == count {
            return Ok(());
        }
        let emitter = SignalEmitter::new(&self.connection, ITEM_PATH)?;
        emitter.emit(ITEM_INTERFACE, "NewStatus", &(pending_status(count),)).await?;
        emitter.emit(ITEM_INTERFACE, "NewToolTip", &()).await?;
        Ok(())
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.monitor.abort();
    }
}

async fn register_tray(watcher: &Proxy<'_>) -> bool {
    let accepted: zbus::Result<()> = watcher.call("RegisterStatusNotifierItem", &(ITEM_PATH,)).await;
    if accepted.is_err() {
        return false;
    }
    watcher.get_property::<bool>("IsStatusNotifierHostRegistered").await.unwrap_or(false)
}

/// A missing watcher or host is nonfatal; launcher and notifications remain usable.
pub async fn start_tray(environment: &Environment, url: &str) -> anyhow::Result<Tray> {
    validate_url(url)?;
    let connection = session_connection(environment).await?;
    let pending = Arc::new(AtomicUsize::new(0));
    connection.object_server().at(ITEM_PATH, StatusItem {
        environment: environment.clone(), url: url.to_owned(),
        pending: Arc::clone(&pending), activation: std::sync::Mutex::new(None),
    }).await.context("could not export rbwBio desktop icon")?;
    let watcher: Proxy<'_> = zbus::proxy::Builder::new(&connection)
        .destination(WATCHER).path(WATCHER_PATH).interface(WATCHER)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build().await?;
    let bus = Proxy::new(&connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus").await?;
    // Subscribe before registration so a starting/replaced watcher cannot be missed.
    let mut owners = bus.receive_signal_with_args("NameOwnerChanged", &[(0, WATCHER)]).await?;
    let mut hosts = watcher.receive_all_signals().await?;
    let registered = Arc::new(AtomicBool::new(register_tray(&watcher).await));
    if !registered.load(Ordering::Acquire) {
        log::info!("rbwBio tray host unavailable; use the application launcher and notifications");
    }
    let monitor_registered = Arc::clone(&registered);
    let monitor = tokio::spawn(async move {
        loop {
            tokio::select! {
                owner = owners.next() => {
                    monitor_registered.store(false, Ordering::Release);
                    let Some(owner) = owner else { break };
                    if let Ok((_name, _old, new)) = owner.body().deserialize::<(String, String, String)>() {
                        if !new.is_empty() {
                            monitor_registered.store(register_tray(&watcher).await, Ordering::Release);
                        }
                    }
                },
                host = hosts.next() => {
                    let Some(host) = host else { break };
                    let header = host.header();
                    match header.member().map(|member| member.as_str()) {
                        Some("StatusNotifierHostUnregistered") => {
                            monitor_registered.store(false, Ordering::Release);
                        },
                        Some("StatusNotifierHostRegistered") => {
                            monitor_registered.store(register_tray(&watcher).await, Ordering::Release);
                        },
                        _ => {},
                    }
                },
            }
        }
        monitor_registered.store(false, Ordering::Release);
    });
    Ok(Tray { connection, registered, pending, monitor })
}

fn xdg_home(variable: &str, fallback: &str) -> anyhow::Result<PathBuf> {
    if let Some(value) = std::env::var_os(variable).filter(|value| Path::new(value).is_absolute()) {
        return Ok(value.into());
    }
    let home = std::env::var_os("HOME").filter(|value| Path::new(value).is_absolute())
        .context("desktop installation requires an absolute home directory")?;
    Ok(PathBuf::from(home).join(fallback))
}

fn system_entry_exists(variable: &str, defaults: &str, suffix: &str) -> bool {
    let paths = std::env::var_os(variable).filter(|value| !value.is_empty())
        .unwrap_or_else(|| defaults.into());
    std::env::split_paths(&paths).filter(|path| path.is_absolute())
        .any(|path| path.join(suffix).is_file())
}

fn owned_file(path: &Path, marker: &str) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let content = std::fs::read_to_string(path)
                .context("could not inspect an existing desktop entry")?;
            Ok(content.lines().any(|line| line.trim() == marker))
        },
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("could not inspect an existing desktop entry"),
    }
}

fn install_owned(path: &Path, contents: &str, marker: &str) -> anyhow::Result<()> {
    let exists = std::fs::symlink_metadata(path).is_ok();
    if exists && !owned_file(path, marker)? {
        anyhow::bail!("preserved a foreign rbwBio desktop file; remove or rename it to install the standard entry");
    }
    let parent = path.parent().context("invalid desktop installation directory")?;
    std::fs::create_dir_all(parent).context("could not create desktop entry directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).context("could not create desktop entry")?;
    file.write_all(contents.as_bytes()).context("could not write desktop entry")?;
    use std::os::unix::fs::PermissionsExt as _;
    file.as_file().set_permissions(std::fs::Permissions::from_mode(0o644))?;
    if exists {
        file.persist(path).map_err(|error| error.error).context("could not update desktop entry")?;
    } else {
        file.persist_noclobber(path).map_err(|error| error.error).context("preserved a concurrently created desktop entry")?;
    }
    Ok(())
}

fn remove_owned(path: &Path, marker: &str) -> anyhow::Result<()> {
    if owned_file(path, marker)? {
        std::fs::remove_file(path).context("could not remove a redundant managed desktop entry")?;
    }
    Ok(())
}

fn desktop_executable(executable: &Path) -> anyhow::Result<String> {
    let value = executable.to_str().context("desktop executable path must be UTF-8")?;
    anyhow::ensure!(executable.is_absolute() && !value.chars().any(char::is_control)
        && !value.contains(['=', '%']), "unsupported desktop executable path");
    let mut quoted = String::from("\"");
    for character in value.chars() {
        // Desktop string unescaping precedes Exec argument unquoting.
        match character {
            '\\' => quoted.push_str("\\\\\\\\"),
            '"' | '$' | '`' => { quoted.push_str("\\\\"); quoted.push(character); },
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

/// Install only XDG launcher/icon/autostart files owned by rbwBio. The supplied
/// executable must be the package's stable path, not a versioned Cellar path.
pub fn install_user_entrypoints(executable: &Path) -> anyhow::Result<()> {
    normal_user()?;
    let executable = desktop_executable(executable)?;
    let data = xdg_home("XDG_DATA_HOME", ".local/share")?;
    let config = xdg_home("XDG_CONFIG_HOME", ".config")?;
    let launcher = data.join("applications/rbwbio.desktop");
    let autostart = config.join("autostart/rbwbio.desktop");
    let packaged = Path::new("/usr/share/applications/rbwbio.desktop").is_file()
        || system_entry_exists("XDG_DATA_DIRS", "/usr/local/share:/usr/share", "applications/rbwbio.desktop");
    if packaged {
        remove_owned(&launcher, OWNED_DESKTOP)?;
    } else {
        install_owned(&data.join("icons/hicolor/scalable/apps/rbwbio.svg"),
            include_str!("../assets/desktop/rbwbio.svg"), OWNED_ICON)?;
        install_owned(&data.join("icons/hicolor/symbolic/apps/rbwbio-symbolic.svg"),
            include_str!("../assets/desktop/rbwbio-symbolic.svg"), OWNED_ICON)?;
        install_owned(&launcher, &include_str!("../assets/desktop/rbwbio.desktop.in").replace("@RBW_EXEC@", &executable), OWNED_DESKTOP)?;
    }
    if system_entry_exists("XDG_CONFIG_DIRS", "/etc/xdg", "autostart/rbwbio.desktop")
        || system_entry_exists("XDG_CONFIG_DIRS", "/etc/xdg", "autostart/rbwbio-autostart.desktop")
    {
        remove_owned(&autostart, OWNED_DESKTOP)?;
    } else {
        install_owned(&autostart, &include_str!("../assets/desktop/rbwbio-autostart.desktop.in").replace("@RBW_EXEC@", &executable), OWNED_DESKTOP)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_url() -> String {
        format!("http://127.0.0.1:43210/{}/", "a".repeat(43))
    }

    #[test]
    fn only_local_capability_urls_can_open() {
        let base = base_url();
        assert!(validate_url(&base).is_ok());
        assert!(validate_url(&format!("{base}#device=550e8400-e29b-41d4-a716-446655440000")).is_ok());
        assert!(validate_url(&format!("{base}#local=550e8400-e29b-41d4-a716-446655440000")).is_ok());
        for rejected in [
            base.replace("127.0.0.1", "localhost"),
            base.replace("127.0.0.1", "example.com"),
            base.replace("http:", "https:"),
            base.replace(":43210", ":0"),
            base.replace("127.0.0.1", "user@127.0.0.1"),
            format!("{base}?approve=true"),
            format!("{base}api/unlock"),
            format!("{base}#approve=true"),
            format!("{base}#local=not-a-uuid"),
            format!("{base}#device=550E8400-E29B-41D4-A716-446655440000"),
            "file:///etc/passwd".into(),
        ] {
            assert!(validate_url(&rejected).is_err());
        }
    }

    #[test]
    fn notification_metadata_cannot_become_markup() {
        assert_eq!(
            escaped_body("<a href=\"secret\">&'</a>"),
            "&lt;a href=&quot;secret&quot;&gt;&amp;&apos;&lt;/a&gt;",
        );
    }

    #[test]
    fn desktop_paths_are_one_literal_argument() {
        assert_eq!(desktop_executable(Path::new("/opt/rbw bio/bin/rbw")).unwrap(),
            "\"/opt/rbw bio/bin/rbw\"");
        assert_eq!(desktop_executable(Path::new("/opt/$bio/bin/rbw")).unwrap(),
            "\"/opt/\\\\$bio/bin/rbw\"");
        assert!(desktop_executable(Path::new("rbw")).is_err());
        assert!(desktop_executable(Path::new("/opt/%f/rbw")).is_err());
        assert!(desktop_executable(Path::new("/opt/rbw\nExec=other")).is_err());
    }

    #[test]
    fn foreign_desktop_files_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rbwbio.desktop");
        let original = "[Desktop Entry]\nName=Someone else's launcher\n";
        std::fs::write(&path, original).unwrap();
        assert!(install_owned(&path, OWNED_DESKTOP, OWNED_DESKTOP).is_err());
        remove_owned(&path, OWNED_DESKTOP).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn managed_desktop_files_update_and_can_be_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("applications/rbwbio.desktop");
        let first = format!("[Desktop Entry]\n{OWNED_DESKTOP}\nName=rbwBio\n");
        let second = format!("[Desktop Entry]\n{OWNED_DESKTOP}\nName=rbwBio Inbox\n");
        install_owned(&path, &first, OWNED_DESKTOP).unwrap();
        install_owned(&path, &second, OWNED_DESKTOP).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), second);
        remove_owned(&path, OWNED_DESKTOP).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn symlink_desktop_files_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("foreign");
        let path = directory.path().join("rbwbio.desktop");
        std::fs::write(&target, OWNED_DESKTOP).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(install_owned(&path, OWNED_DESKTOP, OWNED_DESKTOP).is_err());
        remove_owned(&path, OWNED_DESKTOP).unwrap();
        assert!(path.is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), OWNED_DESKTOP);
    }
}
