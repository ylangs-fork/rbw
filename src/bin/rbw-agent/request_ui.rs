//! Capability-protected, secret-free observation and explicit device review.
use std::sync::{Arc, Mutex};
use anyhow::Context as _;
use axum::{extract::{Path, State}, http::{header, Request, StatusCode}, middleware::{self, Next}, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
use rbw::protocol::Environment;
use tokio::sync::{watch, OnceCell};

static HUB: OnceCell<Arc<Hub>> = OnceCell::const_new();
const MAX_REQUESTS: usize = 128;
type AgentState = Arc<tokio::sync::Mutex<crate::state::State>>;
type ApiError = (StatusCode, Json<serde_json::Value>);

#[derive(Clone, serde::Serialize)]
struct UiRequest {
    id: String,
    kind: &'static str,
    operation: String,
    status: &'static str,
    fingerprint: Option<String>,
    device_type: Option<String>,
    ip_address: Option<String>,
    country_name: Option<String>,
    created_at: u64,
    finished_at: Option<u64>,
    message: Option<String>,
    #[serde(skip)]
    cancel: watch::Sender<bool>,
}
impl UiRequest {
    fn live(&self) -> bool { matches!(self.status, "pending_review" | "authenticating" | "rejecting") }
}
struct Inbox {
    requests: Vec<UiRequest>,
    remote_status: &'static str,
    remote_message: Option<String>,
    checked_at: Option<u64>,
}
pub struct Hub {
    url: String,
    authority: String,
    environment: Environment,
    state: AgentState,
    inbox: Mutex<Inbox>,
    refresh: tokio::sync::Mutex<()>,
    unlocking: std::sync::atomic::AtomicBool,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    tray: Option<rbw::desktop::Tray>,
}
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}
fn desktop_environment(environment: &Environment) -> Environment {
    let mut variables = environment.env_vars();
    for name in rbw::protocol::ENVIRONMENT_VARIABLES {
        if !variables.contains_key(std::ffi::OsStr::new(name)) {
            if let Some(value) = std::env::var_os(name) { variables.insert((*name).into(), value); }
        }
    }
    Environment::new(None, variables.into_iter().collect())
}
pub async fn start(state: AgentState, environment: &Environment) -> anyhow::Result<Arc<Hub>> {
    HUB.get_or_try_init(|| initialize(state, environment)).await.cloned()
}
async fn initialize(state: AgentState, environment: &Environment) -> anyhow::Result<Arc<Hub>> {
    use base64::Engine as _;
    use rand::RngCore as _;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let authority = listener.local_addr()?.to_string();
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let executable = option_env!("RBWBIO_DESKTOP_EXECUTABLE")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::current_exe().ok().map(|path| path.with_file_name("rbw")))
            .context("cannot locate the desktop executable")?;
        if rbw::desktop::install_user_entrypoints(&executable).is_err() {
            log::warn!("rbwBio could not install its user launcher; existing files were preserved");
        }
    }
    let url = format!("http://{authority}/{token}/");
    let environment = desktop_environment(environment);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let tray = match rbw::desktop::start_tray(&environment, &url).await {
        Ok(tray) => Some(tray),
        Err(_) => { log::warn!("rbwBio tray is unavailable; application menu and request page remain available"); None }
    };
    let hub = Arc::new(Hub {
        url, authority, environment, state,
        inbox: Mutex::new(Inbox { requests: Vec::new(), remote_status: "not_logged_in", remote_message: None, checked_at: None }),
        refresh: tokio::sync::Mutex::new(()),
        unlocking: std::sync::atomic::AtomicBool::new(false),
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        tray,
    });
    let routes = Router::new()
        .route("/style.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/state", get(snapshot))
        .route("/api/refresh", post(refresh))
        .route("/api/unlock", post(unlock))
        .route("/api/requests/{kind}/{id}/{action}", post(decide))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .with_state(hub.clone());
    let app = Router::new().route(&format!("/{token}/"), get(index))
        .nest(&format!("/{token}"), routes)
        .layer(middleware::from_fn_with_state(hub.clone(), protect));
    tokio::spawn(async move {
        if axum::serve(listener, app).await.is_err() { log::error!("rbwBio request page stopped"); }
    });
    let polling = hub.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop { interval.tick().await; polling.refresh_requests(false).await; }
    });
    Ok(hub)
}
impl Hub {
    pub fn url(&self) -> &str { &self.url }
    fn request_url(&self, kind: &str, id: &str) -> String { format!("{}#{kind}={id}", self.url) }
    fn inbox(&self) -> std::sync::MutexGuard<'_, Inbox> { self.inbox.lock().expect("request inbox poisoned") }
    fn insert(&self, request: UiRequest) -> anyhow::Result<()> {
        let mut inbox = self.inbox();
        if inbox.requests.len() >= MAX_REQUESTS {
            let index = inbox.requests.iter().position(|request| !request.live())
                .context("too many pending authorization requests")?;
            inbox.requests.remove(index);
        }
        inbox.requests.push(request);
        Ok(())
    }
    fn update(&self, kind: &str, id: &str, status: &'static str, message: &str) {
        let mut inbox = self.inbox();
        if let Some(request) = inbox.requests.iter_mut().find(|r| r.kind == kind && r.id == id) {
            if request.status == "cancelled" && status != "cancelled" { return; }
            request.status = status;
            request.message = Some(message.to_string());
            if !request.live() { request.finished_at = Some(now()); }
        }
    }
    fn ticket(self: &Arc<Self>, kind: &'static str, id: String, operation: &str, fingerprint: Option<&str>) -> anyhow::Result<Ticket> {
        let existing = self.inbox().requests.iter().find(|r| r.kind == kind && r.id == id).cloned();
        let cancel = if let Some(request) = existing {
            anyhow::ensure!(request.live(), "request is no longer pending");
            anyhow::ensure!(request.fingerprint.as_deref() == fingerprint, "request fingerprint changed");
            self.update(kind, &id, "authenticating", "System face verification started");
            request.cancel
        } else {
            let cancel = watch::channel(false).0;
            self.insert(UiRequest {
                id: id.clone(), kind, operation: operation.to_string(), status: "authenticating",
                fingerprint: fingerprint.map(str::to_owned), device_type: None, ip_address: None, country_name: None,
                created_at: now(), finished_at: None, message: Some("System face verification started".into()), cancel: cancel.clone(),
            })?;
            cancel
        };
        Ok(Ticket { hub: self.clone(), kind, id, cancel, completed: false })
    }
    async fn refresh_requests(self: &Arc<Self>, review_again: bool) {
        let _refresh = self.refresh.lock().await;
        let result = tokio::time::timeout(std::time::Duration::from_secs(8), crate::actions::pending_auth_request_infos()).await;
        let requests = match result {
            Ok(Ok(requests)) => requests,
            _ => {
                let mut inbox = self.inbox();
                inbox.remote_status = "offline";
                inbox.remote_message = Some("Cannot fetch device requests. Check your login and server connection.".into());
                inbox.checked_at = Some(now());
                return;
            }
        };
        let mut new_ids = Vec::new();
        {
            let mut inbox = self.inbox();
            inbox.remote_status = "ready";
            inbox.remote_message = None;
            inbox.checked_at = Some(now());
            for record in &mut inbox.requests {
                if record.kind == "device" && record.status == "pending_review" && !requests.iter().any(|r| r.id == record.id) {
                    record.status = "expired";
                    record.finished_at = Some(now());
                    record.message = Some("The request is no longer pending or was handled by another device.".into());
                }
            }
        }
        for request in requests {
            let Some(created) = humantime::parse_rfc3339(&request.creation_date).ok()
                .and_then(|date| date.duration_since(std::time::UNIX_EPOCH).ok()) else {
                let mut inbox = self.inbox();
                inbox.remote_status = "offline";
                inbox.remote_message = Some("The server returned an invalid request timestamp. This request cannot be reviewed.".into());
                continue;
            };
            {
                let mut inbox = self.inbox();
                if let Some(existing) = inbox.requests.iter_mut().find(|r| r.kind == "device" && r.id == request.id) {
                    if existing.status == "pending_review" || (review_again && matches!(existing.status, "failed" | "cancelled" | "expired")) {
                        existing.status = "pending_review";
                        existing.finished_at = None;
                        existing.fingerprint = Some(request.fingerprint);
                        existing.device_type = Some(bounded(&request.device_type));
                        existing.ip_address = Some(bounded(&request.ip_address));
                        existing.country_name = request.country_name.map(|s| bounded(&s));
                        existing.message = Some("The request is still pending. Review its source and fingerprint again.".into());
                        existing.cancel = watch::channel(false).0;
                    }
                    continue;
                }
            }
            let record = UiRequest {
                id: request.id.clone(), kind: "device", operation: "Remote device login approval".into(), status: "pending_review",
                fingerprint: Some(request.fingerprint), device_type: Some(bounded(&request.device_type)),
                ip_address: Some(bounded(&request.ip_address)), country_name: request.country_name.map(|s| bounded(&s)),
                created_at: u64::try_from(created.as_millis()).unwrap_or(u64::MAX), finished_at: None,
                message: Some("Review the source and fingerprint, then explicitly approve. Camera preview never approves a request.".into()), cancel: watch::channel(false).0,
            };
            if self.insert(record).is_ok() { new_ids.push(request.id); }
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            if let Some(tray) = &self.tray {
                let count = self.inbox().requests.iter().filter(|r| r.live()).count();
                let _ = tray.set_pending(count).await;
            }
            for id in new_ids {
                if rbw::desktop::notify_request(&self.environment, "rbwBio · Device request pending review", "A device is requesting login. Open to review its source and fingerprint. It will not be approved automatically.", &self.request_url("device", &id)).await.is_err() {
                    self.update("device", &id, "pending_review", "Notification delivery failed. Review the request in the dashboard.");
                }
            }
        }
    }
}
fn bounded(text: &str) -> String { text.chars().filter(|c| !c.is_control()).take(256).collect() }
struct Ticket { hub: Arc<Hub>, kind: &'static str, id: String, cancel: watch::Sender<bool>, completed: bool }
impl Ticket {
    fn finish(&mut self, success: bool) {
        self.completed = true;
        self.hub.update(self.kind, &self.id, if success { "approved" } else { "failed" }, if success { "System authorization passed (the vault command may still fail)." } else { "System authorization failed or did not complete." });
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.completed {
            self.cancel.send_replace(true);
            self.hub.update(self.kind, &self.id, "cancelled", "This authorization was cancelled.");
        }
    }
}
async fn cancelled(sender: &watch::Sender<bool>) {
    let mut receiver = sender.subscribe();
    if !*receiver.borrow() { let _ = receiver.changed().await; }
}
pub async fn authorize_local(state: AgentState, environment: &Environment, gate: rbw::pam_gate::PamGate, operation: &str) -> anyhow::Result<()> {
    let hub = start(state, environment).await?;
    let mut ticket = hub.ticket("local", uuid::Uuid::new_v4().to_string(), operation, None)?;
    let gate = gate.with_request_link(hub.request_url(ticket.kind, &ticket.id))?;
    let result = tokio::select! {
        biased;
        () = cancelled(&ticket.cancel) => Err(anyhow::anyhow!("local authentication cancelled")),
        result = gate.authorize() => result,
    };
    ticket.finish(result.is_ok());
    result
}
pub async fn authorize_device(environment: &Environment, request_id: &str, fingerprint: &str) -> anyhow::Result<()> {
    let hub = HUB.get().context("open rbw ui on the approving desktop before approving a device")?;
    let mut ticket = hub.ticket("device", request_id.to_string(), "Remote device login approval", Some(fingerprint))?;
    let gate = rbw::pam_gate::PamGate::new()?.with_context(environment.clone(), "Approve device login", format!("Approve device login request {request_id} with fingerprint {fingerprint}"))?
        .with_request_link(hub.request_url("device", request_id))?;
    let result = tokio::select! {
        biased;
        () = cancelled(&ticket.cancel) => Err(anyhow::anyhow!("device approval cancelled")),
        result = gate.authorize() => result,
    };
    ticket.completed = true;
    hub.update("device", request_id, if result.is_ok() { "authenticating" } else { "failed" }, if result.is_ok() { "Face verification passed. Submitting approval to the server." } else { "Face authorization failed. The device was not approved." });
    result
}
pub fn device_finished(request_id: &str, approved: bool) {
    if let Some(hub) = HUB.get() {
        hub.update("device", request_id, if approved { "approved" } else { "failed" }, if approved { "The server accepted the approval." } else { "Approval completion could not be confirmed. Refresh the request status." });
    }
}
async fn protect(State(hub): State<Arc<Hub>>, request: Request<axum::body::Body>, next: Next) -> Response {
    let headers = request.headers();
    let origin = format!("http://{}", hub.authority);
    let host_ok = headers.get(header::HOST).and_then(|v| v.to_str().ok()) == Some(hub.authority.as_str());
    let origin_header = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let origin_ok = origin_header.is_none() || origin_header == Some(origin.as_str());
    let site_ok = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()).is_none_or(|v| matches!(v, "same-origin" | "none"));
    let mutation_ok = request.method() == axum::http::Method::GET || (origin_header == Some(origin.as_str()) && headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(';').next() == Some("application/json")));
    if !(host_ok && origin_ok && site_ok && mutation_ok) { return StatusCode::FORBIDDEN.into_response(); }
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", header::HeaderValue::from_static("no-referrer"));
    h.insert("x-content-type-options", header::HeaderValue::from_static("nosniff"));
    h.insert("content-security-policy", header::HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; media-src 'self' blob: mediastream:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    h.insert("permissions-policy", header::HeaderValue::from_static("camera=(self), microphone=()"));
    response
}
async fn index() -> impl IntoResponse { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], include_str!("request_ui.html")) }
async fn styles() -> impl IntoResponse { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("request_ui.css")) }
async fn script() -> impl IntoResponse { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("request_ui.js")) }
async fn snapshot(State(hub): State<Arc<Hub>>) -> Json<serde_json::Value> {
    let locked = hub.state.lock().await.needs_unlock();
    let config = rbw::config::Config::load().ok();
    let inbox = hub.inbox();
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let tray_available = hub.tray.as_ref().is_some_and(|tray| tray.is_registered());
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let tray_available = false;
    Json(serde_json::json!({
        "version":env!("CARGO_PKG_VERSION"), "profile":rbw::dirs::profile(),
        "server":config.as_ref().and_then(|c| c.base_url.as_deref()).unwrap_or("Bitwarden (default server)"), "locked":locked,
        "desktop":{"tray_available":tray_available},
        "remote":{"status":inbox.remote_status,"message":inbox.remote_message,"checked_at":inbox.checked_at},
        "requests":inbox.requests,
    }))
}
fn api_error(status: StatusCode, message: &str) -> ApiError { (status, Json(serde_json::json!({"error":message}))) }
fn ok() -> Json<serde_json::Value> { Json(serde_json::json!({"ok":true})) }
struct Unlocking<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for Unlocking<'_> {
    fn drop(&mut self) { self.0.store(false, std::sync::atomic::Ordering::Release); }
}
async fn refresh(State(hub): State<Arc<Hub>>, Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> { hub.refresh_requests(true).await; ok() }
async fn unlock(State(hub): State<Arc<Hub>>, Json(_): Json<serde_json::Value>) -> Result<Json<serde_json::Value>, ApiError> {
    use std::sync::atomic::Ordering;
    if hub.unlocking.swap(true, Ordering::AcqRel) { return Err(api_error(StatusCode::CONFLICT, "An unlock prompt is already open.")); }
    let unlocking = Unlocking(&hub.unlocking);
    let result = crate::actions::unlock_from_ui(hub.state.clone(), &hub.environment).await;
    drop(unlocking);
    result.map_err(|_| api_error(StatusCode::BAD_REQUEST, "Unlock did not complete. Check the native password prompt or run rbw unlock in a terminal."))?;
    Ok(ok())
}
async fn decide(State(hub): State<Arc<Hub>>, Path((kind,id,action)): Path<(String,String,String)>, Json(body): Json<serde_json::Value>) -> Result<Json<serde_json::Value>, ApiError> {
    if uuid::Uuid::parse_str(&id).is_err() || !matches!(kind.as_str(), "local" | "device") { return Err(api_error(StatusCode::NOT_FOUND,"Request not found.")); }
    let cancel = {
        let mut inbox = hub.inbox();
        let request = inbox.requests.iter_mut().find(|r| r.kind == kind && r.id == id).ok_or_else(|| api_error(StatusCode::NOT_FOUND,"The request does not exist or its record expired."))?;
        if !request.live() { return Err(api_error(StatusCode::CONFLICT,"The request has ended. Refresh its status.")); }
        match action.as_str() {
            "cancel" if request.status == "rejecting" => return Err(api_error(StatusCode::CONFLICT,"Rejection is already being submitted. Refresh its status.")),
            "cancel" => { request.cancel.send_replace(true); request.status="cancelled"; request.finished_at=Some(now()); request.message=Some(if kind == "device" { "Local waiting stopped. An approval already accepted by the server cannot be revoked here." } else { "This authorization was cancelled." }.into()); return Ok(ok()); }
            "approve" if kind == "device" => {
                if request.status != "pending_review" { return Err(api_error(StatusCode::CONFLICT,"The request is already being processed.")); }
                if body.get("fingerprint").and_then(serde_json::Value::as_str) != request.fingerprint.as_deref() { return Err(api_error(StatusCode::CONFLICT,"The fingerprint does not match. Refresh and compare it again.")); }
                request.status="authenticating"; request.message=Some("Approval confirmed. Verifying the request and your face.".into());
            }
            "reject" if kind == "device" => {
                if request.status != "pending_review" { return Err(api_error(StatusCode::CONFLICT,"Cancel the active authentication first.")); }
                request.status="rejecting"; request.message=Some("Submitting rejection.".into());
            }
            _ => return Err(api_error(StatusCode::BAD_REQUEST,"Unsupported request action.")),
        }
        request.cancel.clone()
    };
    let fingerprint = body.get("fingerprint").and_then(serde_json::Value::as_str).map(str::to_owned);
    tokio::spawn(async move {
        if action == "approve" {
            let result = tokio::select! {
                biased;
                () = cancelled(&cancel) => Err(anyhow::anyhow!("device approval cancelled")),
                result = crate::actions::approve_auth_request_from_ui(hub.state.clone(), &hub.environment, &id, fingerprint.as_deref().unwrap_or_default()) => result,
            };
            device_finished(&id, result.is_ok());
        } else {
            let result = crate::actions::reject_auth_request_from_ui(&id).await;
            hub.update("device", &id, if result.is_ok() { "rejected" } else { "failed" }, if result.is_ok() { "The server accepted the rejection." } else { "The rejection result could not be confirmed. Refresh its status." });
        }
    });
    Ok(ok())
}
