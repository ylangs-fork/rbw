//! Ephemeral IR telemetry and browser-local RGB display. The server opens no camera.

use std::process::ChildStdin;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{ensure, Context as _};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use base64::Engine as _;
use rand::TryRngCore as _;

pub(super) const MAX_LINE: usize = 4096;
pub(super) const PREFIX: &[u8] = b"RBWBIO_PREVIEW ";
const HTML: &str = include_str!("enrollment_preview.html");
const SCRIPT: &str = include_str!("enrollment_preview.js");
const STYLE: &str = include_str!("enrollment_preview.css");

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    darkness: f64,
    threshold: f64,
}

struct Content {
    snapshot: Bytes,
    stdin: Option<ChildStdin>,
    cancelled: bool,
    finished: bool,
    page_ready: bool,
    camera_ready: bool,
    verifying: bool,
    final_seen: bool,
    final_acknowledged: bool,
}

struct Shared {
    token_path: String,
    authority: String,
    origin: String,
    content: Mutex<Content>,
    cancellation: tokio::sync::Notify,
    acknowledgement: tokio::sync::Notify,
}

pub(super) struct Preview {
    shared: Arc<Shared>,
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

pub(super) fn start(open_browser: bool) -> anyhow::Result<Preview> {
    ensure!(!rustix::process::geteuid().is_root(), "the enrollment preview must run as your ordinary user");
    let mut secret = [0_u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut secret)
        .context("cannot generate enrollment preview token")?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let authority = listener.local_addr()?.to_string();
    let origin = format!("http://{authority}");
    let token_path = format!("/{token}/");
    let url = format!("{origin}{token_path}");
    let shared = Arc::new(Shared {
        token_path,
        authority,
        origin,
        content: Mutex::new(Content {
            snapshot: Bytes::from_static(b"{\"status\":\"waiting\"}"),
            stdin: None,
            cancelled: false,
            finished: false,
            page_ready: false,
            verifying: false,
            camera_ready: false,
            final_seen: false,
            final_acknowledged: false,
        }),
        cancellation: tokio::sync::Notify::new(),
        acknowledgement: tokio::sync::Notify::new(),
    });
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (ready, startup) = std::sync::mpsc::sync_channel(1);
    let state = Arc::clone(&shared);
    let server = std::thread::Builder::new().name("rbw-enrollment-preview".into()).spawn(move || {
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(error) => { let _ = ready.send(Err(error)); return; }
            };
            let app = axum::Router::new().fallback(handle).with_state(state);
            let _ = ready.send(Ok(()));
            tokio::select! {
                result = async { axum::serve(listener, app).await } => {
                    if let Err(error) = result { eprintln!("Enrollment preview stopped: {error}"); }
                }
                _ = stopped => {}
            }
        });
        // Abort idle or incomplete HTTP connections rather than waiting for clients.
        runtime.shutdown_timeout(std::time::Duration::from_millis(250));
    })?;
    let preview = Preview { shared, url, stop: Some(stop), server: Some(server) };
    startup.recv().context("enrollment preview server did not start")??;
    if open_browser {
        let desktop = ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|name| {
            std::env::var_os(name).is_some_and(|value| !value.is_empty())
        });
        if !desktop {
            eprintln!("Enrollment preview unavailable: no desktop display. Continue in this terminal.");
        } else {
            open::that_detached(preview.url())
                .context("enrollment preview unavailable: cannot launch the default browser")?;
            eprintln!("Opening the enrollment preview in your default browser...");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let (ready, cancelled) = {
                    let content = preview.shared.content.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (content.camera_ready, content.cancelled)
                };
                ensure!(!cancelled, "face setup was cancelled before enrollment");
                if ready { break; }
                ensure!(std::time::Instant::now() < deadline,
                    "the RGB preview did not become ready within 60 seconds; check browser camera permission (no IR enrollment was started)");
                ensure!(!preview.server.as_ref().is_some_and(JoinHandle::is_finished),
                    "the enrollment preview server stopped before the browser connected");
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    Ok(preview)
}

impl Preview {
    pub(super) fn url(&self) -> &str { &self.url }

    pub(super) fn bind_child_stdin(&self, stdin: ChildStdin) {
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !content.cancelled && !content.finished { content.stdin = Some(stdin); }
    }

    pub(super) fn cancelled(&self) -> bool {
        self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner).cancelled
    }

    pub(super) async fn wait_cancelled(&self) {
        loop {
            let notified = self.shared.cancellation.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled() { return; }
            notified.await;
        }
    }

    pub(super) fn verifying(&self) {
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !content.cancelled && !content.finished {
            content.verifying = true;
            content.snapshot = Bytes::from_static(b"{\"status\":\"verifying\"}");
            drop(content.stdin.take());
        }
    }

    pub(super) fn close_stdin(&self) {
        drop(self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner).stdin.take());
    }

    pub(super) fn ingest(&self, json: &[u8]) -> anyhow::Result<()> {
        ensure!(json.len() <= MAX_LINE - PREFIX.len(), "enrollment preview frame line is too large");
        let frame: Frame = serde_json::from_slice(json).context("invalid enrollment preview frame")?;
        ensure!(frame.darkness.is_finite() && (0.0..=100.0).contains(&frame.darkness)
            && frame.threshold.is_finite() && (0.0..=100.0).contains(&frame.threshold),
            "invalid enrollment preview darkness or threshold");
        #[derive(serde::Serialize)]
        struct Snapshot<'a> { status: &'static str, #[serde(flatten)] frame: &'a Frame }
        let snapshot = Bytes::from(serde_json::to_vec(&Snapshot { status: "active", frame: &frame })?);
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !content.cancelled && !content.finished && !content.verifying { content.snapshot = snapshot; }
        Ok(())
    }

    pub(super) fn finish(&self, status: &str, reason: &str) {
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if content.finished { return; }
        let status = match status {
            "complete" => "complete",
            _ if content.cancelled => "cancelled",
            _ => "failed",
        };
        let reason = if status == "cancelled" { "Face setup was cancelled; face authorization was not enabled." } else { reason };
        #[derive(serde::Serialize)]
        struct Final<'a> { status: &'static str, reason: &'a str }
        content.snapshot = Bytes::from(serde_json::to_vec(&Final { status, reason })
            .expect("serializing final preview text"));
        content.finished = true;
        drop(content.stdin.take());
    }

    /// Wait only for a connected page, and never keep a headless setup alive.
    pub(super) async fn wait_final_ack(&self) -> bool {
        let wait = async {
            loop {
                let notified = self.shared.acknowledgement.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !content.page_ready || content.final_acknowledged { return content.final_acknowledged; }
                }
                notified.await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), wait).await.unwrap_or(false)
    }
}

impl Drop for Preview {
    fn drop(&mut self) {
        self.finish("failed", "Face setup stopped before activation. Check your terminal.");
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(server) = self.server.take() { let _ = server.join(); }
    }
}

async fn handle(State(shared): State<Arc<Shared>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let host_ok = headers.get(header::HOST).and_then(|value| value.to_str().ok()) == Some(shared.authority.as_str());
    let origin = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok());
    let same_origin = origin.is_none() || origin == Some(shared.origin.as_str());
    let cross_site = headers.get("sec-fetch-site").is_some_and(|value| value == "cross-site");
    let path = uri.path().strip_prefix(&shared.token_path);
    if !host_ok || !same_origin || cross_site || uri.query().is_some() || path.is_none() {
        return response(StatusCode::NOT_FOUND, "text/plain", Bytes::new());
    }
    match (method, path.unwrap_or_default()) {
        (Method::GET, "") => response(StatusCode::OK, "text/html; charset=utf-8", Bytes::from_static(HTML.as_bytes())),
        (Method::GET, "app.js") => response(StatusCode::OK, "text/javascript; charset=utf-8", Bytes::from_static(SCRIPT.as_bytes())),
        (Method::GET, "style.css") => response(StatusCode::OK, "text/css; charset=utf-8", Bytes::from_static(STYLE.as_bytes())),
        (Method::GET, "state") => {
            let snapshot = {
                let mut content = shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                content.page_ready = true;
                if content.finished { content.final_seen = true; }
                content.snapshot.clone()
            };
            response(StatusCode::OK, "application/json", snapshot)
        }
        (Method::POST, "ready") if origin == Some(shared.origin.as_str()) => {
            let mut content = shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if content.cancelled || content.finished {
                return response(StatusCode::CONFLICT, "text/plain", Bytes::new());
            }
            content.camera_ready = true;
            response(StatusCode::NO_CONTENT, "text/plain", Bytes::new())
        }
        (Method::POST, "cancel") if origin == Some(shared.origin.as_str()) => {
            let mut content = shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !content.finished {
                content.cancelled = true;
                content.snapshot = Bytes::from_static(b"{\"status\":\"cancelling\"}");
                drop(content.stdin.take());
                shared.cancellation.notify_waiters();
            }
            response(StatusCode::NO_CONTENT, "text/plain", Bytes::new())
        }
        (Method::POST, "ack") if origin == Some(shared.origin.as_str()) => {
            let mut content = shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !content.finished || !content.final_seen {
                return response(StatusCode::CONFLICT, "text/plain", Bytes::new());
            }
            content.final_acknowledged = true;
            shared.acknowledgement.notify_waiters();
            response(StatusCode::NO_CONTENT, "text/plain", Bytes::new())
        }
        _ => response(StatusCode::NOT_FOUND, "text/plain", Bytes::new()),
    }
}

fn response(status: StatusCode, content_type: &'static str, bytes: Bytes) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type.parse().expect("static content type"));
    headers.insert(header::CACHE_CONTROL, "no-store, max-age=0".parse().expect("static header"));
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; media-src 'self' blob:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().expect("static CSP"));
    headers.insert("permissions-policy", "camera=(self), microphone=()".parse().expect("static permissions policy"));
    headers.insert("referrer-policy", "no-referrer".parse().expect("static header"));
    headers.insert("x-content-type-options", "nosniff".parse().expect("static header"));
    headers.insert("cross-origin-resource-policy", "same-origin".parse().expect("static header"));
    headers.insert("x-frame-options", "DENY".parse().expect("static header"));
    response
}

/// Streaming protocol decoder retaining only one line and the final camera path.
#[derive(Default)]
pub(super) struct Protocol {
    line: Vec<u8>,
    output: Vec<u8>,
}

impl Protocol {
    pub(super) fn feed(&mut self, bytes: &[u8], preview: &Preview) -> anyhow::Result<()> {
        for &byte in bytes {
            ensure!(self.line.len() < MAX_LINE, "enrollment output line exceeds 512 KiB");
            self.line.push(byte);
            if byte == b'\n' {
                if let Some(json) = self.line.strip_prefix(PREFIX) {
                    preview.ingest(json)?;
                } else {
                    ensure!(self.output.len() + self.line.len() <= 4096,
                        "installer returned excessive non-preview output");
                    self.output.extend_from_slice(&self.line);
                }
                self.line.clear();
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> anyhow::Result<Vec<u8>> {
        ensure!(self.line.is_empty(), "installer returned an incomplete output line");
        Ok(self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_line_is_bounded() -> anyhow::Result<()> {
        let preview = start(false)?;
        let mut protocol = Protocol::default();
        assert!(protocol.feed(&vec![b'x'; MAX_LINE + 200], &preview).is_err());
        assert_eq!(protocol.line.len(), MAX_LINE);
        let mut protocol = Protocol::default();
        protocol.feed(b"RBWBIO_PRE", &preview)?;
        protocol.feed(b"VIEW {\"darkness\":71.6,\"threshold\":60}\n/dev/video0\n", &preview)?;
        assert_eq!(protocol.finish()?, b"/dev/video0\n");
        Ok(())
    }

    #[test]
    fn refuses_untrusted_requests_and_invalid_frames() -> anyhow::Result<()> {
        let preview = start(false)?;
        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        let base = &preview.shared.origin;
        assert_eq!(client.get(format!("{base}/state")).send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.get(format!("{}state?token=wrong", preview.url())).send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.get(format!("{}state", preview.url())).header("Host", "evil.invalid").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.get(format!("{}state", preview.url())).header("Origin", "https://evil.invalid").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(format!("{}cancel", preview.url())).send()?.status(), StatusCode::NOT_FOUND);
        let response = client.get(format!("{}state", preview.url())).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store, max-age=0");
        assert!(!response.headers().contains_key("access-control-allow-origin"));
        // Reading status while permission is pending must not start IR capture.
        assert!(!preview.shared.content.lock().unwrap().camera_ready);
        let ready = format!("{}ready", preview.url());
        assert_eq!(client.post(&ready).send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(&ready).header("Origin", "https://evil.invalid").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(&ready).header("Origin", &preview.shared.origin).send()?.status(), StatusCode::NO_CONTENT);
        assert!(preview.shared.content.lock().unwrap().camera_ready);
        assert!(preview.ingest(&vec![b'x'; MAX_LINE + 1]).is_err());
        assert!(preview.ingest(br#"{"darkness":101,"threshold":60}"#).is_err());
        assert!(preview.ingest(br#"{"darkness":50,"threshold":-1}"#).is_err());
        preview.ingest(br#"{"darkness":71.6,"threshold":60}"#)?;
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["darkness"], 71.6);
        assert!(preview.ingest(br#"{"darkness":50,"threshold":60,"unexpected":true}"#).is_err());
        Ok(())
    }

    #[test]
    fn cancel_closes_child_stdin_and_erases_frame() -> anyhow::Result<()> {
        let preview = start(false)?;
        preview.ingest(br#"{"darkness":71.6,"threshold":60}"#)?;
        let mut child = std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).spawn()?;
        preview.bind_child_stdin(child.stdin.take().context("missing child stdin")?);
        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        let response = client.post(format!("{}cancel", preview.url())).header("Origin", &preview.shared.origin).send()?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait()? { assert!(status.success()); break; }
            if std::time::Instant::now() >= deadline {
                child.kill()?; child.wait()?;
                anyhow::bail!("cancel did not close enrollment stdin");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(preview.cancelled());
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["status"], "cancelling");
        assert!(state.get("darkness").is_none());
        assert_eq!(client.post(format!("{}ready", preview.url())).header("Origin", &preview.shared.origin).send()?.status(), StatusCode::CONFLICT);
        preview.finish("failed", "Enrollment failed.");
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["status"], "cancelled");
        assert!(state.get("darkness").is_none());
        Ok(())
    }

    #[test]
    fn verifying_erases_frames_and_keeps_server_available() -> anyhow::Result<()> {
        let preview = start(false)?;
        let frame = br#"{"darkness":20,"threshold":60}"#;
        preview.ingest(frame)?;
        preview.verifying();
        // A late recorder frame must not masquerade as the PAM camera.
        preview.ingest(frame)?;
        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["status"], "verifying");
        assert!(state.get("darkness").is_none());
        assert!(!preview.shared.content.lock().unwrap().finished);
        let response = client.post(format!("{}cancel", preview.url()))
            .header("Origin", &preview.shared.origin).send()?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(preview.cancelled());
        Ok(())
    }

    #[test]
    fn final_ack_requires_consumed_result_and_trusted_request() -> anyhow::Result<()> {
        let preview = start(false)?;
        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        let ack = format!("{}ack", preview.url());
        client.get(format!("{}state", preview.url())).send()?.error_for_status()?;
        assert_eq!(client.post(&ack).header("Origin", &preview.shared.origin).send()?.status(), StatusCode::CONFLICT);
        preview.finish("failed", "Face verification timed out.");
        // A request before the final snapshot was fetched cannot acknowledge it.
        assert_eq!(client.post(&ack).header("Origin", &preview.shared.origin).send()?.status(), StatusCode::CONFLICT);
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["status"], "failed");
        assert_eq!(state["reason"], "Face verification timed out.");
        assert!(state.get("darkness").is_none());
        assert_eq!(client.post(&ack).send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(&ack).header("Origin", "https://evil.invalid").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(&ack).header("Origin", &preview.shared.origin)
            .header("Host", "evil.invalid").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(&ack).header("Origin", &preview.shared.origin)
            .header("sec-fetch-site", "cross-site").send()?.status(), StatusCode::NOT_FOUND);
        assert_eq!(client.post(format!("{}/wrong/ack", preview.shared.origin))
            .header("Origin", &preview.shared.origin).send()?.status(), StatusCode::NOT_FOUND);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            // Merely serving the final state, or an untrusted ACK, is not enough.
            assert!(tokio::time::timeout(std::time::Duration::from_millis(20), preview.wait_final_ack()).await.is_err());
        });
        assert_eq!(client.post(&ack).header("Origin", &preview.shared.origin).send()?.status(), StatusCode::NO_CONTENT);
        assert!(runtime.block_on(preview.wait_final_ack()));
        // Neither another finalization nor Drop may replace the acknowledged result.
        preview.finish("complete", "Incorrect replacement.");
        let shared = Arc::clone(&preview.shared);
        drop(preview);
        let content = shared.content.lock().unwrap();
        let retained: serde_json::Value = serde_json::from_slice(&content.snapshot)?;
        assert_eq!(retained, state);
        Ok(())
    }

    #[test]
    fn final_ack_wakes_waiter_and_headless_completion_is_immediate() -> anyhow::Result<()> {
        let preview = start(false)?;
        preview.finish("complete", "Face verification and activation succeeded.");
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            assert!(!tokio::time::timeout(std::time::Duration::from_millis(100), preview.wait_final_ack()).await?);
            let client = reqwest::Client::builder().no_proxy().build()?;
            let state: serde_json::Value = client.get(format!("{}state", preview.url())).send().await?.json().await?;
            assert_eq!(state["status"], "complete");
            let (acknowledged, response) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::join!(
                    preview.wait_final_ack(),
                    client.post(format!("{}ack", preview.url())).header("Origin", &preview.shared.origin).send()
                )
            }).await?;
            assert!(acknowledged);
            assert_eq!(response?.status(), StatusCode::NO_CONTENT);
            Ok::<_, anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn cancellation_wakes_waiter_and_drops_pending_authorization() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct PendingAuthorization(Arc<AtomicBool>);
        impl Drop for PendingAuthorization {
            fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
        }
        let preview = start(false)?;
        preview.verifying();
        let dropped = Arc::new(AtomicBool::new(false));
        let started = AtomicBool::new(false);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let client = reqwest::Client::builder().no_proxy().build()?;
            let verification = async {
                let authorization = async {
                    let _guard = PendingAuthorization(Arc::clone(&dropped));
                    started.store(true, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    biased;
                    _ = preview.wait_cancelled() => {}
                    _ = authorization => panic!("pending authorization completed"),
                }
            };
            let (_, response) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::join!(
                    verification,
                    client.post(format!("{}cancel", preview.url())).header("Origin", &preview.shared.origin).send()
                )
            }).await?;
            assert_eq!(response?.status(), StatusCode::NO_CONTENT);
            assert!(started.load(Ordering::SeqCst));
            assert!(dropped.load(Ordering::SeqCst));
            // A waiter created after the notification must also complete.
            tokio::time::timeout(std::time::Duration::from_millis(100), preview.wait_cancelled()).await?;
            Ok::<_, anyhow::Error>(())
        })?;
        Ok(())
    }
}
