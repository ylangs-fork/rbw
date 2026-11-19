//! Ephemeral, ordinary-user-only enrollment display. Never opens the camera.

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

pub(super) const MAX_LINE: usize = 512 * 1024;
const MAX_JPEG: usize = 200 * 1024;
pub(super) const PREFIX: &[u8] = b"RBWBIO_PREVIEW ";
const HTML: &str = include_str!("enrollment_preview.html");
const SCRIPT: &str = r#"'use strict';
const image = document.querySelector('#camera');
const status = document.querySelector('#status');
const detail = document.querySelector('#detail');
const meter = document.querySelector('#meter');
const cancel = document.querySelector('#cancel');
const placeholder = document.querySelector('.view p');
let ended = false;
function finish(message) {
  ended = true; image.removeAttribute('src'); image.hidden = true;
  status.textContent = message; detail.textContent = 'Return to your terminal to continue.';
  placeholder.textContent = 'Camera closed';
  meter.textContent = '—'; cancel.disabled = true;
}
async function poll() {
  try {
    const response = await fetch('state', {cache: 'no-store', credentials: 'omit'});
    if (!response.ok) throw new Error('disconnected');
    const frame = await response.json();
    if (ended) return;
    if (frame.status !== 'active' && frame.status !== 'waiting') {
      finish(frame.status === 'cancelled' ? 'Enrollment cancelled' : 'Preview finished'); return;
    }
    if (frame.jpeg) {
      image.src = 'data:image/jpeg;base64,' + frame.jpeg; image.hidden = false;
      const dark = frame.darkness > frame.threshold;
      status.textContent = dark ? 'Too dark' : 'Camera active';
      status.dataset.warning = String(dark);
      detail.textContent = dark ? 'Face the IR camera and move closer. Enrollment is waiting for a usable frame.' : 'Keep your face centered and look into the IR camera.';
      meter.textContent = frame.darkness.toFixed(1) + '% dark · limit ' + frame.threshold.toFixed(1) + '%';
    }
  } catch (_) { finish('Preview disconnected'); return; }
  if (!ended) window.setTimeout(poll, 100);
}
cancel.addEventListener('click', async () => {
  cancel.disabled = true;
  try {
    const response = await fetch('cancel', {method: 'POST', credentials: 'omit', cache: 'no-store'});
    if (!response.ok) throw new Error('cancel failed');
    finish('Enrollment cancelled');
  } catch (_) { finish('Preview disconnected'); }
});
window.addEventListener('pagehide', () => { image.removeAttribute('src'); });
poll();
"#;
const STYLE: &str = r#"
:root{color-scheme:dark;font:16px/1.5 system-ui,sans-serif;background:#141516;color:#e5e7eb}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}
main{width:min(100%,780px)}header{display:flex;justify-content:space-between;align-items:center;gap:16px}
h1{font-size:1.55rem;font-weight:600;margin:0}header span,.muted{color:#a2a6ad;font-size:.9rem}
.view{margin:24px 0;background:#0a0b0c;border:1px solid #34363b;border-radius:16px;aspect-ratio:4/3;display:grid;place-items:center;overflow:hidden;position:relative}
.view p{color:#737780;position:absolute}.view img{width:100%;height:100%;object-fit:contain;position:relative}
.panel{border:1px solid #34363b;border-radius:12px;background:#1c1e21;padding:20px}
h2{font-size:1.1rem;margin:0 0 6px}h2[data-warning=true]{color:#f3c783}p{margin:6px 0}
footer{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-top:20px}
button{font:inherit;border:1px solid #555b63;background:#292d32;color:#eee;border-radius:8px;padding:9px 22px;cursor:pointer}
button:hover{background:#363c43}button:focus-visible{outline:2px solid #cbd5e1;outline-offset:3px}button:disabled{opacity:.45;cursor:default}
@media(max-width:480px){body{padding:16px}header,footer{align-items:flex-start;flex-direction:column}.view{margin:18px 0}.panel{padding:16px}}
"#;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    jpeg: String,
    darkness: f64,
    threshold: f64,
}

struct Content {
    snapshot: Bytes,
    stdin: Option<ChildStdin>,
    cancelled: bool,
    finished: bool,
    page_ready: bool,
}

struct Shared {
    token_path: String,
    authority: String,
    origin: String,
    content: Mutex<Content>,
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
        }),
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
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                let ready = preview.shared.content.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner).page_ready;
                if ready { break; }
                ensure!(std::time::Instant::now() < deadline,
                    "the enrollment preview did not connect within 15 seconds; check your default browser and try again (no camera enrollment was started)");
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

    pub(super) fn close_stdin(&self) {
        drop(self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner).stdin.take());
    }

    pub(super) fn ingest(&self, json: &[u8]) -> anyhow::Result<()> {
        ensure!(json.len() <= MAX_LINE - PREFIX.len(), "enrollment preview frame line is too large");
        let frame: Frame = serde_json::from_slice(json).context("invalid enrollment preview frame")?;
        ensure!(frame.darkness.is_finite() && (0.0..=100.0).contains(&frame.darkness)
            && frame.threshold.is_finite() && (0.0..=100.0).contains(&frame.threshold),
            "invalid enrollment preview darkness or threshold");
        ensure!(frame.jpeg.len() <= MAX_JPEG.div_ceil(3) * 4, "enrollment preview JPEG is too large");
        let jpeg = base64::engine::general_purpose::STANDARD.decode(&frame.jpeg)
            .context("invalid enrollment preview JPEG encoding")?;
        ensure!(jpeg.len() <= MAX_JPEG && jpeg.starts_with(&[0xff, 0xd8]) && jpeg.ends_with(&[0xff, 0xd9]),
            "invalid enrollment preview JPEG");
        #[derive(serde::Serialize)]
        struct Snapshot<'a> { status: &'static str, #[serde(flatten)] frame: &'a Frame }
        let snapshot = Bytes::from(serde_json::to_vec(&Snapshot { status: "active", frame: &frame })?);
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !content.cancelled && !content.finished { content.snapshot = snapshot; }
        Ok(())
    }

    pub(super) fn finish(&self, status: &str) -> bool {
        let mut content = self.shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        content.snapshot = Bytes::from_static(match if content.cancelled { "cancelled" } else { status } {
            "complete" => b"{\"status\":\"complete\"}",
            "cancelled" => b"{\"status\":\"cancelled\"}",
            _ => b"{\"status\":\"failed\"}",
        });
        content.finished = true;
        drop(content.stdin.take());
        content.cancelled
    }
}

impl Drop for Preview {
    fn drop(&mut self) {
        self.finish("failed");
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
                content.snapshot.clone()
            };
            response(StatusCode::OK, "application/json", snapshot)
        }
        (Method::POST, "cancel") if origin == Some(shared.origin.as_str()) => {
            let mut content = shared.content.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !content.finished {
                content.cancelled = true;
                content.snapshot = Bytes::from_static(b"{\"status\":\"cancelled\"}");
                drop(content.stdin.take());
            }
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
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().expect("static CSP"));
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
        protocol.feed(b"VIEW {\"jpeg\":\"/9j/2Q==\",\"darkness\":71.6,\"threshold\":60}\n/dev/video0\n", &preview)?;
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
        assert!(preview.ingest(&vec![b'x'; MAX_LINE + 1]).is_err());
        assert!(preview.ingest(br#"{"jpeg":"/9j/2Q==","darkness":101,"threshold":60}"#).is_err());
        assert!(preview.ingest(br#"{"jpeg":"eA==","darkness":50,"threshold":60}"#).is_err());
        preview.ingest(br#"{"jpeg":"/9j/2Q==","darkness":71.6,"threshold":60}"#)?;
        let state: serde_json::Value = client.get(format!("{}state", preview.url())).send()?.json()?;
        assert_eq!(state["darkness"], 71.6);
        assert!(preview.ingest(&serde_json::to_vec(&Frame { jpeg: base64::engine::general_purpose::STANDARD.encode(vec![0_u8; MAX_JPEG + 1]), darkness: 1.0, threshold: 60.0 })?).is_err());
        Ok(())
    }

    #[test]
    fn cancel_closes_child_stdin_and_erases_frame() -> anyhow::Result<()> {
        let preview = start(false)?;
        preview.ingest(br#"{"jpeg":"/9j/2Q==","darkness":71.6,"threshold":60}"#)?;
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
        assert_eq!(state["status"], "cancelled");
        assert!(state.get("jpeg").is_none());
        Ok(())
    }
}
