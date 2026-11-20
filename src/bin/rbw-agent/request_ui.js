'use strict';
// rbwBio request inbox. This page only displays what the local backend reports and
// forwards explicit button clicks. It never decides an outcome itself: approval
// authority stays with the native PAM / server flow in rbw-agent.
// The RGB camera preview is browser-local (getUserMedia -> <video>): no audio,
// no recording, no upload, and it carries no approval meaning whatsoever.

const $ = id => document.getElementById(id);
const el = {
  body: document.body,
  identity: $('identity'),
  pillVault: $('pill-vault'), pillRemote: $('pill-remote'), pillLink: $('pill-link'),
  refresh: $('refresh'),
  bannerLink: $('banner-link'), bannerLinkTitle: $('banner-link-title'), bannerLinkText: $('banner-link-text'),
  bannerLocked: $('banner-locked'), unlock: $('unlock'),
  bannerRemote: $('banner-remote'), bannerRemoteTitle: $('banner-remote-title'), bannerRemoteText: $('banner-remote-text'),
  bannerGlobal: $('banner-global'), bannerGlobalText: $('banner-global-text'), bannerGlobalClose: $('banner-global-close'),
  pending: $('pending'), pendingEmpty: $('pending-empty'), pendingCount: $('pending-count'),
  history: $('history'), historyEmpty: $('history-empty'), historyCount: $('history-count'),
  detailIdle: $('detail-idle'), detailIdleText: $('detail-idle-text'),
  detailMissing: $('detail-missing'), missingBack: $('missing-back'), missingTitle: $('missing-title'),
  record: $('record'), back: $('back'),
  recordKind: $('record-kind'), recordTitle: $('record-title'), recordStatus: $('record-status'),
  recordLead: $('record-lead'),
  recordError: $('record-error'), recordErrorText: $('record-error-text'), recordErrorClose: $('record-error-close'),
  fpPanel: $('fp-panel'), fpValue: $('fp-value'),
  recordMeta: $('record-meta'), recordMessage: $('record-message'),
  cameraPanel: $('camera-panel'), video: $('camera'), cameraNote: $('camera-note'), cameraTag: $('camera-tag'),
  cameraLabel: $('camera-label'), cameraIssue: $('camera-issue'),
  cameraIssueTitle: $('camera-issue-title'), cameraIssueText: $('camera-issue-text'), cameraRetry: $('camera-retry'),
  actions: $('actions'), reviewRow: $('review-row'), review: $('review'),
  approve: $('approve'), reject: $('reject'), cancel: $('cancel'), actionHint: $('action-hint'),
  retryRow: $('retry-row'), recordRefresh: $('record-refresh'),
  footTray: $('foot-tray'), footSync: $('foot-sync'),
  announce: $('announce'),
};

const POLL_MS = 1000;
const POLL_HIDDEN_MS = 5000;
const POLL_MAX_BACKOFF_MS = 5000;
const POLL_TIMEOUT_MS = 6000;
const LIVE = new Set(['pending_review', 'authenticating']);

const KIND_LABEL = {local: 'Local', device: 'Remote'};
const STATUS = {
  local: {
    pending_review: ['Awaiting verification', 'warn'],
    authenticating: ['Verifying face', 'info'],
    approved: ['Authorized', 'ok'],
    rejected: ['Rejected', 'idle'],
    failed: ['Verification failed', 'bad'],
    cancelled: ['Cancelled', 'idle'],
    expired: ['Expired', 'idle'],
  },
  device: {
    pending_review: ['Review fingerprint', 'warn'],
    authenticating: ['Verifying and submitting', 'info'],
    approved: ['Approved', 'ok'],
    rejected: ['Rejected', 'idle'],
    failed: ['Failed', 'bad'],
    cancelled: ['Cancelled', 'idle'],
    expired: ['No longer pending', 'idle'],
  },
};
// Camera is opened only while a request is in the stage where a face is looked at:
// local requests from creation, remote requests only after the user approved.
const CAMERA_WHEN = {
  local: new Set(['pending_review', 'authenticating']),
  device: new Set(['authenticating']),
};

// Labels that identify infrared/depth sensors. IR is reserved for recognition and must not be shown here.
const IR_NAME = /(^|[^a-z])(ir|nir)([^a-z]|$)|infra-?red|depth|windows hello|face auth/i;
const CAMERA_VIDEO = {
  facingMode: 'user',
  width: {ideal: 640},
  height: {ideal: 480},
  frameRate: {ideal: 30, max: 30},
};

// ---------------------------------------------------------------- model
let snapshot = null;        // last good /api/state payload (normalised)
let link = {ok: false, status: 'connecting', detail: ''};
let selection = null;       // {kind, id} from the URL fragment
let reviewed = null;        // {kind, id, fingerprint}: user ticked the comparison box
let globalError = '';       // sticky until dismissed; never touched by polling
let recordError = null;     // {key, text}; sticky until dismissed or selection changes
const inflight = {unlock: false, refresh: false, record: null}; // record: {key, action}
let leaving = false;
let focusRecordHeading = false;
let lastAnnounced = '';

class ApiError extends Error {}

// ---------------------------------------------------------------- helpers
function setText(node, text) { if (node.textContent !== text) node.textContent = text; }
function setHidden(node, hidden) { if (node.hidden !== hidden) node.hidden = hidden; }
function keyOf(record) { return record.kind + ':' + record.id; }
function same(a, b) { return !!a && !!b && a.kind === b.kind && a.id.toLowerCase() === b.id.toLowerCase(); }
function present(value) { return typeof value === 'string' && value.trim() !== '' ? value : null; }
function announce(text) { el.announce.textContent = ''; el.announce.textContent = text; }

function statusInfo(record) {
  const table = STATUS[record.kind] || STATUS.local;
  return table[record.status] || [record.status || 'Unknown', 'idle'];
}
function isLive(record) { return LIVE.has(record.status); }

const fullFormat = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});
const clockFormat = new Intl.DateTimeFormat('en-US', {hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false});
const dayFormat = new Intl.DateTimeFormat('en-US', {month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false});
function fullTime(ms) { return Number.isFinite(ms) ? fullFormat.format(new Date(ms)) : '—'; }
function shortTime(ms) {
  if (!Number.isFinite(ms)) return '—';
  const date = new Date(ms);
  return date.toDateString() === new Date().toDateString() ? clockFormat.format(date) : dayFormat.format(date);
}

function parseHash() {
  const match = /^#(local|device)=([0-9A-Za-z-]{1,64})$/.exec(location.hash);
  return match ? {kind: match[1], id: match[2]} : null;
}

function normalise(raw) {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.requests)) throw new Error('bad state');
  const requests = [];
  for (const item of raw.requests) {
    if (!item || typeof item.id !== 'string' || (item.kind !== 'local' && item.kind !== 'device')) continue;
    requests.push({
      id: item.id,
      kind: item.kind,
      operation: present(item.operation),
      status: typeof item.status === 'string' ? item.status : 'failed',
      fingerprint: present(item.fingerprint),
      device_type: present(item.device_type),
      ip_address: present(item.ip_address),
      country_name: present(item.country_name),
      created_at: Number(item.created_at),
      finished_at: item.finished_at == null ? null : Number(item.finished_at),
      message: present(item.message),
    });
  }
  const remote = raw.remote && typeof raw.remote === 'object' ? raw.remote : {};
  return {
    version: present(raw.version),
    profile: present(raw.profile),
    server: present(raw.server),
    locked: raw.locked === true,
    trayAvailable: !!(raw.desktop && raw.desktop.tray_available === true),
    remote: {
      status: typeof remote.status === 'string' ? remote.status : 'offline',
      message: present(remote.message),
      checkedAt: remote.checked_at == null ? null : Number(remote.checked_at),
    },
    requests,
  };
}

function selectedRecord() {
  if (!snapshot || !selection) return null;
  return snapshot.requests.find(record => same(record, selection)) || null;
}

// ---------------------------------------------------------------- HTTP
async function getState() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
  try {
    const response = await fetch('api/state', {credentials: 'omit', cache: 'no-store', signal: controller.signal});
    if (!response.ok) {
      const error = new Error('http');
      error.httpStatus = response.status;
      throw error;
    }
    return normalise(await response.json());
  } finally {
    clearTimeout(timer);
  }
}

// Mutations are sent exactly once. A lost connection is reported as "unconfirmed",
// never retried: the next state poll shows what the backend actually did.
async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
    });
  } catch (_) {
    throw new ApiError('Delivery to the agent could not be confirmed. Nothing was retried automatically. Check the latest status before trying again.');
  }
  let data = null;
  try { data = await response.json(); } catch (_) { /* non-JSON error body */ }
  if (response.ok && data && data.ok === true) return;
  const reason = data && typeof data.error === 'string' && data.error.trim() ? data.error.trim().slice(0, 300) : '';
  throw new ApiError(reason || 'The agent rejected the operation (HTTP ' + response.status + ').');
}

// ---------------------------------------------------------------- polling
let pollTimer = 0;
let polling = false;
let pollAgain = false;
let failures = 0;

function schedulePoll() {
  clearTimeout(pollTimer);
  let delay = document.hidden ? POLL_HIDDEN_MS : POLL_MS;
  if (failures > 0) delay = Math.min(POLL_MAX_BACKOFF_MS, Math.max(delay, POLL_MS * 2 ** Math.min(failures, 3)));
  pollTimer = setTimeout(poll, delay);
}

async function poll() {
  if (polling) { pollAgain = true; return; }
  polling = true;
  clearTimeout(pollTimer);
  try {
    snapshot = await getState();
    failures = 0;
    link = {ok: true, status: 'ok', detail: ''};
  } catch (error) {
    failures += 1;
    const code = error && error.httpStatus;
    if (code === 401 || code === 403 || code === 404) {
      link = {ok: false, status: 'invalid', detail: ''};
    } else if (error && error.name === 'AbortError') {
      link = {ok: false, status: 'timeout', detail: ''};
    } else if (error && error.httpStatus) {
      link = {ok: false, status: 'http', detail: String(error.httpStatus)};
    } else {
      link = {ok: false, status: 'down', detail: ''};
    }
  } finally {
    polling = false;
  }
  render();
  if (pollAgain) { pollAgain = false; poll(); } else schedulePoll();
}

// ---------------------------------------------------------------- camera
const cam = {key: null, status: 'idle', error: null, stream: null, label: ''};
let generation = 0; // bumped by every stop; invalidates in-flight starts and old track listeners

class CameraProblem extends Error {
  constructor(title, message) { super(message); this.title = title; }
}

function stopStream(candidate) {
  if (candidate) for (const track of candidate.getTracks()) track.stop();
}
function stopCamera() {
  generation += 1;
  const current = cam.stream;
  cam.stream = null;
  cam.label = '';
  stopStream(current);
  el.video.pause();
  el.video.srcObject = null;
}
function wantedCameraKey() {
  if (leaving || document.hidden) return null;
  const record = selectedRecord();
  if (!record || !CAMERA_WHEN[record.kind].has(record.status)) return null;
  return keyOf(record);
}
function syncCamera() {
  const want = wantedCameraKey();
  if (want === cam.key) return;
  stopCamera();
  cam.key = want;
  cam.error = null;
  cam.status = want ? 'starting' : 'idle';
  if (want) startCamera();
}
function failCamera(title, message) {
  stopCamera();
  cam.status = 'error';
  cam.error = {title, message};
  renderCamera();
}
function describeCamera(error) {
  if (error instanceof CameraProblem) return [error.title, error.message];
  switch (error && error.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return ['Camera permission denied',
        'Allow camera access using the camera or site-permissions icon in the address bar, then select Retry camera.'];
    case 'NotFoundError':
    case 'OverconstrainedError':
      return ['No RGB camera available', 'The browser could not find an RGB camera. Connect or enable your camera and try again.'];
    case 'NotReadableError':
    case 'AbortError':
      return ['Camera unavailable', 'Another application or tab may be using the camera. Close it and try again.'];
    default:
      return ['Camera preview failed',
        'The browser could not start the RGB camera' + (error && error.message ? ' (' + error.message + ')' : '') + '.'];
  }
}
function labelOf(stream) {
  const track = stream.getVideoTracks()[0];
  return track ? track.label : '';
}
function deviceIdOf(stream) {
  const track = stream.getVideoTracks()[0];
  return track && track.getSettings ? track.getSettings().deviceId : undefined;
}
// A stream that arrives after the page moved on is stopped immediately.
async function openCamera(token, video) {
  const opened = await navigator.mediaDevices.getUserMedia({audio: false, video});
  if (token !== generation) { stopStream(opened); return null; }
  return opened;
}
async function acquireCamera(token) {
  let opened = await openCamera(token, CAMERA_VIDEO);
  if (!opened || !IR_NAME.test(labelOf(opened))) return opened;
  const rejected = deviceIdOf(opened);
  stopStream(opened);
  const devices = (await navigator.mediaDevices.enumerateDevices())
    .filter(device => device.kind === 'videoinput' && device.deviceId !== rejected && !IR_NAME.test(device.label));
  if (token !== generation) return null;
  let failure = null;
  for (const device of devices) {
    try {
      opened = await openCamera(token, {...CAMERA_VIDEO, deviceId: {exact: device.deviceId}});
    } catch (error) {
      if (token !== generation) return null;
      failure = error;
      continue;
    }
    if (!opened) return null;
    if (!IR_NAME.test(labelOf(opened))) return opened;
    stopStream(opened);
  }
  if (failure) throw failure;
  throw new CameraProblem('Only an infrared camera was found',
    'The only available camera is infrared. It is reserved for face recognition and is not displayed here. Preview availability does not affect local verification.');
}
function isPlaying() {
  const video = el.video;
  return !video.paused && !video.ended && video.readyState >= 2 && video.videoWidth > 0;
}
function onPlaying() {
  if (!cam.stream || cam.status === 'live' || !isPlaying()) return;
  cam.status = 'live';
  cam.label = labelOf(cam.stream);
  renderCamera();
}
async function startCamera() {
  const token = generation;
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    failCamera('Camera preview is not supported',
      'Camera access requires a recent Chrome, Chromium or Firefox browser at the local http://127.0.0.1 address. Preview availability does not affect local verification.');
    return;
  }
  let opened;
  try {
    opened = await acquireCamera(token);
  } catch (error) {
    if (token === generation) { const [title, message] = describeCamera(error); failCamera(title, message); }
    return;
  }
  if (!opened) return;
  if (token !== generation) { stopStream(opened); return; }
  cam.stream = opened;
  for (const track of opened.getVideoTracks()) {
    track.addEventListener('ended', () => {
      if (token !== generation) return;
      failCamera('Camera disconnected', 'The camera was disconnected or taken by another application. Preview stopped; this does not change the local verification result.');
    });
  }
  el.video.muted = true;
  el.video.srcObject = opened;
  try {
    await el.video.play();
  } catch (error) {
    if (token === generation) {
      failCamera('Camera preview could not play',
        'The browser did not start video playback' + (error && error.message ? ' (' + error.message + ')' : '') + '.');
    }
    return;
  }
  if (token === generation) onPlaying();
}

function renderCamera() {
  const record = selectedRecord();
  const active = cam.key !== null && record && cam.key === keyOf(record);
  setHidden(el.cameraPanel, !active);
  if (!active) { setHidden(el.video, true); return; }
  const live = cam.status === 'live';
  setHidden(el.video, !live);
  setHidden(el.cameraTag, !live);
  setHidden(el.cameraNote, live);
  if (cam.status === 'error') setText(el.cameraNote, 'RGB preview unavailable');
  else setText(el.cameraNote, 'Requesting camera permission… Select Allow if your browser asks.');
  setText(el.cameraLabel, cam.label ? 'Preview camera: ' + cam.label : '');
  setHidden(el.cameraLabel, !(live && cam.label));
  const failed = cam.status === 'error' && cam.error;
  setHidden(el.cameraIssue, !failed);
  if (failed) {
    setText(el.cameraIssueTitle, cam.error.title);
    setText(el.cameraIssueText, cam.error.message);
  }
}

// ---------------------------------------------------------------- rendering: shell
function renderStatus() {
  const online = link.ok;
  const tone = online ? 'ok' : (link.status === 'connecting' ? 'idle' : 'bad');
  setText(el.pillLink, online ? 'Agent: connected' : link.status === 'connecting' ? 'Agent: connecting' : 'Agent: disconnected');
  el.pillLink.dataset.tone = tone;

  setHidden(el.bannerLink, online || link.status === 'connecting');
  if (!online && link.status !== 'connecting') {
    let title = 'Cannot connect to the rbwBio agent';
    let text = 'The page cannot read the agent status.';
    if (link.status === 'invalid') {
      title = 'This page link is no longer valid';
      text = 'The agent restarted or no longer accepts this address. Run rbw ui again or open a new notification.';
    } else if (link.status === 'timeout') {
      text = 'The agent response timed out.';
    } else if (link.status === 'http') {
      text = 'The agent returned an unexpected status (HTTP ' + link.detail + ').';
    } else {
      text = 'The agent may have stopped. Run rbw ui to start it again.';
    }
    if (snapshot) text += ' The data below is the last successful snapshot and may be stale. Actions are disabled until the connection returns.';
    setText(el.bannerLinkTitle, title);
    setText(el.bannerLinkText, text);
  }

  if (!snapshot) {
    setText(el.identity, 'Connecting to the local agent…');
    setText(el.pillVault, 'Vault: —'); el.pillVault.dataset.tone = 'idle';
    setText(el.pillRemote, 'Device approval: —'); el.pillRemote.dataset.tone = 'idle';
    setHidden(el.bannerLocked, true);
    setHidden(el.bannerRemote, true);
    setText(el.footTray, '');
    setText(el.footSync, '');
    return;
  }

  const parts = [];
  if (snapshot.profile) parts.push('Profile: ' + snapshot.profile);
  if (snapshot.server) parts.push(snapshot.server);
  if (snapshot.version) parts.push('rbw ' + snapshot.version);
  setText(el.identity, parts.join(' · ') || 'rbwBio');

  setText(el.pillVault, snapshot.locked ? 'Vault: locked' : 'Vault: unlocked');
  el.pillVault.dataset.tone = snapshot.locked ? 'warn' : 'ok';
  setHidden(el.bannerLocked, !snapshot.locked);
  el.unlock.disabled = inflight.unlock || !online;
  setText(el.unlock, inflight.unlock ? 'Waiting for pinentry…' : 'Unlock…');

  const remote = snapshot.remote;
  const remoteMap = {
    ready: ['Device approval: ready', 'ok'],
    offline: ['Device approval: offline', 'bad'],
    not_logged_in: ['Device approval: not logged in', 'warn'],
  };
  const [remoteText, remoteTone] = remoteMap[remote.status] || ['Device approval: ' + remote.status, 'idle'];
  setText(el.pillRemote, remoteText);
  el.pillRemote.dataset.tone = remoteTone;
  const remoteProblem = remote.status !== 'ready';
  setHidden(el.bannerRemote, !remoteProblem);
  if (remoteProblem) {
    el.bannerRemote.dataset.tone = remote.status === 'offline' ? 'bad' : 'warn';
    setText(el.bannerRemoteTitle, remote.status === 'not_logged_in' ? 'Not logged in to Bitwarden' : 'Cannot check device requests right now');
    setText(el.bannerRemoteText,
      (remote.message || (remote.status === 'not_logged_in'
        ? 'Run rbw login in a terminal first.'
        : 'The agent cannot reach the Bitwarden server.')) + ' Local authorization is unaffected.');
  }

  setText(el.footTray, snapshot.trayAvailable
    ? 'System tray icon registered.'
    : 'No system tray detected. Open this page from the application menu (rbwBio) or a notification.');
  setText(el.footSync, Number.isFinite(remote.checkedAt) && remote.checkedAt
    ? 'Device requests last checked at ' + fullTime(remote.checkedAt) : 'Device requests have not been checked yet');

  el.refresh.disabled = inflight.refresh || !online;
  el.recordRefresh.disabled = inflight.refresh || !online;
  setText(el.recordRefresh, inflight.refresh ? 'Rechecking…' : 'Recheck requests');
  setText(el.refresh, inflight.refresh ? 'Refreshing…' : 'Refresh');

  setHidden(el.bannerGlobal, !globalError);
  setText(el.bannerGlobalText, globalError);
}

// ---------------------------------------------------------------- rendering: lists
let listSignature = '';

function rowTitle(record) {
  return record.kind === 'local'
    ? (record.operation || 'Local authorization')
    : (record.device_type || 'Unknown device');
}
function rowSub(record) {
  if (record.kind === 'local') return 'Local authorization';
  const place = [record.ip_address, record.country_name].filter(Boolean).join(' · ');
  return place || 'Device approval';
}

function buildRow(record, selected) {
  const [label, tone] = statusInfo(record);
  const li = document.createElement('li');
  const link = document.createElement('a');
  link.className = 'row-link';
  link.href = '#' + record.kind + '=' + encodeURIComponent(record.id);
  link.dataset.key = keyOf(record);
  if (selected) link.setAttribute('aria-current', 'true');

  const main = document.createElement('div');
  main.className = 'row-main';
  const chip = document.createElement('span');
  chip.className = 'chip';
  chip.dataset.kind = record.kind;
  chip.textContent = KIND_LABEL[record.kind];
  const title = document.createElement('span');
  title.className = 'row-title';
  title.textContent = rowTitle(record);
  main.append(chip, title);

  const sub = document.createElement('div');
  sub.className = 'row-sub';
  sub.textContent = rowSub(record);

  const side = document.createElement('div');
  side.className = 'row-side';
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.dataset.tone = tone;
  badge.textContent = label;
  const time = document.createElement('span');
  time.className = 'row-time';
  time.textContent = shortTime(record.finished_at && !isLive(record) ? record.finished_at : record.created_at);
  side.append(badge, time);

  link.append(main, sub, side);
  li.append(link);
  return li;
}

function renderLists() {
  const all = snapshot ? snapshot.requests : [];
  const pending = all.filter(isLive).sort((a, b) => b.created_at - a.created_at);
  const history = all.filter(record => !isLive(record))
    .sort((a, b) => (b.finished_at || b.created_at) - (a.finished_at || a.created_at));

  setText(el.pendingCount, String(pending.length));
  setText(el.historyCount, String(history.length));
  const loaded = snapshot !== null;
  setHidden(el.pendingEmpty, pending.length > 0);
  setText(el.pendingEmpty, !loaded
    ? 'Connecting to the agent…'
    : 'No pending requests. Requests from local applications and remote devices appear here and trigger a desktop notification.');
  setHidden(el.historyEmpty, history.length > 0 || !loaded);
  document.title = (pending.length ? '(' + pending.length + ') ' : '') + 'rbwBio · Requests';

  const signature = JSON.stringify([
    selection, pending.map(r => [r.kind, r.id, r.status, rowTitle(r), rowSub(r), r.created_at, r.finished_at]),
    history.map(r => [r.kind, r.id, r.status, rowTitle(r), rowSub(r), r.created_at, r.finished_at]),
  ]);
  if (signature === listSignature) return;
  listSignature = signature;

  const active = document.activeElement;
  const focusKey = active && active.classList && active.classList.contains('row-link') ? active.dataset.key : null;
  el.pending.replaceChildren(...pending.map(record => buildRow(record, same(record, selection))));
  el.history.replaceChildren(...history.map(record => buildRow(record, same(record, selection))));
  if (focusKey) {
    for (const link of document.querySelectorAll('.row-link')) {
      if (link.dataset.key === focusKey) { link.focus({preventScroll: true}); break; }
    }
  }
}

// ---------------------------------------------------------------- rendering: detail
let metaSignature = '';
let fpSignature = '';

function leadFor(record) {
  const s = record.status;
  if (record.kind === 'local') {
    if (s === 'pending_review' || s === 'authenticating') {
      return 'A local application is requesting vault access. Local PAM verifies your face using the infrared camera; this is not a remote device approval. Authenticate only if you initiated this operation. This page cannot approve it.';
    }
    if (s === 'approved') {
      return 'Local face verification passed and access was authorized. This does not mean the whole command succeeded: entry lookup, for example, may still fail. Check the terminal output.';
    }
    if (s === 'rejected') return 'This local authorization was rejected.';
    if (s === 'cancelled') return 'This local authorization was cancelled.';
    if (s === 'expired') return 'This local authorization expired without approval.';
    return 'This local authorization did not pass.';
  }
  if (s === 'pending_review') {
    return 'Another device is requesting access to your Bitwarden account. Compare the fingerprint below and explicitly select Approve before local face verification and submission of the encrypted key to the server. Opening this page or selecting a request never approves it.';
  }
  if (s === 'authenticating') {
    return 'You confirmed approval. Local face verification and server submission are in progress. Approval completes only when the server accepts it; face verification alone is not completion.';
  }
  if (s === 'approved') return 'The server accepted this approval. The requesting device can now finish signing in.';
  if (s === 'rejected') return 'This device login request was rejected.';
  if (s === 'cancelled') return 'Approval was cancelled locally. An approval already accepted by the server cannot be revoked here. Refresh to confirm its status.';
  if (s === 'expired') return 'This request is no longer pending or was handled by another device. Check the requesting device for the result.';
  return 'Approval completion could not be confirmed. The server may have processed it; refresh to check its status.';
}

function metaRows(record) {
  const none = 'Not provided';
  if (record.kind === 'local') {
    return [
      ['Request type', 'Local authorization'],
      ['Operation', record.operation || none, true],
      ['Request ID', record.id, true],
      ['Started', fullTime(record.created_at)],
      ['Finished', record.finished_at ? fullTime(record.finished_at) : (isLive(record) ? 'In progress' : none)],
    ];
  }
  return [
    ['Request type', 'Device approval'],
    ['Device type', record.device_type || none],
    ['IP address', record.ip_address || none, true],
    ['Country / region', record.country_name || none],
    ['Requested', fullTime(record.created_at)],
    ['Request ID', record.id, true],
    ['Finished', record.finished_at ? fullTime(record.finished_at) : (isLive(record) ? 'In progress' : none)],
  ];
}

function fingerprintWords(fingerprint) {
  const words = fingerprint ? fingerprint.split('-') : [];
  return words.length === 5 && words.every(word => /^[A-Za-z]+$/.test(word)) ? words : null;
}

function canApprove(record) {
  return !!record && record.kind === 'device' && record.status === 'pending_review'
    && link.ok && snapshot && !snapshot.locked && !inflight.record
    && !!fingerprintWords(record.fingerprint)
    && !!reviewed && reviewed.kind === record.kind && reviewed.id === record.id
    && reviewed.fingerprint === record.fingerprint;
}

function renderRecord() {
  const record = selectedRecord();
  const waiting = selection !== null && snapshot === null;
  const missing = selection !== null && snapshot !== null && !record;
  setHidden(el.detailIdle, selection !== null);
  setHidden(el.detailMissing, !missing);
  setHidden(el.record, !record);
  el.body.dataset.view = selection ? 'detail' : 'list';
  if (waiting) {
    setHidden(el.detailIdle, false);
    setText(el.detailIdleText, 'Loading this request…');
  } else {
    setText(el.detailIdleText, 'Select a request from the list to see its details. Viewing or selecting a request never approves it.');
  }
  if (!record) {
    reviewed = null;
    if (missing && focusRecordHeading) { focusRecordHeading = false; el.missingTitle.focus(); }
    return;
  }

  // The review tick belongs to exactly one request, one fingerprint, while pending.
  if (reviewed && !(reviewed.kind === record.kind && reviewed.id === record.id
      && reviewed.fingerprint === record.fingerprint && record.status === 'pending_review')) {
    reviewed = null;
  }

  const [statusLabel, tone] = statusInfo(record);
  el.record.dataset.kind = record.kind;
  setText(el.recordKind, record.kind === 'local' ? 'Local authorization · LOCAL' : 'Device approval · REMOTE DEVICE');
  setText(el.recordTitle, rowTitle(record));
  setText(el.recordStatus, statusLabel);
  el.recordStatus.dataset.tone = tone;
  setText(el.recordLead, leadFor(record));

  const statusKey = keyOf(record) + '|' + record.status;
  if (lastAnnounced !== statusKey) {
    if (lastAnnounced.startsWith(keyOf(record) + '|')) announce(rowTitle(record) + '：' + statusLabel);
    lastAnnounced = statusKey;
  }

  const rowsSignature = JSON.stringify(metaRows(record));
  if (rowsSignature !== metaSignature) {
    metaSignature = rowsSignature;
    const nodes = [];
    for (const [name, value, mono] of metaRows(record)) {
      const dt = document.createElement('dt');
      dt.textContent = name;
      const dd = document.createElement('dd');
      dd.textContent = value;
      if (mono) dd.className = 'mono';
      nodes.push(dt, dd);
    }
    el.recordMeta.replaceChildren(...nodes);
  }

  // Backend explanation for the outcome, displayed verbatim as text.
  setHidden(el.recordMessage, !record.message);
  setText(el.recordMessage, record.message ? 'Agent message: ' + record.message : '');

  // Sticky per-record action error (not cleared by polling).
  const shownError = recordError && recordError.key === keyOf(record) ? recordError.text : '';
  setHidden(el.recordError, !shownError);
  setText(el.recordErrorText, shownError);

  renderFingerprint(record);
  // Failed/cancelled/expired attempts can be re-read from the backend. This only
  // lists requests again; it never approves or starts face verification.
  setHidden(el.retryRow, isLive(record) || record.status === 'approved' || record.status === 'rejected');
  renderActions(record);
  renderCamera();

  if (focusRecordHeading) { focusRecordHeading = false; el.recordTitle.focus(); }
}

function renderFingerprint(record) {
  const show = record.kind === 'device';
  setHidden(el.fpPanel, !show);
  if (!show) return;
  const words = fingerprintWords(record.fingerprint);
  const signature = record.fingerprint || '';
  if (signature === fpSignature && el.fpValue.childNodes.length) return;
  fpSignature = signature;
  if (!record.fingerprint) {
    el.fpValue.textContent = 'The agent did not provide a fingerprint. This request cannot be approved.';
    el.fpValue.removeAttribute('aria-label');
    return;
  }
  if (!words) {
    el.fpValue.textContent = record.fingerprint;
    el.fpValue.setAttribute('aria-label', 'Invalid fingerprint format: ' + record.fingerprint);
    return;
  }
  el.fpValue.replaceChildren(...words.map(word => {
    const span = document.createElement('span');
    span.className = 'word';
    span.textContent = word;
    return span;
  }));
  el.fpValue.setAttribute('aria-label', 'Fingerprint: ' + words.join(', '));
}

function renderActions(record) {
  const mine = inflight.record && inflight.record.key === keyOf(record) ? inflight.record.action : null;
  const busy = inflight.record !== null;
  const device = record.kind === 'device';
  const pendingDevice = device && record.status === 'pending_review';
  const cancellable = (record.kind === 'local' && isLive(record)) || (device && record.status === 'authenticating');
  const showActions = pendingDevice || cancellable;
  setHidden(el.actions, !showActions);
  setHidden(el.reviewRow, !pendingDevice);
  setHidden(el.approve, !pendingDevice);
  setHidden(el.reject, !pendingDevice);
  setHidden(el.cancel, !cancellable);
  if (!showActions) return;

  const valid = pendingDevice && !!fingerprintWords(record.fingerprint);
  el.review.disabled = !valid || busy || !link.ok;
  el.review.checked = !!reviewed;
  el.approve.disabled = !canApprove(record);
  el.reject.disabled = !pendingDevice || busy || !link.ok;
  el.cancel.disabled = !cancellable || busy || !link.ok;
  setText(el.approve, mine === 'approve' ? 'Approving…' : 'Approve and verify face');
  setText(el.reject, mine === 'reject' ? 'Rejecting…' : 'Reject');
  setText(el.cancel, mine === 'cancel' ? 'Cancelling…' : 'Cancel request');

  let hint = '';
  if (!link.ok) hint = 'The agent connection was lost. Actions are paused.';
  else if (mine) hint = 'Waiting for the agent to finish. Do not submit the action again.';
  else if (pendingDevice) {
    if (!valid) hint = 'The fingerprint is missing or invalid. Approval is disabled; you can still reject this request.';
    else if (snapshot.locked) hint = 'The vault is locked. Select Unlock above before approving. Rejection does not require unlocking.';
    else if (!reviewed) hint = 'Confirm the fingerprint comparison to enable approval. Rejection does not require face verification.';
    else hint = 'Local face verification starts only after you select Approve. Approval completes after verification passes and the server accepts it.';
  } else if (record.kind === 'local') {
    hint = 'Cancelling stops this local authorization and returns failure to the requesting application. This page cannot approve it.';
  } else {
    hint = 'Cancelling stops local waiting. An approval already accepted by the server cannot be revoked here; refresh to check its status.';
  }
  setText(el.actionHint, hint);
}

function render() {
  renderStatus();
  renderLists();
  renderRecord();
  syncCamera();
  renderCamera();
}

// ---------------------------------------------------------------- actions
function recordPath(record, action) {
  return 'api/requests/' + record.kind + '/' + encodeURIComponent(record.id) + '/' + action;
}

async function recordAction(record, action, body) {
  if (inflight.record || !link.ok) return;
  const key = keyOf(record);
  inflight.record = {key, action};
  if (recordError && recordError.key === key) recordError = null;
  render();
  try {
    await post(recordPath(record, action), body);
  } catch (error) {
    recordError = {key, text: error instanceof ApiError ? error.message : 'The operation failed.'};
  } finally {
    inflight.record = null;
  }
  render();
  poll();
}

async function globalAction(name, path) {
  if (inflight[name] || !link.ok) return;
  inflight[name] = true;
  globalError = '';
  render();
  try {
    await post(path, {});
  } catch (error) {
    globalError = error instanceof ApiError ? error.message : 'The operation failed.';
  } finally {
    inflight[name] = false;
  }
  render();
  poll();
}

el.approve.addEventListener('click', () => {
  const record = selectedRecord();
  // Approval requires: pending remote record, fingerprint the user ticked == fingerprint now shown.
  if (!canApprove(record)) return;
  const fingerprint = reviewed.fingerprint;
  reviewed = null; // every attempt needs a fresh comparison
  recordAction(record, 'approve', {fingerprint});
});
el.reject.addEventListener('click', () => {
  const record = selectedRecord();
  if (record && record.kind === 'device' && record.status === 'pending_review') recordAction(record, 'reject', {});
});
el.cancel.addEventListener('click', () => {
  const record = selectedRecord();
  if (record && isLive(record)) recordAction(record, 'cancel', {});
});
el.review.addEventListener('change', () => {
  const record = selectedRecord();
  reviewed = el.review.checked && record && record.kind === 'device' && record.status === 'pending_review' && record.fingerprint
    ? {kind: record.kind, id: record.id, fingerprint: record.fingerprint}
    : null;
  if (record) renderActions(record);
});
el.unlock.addEventListener('click', () => globalAction('unlock', 'api/unlock'));
el.refresh.addEventListener('click', () => globalAction('refresh', 'api/refresh'));
el.recordRefresh.addEventListener('click', () => globalAction('refresh', 'api/refresh'));
el.bannerGlobalClose.addEventListener('click', () => { globalError = ''; render(); });
el.recordErrorClose.addEventListener('click', () => { recordError = null; render(); });
el.cameraRetry.addEventListener('click', () => {
  stopCamera();
  cam.key = null;
  syncCamera();
  renderCamera();
});

function showList() {
  history.pushState(null, '', location.pathname + location.search);
  route(false);
}
el.back.addEventListener('click', showList);
el.missingBack.addEventListener('click', showList);

// ---------------------------------------------------------------- routing / lifecycle
function route(userNavigated) {
  const next = parseHash();
  if (!same(next, selection)) {
    reviewed = null;
    recordError = null;
    focusRecordHeading = userNavigated && next !== null;
  }
  selection = next;
  render();
}

window.addEventListener('hashchange', () => route(true));
document.addEventListener('visibilitychange', () => {
  syncCamera();
  renderCamera();
  if (!document.hidden) poll();
});
window.addEventListener('pagehide', () => {
  leaving = true;
  stopCamera();
  cam.key = null;
  cam.status = 'idle';
});
window.addEventListener('pageshow', event => {
  if (!event.persisted) return;
  leaving = false;
  render();
  poll();
});
el.video.addEventListener('playing', onPlaying);
el.video.addEventListener('loadeddata', onPlaying);

route(false);
poll();
