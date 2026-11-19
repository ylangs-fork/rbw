'use strict';
// RGB preview is browser-native getUserMedia, shown in a local <video> only.
// Media never leaves this tab: only state/ready/cancel/ack signals use fetch.
const video = document.querySelector('#camera');
const viewNote = document.querySelector('#view-note');
const viewTag = document.querySelector('#view-tag');
const cameraLabel = document.querySelector('#camera-label');
const issue = document.querySelector('#camera-issue');
const issueTitle = document.querySelector('#issue-title');
const issueDetail = document.querySelector('#issue-detail');
const status = document.querySelector('#status');
const detail = document.querySelector('#detail');
const meter = document.querySelector('#meter');
const cancel = document.querySelector('#cancel');

const POLL_MS = 150;
const CONSTRAINTS = {
  audio: false,
  video: {
    facingMode: 'user',
    width: {ideal: 640},
    height: {ideal: 480},
    frameRate: {ideal: 30, max: 30},
  },
};
// Labels that identify infrared/depth sensors. IR must never be shown as RGB.
const IR_NAME = /(^|[^a-z])(ir|nir)([^a-z]|$)|infra-?red|depth|windows hello|face auth/i;

let ended = false;           // terminal result rendered or preview disconnected
let cancelRequested = false; // user pressed Cancel (or server reported cancelling)
let leaving = false;         // pagehide
let stream = null;
let generation = 0;          // bumped by every stop; invalidates in-flight starts
let camera = 'starting';     // starting | live | error | stopped
let readySent = false;
let lastState = null;

class CameraProblem extends Error {
  constructor(title, message) { super(message); this.title = title; }
}

function stopStream(candidate) {
  if (candidate) for (const track of candidate.getTracks()) track.stop();
}
function stopCamera() {
  generation += 1;
  const current = stream;
  stream = null;
  if (current) {
    for (const track of current.getTracks()) track.removeEventListener('ended', onTrackEnded);
    stopStream(current);
  }
  video.pause();
  video.srcObject = null;
  video.hidden = true;
  viewTag.hidden = true;
  cameraLabel.hidden = true;
  cameraLabel.textContent = '';
}
function shouldStop(token) {
  return token !== generation || ended || cancelRequested || leaving;
}

function showIssue(title, message) {
  issueTitle.textContent = title;
  issueDetail.textContent = message;
  issue.hidden = false;
}
function failCamera(title, message) {
  stopCamera();
  camera = 'error';
  viewNote.textContent = 'RGB preview unavailable';
  viewNote.hidden = false;
  showIssue(title, message);
  render();
  if (readySent && !ended && !cancelRequested && !leaving) {
    cancelRequested = true;
    fetch('cancel', {method: 'POST', credentials: 'omit', cache: 'no-store'})
      .then(response => { if (!response.ok) throw new Error('cancel rejected'); })
      .catch(() => {
        if (!ended && !leaving) showIssue(title, message + ' Cancellation could not be confirmed; check your terminal.');
      });
  }
}
function closeView(message) {
  stopCamera();
  if (camera !== 'error') camera = 'stopped';
  viewNote.textContent = message;
  viewNote.hidden = false;
}

function describe(error) {
  if (error instanceof CameraProblem) return [error.title, error.message];
  switch (error && error.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return ['Camera access is blocked',
        'Allow camera access for this page from the lock or camera icon in the address bar, then cancel and run face setup again. Reloading or closing this page also cancels setup.'];
    case 'NotFoundError':
    case 'OverconstrainedError':
      return ['No RGB camera found',
        'This browser sees no usable color webcam. Connect or enable the built-in webcam, then cancel and run face setup again.'];
    case 'NotReadableError':
    case 'AbortError':
      return ['Camera is unavailable',
        'Another application or browser tab may be using the RGB webcam. Close it, then cancel and run face setup again.'];
    default:
      return ['Camera preview failed',
        'The browser could not start the RGB camera' + (error && error.message ? ' (' + error.message + ')' : '') + '. Cancel and run face setup again.'];
  }
}

function labelOf(candidate) {
  const track = candidate.getVideoTracks()[0];
  return track ? track.label : '';
}
function deviceOf(candidate) {
  const track = candidate.getVideoTracks()[0];
  return track && track.getSettings ? track.getSettings().deviceId : undefined;
}

// Opens one camera. Rejects streams that arrive after cancellation by stopping them.
async function open(token, videoConstraints) {
  const opened = await navigator.mediaDevices.getUserMedia({audio: false, video: videoConstraints});
  if (shouldStop(token)) { stopStream(opened); return null; }
  return opened;
}

async function acquire(token) {
  let opened = await open(token, CONSTRAINTS.video);
  if (!opened || !IR_NAME.test(labelOf(opened))) return opened;
  // The default camera is an IR sensor: release it, then look for a real RGB camera.
  const rejected = deviceOf(opened);
  stopStream(opened);
  const devices = (await navigator.mediaDevices.enumerateDevices())
    .filter(device => device.kind === 'videoinput' && device.deviceId !== rejected && !IR_NAME.test(device.label));
  if (shouldStop(token)) return null;
  let failure = null;
  for (const device of devices) {
    try {
      opened = await open(token, {...CONSTRAINTS.video, deviceId: {exact: device.deviceId}});
    } catch (error) {
      if (shouldStop(token)) return null;
      failure = error;
      continue;
    }
    if (!opened) return null;
    if (!IR_NAME.test(labelOf(opened))) return opened;
    stopStream(opened);
  }
  if (failure) throw failure;
  throw new CameraProblem('No RGB camera found',
    'The only camera this browser offers is an infrared sensor, which is reserved for face recognition. Connect or enable a color webcam, then cancel and run face setup again.');
}

function isPlaying() {
  return !video.paused && !video.ended && video.readyState >= 2 && video.videoWidth > 0;
}
async function onPlaying() {
  if (readySent || !stream || !isPlaying() || shouldStop(generation)) return;
  readySent = true;
  camera = 'live';
  video.hidden = false;
  viewNote.hidden = true;
  viewTag.hidden = false;
  const name = labelOf(stream);
  cameraLabel.textContent = name ? 'Preview camera: ' + name : '';
  cameraLabel.hidden = !name;
  issue.hidden = true;
  render();
  try {
    const response = await fetch('ready', {method: 'POST', credentials: 'omit', cache: 'no-store'});
    if (!response.ok) throw new Error('ready rejected');
  } catch (_) {
    if (!ended && !cancelRequested && !leaving) {
      failCamera('Setup was not notified',
        'The local setup process did not accept the preview-ready signal, so IR capture cannot start. Check your terminal, then cancel and run setup again.');
    }
  }
}
function onTrackEnded() {
  if (ended || cancelRequested || leaving) return;
  failCamera('RGB camera stopped',
    'The webcam was disconnected or taken by another application. Cancel and run face setup again once it is available.');
}

async function startCamera() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    failCamera('Camera preview is not supported',
      'This browser cannot open a camera for this page. Use a current Chrome, Edge or Firefox on this computer with the exact link printed in the terminal, or cancel.');
    return;
  }
  const token = generation;
  let opened;
  try {
    opened = await acquire(token);
  } catch (error) {
    if (!shouldStop(token)) { const [title, message] = describe(error); failCamera(title, message); }
    return;
  }
  if (!opened) return;
  if (shouldStop(token)) { stopStream(opened); return; }
  stream = opened;
  for (const track of opened.getVideoTracks()) track.addEventListener('ended', onTrackEnded);
  video.muted = true;
  video.srcObject = opened;
  try {
    await video.play();
  } catch (error) {
    if (!shouldStop(token)) {
      failCamera('Camera preview could not play',
        'The browser would not start the video' + (error && error.message ? ' (' + error.message + ')' : '') + '. Cancel and run face setup again.');
    }
    return;
  }
  if (!shouldStop(token)) onPlaying();
}

// IR recognition status; never replaces the camera issue banner.
function render() {
  if (ended) return;
  status.dataset.warning = 'false';
  const state = lastState && lastState.status;
  if (cancelRequested || state === 'cancelling') {
    status.textContent = 'Cancelling face setup';
    detail.textContent = 'Waiting for enrollment or verification to stop and changes to be rolled back.';
    meter.textContent = 'IR darkness — · limit —';
  } else if (state === 'verifying') {
    status.textContent = 'Verifying face';
    detail.textContent = 'Look at the camera. The color preview is only for positioning; verification uses the IR camera. Keep this page open while it finishes.';
    meter.textContent = 'IR darkness — · limit —';
  } else if (state === 'active') {
    const dark = lastState.darkness > lastState.threshold;
    status.textContent = dark ? 'Too dark for IR recognition' : 'IR camera active';
    status.dataset.warning = String(dark);
    detail.textContent = dark
      ? 'Face the camera and move closer. This reading comes from the IR camera, not the color preview; enrollment is waiting for a usable IR frame.'
      : 'Keep your face centered in the preview and look at the camera. Recognition uses the IR camera.';
    meter.textContent = Number.isFinite(lastState.darkness) && Number.isFinite(lastState.threshold)
      ? 'IR darkness ' + lastState.darkness.toFixed(1) + '% · limit ' + lastState.threshold.toFixed(1) + '%'
      : 'IR darkness — · limit —';
  } else if (camera === 'error') {
    status.textContent = 'IR recognition has not started';
    status.dataset.warning = 'true';
    detail.textContent = 'Setup needs a playing RGB preview first. Fix the camera issue above, then cancel and run face setup again.';
    meter.textContent = 'IR darkness — · limit —';
  } else if (camera === 'live') {
    status.textContent = 'Starting IR camera';
    detail.textContent = 'The color preview is live. Waiting for the IR camera to start for recognition.';
    meter.textContent = 'IR darkness — · limit —';
  } else {
    status.textContent = 'Waiting for camera preview';
    detail.textContent = 'Allow camera access when your browser asks. IR recognition starts once the preview is playing.';
    meter.textContent = 'IR darkness — · limit —';
  }
}

async function finish(frame) {
  ended = true;
  closeView('Camera closed');
  issue.hidden = true;
  status.dataset.warning = 'false';
  status.textContent = frame.status === 'complete' ? 'Face authorization enabled' :
    frame.status === 'cancelled' ? 'Face setup cancelled' : 'Face setup failed';
  detail.textContent = typeof frame.reason === 'string' ? frame.reason : '';
  meter.textContent = '—';
  cancel.disabled = true;
  // Acknowledge only after the final result has been rendered, never a live state.
  await new Promise(resolve => window.requestAnimationFrame(resolve));
  try { await fetch('ack', {method: 'POST', credentials: 'omit', cache: 'no-store'}); } catch (_) {}
}

async function poll() {
  try {
    const response = await fetch('state', {cache: 'no-store', credentials: 'omit'});
    if (!response.ok) throw new Error('disconnected');
    const frame = await response.json();
    if (ended) return;
    if (['complete', 'failed', 'cancelled'].includes(frame.status)) {
      await finish(frame); return;
    }
    if (frame.status === 'cancelling') {
      cancelRequested = true;
      cancel.disabled = true;
      closeView('Camera closing');
    }
    lastState = frame;
    render();
  } catch (_) {
    if (!ended) {
      ended = true;
      closeView('Camera closed');
      issue.hidden = true;
      status.dataset.warning = 'false';
      status.textContent = 'Preview disconnected';
      detail.textContent = 'Check your terminal for the actual face setup result.';
      meter.textContent = '—';
      cancel.disabled = true;
    }
    return;
  }
  if (!ended) window.setTimeout(poll, POLL_MS);
}

cancel.addEventListener('click', async () => {
  cancel.disabled = true;
  cancelRequested = true;
  closeView('Camera closing');
  render();
  try {
    const response = await fetch('cancel', {method: 'POST', credentials: 'omit', cache: 'no-store'});
    if (!response.ok) throw new Error('cancel failed');
  } catch (_) {
    if (!ended) {
      showIssue('Cancellation could not be confirmed', 'Check your terminal or press Cancel again. The RGB camera is closed.');
      cancelRequested = false;
      cancel.disabled = false;
    }
  }
});
video.addEventListener('playing', onPlaying);
video.addEventListener('loadeddata', onPlaying);
window.addEventListener('pagehide', () => {
  leaving = true;
  stopCamera();
  // Leaving an unfinished setup cancels it so the backend closes IR too.
  if (!ended && !cancelRequested) {
    cancelRequested = true;
    try { fetch('cancel', {method: 'POST', credentials: 'omit', cache: 'no-store', keepalive: true}).catch(() => {}); } catch (_) {}
  }
});

// Poll immediately so cancellation or a final result is seen even while the
// permission prompt is still open; the camera starts concurrently.
render();
poll();
startCamera();
