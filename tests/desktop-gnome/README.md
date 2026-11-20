# Disposable GNOME desktop acceptance environment

This fixture runs **real Ubuntu 24.04 GNOME Shell**, including its native
`org.freedesktop.Notifications` service, on Xvfb/X11 with Mesa software rendering.
There is deliberately **no StatusNotifierWatcher, appindicator extension or tray
host**. The session bus, system bus, home, browser profile and display are private
to the container. It does not access the host desktop, Waybar, extensions, PAM,
cameras, vault or credentials. It is a Shell session under `dbus-run-session`, not
a full systemd/login-manager installation. This exercises Shell launch/search and
notifications; it does not establish login-session, hardware or human-PAM assurance.

No application binary is built here. The parent supplies the actual installed
package and an architecture-matching, precompiled Chrome/Chromium directory. There
is no Ubuntu `chromium-browser` snap dependency. The base is an official Ubuntu
24.04 multi-platform digest; the packaging smoke image's Ubuntu 22.04 digest cannot
provide the requested 24.04 GNOME environment. Distro packages are resolved at
build time, so record the resulting image ID and package manifest with evidence.
No validation has been executed by the author of this fixture.

## Build and install the parent's package

From the repository root:

```sh
docker buildx build --load --progress=plain \
  -t rbwbio-gnome-fixture tests/desktop-gnome
```

Install the parent's real `.deb` into a derived disposable image **before** the
session starts. The package is supplied separately; no production/packaging source
is changed by this fixture. For example, with an otherwise empty directory
`$PACKAGE_DIRECTORY` containing the parent's `rbwbio.deb`:

```sh
docker buildx build --load --progress=plain -t rbwbio-gnome-app \
  -f - "$PACKAGE_DIRECTORY" <<'DOCKERFILE'
# syntax=docker/dockerfile:1.7-labs
FROM rbwbio-gnome-fixture
COPY rbwbio.deb /tmp/rbwbio.deb
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends /tmp/rbwbio.deb \
    && rm /tmp/rbwbio.deb
DOCKERFILE
```

If the parent instead deploys binaries, it must also deploy the *actual* desktop
entry and icons at their intended XDG locations. Do not replace the launcher with
a test URL or fixture script. Verify package installation and policy separately;
this environment does not edit `/etc/pam.d` or provide an authorization mock.

## Start and wait for actual readiness

`$BROWSER_DIRECTORY` must contain the precompiled browser executable `chrome` and
its accompanying libraries/resources, readable by uid 1100. Set
`GNOME_TEST_BROWSER` to another executable path inside that mount if necessary.
Use a unique container name you own:

```sh
container=rbwbio-gnome-acceptance
docker run -d --name "$container" --network none --shm-size=2g \
  --pids-limit=1024 \
  --mount "type=bind,src=$BROWSER_DIRECTORY,dst=/opt/browser,readonly" \
  -e GNOME_TEST_BROWSER=/opt/browser/chrome \
  -e GNOME_TEST_VIRTUAL_CAMERA=1 \
  rbwbio-gnome-app

ready=false
for attempt in $(seq 1 120); do
  if docker exec --user desktop "$container" \
      test -f /home/desktop/.cache/desktop-gnome/ready; then
    ready=true
    break
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
    docker logs "$container"
    exit 1
  fi
  sleep 1
done
[ "$ready" = true ] || { docker logs "$container"; exit 1; }
docker exec --user desktop "$container" /opt/desktop-gnome/desktop.sh status
docker exec --user desktop "$container" /opt/desktop-gnome/desktop.sh \
  exec /opt/desktop-gnome/probe.py --require-app
```

Startup prints `GNOME_DESKTOP_READY` only after checking all of:

- X11 has GNOME Shell as its actual window manager.
- Shell and Notifications D-Bus names belong to the launched `gnome-shell` PID,
  running as uid 1100, not a mock notification daemon.
- `GetServerInformation` and `GetCapabilities` succeed; `actions` is advertised.
- Neither standard StatusNotifierWatcher name has an owner.
- The headed browser's real loopback CDP `/json/version` responds.

The probe reports real capabilities and launcher availability in JSON; it does
not claim application loading, notification clicks, camera success or auth success.
A stale sentinel is removed when a desktop component exits. `status` rechecks the
real services rather than trusting the sentinel alone.

The image entrypoint starts only its container-private system bus as root, then
uses `setpriv` to start Xvfb, GNOME, browser and applications as `desktop` (uid 1100).
`XDG_RUNTIME_DIR=/run/user/1100` is owned by that user with mode 0700. Browser
sandboxing is disabled **only inside this disposable container**, to avoid host
sandbox/user-namespace changes. Never use this browser with a real account or
publish its CDP endpoint. Do not use `--privileged`, host networking, host D-Bus/X11
mounts, a host home/profile mount, or physical camera device mounts.

`--network none` is appropriate for launcher, locked/offline panel and native
notification checks. For a real synthetic device-request roundtrip, the parent
may instead attach this owned container to its disposable server's isolated
Docker network and configure only its synthetic account/server through normal
application commands. This fixture never contacts the TN server or real vault.
Do not interpret the expected offline status with `--network none` as a tray error.

## Screenshots and real Shell input

All commands must use `--user desktop` so they join the saved session environment:

```sh
desktop() {
  docker exec --user desktop "$container" /opt/desktop-gnome/desktop.sh "$@"
}
artifacts=$(mktemp -d)
desktop screenshot /home/desktop/.cache/desktop-gnome/screenshots/shell.png
docker cp "$container":/home/desktop/.cache/desktop-gnome/screenshots/shell.png \
  "$artifacts/shell.png"
```

Screenshots may contain the application's capability URL in the browser address
bar. Keep screenshots, browser profile and session logs private; do not publish
raw URLs or log `/json/list` output. The readiness JSON does not print target URLs.

1. `desktop launcher-search` sends Escape, Super and literal `rbwBio` to the real
   GNOME overview. Capture a screenshot and inspect the actual application result.
2. Click the result at coordinates measured from that screenshot with
   `desktop click X Y`, or use `desktop key Return` once the real result is selected.
   This goes through the installed `.desktop` entry, **not** direct `rbw ui`,
   `gio launch` or a pre-opened capability URL.
3. Capture the resulting browser panel. Use the real browser's controls/CDP to
   inspect rendered status and click a refresh or select a request. Confirm the
   panel loads without an error blocking operations when no tray host exists.
   The backend's real state must report `desktop.tray_available=false`; the tray
   watcher probe alone does not prove the application behaved correctly.
4. Repeat `desktop status` after app startup to confirm no tray host appeared.

A `.desktop` file being installed or a browser process existing is **not** a pass
for the launcher test. Retain before/after screenshots and actual page evidence.
Do not inject DOM, invent notifications, write app state or synthesize approval.

## Actionable notifications

First, the fixture can independently verify the native notification service.
In one terminal run:

```sh
docker exec --user desktop "$container" \
  /opt/desktop-gnome/desktop.sh notify-probe
```

In another terminal, capture the banner, then click its actual **Open fixture**
button using screenshot coordinates. If it is no longer in the banner, use
`desktop notification-center` (Super+M), capture again, expand the actual item if
needed and click its button. Do not assume coordinates. The waiting command prints
`NATIVE_NOTIFICATION_OPEN_ACTION` only if `notify-send` receives the native `open`
action. Dismissal is failure, not a fabricated action. This disposable fixture
notification has no relationship to rbw authorization or the panel.

Then test the **application's** notification separately:

- Have the parent's isolated synthetic request workflow produce an actual pending
  application request. Take a screenshot of the real rbwBio banner/history item.
- Click its Open/default action before the application's notification subscription
  expires (the contract bounds it to 60 seconds). Capture the actual resulting
  request detail in the browser, including the expected request ID/fingerprint.
- Verify that the request remains pending and no authorization/key release occurs
  merely from opening the notification/page. Use the parent's server-side evidence,
  not a fixture success marker. Explicit approval remains a separate UI operation
  and native PAM remains the authority. Do not fake PAM to get a green screenshot.

The native fixture action proves only native GNOME notification interaction. It
is **not** evidence that the application's handler opens the correct deep link.

## Real browser CDP, exposed only on host loopback

The browser listens on **container loopback** `127.0.0.1:9222`; no Docker port is
published. Ordinary Docker `-p` cannot forward to that container-loopback listener.
The optional host-side stdlib Python tunnel bridges each connection through an
owned `docker exec ... socat` process, without making CDP listen on container eth0:

```sh
python3 tests/desktop-gnome/cdp-forward.py "$container" --port 19222
# Wait for GNOME_CDP_TUNNEL_READY, then in another terminal:
curl --fail --silent http://127.0.0.1:19222/json/version
```

Point the parent's real browser driver at `http://127.0.0.1:19222`. For example,
with an available agent-browser installation, `agent-browser --cdp 19222 snapshot -i`
attaches to this already-running browser. List/select the actual target tab before
clicks or screenshots. Do not launch a second browser, change the profile or
navigate an unrelated user's tab. The tunnel forwards HTTP and WebSocket bytes
unchanged, including real UI/CDP input. Ctrl+C closes the tunnel and only its own
exec processes; it does not stop the desktop/browser container.

Virtual camera is opt-in (`GNOME_TEST_VIRTUAL_CAMERA=1`): Chrome's built-in synthetic
video device is enabled, but **permissions are not auto-granted**. Click the real
browser permission prompt. For camera lifecycle proof, select an actual pending
request, observe the actual video element/track, then resolve/deselect/exit through
real controls and inspect the previously observed track's `readyState` through a
retained CDP object handle. Do not store synthetic track state in the page or
inject a replacement camera element. A playing synthetic RGB preview or an ended
track proves only browser UI lifecycle. It does not prove IR recognition, real
camera access, face identity, PAM, or human approval.

## Diagnostics and cleanup

Private files under `/home/desktop/.cache/desktop-gnome/` include:
`probe.json`, `probe-error.log`, `xvfb.log`, `gnome-shell.log`, `browser.log`,
`session.env`, `shell.pid`, `screenshots/` and the temporary browser profile.
Use `docker cp` into a private artifact directory. Inspect errors rather than
substituting a mock service, shell extension, synthetic UI state or host display.

Record environment provenance when the parent executes acceptance:

```sh
docker image inspect rbwbio-gnome-app --format '{{.Id}}'
docker exec --user desktop "$container" dpkg-query -W >"$artifacts/packages.txt"
```

After preserving only the needed private evidence, stop the tunnel with Ctrl+C
and remove **only the named container created above**:

```sh
docker rm -f "$container"
```

No host service/session is stopped and no host configuration is changed.

Primary references: [Ubuntu GNOME Shell options](https://manpages.ubuntu.com/manpages/noble/man1/gnome-shell.1.html),
[freedesktop notification methods/actions](https://specifications.freedesktop.org/notification/latest/protocol.html),
[Chrome remote-debugging profile requirements](https://developer.chrome.com/blog/remote-debugging-port),
[official Ubuntu 24.04 image metadata](https://hub.docker.com/v2/repositories/library/ubuntu/tags/24.04).
