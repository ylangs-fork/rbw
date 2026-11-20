# Real device-approval protocol acceptance

This is an executable **synthetic-account integration harness**, not a biometric
or real-browser success claim. It runs the production `rbw`, `rbw-agent`, local
HTTP UI backend, native PAM client/helper and encrypted Vaultwarden protocol.
Only the human verdict, notification daemon and browser-launch receiver are
explicit, disposable test fixtures. Nothing seeds an rbw database, fabricates
server responses, or changes production authorization.

## Build and run

From the repository root, with Python 3.8+, Docker and BuildKit available:

```sh
DOCKER_BUILDKIT=1 docker build --progress=plain \
  --target runtime -f tests/device-approval/Dockerfile \
  -t rbw-device-approval:local .
python3 tests/device-approval/run.py
```

Build **after** the final production-source changes. The Dockerfile copies the
actual current `Cargo.toml`, `Cargo.lock`, `src/` and desktop assets, runs
`cargo build --locked --release --no-default-features --bins`, and installs those
binaries into the runtime image. It does not run any tests during the build.
Rust 1.92.0/bookworm matches the existing native smoke builder convention.
BuildKit caches `/usr/local/cargo/registry`, `/usr/local/cargo/git` and
`/src/target`, plus apt downloads/lists; rebuilding after edits reuses these
caches instead of compiling another host target or modifying host tools.
The runtime has Python cryptography/D-Bus/GLib, native PAM, `gdbus` and
`notify-send` installed by apt; no host Python packages are needed.

The runner creates a uniquely named Docker network and an ephemeral
`vaultwarden/server:1.35.0` container. This is a **compatible pinned upstream
release**, not a claim that it is the TN server's reported
`Vaultwarden2026.6.0 (git46ae59ea)`. The inspected upstream account/auth-request
contracts are linked below. An explicit alternative version/digest can be used:

```sh
python3 tests/device-approval/run.py --server-image vaultwarden/server:1.35.0
```

Registration uses the server's normal defaults. No registration override, admin
token, email-verification override, database injection or server patch is used.
The server's data directory is its own tmpfs. No ports are published, no Docker
socket/home/config/PAM/device is mounted, and no privileged container is needed.
Only a fresh private artifact directory is bind-mounted for cleanup recovery.
Images must already be available or pullable; Docker setup commands have finite
120-second deadlines. The complete attached acceptance run has a 420-second
deadline, with a separate bounded graceful-cleanup window.

## Deliberate external-server mode

**Not executed by this assignment.** The parent can explicitly authorize one
new disposable synthetic account on TN with:

```sh
python3 tests/device-approval/run.py --server https://vault-tnl.csylang.uk
```

`--server` never starts/reconfigures a Vaultwarden server. HTTPS is required
except for explicitly supplied loopback URLs (which refer to the runner's own
network namespace). Server DNS/TLS must be reachable from Docker. The account
must be permitted to register and use normal password login under the server's
existing policy. A server that requires verification before login fails closed;
the harness never weakens that policy or uses an existing account. There are no
email/password/token flags and no account-reuse mode. The only possible account
email is `rbwbio-device-<fresh UUID>@example.invalid`.

## Assertions performed

1. Generate a real PBKDF2-SHA256 identity (600,000 iterations), random 64-byte
   User Key, RSA account key pair, Bitwarden type-2 AES-CBC/HMAC encrypted account
   keys, and an encrypted synthetic login item. Register via the ordinary API.
2. Start two independent non-root rbw profiles, each with its own HOME, config,
   cache, device identifier, runtime/socket, foreground agent, session bus and
   actionable freedesktop notification fixture. Log both into that synthetic
   account using the actual CLI and native pinentry protocol exactly once.
   Pinentry permits the generated password only for initial login, then denies.
3. Lock the requester, prove ordinary secret retrieval fails, and run actual
   `rbw unlock --device`. Parse its safe request UUID/five-word fingerprint and
   discover the same request by **GET `api/state`**, using the approver's normal
   background discovery (not a synthetic inbox or injected server state).
4. Fetch the actual page/JS/CSS, list requests with the actual CLI, emit the
   standard notification `ActionInvoked(..., "open")` signal over the real
   session bus, and confirm the production handler delivers the exact request
   deep link to its xdg-open receiver. Repeatedly prove the requester remains
   locked/waiting, PAM has not run, and the authenticated server request is
   byte-for-field unchanged with no response date, approval or encrypted key.
   Opening is an HTTP page fetch here, **not** a claim of rendered browser or
   camera success; real GNOME/browser acceptance is the parent's separate slice.
5. Submit a syntactically valid but incorrect five-word fingerprint; demand a
   4xx response, unchanged pending review/server state and no PAM. Explicitly
   reject and require the requester to exit nonzero and still fail decryption.
   Rejecting must not invoke PAM.
6. Start a second actual request, compare its fresh fingerprint, and reject a
   stale fingerprint from the first request with the same no-side-effect checks.
7. POST approval with the **exact** second fingerprint. The native test-only PAM
   module records entry and waits for root's control file. While it waits, prove
   the requester is still locked and the server still has no approval/key. Only
   then release a native PAM success. Require exactly one matching native PAM
   entry/success, terminal GUI approval, a real server RSA-encrypted User Key,
   successful requester CLI exit/unlocked state and **exact byte equality** of
   actual `rbw get <item UUID>` output to the synthetic secret plus newline.
   This exercises the real requester token exchange, encrypted-key recovery,
   sync and vault decryption, not merely event counters.
8. Start a third request, lock the approver, and explicitly approve with its
   correct fingerprint. Require failure, no PAM, no password pinentry, no server
   mutation/key release, and a still-locked requester/approver. Refresh and reject
   the still-pending request to finish its requester deterministically.
9. Restart only the synthetic approver's agent with `face_auth=false`, unlock its
   existing cache through native pinentry, and **do not open UI in that fresh
   agent**. Explicitly run real `rbw auth-request approve <request UUID>`. Require
   exact review metadata, fresh native PAM entry, no key release while PAM waits,
   native success, server approval, successful requester exit and exact secret
   decryption again. This catches missing on-demand hub initialization and an
   incorrect ordinary-session bypass of remote-approval PAM.
10. Check the HTTP DTO allowlist and captured diagnostics for generated plaintext
   password/secret/User Key/token material. No secret/request access code is
   printed; normal stdout contains English phase markers and safe UUID or
   fingerprint metadata only. All CLI output and HTTP bodies stay captured.
11. Stop only these two profiles and delete only this run's synthetic account
    through authenticated `POST /api/accounts/delete`, after checking the normal
    authenticated profile email/UUID. Require its token to stop authenticating.
    Remove this run's containers/network/private temporary data.

HTTP calls have 8-second timeouts; CLI commands 20 seconds (5 for stopping);
readiness/discovery has bounded polling; requester completion has 25 seconds.
The gated native PAM fixture independently denies after 30 seconds. Delays do
not turn a negative case into success: hangs and wrong exit codes fail the run.
The fixture controls are root-owned and not group/world writable; receipts
observe execution but confer no authority.

## Cleanup failure and private recovery

Signals request bounded graceful cleanup. An external-server deletion failure
leaves **only** a mode-0600 `account-recovery.json` in the runner's mode-0700
private temporary directory. The runner prints the exact safe `--cleanup`
command with the generated path. Run that printed command to authenticate the
same generated identity, verify its email/UUID, and retry the normal account-delete
API. It does not read any rbw profile or real vault. Do not print, upload or commit
the recovery file: its password hash/token can authenticate the synthetic account.
A successful retry deletes the file; the now-empty parent directory can be
removed normally. Recovery refuses symlinks, non-private files, files owned by
another user and account names outside the exact run UUID pattern.

For default isolated mode, failed authenticated deletion still makes the test
fail, but destroying the runner's own tmpfs-backed server removes that disposable
account and the no-longer-useful credentials. If Docker cannot remove an owned
container/network, its unique name is reported and the run fails. SIGKILL/daemon
failure cannot guarantee authenticated remote deletion; keep the private recovery
file and use the printed cleanup command. The harness never falls back to an
admin endpoint, SQL deletion, disabling registration checks, or another user's
credentials.

## Primary contracts

- [Vaultwarden 1.35.0 registration, account deletion and auth-request routes](https://github.com/dani-garcia/vaultwarden/blob/1.35.0/src/api/core/accounts.rs)
- [Vaultwarden 1.35.0 password-or-OTP account-delete validation](https://github.com/dani-garcia/vaultwarden/blob/1.35.0/src/api/mod.rs)
- Current repository `src/api.rs`, `src/identity.rs`, `src/cipherstring.rs` and
  `src/device_auth.rs` define the actual client wire/crypto formats.
- `tests/ssh_agent_e2e_fixture.rs`, `tests/pam_howdy_smoke.c` and
  `tests/face_smoke_notifications.py` informed the disposable fixtures; none of
  those existing files is changed. Unlike the offline SSH fixture, this harness
  registers, logs in and creates the encrypted item on a real server.

No build, runtime acceptance, TN access, actual human PAM authentication or
camera/hardware verification was executed while implementing these new files.
