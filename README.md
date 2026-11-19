# rbwBio

**rbwBio** is a fork of the unofficial command line client
[`rbw`](https://github.com/doy/rbw) for [Bitwarden](https://bitwarden.com/),
with opt-in face authorization on GNU/Linux. The executable names remain `rbw`
and `rbw-agent`; existing configuration, encrypted vault data, `RBW_PROFILE`
profiles and integrations keep their existing names and locations. Neither
the crate (`rbw`) nor the repository needs renaming.

Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Maintenance

The upstream `rbw` project considers its original feature set essentially
complete. This fork maintains rbwBio's face authorization and local approval
features while retaining the existing command and data interfaces.

## Installation

Install **rbwBio** from the Homebrew tap below, or build this repository.
The distribution packages listed here are upstream `rbw`, not rbwBio.

### Arch Linux

`rbw` is available in the [extra
repository](https://archlinux.org/packages/extra/x86_64/rbw/).
Alternatively, you can install
[`rbw-git`](https://aur.archlinux.org/packages/rbw-git/) from the AUR, which
will always build from the latest master commit.

### Debian/Ubuntu

`rbw` is officially packaged for Debian as
[`rust-rbw`](https://tracker.debian.org/pkg/rust-rbw) and is available in
testing (forky). You can install it using `sudo apt install rbw`.

Alternatively, you can download a Debian package from
[https://git.tozt.net/rbw/releases/deb/
](https://git.tozt.net/rbw/releases/deb/). The packages are signed by
[`minisign`](https://github.com/jedisct1/minisign), and can be verified using
the public key `RWTM0AZ5RpROOfAIWx1HvYQ6pw1+FKwN6526UFTKNImP/Hz3ynCFst3r`.

### Fedora/EPEL

`rbw` is available in [Fedora and EPEL 9](https://bodhi.fedoraproject.org/updates/?packages=rust-rbw)
(for RHEL and compatible distributions).

You can install it using `sudo dnf install rbw`.

### Homebrew

Install rbwBio from its own tap, not `homebrew/core`:

```sh
brew install ylang-ylang/tap/rbwbio
```

Existing installations of this tap's `rbw` formula migrate to `rbwbio` on
`brew update` and `brew upgrade`. Do not install both formulas: they provide the
same `rbw` and `rbw-agent` binaries. Your existing configuration and vault data
are preserved; continue using `rbw login` and your existing integrations.

Linux face authorization is optional and deploys the bundled runtime only after
you opt in; see "Face enrollment" below. macOS supports requester/remote use,
not local Howdy enrollment. Homebrew uses a precompiled bottle when one is
available for your platform; otherwise it builds rbwBio from source.

### Nix

`rbw` is available in the
[NixOS repository](https://search.nixos.org/packages?show=rbw). You can try
it out via `nix-shell -p rbw`.

### Alpine

`rbw` is available in the [community repository](https://pkgs.alpinelinux.org/packages?name=rbw). You can install it with `apk add rbw`.

### Other

With a working Rust installation, build rbwBio from this repository with
`cargo install --locked --path .`, or use
`cargo install --locked --git https://github.com/ylangs-fork/rbw`.
The crate name remains `rbw`. This requires that the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program is installed (to display password prompts). On GNU/Linux, PAM-backed
local approval also requires PAM development files when building from source
(`libpam0g-dev` on Debian/Ubuntu, or the distribution equivalent) and the
chosen PAM modules at runtime.

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: Idle timeout in seconds for ordinary rbw sessions when face
  authorization has been explicitly declined. Successful requests renew it.
* `l1_timeout`: The maximum number of seconds that an unlocked L1 session can
  keep User Key material in the agent. Defaults to `86400` (24 hours). On a
  machine without a secure `/etc/pam.d/rbw-device-auth` policy at agent
  startup, the effective lifetime is capped at 600 seconds and is never
  renewed by ordinary requests. On a machine with that policy, each successful
  PAM authorization renews the configured lifetime.
* `face_auth`: Enrollment decision recorded by the login wizard. `false` uses
  ordinary rbw sessions; `true` requires face authorization even if the PAM
  policy is later removed. An absent value leaves existing installations in
  their previous auto-detected local/remote mode until interactive onboarding.
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.
* `unlock_helper`: Optional shell-style command invoked during `rbw unlock`
  before pinentry is consulted. The command is split with
  [`shlex`](https://docs.rs/shlex/), executed with an empty environment, no
  stdin, and a 30-second timeout. The helper must print `OK <hex>` to stdout
  (optionally followed by a newline), where `<hex>` decodes to exactly 64
  bytes representing the raw User Key. Any failure (spawn error, non-zero
  exit, timeout, malformed output, wrong length) prints a short generic
  message to stderr and falls back to the normal pinentry-based unlock.
  Set with `rbw config set unlock_helper <cmd>`; clear with
  `rbw config unset unlock_helper` or by passing an empty value:
  `rbw config set unlock_helper ""`.

### Local authorization sessions

After a successful Master Password, device, or `unlock_helper` unlock, the
agent enters an L1 session. Ordinary requests never extend this session. When a
secure dedicated policy exists at `/etc/pam.d/rbw-device-auth` when the agent
starts, secret reads and explicit syncs require a fresh PAM authorization; a
successful authorization both permits that action and renews `l1_timeout`.
This makes PAM a user-presence gate, not a source of key material.

If no secure policy exists when the agent starts, it selects remote mode for
that process: the general secret-access gate is bypassed, the effective L1
lifetime is capped at ten minutes, and no request can renew it. The mode is
fixed until the agent restarts. If a local-mode policy is later removed or
becomes insecure, access fails closed rather than silently downgrading to
remote mode.

When L1 expires, `rbw lock` is run, or the agent exits, the in-memory User Key
and organization keys are cleared. Configuration changes take effect after the
agent is restarted (for example with `rbw stop-agent`).

### Face enrollment (GNU/Linux)

Install rbwBio, then log in normally:

```sh
brew install ylang-ylang/tap/rbwbio
rbw login
```

After a successful interactive login, rbwBio asks once:

```text
Enable face authorization for rbw? [y/N]
```

Press Enter to keep ordinary rbw behavior. Opting in deploys the precompiled
Howdy runtime installed with the package, discovers the IR camera, enrolls your
face, verifies recognition and desktop notifications, and activates the agent
mode. No manual Howdy, PAM editing or agent restart commands are required.
System deployment requests administrator authorization, but never runs apt,
pip, a compiler, or a network download. Missing precompiled components fail
explicitly instead of falling back to a build on your laptop.

Enrollment is offered only with interactive input/output; pipelines never prompt.
Use `rbw setup --apply` to opt in later or repair enrollment. `rbw setup` and
`rbw setup --check` remain read-only diagnostics. No sudo/login PAM policy is
changed, and an administrator's foreign rbw policy is never overwritten.

Master Password still unlocks a cold password vault. Face authorization gates
subsequent secret reads, explicit syncs, device approvals and default-policy SSH
signatures; it does not supply or derive encryption keys. Each local authorization
sends a secret-free desktop notification while recognition runs. Face failure,
cancellation, notification delivery failure or a missing policy rejects access.
Desktop Do Not Disturb can hide a notification even after the daemon accepts it.

Failed enrollment is not saved as enabled. The bundled GNU/Linux x86_64 runtime
requires glibc 2.35 or newer, including Ubuntu 22.04/24.04 and compatible
Manjaro x86_64 installations. Unsupported hardware/platforms are reported
instead of silently enabling a fallback. Actual camera recognition must be
verified on the target laptop; synthetic PAM smoke cannot prove face accuracy
or spoof resistance.

Howdy is a convenience gate, not hardware-backed Face ID or protection against
root. Its [security warning](https://github.com/boltgolt/howdy#a-note-on-security)
notes spoofing risks. Keep your system password and Master Password recovery
paths. macOS supports requester/remote use, not local Howdy enrollment.

### No-hardware face smoke

The Docker smoke in `tests/face_setup_smoke.sh` runs the real CLI, agent,
PAM transaction, and encrypted offline fixture. Its test image alone supplies
a synthetic `pam_howdy.so` to produce success, rejection, cancellation and
blocking behavior. It cannot validate camera drivers, face matching, liveness,
false accepts, or the laptop's camera/model permissions. No simulator or
authorization bypass is installed by the Homebrew formula.
The published runtime pinned in `src/bin/rbw/face-runtime.json` is mounted at
`/input/face-runtime.tar.gz` for offline deployment checks. The smoke also drives
real login PTYs, verifies default-No and failed-enrollment rollback, deploys the
actual bundle without a compiler/package resolver, and exercises its native
notification executable over an isolated user-session D-Bus service.

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries, `rbw sync`
will log in and establish an L1 session before downloading the password database,
and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw stop-agent`.

`rbw help` can be used to get more information about the available
functionality.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag will show the output as JSON. In addition to matching against the name,
you can pass a UUID as the name to search for the entry with that id, or a
URL to search for an entry with a matching website entry.

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).

### Login with device

A device which has previously logged in and is registered with the server can
request approval instead of entering the Master Password:

```sh
rbw unlock --device
```

The command displays a five-word fingerprint and waits up to five minutes for
another unlocked device to answer. Approval on GNU/Linux is gated by the fixed
PAM service `rbw-device-auth`. An administrator must install a dedicated policy at
`/etc/pam.d/rbw-device-auth`; `rbw-agent` fails closed if that path is missing,
is not a regular root-owned file, or is writable by group or other users. It
does not fall back to `/etc/pam.d/other` or allow the service name to be changed
through rbw configuration or the environment.

For face authorization, `rbw setup --apply` installs a dedicated policy using
the root-controlled native Howdy module. The policy uses `auth required` for
Howdy and a separate account-management rule; a face failure cannot fall back
to a permissive authentication module.
Keep the policy root-owned and not writable by group or other users (typically
mode `0644`). PAM secret prompts are displayed through rbw's configured
pinentry together with the validated request UUID and locally derived five-word
fingerprint; PAM-provided prompt and error text is not reflected into rbw output
or logs.

PAM is linked only in GNU/Linux builds. The portable musl release remains able
to request a device unlock, but fails closed if asked to approve locally; use a
GNU/Linux source build or Debian package for the approver. macOS and Android
builds likewise keep requester support without PAM approval.

Then compare the fingerprint shown on both devices before approving:

```sh
rbw auth-request list
rbw auth-request approve <request-id-or-number>
# or: rbw auth-request reject <request-id-or-number>
```

The list output shows a leading number for each pending request. You can
approve or reject by that number instead of copying the full request ID. When
only one request is pending, the ID or number can be omitted entirely.

Each approval requires a new successful PAM authentication. The approver agent
must already be unlocked: PAM provides only a local authorization decision for
releasing the in-memory User Key and never supplies, derives, stores, or recovers
that key. A remote requester cannot select the PAM service or claim a successful
local authentication; neither value exists in the public IPC or server protocol.
Device approval does not bypass Master Password Reprompt on individual vault
entries.

PAM returns an authorization decision, not an attestation of which module or
hardware produced it. The root-owned local policy is the trust authority. If
local user presence is required, administrators must not configure remote or
non-user-presence modules in `rbw-device-auth`; rbw intentionally does not impose
a module allowlist.

Locking or clearing the agent cancels active device-auth waits, terminates an
in-progress local-auth helper, and prevents a late local key install. It cannot
recall an approval the server accepted just before cancellation. Closing the
requester CLI after it prints the metadata does not proactively cancel the agent
task; explicitly lock the agent or let the five-minute request deadline expire.

### rbw SSH agent

The rbw SSH agent is a **local Unix-socket service and does not make network
connections**. It exposes the read-only `ssh-agent` protocol so OpenSSH, Git,
and compatible tools can use SSH private keys stored in the vault without
writing those keys to `~/.ssh`.

The service is opt-in. Enable it, start/unlock rbw, and point clients at its
socket:

```sh
rbw config set ssh_agent.enabled true
rbw unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent.sock"
ssh-add -L
ssh user@example.net
git push
```

For profiles, the socket is
`$XDG_RUNTIME_DIR/rbw-<profile>/ssh-agent.sock`. The runtime directory is mode
`0700` and the socket is mode `0600`. The agent only supports listing identities
and signing; requests to add, remove, lock, or otherwise mutate keys fail.
Bitwarden SSH-key items are discovered automatically. A secure note is also
usable when its notes field consists of an unencrypted OpenSSH private-key PEM.
(The note remains encrypted in the vault; "unencrypted" here means that the PEM
itself has no second passphrase.)

Signing policy is configured globally and can be overridden by OpenSSH SHA256
fingerprint:

```sh
rbw config set ssh_agent.default_policy l1
rbw config set 'ssh_agent.policy.SHA256:BASE64_FINGERPRINT' always
```

Policies are:

* `always`: require a fresh local PAM authorization for every signature. If the
  PAM gate is unavailable, signing fails closed. Remote approval for this case
  is a separate integration phase.
* `l1` (default): allow while the rbw agent is already unlocked. An expired or
  locked session must first be unlocked normally; face authorization cannot
  recreate a cold session.
* `never`: do not add an authorization gate beyond access to the unlocked rbw
  agent.

The dedicated PAM service is `/etc/pam.d/rbw-device-auth`. Use `rbw setup` to
configure its native Howdy face policy. Existing administrator-controlled PAM
policies remain the local trust authority, not a hardware attestation.

#### sudo with the rbw SSH agent

`sudo` can use the same agent through the distribution-provided
`pam_ssh_agent_auth` module while retaining the normal password path as a
fallback:

1. Install `pam_ssh_agent_auth` using the distribution package manager.
2. Add the following before the existing password/common-auth rule in
   `/etc/pam.d/sudo` (the exact include layout is distribution-specific):

   ```pam
   auth sufficient pam_ssh_agent_auth.so file=~/.ssh/authorized_keys
   auth required   pam_unix.so
   ```

   If the distribution already includes `pam_unix` indirectly, keep that
   existing include instead of adding a duplicate. Keep an independent root
   shell open while testing PAM changes.
3. Put the public key printed by `ssh-add -L` in the invoking user's
   `~/.ssh/authorized_keys` (or the file selected above).
4. Preserve `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/rbw/ssh-agent.sock` for sudo as
   required by the distribution's sudo environment policy.

If rbw is stopped, locked, or rejects signing, `pam_ssh_agent_auth` does not
succeed and the retained password rule prompts normally.

### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
