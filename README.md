# rbw

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Maintenance

I consider `rbw` to be essentially feature-complete for me at this point. While
I still use it on a daily basis, and will continue to fix regressions as they
occur, I am unlikely to spend time implementing new features on my own. If you
would like to see new functionality in `rbw`, I am more than happy to review
and merge pull requests implementing those features.

## Installation

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

`rbw` is available in the [Homebrew repository](https://formulae.brew.sh/formula/rbw). You can install it via `brew install rbw`.

### Nix

`rbw` is available in the
[NixOS repository](https://search.nixos.org/packages?show=rbw). You can try
it out via `nix-shell -p rbw`.

### Alpine

`rbw` is available in the [community repository](https://pkgs.alpinelinux.org/packages?name=rbw). You can install it with `apk add rbw`.

### Other

With a working Rust installation, `rbw` can be installed via `cargo install
--locked rbw`. This requires that the
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
* `lock_timeout`: Legacy setting retained for configuration compatibility. The
  L0/L1 session lifetime is governed by `l1_timeout`.
* `l1_timeout`: The maximum number of seconds that an unlocked L1 session can
  keep User Key material in the agent. Defaults to `86400` (24 hours). On a
  machine without a secure `/etc/pam.d/rbw-device-auth` policy at agent
  startup, the effective lifetime is capped at 600 seconds and is never
  renewed by ordinary requests. On a machine with that policy, each successful
  PAM authorization renews the configured lifetime.
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

For example, a fingerprint-only policy using `pam_fprintd` can contain:

```pam
#%PAM-1.0
auth required pam_fprintd.so
account required pam_permit.so
```

A password policy can use `pam_unix.so`, while a face-recognition system such as
Howdy can install its own PAM module instead. Exact module names and control
flags are distribution-specific and remain a system-administrator decision.
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
* `l1` (default): allow while the rbw agent is already unlocked; otherwise
  require PAM and fail closed if it is unavailable.
* `never`: do not add an authorization gate beyond access to the unlocked rbw
  agent.

The PAM service is `/etc/pam.d/rbw-device-auth`; its root-owned policy can use
`pam_fprintd`, Howdy, a password module, or another administrator-selected PAM
module.

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
