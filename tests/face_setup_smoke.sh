#!/bin/bash
# Docker-only, offline, synthetic-data smoke. No camera/hardware assurance.
# docker build --progress=plain -f tests/Dockerfile.face-smoke -t rbw-face-smoke .
# docker run --rm --network none rbw-face-smoke
set -euo pipefail

fail() { printf 'face smoke failed: %s\n' "$*" >&2; exit 1; }
[[ -f /.dockerenv && $(id -u) == 0 ]] || fail 'run only in the disposable test container as root'
[[ $(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n') == lo ]] || fail 'run with --network none'
export HOME=/home/rbw RBW_PROFILE=face-smoke XDG_RUNTIME_DIR=/tmp/face-smoke-runtime
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw-face-smoke/ssh-agent.sock"
policy=/etc/pam.d/rbw-device-auth
module=/usr/lib/security/pam_howdy.so
fixture=/opt/face-fixture
login=e8b2cf42-8700-4f48-bb29-83b81b147de1
work=$(mktemp -d /tmp/face-smoke.XXXXXX)
chown rbw:rbw "$work"
control=/run/face-smoke
install -d -m 0755 "$control"
printf 'success\n' >"$control/result"
printf 'deny\n' >"$control/pinentry"
chmod 0644 "$control/result" "$control/pinentry"
touch "$control/events" "$control/pinentry-events"
chmod 0622 "$control/events" "$control/pinentry-events"

user() {
    runuser -u rbw -- env HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" "$@"
}
stop_agent() {
    if [[ -n ${agent_pid:-} ]]; then
        user timeout 5 rbw stop-agent >"$work/quit.out" 2>"$work/quit.err" || true
        kill "$agent_pid" 2>/dev/null || true
        wait "$agent_pid" 2>/dev/null || true
        agent_pid=
    fi
}
cleanup() {
    if [[ -n ${request_pid:-} ]]; then kill "$request_pid" 2>/dev/null || true; fi
    stop_agent
    # Plaintext is never retained or included in failure diagnostics.
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
trap 'printf "face smoke stopped at line %s (output suppressed)\n" "$LINENO" >&2' ERR

assert_no_secret() {
    if grep -Fq -f "$fixture/expected-secret" "$@" || \
        grep -Fq 'rbw-e2e-password' "$@"; then
        fail 'credential appeared in diagnostic output'
    fi
}
expect_failure() {
    local label=$1 code
    shift
    if "$@" >"$work/$label.out" 2>"$work/$label.err"; then
        fail "$label unexpectedly succeeded"
    else
        code=$?
    fi
    [[ $code != 124 && $code != 137 ]] || fail "$label hung instead of denying"
    assert_no_secret "$work/$label.out" "$work/$label.err"
}
denied_get() {
    local label=$1
    expect_failure "$label" user timeout 5 rbw get "$login"
    [[ ! -s "$work/$label.out" ]] || fail "$label emitted secret-request output"
}
get_secret() {
    user timeout 5 rbw get "$login" >"$work/plaintext" 2>"$work/get.err"
    cmp -s "$work/plaintext" "$fixture/expected-secret" || fail 'real decryption did not match the synthetic fixture'
    rm "$work/plaintext"
    assert_no_secret "$work/get.err"
}
start_agent() {
    rm -f "$SSH_AUTH_SOCK" "$(dirname "$SSH_AUTH_SOCK")/socket"
    user rbw-agent --no-daemonize >"$work/agent.log" 2>&1 &
    agent_pid=$!
    for _ in {1..100}; do
        if [[ -S "$SSH_AUTH_SOCK" && -S "$(dirname "$SSH_AUTH_SOCK")/socket" ]]; then return; fi
        kill -0 "$agent_pid" 2>/dev/null || fail 'agent exited before socket readiness'
        sleep 0.05
    done
    fail 'agent socket readiness timed out'
}
cold_unlock() {
    printf 'allow\n' >"$control/pinentry"
    user timeout 10 rbw unlock >"$work/unlock.out" 2>"$work/unlock.err"
    printf 'deny\n' >"$control/pinentry"
    user timeout 5 rbw unlocked >"$work/unlocked.out" 2>"$work/unlocked.err"
}
now() { python3 -c 'import time; print(time.monotonic())'; }
until_time() {
    python3 - "$1" "$2" <<'PY'
import sys, time
time.sleep(max(0, float(sys.argv[1]) + float(sys.argv[2]) - time.monotonic()))
PY
}
set_result() { printf '%s\n' "$1" >"$control/result"; }
event_count() { wc -l <"$control/events"; }
system_pam_snapshot() {
    find /etc/pam.d -maxdepth 1 -type f ! -name rbw-device-auth -exec sha256sum '{}' + | sort
}

[[ ! -e $policy ]] || fail 'test image unexpectedly has an existing rbw policy'
system_pam_snapshot >"$work/system-pam.before"
expect_failure control-write user test -w "$control/result"

# Setup never silently installs Howdy, requests auth, or overwrites a stranger.
mv "$module" "$fixture/hidden-pam_howdy.so"
expect_failure missing-check rbw setup --check
expect_failure missing-default rbw setup
expect_failure missing-apply rbw setup --apply
[[ ! -e $policy ]] || fail 'missing Howdy wrote a policy'
mv "$fixture/hidden-pam_howdy.so" "$module"
expect_failure readonly-check user rbw setup --check
expect_failure readonly-default user rbw setup
expect_failure unprivileged-apply user rbw setup --apply
[[ ! -e $policy ]] || fail 'readonly/unprivileged setup wrote a policy'
[[ $(event_count) == 0 ]] || fail 'setup attempted authentication'
rbw setup --apply >"$work/apply.out" 2>"$work/apply.err"
[[ -f $policy && ! -L $policy ]] || fail 'setup did not install a regular policy'
[[ $(stat -c '%u:%a' "$policy") == 0:644 ]] || fail 'policy is not root-owned mode 0644'
python3 - "$policy" "$module" <<'PY'
import os, pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
auth = [line.split() for line in lines if line.startswith('auth ')]
account = [line.split() for line in lines if line.startswith('account ')]
assert auth == [['auth', 'required', sys.argv[2]]], 'not a face-only native policy'
assert len(account) == 1 and len(account[0]) == 3, 'unexpected account policy'
assert account[0][:2] == ['account', 'required']
permit = pathlib.Path(account[0][2])
assert permit.is_absolute() and permit.name == 'pam_permit.so' and permit.is_file()
assert permit.stat().st_uid == 0 and not (permit.stat().st_mode & 0o022)
assert all(line.startswith('#') or not line or line.split() in auth + account for line in lines)
PY
cp "$policy" "$work/managed-policy"
policy_stat=$(stat -c '%i:%Y:%Z' "$policy")
rbw setup --apply >"$work/apply-again.out" 2>"$work/apply-again.err"
cmp -s "$policy" "$work/managed-policy" || fail 'second apply changed policy content'
[[ $(stat -c '%i:%Y:%Z' "$policy") == "$policy_stat" ]] || fail 'idempotent apply replaced the policy'
user rbw setup --check >"$work/check.out" 2>"$work/check.err"
user rbw setup >"$work/default.out" 2>"$work/default.err"
printf '# Foreign policy: must not overwrite\nauth required pam_deny.so\n' >"$policy"
cp "$policy" "$work/foreign-policy"
expect_failure foreign-apply rbw setup --apply
expect_failure foreign-check rbw setup --check
cmp -s "$policy" "$work/foreign-policy" || fail 'foreign policy was overwritten'
install -o root -g root -m 0644 "$work/managed-policy" "$policy"
printf 'face smoke: readonly, missing-module, privileged apply, idempotence, foreign-policy protection passed\n'

# Eight-second local L1. Successful authorization renews; failures and aborts do not.
start_agent
cold_unlock
[[ $(wc -l <"$control/pinentry-events") == 1 ]] || fail 'cold unlock did not use the synthetic master-password prompt exactly once'
set_result success
get_secret
original=$(now)
until_time "$original" 5
get_secret
renewed=$(now)
until_time "$original" 9
user timeout 5 rbw unlocked >"$work/renewed.out" 2>"$work/renewed.err"
for outcome in auth_err abort; do
    set_result "$outcome"
    before=$(event_count)
    denied_get "face-$outcome"
    [[ $(event_count) -gt $before ]] || fail "$outcome did not reach real system PAM"
done
until_time "$renewed" 9
expect_failure local-expired user timeout 5 rbw unlocked
denied_get local-expired-get
printf 'face smoke: master-password cold unlock, real decrypt, success-only renewal, denial/abort, expiry passed\n'

# Removing the policy during a local agent session cannot select remote mode.
set_result success
cold_unlock
mv "$policy" "$work/temporarily-removed-policy"
denied_get removed-policy
install -o root -g root -m 0644 "$work/temporarily-removed-policy" "$policy"
get_secret

# OpenSSH is the signing consumer; verify the successful signature, not only exit status.
printf 'face smoke nonsecret payload\n' >"$work/payload"
chown rbw:rbw "$work/payload"
user timeout 5 ssh-keygen -Y sign -q -U -f "$fixture/public-key" -n file "$work/payload" \
    >"$work/sign.out" 2>"$work/sign.err"
printf 'face-smoke %s\n' "$(cat "$fixture/public-key")" >"$work/allowed-signers"
ssh-keygen -Y verify -f "$work/allowed-signers" -I face-smoke -n file \
    -s "$work/payload.sig" <"$work/payload" >"$work/verify.out" 2>"$work/verify.err"
for outcome in auth_err abort; do
    rm -f "$work/payload.sig"
    set_result "$outcome"
    expect_failure "sign-$outcome" user timeout 5 ssh-keygen -Y sign -q -U \
        -f "$fixture/public-key" -n file "$work/payload"
    [[ ! -e "$work/payload.sig" ]] || fail 'denied SSH request wrote a signature'
done
printf 'face smoke: runtime policy removal fails closed, SSH always success/verify and denial/abort passed\n'

# Both consumers must cancel a blocking native PAM module and its descendant on lock.
for consumer in cli ssh; do
    set_result success
    cold_unlock
    set_result block
    before=$(event_count)
    if [[ $consumer == cli ]]; then
        user timeout 10 rbw get "$login" >"$work/blocked.out" 2>"$work/blocked.err" &
    else
        rm -f "$work/payload.sig"
        user timeout 10 ssh-keygen -Y sign -q -U -f "$fixture/public-key" \
            -n file "$work/payload" >"$work/blocked.out" 2>"$work/blocked.err" &
    fi
    request_pid=$!
    ready=false
    for _ in {1..60}; do
        if [[ $(event_count) -gt $before ]]; then ready=true; break; fi
        sleep 0.05
    done
    [[ $ready == true ]] || fail "$consumer never entered blocking native PAM"
    read -r outcome helper descendant < <(tail -n 1 "$control/events")
    [[ $outcome == block && $helper -gt 1 && $descendant -gt 1 ]] || fail 'missing blocking helper receipt'
    user timeout 3 rbw lock >"$work/lock.out" 2>"$work/lock.err"
    gone=false
    for _ in {1..60}; do
        if [[ ! -e /proc/$helper && ! -e /proc/$descendant ]]; then gone=true; break; fi
        sleep 0.05
    done
    [[ $gone == true ]] || fail "$consumer lock left a PAM helper/descendant running"
    if wait "$request_pid"; then fail "$consumer request succeeded after lock"; else code=$?; fi
    request_pid=
    [[ $code != 124 && $code != 137 ]] || fail "$consumer request waited for outer timeout instead of cancellation"
    [[ ! -s "$work/blocked.out" ]] || fail 'cancelled request emitted output'
    [[ ! -e "$work/payload.sig" ]] || fail 'cancelled request wrote a signature'
    assert_no_secret "$work/blocked.out" "$work/blocked.err"
    expect_failure "locked-$consumer" user timeout 5 rbw unlocked
done
printf 'face smoke: lock cancels blocking CLI/SSH PAM helpers and descendants passed\n'
stop_agent

# No-PAM remote mode: short configured window exercises the real fixed deadline.
# This does NOT wait 600 seconds or replace the unit test for the 10-minute cap.
rm "$policy"
python3 - "$HOME/.config/rbw-face-smoke/config.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
config = json.loads(path.read_text())
config['l1_timeout'] = 6
path.write_text(json.dumps(config))
PY
start_agent
cold_unlock
before=$(event_count)
remote=$(now)
get_secret
until_time "$remote" 3
get_secret
user timeout 5 rbw list --fields id >"$work/remote-list.out" 2>"$work/remote-list.err"
user timeout 5 rbw unlocked >"$work/remote-live.out" 2>"$work/remote-live.err"
until_time "$remote" 7
expect_failure remote-expired user timeout 5 rbw unlocked
denied_get remote-expired-get
[[ $(event_count) == "$before" ]] || fail 'remote requests unexpectedly reached PAM'
stop_agent
if pgrep -u rbw -f -- '--local-auth-helper' >/dev/null; then fail 'a local-auth helper survived teardown'; fi
system_pam_snapshot >"$work/system-pam.after"
cmp -s "$work/system-pam.before" "$work/system-pam.after" || fail 'setup changed another system PAM service'
assert_no_secret "$work"/*.log "$work"/*.out "$work"/*.err
printf 'face smoke passed: offline synthetic vault, native system PAM, no hardware safety claim; remote fixed-window expiry exercised at 6s (600s cap remains unit-tested)\n'
