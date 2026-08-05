#!/bin/bash
set -euo pipefail

export HOME=/home/rbw
export RBW_PROFILE=ssha-e2e
export XDG_RUNTIME_DIR=/tmp/rbw-e2e-runtime
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw-ssha-e2e/ssh-agent.sock"

cleanup() {
    if [[ -n "${agent_pid:-}" ]]; then kill "$agent_pid" 2>/dev/null || true; fi
    if [[ -n "${sshd_pid:-}" ]]; then kill "$sshd_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

/usr/sbin/sshd -D -e -p 2222 &
sshd_pid=$!

runuser -u rbw -- env \
    HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    rbw-agent --no-daemonize > /tmp/rbw-agent.log 2>&1 &
agent_pid=$!

for _ in $(seq 1 100); do
    [[ -S "$SSH_AUTH_SOCK" ]] && break
    sleep 0.05
done
[[ -S "$SSH_AUTH_SOCK" ]]
[[ "$(stat -c '%a' "$(dirname "$SSH_AUTH_SOCK")")" == "700" ]]
[[ "$(stat -c '%a' "$SSH_AUTH_SOCK")" == "600" ]]

runuser -u rbw -- env \
    HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    rbw unlock

listed="$(runuser -u rbw -- env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" ssh-add -L)"
expected="$(cat /tmp/id_ed25519.pub)"
[[ "$listed" == "$expected" ]]

printf 'rbw ssh-agent signing fixture\n' > /tmp/payload
chown rbw:rbw /tmp/payload
runuser -u rbw -- env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
    ssh-keygen -Y sign -q -U -f /tmp/id_ed25519.pub -n file /tmp/payload
[[ -s /tmp/payload.sig ]]

runuser -u rbw -- env \
    HOME="$HOME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
    GIT_SSH_COMMAND='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222' \
    git ls-remote ssh://git@127.0.0.1:2222/home/git/repo.git >/tmp/git-ls-remote.out

# The fixture's default l1 policy allowed the signatures above because the
# agent was unlocked. A per-key `always` override must now require PAM and
# fail closed because this image deliberately has no rbw PAM policy.
fingerprint="$(ssh-keygen -lf /tmp/id_ed25519.pub -E sha256 | awk '{print $2}')"
[[ ! -e /etc/pam.d/rbw-device-auth ]]
runuser -u rbw -- env \
    HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    rbw config set "ssh_agent.policy.$fingerprint" always
wait "$agent_pid" || true

runuser -u rbw -- env \
    HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    rbw-agent --no-daemonize >/tmp/rbw-agent-policy.log 2>&1 &
agent_pid=$!
for _ in $(seq 1 100); do
    [[ -S "$SSH_AUTH_SOCK" ]] && break
    sleep 0.05
done
[[ -S "$SSH_AUTH_SOCK" ]]
runuser -u rbw -- env \
    HOME="$HOME" RBW_PROFILE="$RBW_PROFILE" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    rbw unlock

if printf 'policy must deny this signature\n' >/tmp/policy-payload && \
    chown rbw:rbw /tmp/policy-payload && \
    runuser -u rbw -- env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
        ssh-keygen -Y sign -q -U -f /tmp/id_ed25519.pub \
            -n file /tmp/policy-payload \
            >/tmp/ssh-agent-policy-denied.out \
            2>/tmp/ssh-agent-policy-denied.log; then
    echo 'per-key always policy signed without the required PAM gate' >&2
    exit 1
fi
[[ ! -e /tmp/policy-payload.sig ]]

echo 'ssh-agent Docker E2E passed: identities, owner-only socket, l1 signing, Git-over-SSH, and fail-closed per-key policy'
