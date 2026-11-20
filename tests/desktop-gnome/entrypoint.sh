#!/bin/bash
set -euo pipefail
if [[ $(id -u) != 0 ]]; then
    echo 'Start this test image with its default entrypoint user; the session drops to desktop.' >&2
    exit 1
fi
install -d -m 0700 -o desktop -g desktop /run/user/1100
install -d -m 0755 /run/dbus
# Never mount a host system/session bus into this disposable container.
dbus-daemon --system --fork --nopidfile
exec setpriv --reuid=1100 --regid=1100 --init-groups \
    dbus-run-session -- /opt/desktop-gnome/session.sh
