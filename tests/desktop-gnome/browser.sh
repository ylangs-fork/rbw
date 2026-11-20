#!/bin/bash
set -euo pipefail
[[ $(id -u) == 1100 ]] || { echo 'Refusing root or non-test-user browser.' >&2; exit 1; }
: "${GNOME_TEST_BROWSER:=/opt/browser/chrome}"
args=(
    --user-data-dir="$HOME/.cache/desktop-gnome/chrome-profile"
    --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222
    --ozone-platform=x11 --use-gl=angle --use-angle=swiftshader --enable-unsafe-swiftshader
    --no-first-run --no-default-browser-check --password-store=basic --start-maximized
    # Container-only: no privileged sandbox setup or host user-namespace changes.
    --no-sandbox
)
if [[ ${GNOME_TEST_VIRTUAL_CAMERA:-0} == 1 ]]; then
    args+=(--use-fake-device-for-media-stream)
fi
# No fake permission grant: the operator must click the real browser permission prompt.
exec "$GNOME_TEST_BROWSER" "${args[@]}" "$@"
