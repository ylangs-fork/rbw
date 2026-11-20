#!/bin/bash
set -euo pipefail
umask 077
[[ $(id -u) == 1100 ]] || { echo 'Refusing non-test-user desktop session.' >&2; exit 1; }
[[ -x $GNOME_TEST_BROWSER ]] || { echo 'Mount the parent-supplied precompiled browser and set GNOME_TEST_BROWSER.' >&2; exit 1; }
[[ $(stat -c '%a:%u' "$XDG_RUNTIME_DIR") == 700:1100 ]] || exit 1
state=$HOME/.cache/desktop-gnome
mkdir -p "$state/screenshots"
rm -f "$state/ready" "$state/session.env" "$state/shell.pid"
children=()
cleanup() {
    trap - EXIT TERM INT
    rm -f "$state/ready" "$state/session.env"
    # Only direct processes created by this session; container teardown owns descendants.
    for pid in "${children[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${children[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
Xvfb "$DISPLAY" -screen 0 1440x1000x24 -nolisten tcp -noreset >"$state/xvfb.log" 2>&1 &
xvfb_pid=$!; children+=("$xvfb_pid")
x_ready=false
for _ in {1..100}; do
    kill -0 "$xvfb_pid" || { echo 'Xvfb exited; inspect xvfb.log.' >&2; exit 1; }
    if xdpyinfo >/dev/null 2>&1; then x_ready=true; break; fi
    sleep 0.1
done
$x_ready || { echo 'Xvfb readiness timed out.' >&2; exit 1; }
# These settings affect only this disposable user's private dconf database.
gsettings set org.gnome.desktop.session idle-delay 0
gsettings set org.gnome.desktop.screensaver lock-enabled false
gsettings set org.gnome.desktop.interface enable-animations false
gsettings set org.gnome.desktop.notifications show-banners true
gsettings set org.gnome.shell disable-user-extensions true
xdg-mime default desktop-gnome-browser.desktop text/html
xdg-mime default desktop-gnome-browser.desktop x-scheme-handler/http
xdg-mime default desktop-gnome-browser.desktop x-scheme-handler/https
export BROWSER=/opt/desktop-gnome/browser.sh
dbus-update-activation-environment DISPLAY XDG_RUNTIME_DIR HOME XDG_CURRENT_DESKTOP \
    XDG_SESSION_TYPE XDG_SESSION_DESKTOP GNOME_SHELL_SESSION_MODE BROWSER \
    XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME
gnome-shell --x11 --sm-disable --mode=user >"$state/gnome-shell.log" 2>&1 &
shell_pid=$!; children+=("$shell_pid")
printf '%s\n' "$shell_pid" >"$state/shell.pid"
# A persistent, ordinary headed browser makes subsequent xdg-open use this CDP instance.
/opt/desktop-gnome/browser.sh about:blank >"$state/browser.log" 2>&1 &
browser_pid=$!; children+=("$browser_pid")
for name in HOME USER LOGNAME DISPLAY XDG_RUNTIME_DIR XDG_CONFIG_HOME XDG_DATA_HOME \
    XDG_CACHE_HOME XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP XDG_SESSION_TYPE \
    GNOME_SHELL_SESSION_MODE DBUS_SESSION_BUS_ADDRESS BROWSER GNOME_TEST_BROWSER \
    GNOME_TEST_VIRTUAL_CAMERA LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER; do
    printf 'export %s=%q\n' "$name" "${!name}" >>"$state/session.env"
done
ready=false
for _ in {1..180}; do
    kill -0 "$shell_pid" && kill -0 "$browser_pid" || {
        echo 'GNOME Shell or browser exited; inspect container-private logs.' >&2; exit 1;
    }
    if /opt/desktop-gnome/probe.py --shell-pid "$shell_pid" >"$state/probe.json" 2>"$state/probe-error.log"; then
        ready=true; break
    fi
    sleep 0.5
done
$ready || { echo 'GNOME/CDP readiness timed out; inspect probe-error.log and session logs.' >&2; exit 1; }
printf '%s\n' GNOME_DESKTOP_READY >"$state/ready"
echo 'GNOME_DESKTOP_READY display=:99 cdp=127.0.0.1:9222 user=1100 tray-host=absent'
# Failure of either real desktop component ends the environment instead of leaving a stale sentinel.
wait -n "$xvfb_pid" "$shell_pid" "$browser_pid"
exit 1
