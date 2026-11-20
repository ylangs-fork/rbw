#!/bin/bash
set -euo pipefail
[[ $(id -u) == 1100 ]] || { echo 'Use docker exec --user desktop.' >&2; exit 1; }
state=$HOME/.cache/desktop-gnome
[[ -f $state/ready && -f $state/session.env ]] || { echo 'Session is not ready.' >&2; exit 1; }
# Written with shell escaping by our own uid in a private directory.
source "$state/session.env"
command=${1:-status}
if (( $# )); then shift; fi
case "$command" in
    status)
        exec /opt/desktop-gnome/probe.py --shell-pid "$(cat "$state/shell.pid")"
        ;;
    screenshot)
        path=${1:-$state/screenshots/desktop-$(date -u +%Y%m%dT%H%M%SZ).png}
        scrot "$path"
        printf '%s\n' "$path"
        ;;
    launcher-search)
        # Opens the real Shell overview; it does not invoke gio launch or an app command.
        xdotool key --clearmodifiers Escape
        sleep 0.2
        xdotool key --clearmodifiers super
        sleep 0.5
        xdotool type --clearmodifiers --delay 90 'rbwBio'
        ;;
    notification-center)
        xdotool key --clearmodifiers super+m
        ;;
    click)
        [[ $# == 2 && $1 =~ ^[0-9]+$ && $2 =~ ^[0-9]+$ ]] || { echo 'click X Y' >&2; exit 2; }
        xdotool mousemove --sync "$1" "$2" click 1
        ;;
    key)
        [[ $# -gt 0 ]] || exit 2
        xdotool key --clearmodifiers "$@"
        ;;
    notify-probe)
        # Tests only the real native notification service, never rbw authorization.
        # Run in a separate docker exec while another invocation captures/clicks the banner.
        action=$(notify-send --app-name='GNOME acceptance fixture' --icon=dialog-information \
            --expire-time=60000 --wait --action=open='Open fixture' \
            'Disposable notification fixture' 'Click Open fixture to observe the native action signal.')
        if [[ $action == open ]]; then
            echo 'NATIVE_NOTIFICATION_OPEN_ACTION'
        else
            echo 'Notification closed without the fixture action.' >&2
            exit 1
        fi
        ;;
    exec)
        [[ $# -gt 0 ]] || exit 2
        exec "$@"
        ;;
    *)
        echo 'Commands: status, screenshot [PATH], launcher-search, notification-center, click X Y, key KEYS..., notify-probe, exec COMMAND...' >&2
        exit 2
        ;;
esac
