#!/usr/bin/python3
"""Read-only checks of the actual GNOME Shell, X11 WM and loopback browser."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

from gi.repository import Gio, GLib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell-pid", type=int)
    parser.add_argument("--require-app", action="store_true")
    args = parser.parse_args()
    if os.getuid() != 1100:
        raise RuntimeError("Probe must run as the ordinary test user")
    if args.shell_pid is None:
        args.shell_pid = int((Path.home() / ".cache/desktop-gnome/shell.pid").read_text())
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

    def call(destination, path, interface, method, signature=None, values=()):
        parameters = GLib.Variant(signature, values) if signature else None
        return bus.call_sync(destination, path, interface, method, parameters, None,
                             Gio.DBusCallFlags.NONE, 3000, None).unpack()

    def bus_call(method, value):
        return call("org.freedesktop.DBus", "/org/freedesktop/DBus",
                    "org.freedesktop.DBus", method, "(s)", (value,))[0]

    owners = {}
    for name in ("org.gnome.Shell", "org.freedesktop.Notifications"):
        if not bus_call("NameHasOwner", name):
            raise RuntimeError(f"Real GNOME service not ready: {name}")
        owner = bus_call("GetNameOwner", name)
        pid = bus_call("GetConnectionUnixProcessID", owner)
        if pid != args.shell_pid:
            raise RuntimeError(f"{name} is not owned by the launched GNOME Shell")
        if Path(f"/proc/{pid}/exe").resolve().name != "gnome-shell":
            raise RuntimeError("Notification provider is not the GNOME Shell executable")
        if Path(f"/proc/{pid}").stat().st_uid != 1100:
            raise RuntimeError("GNOME Shell is not running as the ordinary test user")
        owners[name] = pid
    watchers = {name: bus_call("NameHasOwner", name) for name in (
        "org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher")}
    if any(watchers.values()):
        raise RuntimeError("A tray watcher is present; this is the intentional no-host scenario")
    info = call("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications", "GetServerInformation")
    capabilities = call("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                        "org.freedesktop.Notifications", "GetCapabilities")[0]
    if "actions" not in capabilities:
        raise RuntimeError("The native notification service does not advertise actions")
    root = subprocess.check_output(
        ["xprop", "-root", "_NET_SUPPORTING_WM_CHECK"], text=True).strip()
    if "window id # 0x" not in root:
        raise RuntimeError("X11 has no supporting window manager")
    wm_window = root.split("#", 1)[1].strip()
    wm_name = subprocess.check_output(
        ["xprop", "-id", wm_window, "_NET_WM_NAME"], text=True).strip()
    if "GNOME Shell" not in wm_name:
        raise RuntimeError("X11 window manager is not GNOME Shell")
    # Deliberately do not print target URLs or debugger URLs: a panel URL is a capability.
    with urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=3) as response:
        browser = json.load(response)
    if not browser.get("webSocketDebuggerUrl") or not browser.get("Browser"):
        raise RuntimeError("The real browser CDP endpoint is incomplete")
    app = Gio.DesktopAppInfo.new("rbwbio.desktop")
    if args.require_app and app is None:
        raise RuntimeError("The installed native rbwbio.desktop launcher is missing")
    print(json.dumps({
        "user_id": os.getuid(), "display": os.environ.get("DISPLAY"),
        "native_service_pids": owners, "notification_server": list(info),
        "notification_capabilities": sorted(capabilities),
        "tray_watchers": watchers, "window_manager": wm_name,
        "browser": browser["Browser"], "cdp": "127.0.0.1:9222",
        "application_launcher_installed": app is not None,
        "virtual_camera_requested": os.environ.get("GNOME_TEST_VIRTUAL_CAMERA") == "1",
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"GNOME_NOT_READY: {error}", file=sys.stderr)
        sys.exit(1)
