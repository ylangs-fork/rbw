#!/usr/bin/python3
"""Disposable smoke-only desktop daemon; exercises native notify-send over D-Bus."""
import json
import os
import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = dbus.service.BusName("org.freedesktop.Notifications", bus)


class Notifications(dbus.service.Object):
    def __init__(self):
        super().__init__(name, "/org/freedesktop/Notifications")
        self.sequence = 0

    @dbus.service.method("org.freedesktop.Notifications", in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["body", "actions", "icon-static"]

    @dbus.service.method("org.freedesktop.Notifications", in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("rbw smoke", "test only", "1", "1.2")

    @dbus.service.method("org.freedesktop.Notifications", in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app, replaces, icon, summary, body, actions, hints, expires):
        with open("/run/face-smoke/notification-result", encoding="utf8") as control:
            reject = control.read().strip() == "deny"
        if reject:
            raise dbus.exceptions.DBusException(
                "Synthetic notification rejection", name="org.freedesktop.Notifications.Error"
            )
        self.sequence += 1
        with open("/run/face-smoke/notifications", "a", encoding="utf8") as receipt:
            receipt.write(json.dumps({"id": self.sequence, "summary": str(summary), "body": str(body), "actions": list(map(str, actions))}) + "\n")
        return self.sequence

    @dbus.service.method("org.freedesktop.Notifications", in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        self.NotificationClosed(notification_id, 3)

    @dbus.service.signal("org.freedesktop.Notifications", signature="uu")
    def NotificationClosed(self, notification_id, reason):
        return None

    @dbus.service.signal("org.freedesktop.Notifications", signature="us")
    def ActionInvoked(self, notification_id, action):
        return None


service = Notifications()
with open(sys.argv[1], "w", encoding="utf8") as ready:
    ready.write("ready\n")
GLib.MainLoop().run()
