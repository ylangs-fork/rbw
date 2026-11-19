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
        return ["body"]

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
            receipt.write(json.dumps({"summary": str(summary), "body": str(body)}) + "\n")
        return self.sequence

    @dbus.service.method("org.freedesktop.Notifications", in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        pass


service = Notifications()
with open(sys.argv[1], "w", encoding="utf8") as ready:
    ready.write("ready\n")
GLib.MainLoop().run()
