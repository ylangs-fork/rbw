#!/usr/bin/python3
"""Disposable real D-Bus notification service, based on face_smoke_notifications.py.

The extra test interface emits the standard ActionInvoked signal; production
still calls org.freedesktop.Notifications and handles its normal action path.
No authorization, browser state, or server response is synthesized here.
"""
import json
import pathlib
import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = dbus.service.BusName("org.freedesktop.Notifications", bus)
INTERFACE = "org.freedesktop.Notifications"
TEST_INTERFACE = "org.rbwBio.DeviceApprovalFixture"


class Notifications(dbus.service.Object):
    def __init__(self):
        super().__init__(name, "/org/freedesktop/Notifications")
        self.sequence = 0
        self.live = {}

    @dbus.service.method(INTERFACE, in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["body", "actions"]

    @dbus.service.method(INTERFACE, in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("rbw device approval fixture", "test only", "1", "1.2")

    @dbus.service.method(INTERFACE, in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app, replaces, icon, summary, body, actions, hints, expires):
        self.sequence += 1
        record = {"id": self.sequence, "summary": str(summary), "body": str(body),
                  "actions": [str(action) for action in actions]}
        self.live[self.sequence] = record
        with pathlib.Path(sys.argv[2]).open("a", encoding="utf8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        return self.sequence

    @dbus.service.signal(INTERFACE, signature="us")
    def ActionInvoked(self, notification_id, action_key):
        pass

    @dbus.service.signal(INTERFACE, signature="uu")
    def NotificationClosed(self, notification_id, reason):
        pass

    @dbus.service.method(INTERFACE, in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        self.live.pop(int(notification_id), None)
        self.NotificationClosed(notification_id, dbus.UInt32(3))

    @dbus.service.method(TEST_INTERFACE, in_signature="us", out_signature="")
    def Activate(self, notification_id, action_key):
        record = self.live.get(int(notification_id))
        if record is None or str(action_key) not in record["actions"][::2]:
            raise dbus.exceptions.DBusException(
                "Unknown notification action", name=TEST_INTERFACE + ".InvalidAction")
        self.ActionInvoked(notification_id, action_key)


service = Notifications()
pathlib.Path(sys.argv[1]).write_text("ready\n", encoding="utf8")
GLib.MainLoop().run()
