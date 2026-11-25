#!/usr/bin/env python3
"""Interactive real-requester probe; never log secrets or manufacture a 2FA code."""
import argparse
import datetime
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


class LiveRequest:
    def __init__(self):
        self.tty = None
        self.started_ticks = int(
            time.clock_gettime(time.CLOCK_BOOTTIME) * os.sysconf("SC_CLK_TCK")
        )

    def cleanup(self):
        check = subprocess.run(
            ["pgrep", "-a", "pinentry-curses"], capture_output=True, text=True,
            check=False,
        )
        if check.returncode not in (0, 1):
            raise RuntimeError("pinentry process check failed: " + check.stderr.strip())
        print("PINENTRY_POST_RUN_CHECK:", check.stdout.strip() or "none", flush=True)
        if self.tty is None:
            return
        for row in check.stdout.splitlines():
            pid = int(row.split()[0])
            proc = Path("/proc") / str(pid)
            try:
                if proc.stat().st_uid != os.getuid():
                    continue
                before = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
                args = (proc / "cmdline").read_bytes().split(b"\0")
                pos = args.index(b"--ttyname")
                if (args[pos + 1] != os.fsencode(self.tty)
                        or int(before) < self.started_ticks):
                    continue
                # Pin identity before signalling: never kill a reused/unrelated PID.
                fd = os.pidfd_open(pid)
                try:
                    after = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
                    if before == after:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                        print("CLEANED_OWN_PINENTRY_PID=" + str(pid), flush=True)
                finally:
                    os.close(fd)
            except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
                continue

    @staticmethod
    def cancel(signum, _frame):
        raise SystemExit(128 + signum)

    def run(self, item_id):
        if not os.isatty(0):
            raise SystemExit(
                "Live MFA acceptance requires an interactive tmux terminal; "
                "no request was sent. Do not wrap it in pi-notify run."
            )
        self.tty = os.ttyname(0)
        env = os.environ.copy()
        env["RBW_TTY"] = self.tty
        print("LIVE_REQUEST_START_UTC=" + datetime.datetime.now(
            datetime.timezone.utc).isoformat(), flush=True)
        result = subprocess.run(
            ["rbw", "unlock", "--device"], env=env, timeout=330, check=False,
        )
        print("DEVICE_UNLOCK_EXIT=" + str(result.returncode), flush=True)
        if result.returncode:
            return result.returncode
        print("UNLOCKED_MONOTONIC_NS=" + str(time.monotonic_ns()), flush=True)
        # The real value goes directly to /dev/null, not a log or Python buffer.
        result = subprocess.run(
            ["rbw", "get", item_id], env=env, stdout=subprocess.DEVNULL,
            timeout=40, check=False,
        )
        print("SECRET_READ_EXIT=" + str(result.returncode), flush=True)
        print("SECRET_CONTENT_DISCARDED=true", flush=True)
        return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--item-id", required=True, type=uuid.UUID,
                        help="Existing test login UUID")
    args = parser.parse_args()
    os.umask(0o077)
    probe = LiveRequest()
    signal.signal(signal.SIGTERM, probe.cancel)
    try:
        return probe.run(str(args.item_id))
    except subprocess.TimeoutExpired as error:
        print("LIVE_PHASE_TIMEOUT=" + str(error.timeout), flush=True)
        return 124
    finally:
        probe.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
