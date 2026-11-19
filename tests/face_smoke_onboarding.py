#!/usr/bin/python3
"""Drive the actual offline CLI through a PTY without exposing prompt output."""
import errno
import os
import pty
import select
import signal
import subprocess
import sys
import time

mode = sys.argv[1]
master, slave = pty.openpty()
process = subprocess.Popen(
    sys.argv[2:] or ["rbw", "login"], stdin=slave, stdout=slave, stderr=slave, start_new_session=True
)
os.close(slave)
prompt = b"Enable face authorization for rbw? [y/N] "
output = bytearray()
answered = False
deadline = time.monotonic() + 30
try:
    while True:
        if time.monotonic() > deadline:
            raise AssertionError("interactive login timed out")
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                data = os.read(master, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            output.extend(data)
            if prompt in output and not answered:
                if mode == "quiet":
                    raise AssertionError("saved choice unexpectedly prompted again")
                os.write(master, {"default": b"\n", "no": b"n\n", "yes": b"y\n", "yes-failed": b"y\n"}[mode])
                answered = True
            if not data:
                break
        if process.poll() is not None and not readable:
            break
    code = process.wait(timeout=2)
    assert code == 0 or mode == "yes-failed", "interactive login failed"
    assert mode == "quiet" or answered, "login never offered face enrollment"
    assert output.count(prompt) <= 1, "login offered face enrollment repeatedly"
    print("interactive login smoke passed:", mode)
finally:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    os.close(master)
