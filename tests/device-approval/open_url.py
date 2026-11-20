#!/usr/bin/python3
"""Test-only xdg-open receiver; records delivery, does NOT claim a real browser.

HTTP page/assets are fetched by harness.py. Real browser/desktop acceptance is
separate. Installed only inside the dedicated disposable acceptance image.
"""
import os
import pathlib
import re
import sys

if len(sys.argv) != 2 or not re.fullmatch(
    r"http://127\.0\.0\.1:[0-9]+/[A-Za-z0-9_-]{43}/(?:#(?:local|device)=[0-9a-f-]{36})?",
    sys.argv[1],
):
    sys.exit(1)
path = pathlib.Path(os.environ["HOME"]) / "opened-urls"
with path.open("a", encoding="ascii") as output:
    output.write(sys.argv[1] + "\n")
