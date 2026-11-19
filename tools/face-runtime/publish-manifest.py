#!/usr/bin/python3
"""Bind an observed bundle hash to its real, already-published HTTPS release URL."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("url")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if urllib.parse.urlsplit(args.url).scheme != "https":
        parser.error("release URL must use HTTPS")
    local = hashlib.sha256()
    with args.archive.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            local.update(block)
    published = hashlib.sha256()
    with urllib.request.urlopen(args.url, timeout=120) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            published.update(block)
    if local.digest() != published.digest():
        raise SystemExit("published artifact differs from local archive")
    with tarfile.open(args.archive) as archive:
        stream = archive.extractfile("rbw-howdy/bundle-manifest.json")
        if stream is None:
            raise SystemExit("bundle manifest missing")
        manifest = json.load(stream)
    if manifest["schema"] != 1 or manifest["platform"] != "linux-x86_64-ubuntu22.04":
        raise SystemExit("unsupported bundle manifest")
    result = {"version": manifest["version"], "platform": manifest["platform"],
              "url": args.url, "sha256": local.hexdigest()}
    # Print only. Existing source files must be updated through the owner's edit tool.
    print(json.dumps(result, indent=2))
    if args.output.exists():
        raise SystemExit("refusing to overwrite an existing source manifest; apply printed JSON with edit")
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
