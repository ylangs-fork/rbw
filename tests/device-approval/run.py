#!/usr/bin/env python3
"""Run the disposable real-server device-approval chain; never uses host rbw/PAM.

Build the dedicated image first, as documented in README.md. --server explicitly
opts into creating/deleting one unique synthetic account on that server.
--cleanup retries only a retained private synthetic account recovery manifest.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import shlex
import sys
import tempfile
import urllib.error
import time
import urllib.parse
import urllib.request
import uuid


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def docker(*args, seconds=120):
    try:
        result = subprocess.run(["docker", *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=seconds, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("Docker operation failed or exceeded its finite deadline") from None
    require(result.returncode == 0, "Docker " + args[0] + " failed (private output suppressed)")
    return result.stdout.decode().strip()


def server_url(value):
    url = urllib.parse.urlsplit(value)
    require(url.scheme in ("http", "https") and url.hostname and not url.username
            and not url.password and not url.query and not url.fragment,
            "server must be an HTTP(S) base URL without credentials/query/fragment")
    require(url.scheme == "https" or url.hostname in ("localhost", "127.0.0.1", "::1"),
            "external non-loopback server must use HTTPS")
    return value.rstrip("/")


def cleanup_manifest(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o077 == 0,
            "cleanup manifest must be a private regular file owned by this user")
    account = json.loads(path.read_text())
    identifier = str(uuid.UUID(account["run_id"]))
    require(account["email"] == "rbwbio-device-" + identifier + "@example.invalid"
            and account["registration_attempted"] is True,
            "refusing cleanup outside this harness's unique reserved-domain account")
    server = server_url(account["server"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(route, body=None, token=None, form=False):
        headers = {"Bitwarden-Client-Name": "cli", "Bitwarden-Client-Version": "2026.6.0",
                   "User-Agent": "rbwBio-device-acceptance/1"}
        data = None
        if body is not None:
            data = (urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode())
            headers["Content-Type"] = ("application/x-www-form-urlencoded" if form else "application/json")
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(server + route, data=data, headers=headers)
        try:
            with opener.open(req, timeout=30) as response:
                return response.status, response.read(1024 * 1024)
        except urllib.error.HTTPError as error:
            return error.code, error.read(1024 * 1024)
        except OSError as error:
            raise Failure("cleanup HTTP transport failed [" + type(error).__name__ +
                          "] (private details suppressed)") from None
    token = account.get("token")
    status, raw = request("/api/accounts/profile", token=token) if token else (401, b"")
    if not 200 <= status < 300:
        status, raw = request("/identity/connect/token", {
            "grant_type": "password", "scope": "api offline_access", "client_id": "cli",
            "deviceType": 8, "deviceName": "rbwBio disposable cleanup",
            "deviceIdentifier": str(uuid.uuid4()), "username": account["email"],
            "password": account["password_hash"]}, form=True)
        require(status == 200, "synthetic cleanup login failed; recovery file retained")
        token = json.loads(raw)["access_token"]
        status, raw = request("/api/accounts/profile", token=token)
    require(status == 200, "cleanup could not authenticate synthetic profile")
    profile = json.loads(raw)
    email = profile.get("email", profile.get("Email"))
    account_id = profile.get("id", profile.get("Id"))
    require(email == account["email"] and
            (not account.get("account_id") or account_id == account["account_id"]),
            "refusing cleanup for a different profile")
    require(str(uuid.UUID(account_id)) == account_id, "cleanup profile UUID invalid")
    pending = account.get("auth_request_ids", [])
    require(isinstance(pending, list) and all(isinstance(value, str) and
            str(uuid.UUID(value)) == value for value in pending), "invalid cleanup request IDs")
    deadline = time.monotonic() + 1000
    while pending:
        remaining = []
        for request_id in pending:
            status, _ = request("/api/auth-requests/" + request_id, token=token)
            if status == 200:
                remaining.append(request_id)
            else:
                require(status in (400, 404, 410), "cleanup cannot verify normal request expiry")
        pending = remaining
        require(not pending or time.monotonic() < deadline,
                "normal request expiry exceeded cleanup deadline; recovery file retained")
        if pending:
            time.sleep(5)
    status, _ = request("/api/accounts/delete", {"masterPasswordHash": account["password_hash"]}, token)
    require(200 <= status < 300, "authenticated account deletion failed; recovery file retained")
    require(request("/api/accounts/profile", token=token)[0] in (400, 401, 403, 404),
            "deleted synthetic profile still authenticates; recovery file retained")
    path.unlink()
    print("device-approval: authenticated synthetic account deletion confirmed " + account_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="rbw-device-approval:local",
                        help="already built dedicated harness image")
    parser.add_argument("--server", help="deliberate external synthetic-account mode; HTTPS required")
    parser.add_argument("--server-image", default="vaultwarden/server:1.35.0",
                        help="pinned official compatible server image used only without --server")
    parser.add_argument("--cleanup", type=pathlib.Path,
                        help="retry authenticated deletion from private recovery manifest")
    args = parser.parse_args()
    if args.cleanup:
        require(not args.server, "--cleanup reads the server only from its private manifest")
        cleanup_manifest(args.cleanup)
        return 0
    external = server_url(args.server) if args.server else None
    require(re.search(r"@sha256:[0-9a-f]{64}$|:[0-9][A-Za-z0-9_.-]*$", args.server_image),
            "server image must use a pinned version or digest, never latest")
    labels = json.loads(docker("image", "inspect", "--format", "{{json .Config.Labels}}", args.image)) or {}
    require(labels.get("org.rbwbio.test.device-approval") == "1", "not the dedicated acceptance image")
    identifier = uuid.uuid4().hex
    network = "rbwbio-device-" + identifier
    server_name = network + "-server"
    runner_name = network + "-runner"
    artifacts = pathlib.Path(tempfile.mkdtemp(prefix="rbwbio-device-private-"))
    artifacts.chmod(0o700)
    # Pre-create with host ownership; container truncation preserves it under
    # both rootful and rootless Docker without guessing user-namespace mappings.
    recovery = artifacts / "account-recovery.json"
    recovery.write_text("")
    recovery.chmod(0o600)
    created = []
    removed = set()
    network_created = False
    attached = None
    outcome = 1
    def interrupted(signum, frame):
        raise Failure("interrupted; stopping only this invocation's containers")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        docker("network", "create", "--label", "org.rbwbio.acceptance=" + identifier, network)
        network_created = True
        if not external:
            # Default registration settings, no admin token, no registration override.
            docker("create", "--name", server_name, "--network", network,
                   "--network-alias", "vaultwarden", "--label", "org.rbwbio.acceptance=" + identifier,
                   "--tmpfs", "/data:rw,nosuid,nodev,mode=0700", "--env", "LOG_LEVEL=error",
                   "--env", "WEB_VAULT_ENABLED=false", args.server_image)
            created.append(server_name)
            docker("start", server_name)
        server = external or "http://vaultwarden:80"
        docker("create", "--name", runner_name, "--network", network,
               "--label", "org.rbwbio.acceptance=" + identifier,
               "--mount", "type=bind,src=" + str(artifacts) + ",dst=/artifacts",
               "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--tmpfs", "/run:rw,nosuid,nodev,mode=0755",
               args.image, "--server", server)
        created.append(runner_name)
        # The driver prints only safe phases/UUID/fingerprint metadata, not CLI/server output.
        attached = subprocess.Popen(["docker", "start", "--attach", runner_name], stdin=subprocess.DEVNULL)
        try:
            outcome = attached.wait(timeout=1500)
        except subprocess.TimeoutExpired:
            raise Failure("full protocol acceptance exceeded 1500 seconds") from None
    finally:
        # Graceful TERM gives Python a chance to delete the synthetic account.
        # No globally named service, host profile, PAM file or unrelated container is touched.
        if runner_name in created:
            try:
                docker("stop", "--time", "60", runner_name, seconds=75)
            except Failure:
                pass
        if attached is not None and attached.poll() is None:
            attached.terminate()
            try:
                attached.wait(timeout=5)
            except subprocess.TimeoutExpired:
                attached.kill()
                attached.wait(timeout=5)
        for container in reversed(created):
            try:
                docker("rm", "--force", container, seconds=20)
                removed.add(container)
            except Failure:
                print("device-approval: could not remove own container " + container, file=sys.stderr)
                outcome = 1
        if network_created:
            try:
                docker("network", "rm", network, seconds=20)
            except Failure:
                print("device-approval: could not remove own network " + network, file=sys.stderr)
                outcome = 1
        if recovery.exists() and recovery.stat().st_size:
            outcome = 1
            if not external and server_name in removed:
                print("device-approval: normal account deletion incomplete; own ephemeral server destroyed",
                      file=sys.stderr)
                shutil.rmtree(artifacts)
            else:
                print("device-approval: private recovery retained at " + str(recovery), file=sys.stderr)
                if external:
                    print("device-approval: retry deletion: " + shlex.join([
                        sys.executable, str(pathlib.Path(__file__).resolve()), "--cleanup", str(recovery)]),
                        file=sys.stderr)
                else:
                    print("device-approval: own server removal failed; private recovery belongs only to that container",
                          file=sys.stderr)
        else:
            shutil.rmtree(artifacts)
    return outcome


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Do not leak private HTTP responses, tokens or subprocess output in tracebacks.
        error = sys.exc_info()[1]
        detail = str(error) if isinstance(error, Failure) else "operation failed (private details suppressed)"
        print("device-approval: FAIL: " + detail, file=sys.stderr)
        sys.exit(1)
