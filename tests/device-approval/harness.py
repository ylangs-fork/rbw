#!/usr/bin/python3
"""Real Vaultwarden/rbw/device-review/PAM round trip in a disposable container.

No production authorization is mocked. Only the human PAM verdict, desktop
notification daemon and browser-launch receiver are labelled test fixtures.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FIXTURE = pathlib.Path("/opt/device-approval")
CONTROL = pathlib.Path("/run/face-smoke")
ARTIFACTS = pathlib.Path("/artifacts")
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def phase(message):
    print("device-approval: " + message, flush=True)


def eventually(predicate, label, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise Failure(label + " timed out")


def http(url, method="GET", body=None, token=None, form=False, origin=None):
    headers = {"Accept": "application/json", "Bitwarden-Client-Name": "cli",
               "Bitwarden-Client-Version": "2026.6.0"}
    data = None
    if body is not None:
        data = (urllib.parse.urlencode(body).encode() if form else
                json.dumps(body).encode())
        headers["Content-Type"] = ("application/x-www-form-urlencoded" if form
                                   else "application/json")
    if token:
        headers["Authorization"] = "Bearer " + token
    if origin:
        headers.update({"Origin": origin, "Sec-Fetch-Site": "same-origin"})
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with HTTP.open(request, timeout=8) as response:
            return response.status, response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, error.read(2 * 1024 * 1024)
    except (OSError, ValueError):
        raise Failure("HTTP transport failed (response and URL suppressed)") from None


def parsed(response, label):
    status, raw = response
    require(200 <= status < 300, label + " failed (HTTP " + str(status) + ")")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure(label + " returned invalid JSON") from None


def b64(data):
    return base64.b64encode(data).decode("ascii")


def encrypted(keys, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(keys[:32]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(keys[32:], iv + ciphertext, hashlib.sha256).digest()
    return "2." + "|".join(map(b64, (iv, ciphertext, mac)))


def field(record, name):
    return record.get(name, record.get(name[0].upper() + name[1:]))


class Harness:
    def __init__(self, server):
        self.server = server.rstrip("/")
        self.identifier = str(uuid.uuid4())
        self.email = "rbwbio-device-" + self.identifier + "@example.invalid"
        self.password = "Rbwbio-" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        self.secret = ("synthetic-device-secret-" + str(uuid.uuid4())).encode()
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="device-approval-"))
        self.work.chmod(0o711)
        self.user = pwd.getpwnam("rbw")
        self.profiles = {}
        self.processes = []
        self.logs = []
        self.private = [self.password.encode(), self.secret]
        self.recovery = ARTIFACTS / "account-recovery.json"
        self.account = None
        self.url = None
        self.sequence = 0

    def owned(self, path, text="", mode=0o600):
        path.write_text(text, encoding="utf8")
        path.chmod(mode)
        os.chown(path, self.user.pw_uid, self.user.pw_gid)

    def save_recovery(self):
        self.recovery.write_text(json.dumps(self.account), encoding="utf8")
        self.recovery.chmod(0o600)

    def command(self, role, *args):
        profile = self.profiles[role]
        return ["/usr/sbin/runuser", "-u", "rbw", "--", "/usr/bin/env", "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
                "HOME=" + str(profile["home"]), "USER=rbw", "LOGNAME=rbw",
                "RBW_PROFILE=" + profile["name"],
                "XDG_RUNTIME_DIR=" + str(profile["runtime"]),
                "DBUS_SESSION_BUS_ADDRESS=" + profile["bus"], *args]

    def check_private(self, data):
        require(not any(value and value in data for value in self.private),
                "private synthetic material leaked into public diagnostics")

    def cli(self, role, *args, success=True, seconds=20, plaintext=False):
        try:
            result = subprocess.run(self.command(role, "rbw", *args),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=seconds, check=False)
        except subprocess.TimeoutExpired:
            raise Failure("CLI " + role + " " + args[0] + " timed out") from None
        self.check_private(result.stderr)
        if not plaintext:
            self.check_private(result.stdout)
        require((result.returncode == 0) == success,
                "CLI " + role + " " + args[0] + " had unexpected exit " + str(result.returncode))
        if not success:
            require(result.stdout == b"", "denied CLI emitted output")
        return result

    def start(self, role, name, *args):
        log = self.work / (role + "-" + name + ".log")
        with log.open("wb") as stream:
            process = subprocess.Popen(self.command(role, *args), stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=stream)
        self.processes.append(process)
        self.logs.append(log)
        return process

    def prepare_profiles(self):
        for role in ("requester", "approver"):
            home = self.work / role
            home.mkdir(mode=0o700)
            os.chown(home, self.user.pw_uid, self.user.pw_gid)
            runtime = home / "runtime"
            runtime.mkdir(mode=0o700)
            os.chown(runtime, self.user.pw_uid, self.user.pw_gid)
            name = role + "-" + self.identifier
            self.profiles[role] = {"home": home, "runtime": runtime, "name": name,
                                   "bus": "unix:path=" + str(runtime / "bus")}
            self.owned(home / "credentials.json", json.dumps({"password": self.password}))
            self.owned(home / "pinentry-allow", "allow\n")
            self.owned(home / "pinentry-events")
            self.owned(home / "opened-urls")
            self.owned(home / "notifications")
            config_dir = home / ".config" / ("rbw-" + name)
            config_dir.mkdir(parents=True, mode=0o700)
            for parent in (config_dir.parent, config_dir):
                os.chown(parent, self.user.pw_uid, self.user.pw_gid)
            # Only this new synthetic profile; no migration or real config access.
            self.owned(config_dir / "config.json", json.dumps({
                "email": self.email, "base_url": self.server,
                "pinentry": str(FIXTURE / "pinentry.py"), "face_auth": True,
                "sync_interval": 0, "l1_timeout": 600, "lock_timeout": 600,
                "ssh_agent": {"enabled": False}}))
            bus = self.start(role, "bus", "dbus-daemon", "--session", "--nofork",
                             "--address=" + self.profiles[role]["bus"])
            eventually(lambda: (runtime / "bus").is_socket() if bus.poll() is None else
                       require(False, "session bus exited"), "session bus readiness")
            ready = home / "notification-ready"
            service = self.start(role, "notifications", "python3", str(FIXTURE / "notifications.py"),
                                 str(ready), str(home / "notifications"))
            eventually(lambda: ready.exists() if service.poll() is None else
                       require(False, "notification fixture exited"), "notification readiness")
            agent = self.start(role, "agent", "rbw-agent", "--no-daemonize")
            self.profiles[role]["agent"] = agent
            sock = runtime / ("rbw-" + name) / "socket"
            eventually(lambda: sock.is_socket() if agent.poll() is None else
                       require(False, "agent exited"), "agent socket readiness")

    def register(self):
        # This matches rbw/src/identity.rs and cipherstring.rs; the server receives
        # real Bitwarden password hashes and authenticated encrypted account keys.
        master = hashlib.pbkdf2_hmac("sha256", self.password.encode(), self.email.encode(), 600000)
        password_hash = b64(hashlib.pbkdf2_hmac("sha256", master, self.password.encode(), 1))
        stretched = b"".join(hmac.new(master, label + b"\x01", hashlib.sha256).digest()
                             for label in (b"enc", b"mac"))
        user_key = os.urandom(64)
        self.private.extend([password_hash.encode(), user_key, b64(user_key).encode()])
        account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_der = account_key.private_bytes(serialization.Encoding.DER,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())
        public_der = account_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.account = {"server": self.server, "email": self.email, "run_id": self.identifier,
                        "password_hash": password_hash, "token": None, "account_id": None,
                        "registration_attempted": True, "registered": False}
        self.save_recovery()
        registration = http(self.server + "/api/accounts/register", "POST", {
            "email": self.email, "name": "rbwBio synthetic device acceptance",
            "masterPasswordHash": password_hash, "key": encrypted(stretched, user_key),
            "kdf": 0, "kdfIterations": 600000,
            "keys": {"publicKey": b64(public_der),
                     "encryptedPrivateKey": encrypted(user_key, private_der)}})
        if 400 <= registration[0] < 500:
            # A definite registration rejection created no account. Transport/5xx
            # ambiguity instead retains the private recovery credential.
            self.recovery.unlink()
            self.account = None
        parsed(registration, "synthetic registration")
        self.account["registered"] = True
        self.save_recovery()
        for role in ("requester", "approver"):
            self.cli(role, "login")
            self.cli(role, "unlocked")
            (self.profiles[role]["home"] / "pinentry-allow").write_text("deny\n")
        token = self.profile_token("approver")
        profile = parsed(http(self.server + "/api/accounts/profile", token=token), "synthetic profile")
        require(field(profile, "email") == self.email, "profile identity mismatch")
        self.account.update(token=token, account_id=field(profile, "id"))
        require(str(uuid.UUID(self.account["account_id"])) == self.account["account_id"],
                "invalid synthetic account UUID")
        self.save_recovery()
        # Real encrypted server item; neither local db nor authorization is seeded.
        cipher = parsed(http(self.server + "/api/ciphers", "POST", {
            "type": 1, "name": encrypted(user_key, b"Synthetic device acceptance"),
            "notes": None, "folderId": None, "organizationId": None,
            "favorite": False, "reprompt": 0,
            "login": {"username": encrypted(user_key, self.email.encode()),
                      "password": encrypted(user_key, self.secret), "uris": [], "totp": None}}, token),
                        "synthetic encrypted item creation")
        self.item = field(cipher, "id")
        require(str(uuid.UUID(self.item)) == self.item, "invalid synthetic item UUID")
        for role in ("requester", "approver"):
            self.cli(role, "sync")
        phase("synthetic account and encrypted item ready " + self.account["account_id"])

    def profile_token(self, role):
        root = self.profiles[role]["home"] / ".cache" / ("rbw-" + self.profiles[role]["name"])
        databases = list(root.glob("*.json"))
        require(len(databases) == 1, "expected one isolated synthetic profile database")
        database = json.loads(databases[0].read_text())
        token = database["access_token"]
        self.private.extend(value.encode() for value in (token, database.get("refresh_token", "")) if value)
        return token

    def open_ui(self):
        self.cli("approver", "ui")
        opened = self.profiles["approver"]["home"] / "opened-urls"
        eventually(lambda: opened.read_text().splitlines(), "UI browser-launch receipt")
        self.url = opened.read_text().splitlines()[-1]
        require(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+/[A-Za-z0-9_-]{43}/", self.url),
                "invalid local capability URL")
        self.origin = "http://" + urllib.parse.urlsplit(self.url).netloc
        require(not self.state()["locked"], "approver unexpectedly locked after login")

    def ui(self, path, method="GET", body=None):
        response = http(self.url + path, method, body, origin=self.origin)
        self.check_private(response[1])
        return response

    def state(self):
        state = parsed(self.ui("api/state"), "GUI state")
        require(set(state) == {"version", "profile", "server", "locked", "desktop", "remote", "requests"},
                "GUI state exposed undocumented fields")
        allowed = {"id", "kind", "operation", "status", "fingerprint", "device_type", "ip_address",
                   "country_name", "created_at", "finished_at", "message"}
        require(all(set(request) <= allowed for request in state["requests"]),
                "GUI request exposed undocumented/private fields")
        require(state["profile"] == "rbw-" + self.profiles["approver"]["name"],
                "GUI served the wrong profile")
        return state

    def request_state(self, request_id):
        return next((record for record in self.state()["requests"]
                     if record["kind"] == "device" and record["id"] == request_id), None)

    def server_request(self, request_id):
        return http(self.server + "/api/auth-requests/" + request_id,
                    token=self.profile_token("approver"))

    def server_pending(self, request_id):
        record = parsed(self.server_request(request_id), "authenticated server request")
        require(field(record, "requestApproved") is None and not field(record, "key")
                and field(record, "responseDate") is None,
                "server released a key or answered without explicit review/PAM")
        return record

    def events(self):
        return (CONTROL / "events").read_text().splitlines()

    def result(self, value):
        path = CONTROL / "result.next"
        path.write_text(value + "\n")
        path.chmod(0o644)
        path.replace(CONTROL / "result")

    def new_request(self):
        self.cli("requester", "lock")
        self.cli("requester", "unlocked", success=False)
        self.cli("requester", "get", self.item, success=False)
        self.sequence += 1
        output = self.work / ("unlock-" + str(self.sequence) + ".out")
        error = self.work / ("unlock-" + str(self.sequence) + ".err")
        with output.open("wb") as out, error.open("wb") as err:
            process = subprocess.Popen(self.command("requester", "rbw", "unlock", "--device"),
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        self.processes.append(process)
        self.logs.append(error)
        def pending():
            self.check_private(error.read_bytes())
            text = error.read_text()
            match = re.search(r"^Auth request: ([0-9a-f-]{36})$", text, re.MULTILINE)
            fingerprint = re.search(r"^Fingerprint: ([a-z]+(?:-[a-z]+){4})$", text, re.MULTILINE)
            if match and fingerprint:
                return match.group(1), fingerprint.group(1)
            require(process.poll() is None, "requester exited before pending request")
            return None
        request_id, fingerprint = eventually(pending, "requester pending output")
        require(str(uuid.UUID(request_id)) == request_id, "request UUID not canonical")
        baseline = self.server_pending(request_id)
        def discovered():
            require(process.poll() is None, "requester finished before GUI review")
            record = self.request_state(request_id)
            if record:
                require(record["status"] == "pending_review", "GUI auto-processed an unreviewed request")
                require(record["fingerprint"] == fingerprint, "requester/GUI fingerprints differ")
                require(record["device_type"] and record["ip_address"] and record["created_at"],
                        "GUI omitted device provenance")
                return record
            return None
        eventually(discovered, "background GET discovery")
        phase("pending " + request_id + " " + fingerprint)
        return {"id": request_id, "fingerprint": fingerprint, "process": process,
                "out": output, "err": error, "baseline": baseline}

    def unchanged(self, request, before, seconds=3):
        deadline = time.monotonic() + seconds
        while True:
            require(self.events() == before, "unreviewed/invalid approval invoked native PAM")
            require(request["process"].poll() is None, "unreviewed requester completed")
            require(self.server_pending(request["id"]) == request["baseline"],
                    "invalid/non-mutating action changed server authorization state")
            self.cli("requester", "unlocked", success=False)
            if time.monotonic() >= deadline:
                break
            time.sleep(0.2)

    def decide(self, request, action, fingerprint=None):
        body = {} if fingerprint is None else {"fingerprint": fingerprint}
        return self.ui("api/requests/device/" + request["id"] + "/" + action, "POST", body)

    def final_status(self, request, expected):
        def settled():
            record = self.request_state(request["id"])
            require(record is not None, "GUI lost active request")
            if record["status"] in ("pending_review", "authenticating"):
                return False
            require(record["status"] == expected, "GUI decision had unexpected terminal state")
            return True
        eventually(settled, "GUI " + expected + " state")

    def wait_requester(self, request, approved):
        try:
            result = request["process"].wait(timeout=25)
        except subprocess.TimeoutExpired:
            raise Failure("requester did not finish after explicit server decision") from None
        self.check_private(request["err"].read_bytes())
        require(request["out"].read_bytes() == b"", "unlock emitted unexpected output")
        require((result == 0) == approved, "requester decision exit status incorrect")
        self.cli("requester", "unlocked", success=approved)
        if not approved:
            self.cli("requester", "get", self.item, success=False)

    def reject(self, request):
        before = self.events()
        parsed(self.decide(request, "reject"), "explicit GUI rejection")
        self.final_status(request, "rejected")
        self.wait_requester(request, False)
        status, raw = self.server_request(request["id"])
        if status == 200:
            record = json.loads(raw)
            require(field(record, "requestApproved") is False and not field(record, "key"),
                    "server rejection retained or released an approval key")
        else:
            require(status in (400, 404, 410), "unexpected rejected-request server response")
        require(self.events() == before, "rejection invoked PAM")

    def exercise(self):
        self.open_ui()
        phase("read-only discovery and notification Open")
        self.result("success")  # Unconditional approval would now genuinely unlock.
        before = self.events()
        first = self.new_request()
        for asset in ("", "app.js", "style.css"):
            response = self.ui(asset)
            require(response[0] == 200 and response[1], "request-page asset unavailable")
        self.cli("approver", "auth-request", "list", "--raw")
        receipt = self.profiles["approver"]["home"] / "notifications"
        def notification():
            records = [json.loads(line) for line in receipt.read_text().splitlines()]
            return next((record for record in reversed(records)
                         if set(record["actions"][::2]) == {"default", "open"}), None)
        notice = eventually(notification, "actionable pending notification")
        require(set(notice["actions"][::2]) == {"default", "open"},
                "notification exposed authorization actions or omitted Open")
        opened = self.profiles["approver"]["home"] / "opened-urls"
        count = len(opened.read_text().splitlines())
        result = subprocess.run(self.command("approver", "gdbus", "call", "--session",
            "--dest", "org.freedesktop.Notifications", "--object-path", "/org/freedesktop/Notifications",
            "--method", "org.rbwBio.DeviceApprovalFixture.Activate", str(notice["id"]), "open"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
        require(result.returncode == 0, "notification Open signal failed")
        eventually(lambda: len(opened.read_text().splitlines()) > count, "native notification Open handler")
        require(opened.read_text().splitlines()[-1] == self.url + "#device=" + first["id"],
                "notification opened wrong request detail")
        require(self.ui("")[0] == 200, "notification detail GET failed")
        self.unchanged(first, before)
        phase("wrong fingerprint is side-effect free; explicit rejection")
        words = first["fingerprint"].split("-")
        words[0] = "different" if words[0] == "wrong" else "wrong"
        wrong = "-".join(words)
        response = self.decide(first, "approve", wrong)
        require(400 <= response[0] < 500, "wrong fingerprint was accepted")
        self.unchanged(first, before)
        require(self.request_state(first["id"])["status"] == "pending_review",
                "wrong fingerprint consumed pending review")
        self.reject(first)
        phase("stale fingerprint then explicit approval held at native PAM")
        second = self.new_request()
        require(second["fingerprint"] != first["fingerprint"], "fresh request reused old fingerprint")
        before = self.events()
        response = self.decide(second, "approve", first["fingerprint"])
        require(400 <= response[0] < 500, "stale fingerprint was accepted")
        self.unchanged(second, before)
        self.result("wait")
        parsed(self.decide(second, "approve", second["fingerprint"]), "exact fingerprint approval")
        def pam_started():
            events = self.events()
            require(events[:len(before)] == before, "PAM receipt history changed")
            if len(events) == len(before):
                return False
            require(len(events) == len(before) + 1 and events[-1].startswith("entered "),
                    "unexpected PAM verdict before fixture release")
            return True
        eventually(pam_started, "explicit approval native PAM entry", 15)
        self.unchanged(second, self.events(), seconds=2)
        self.result("success")
        self.final_status(second, "approved")
        self.wait_requester(second, True)
        events = self.events()[len(before):]
        require(len(events) == 2 and events[0].split()[0] == "entered" and
                events[1].split()[0] == "success" and events[0].split()[1] == events[1].split()[1],
                "approval did not traverse exactly one native PAM success")
        approved = parsed(self.server_request(second["id"]), "server approval receipt")
        require(field(approved, "requestApproved") is True and field(approved, "responseDate")
                and isinstance(field(approved, "key"), str) and field(approved, "key").startswith("4."),
                "server did not persist an RSA encrypted User Key approval")
        # This is actual requester CLI decryption, not a counter or seeded db check.
        result = self.cli("requester", "get", self.item, plaintext=True)
        require(result.stdout == self.secret + b"\n", "actual requester decrypted a different synthetic secret")
        phase("requester decrypts exact synthetic secret after server token exchange")
        self.result("success")
        third = self.new_request()
        approver_pinentry = self.profiles["approver"]["home"] / "pinentry-events"
        pinentry_before = approver_pinentry.read_bytes()
        self.cli("approver", "lock")
        self.cli("approver", "unlocked", success=False)
        require(self.state()["locked"], "GUI did not reflect locked approver")
        before = self.events()
        response = self.decide(third, "approve", third["fingerprint"])
        if 200 <= response[0] < 300:
            self.final_status(third, "failed")
        else:
            require(400 <= response[0] < 500, "locked approval returned unexpected HTTP status")
        self.unchanged(third, before)
        require(self.state()["locked"], "approval implicitly unlocked approver")
        require(approver_pinentry.read_bytes() == pinentry_before,
                "locked approval implicitly invoked password pinentry")
        # Refresh explicitly re-enables review after the failed locked attempt.
        parsed(self.ui("api/refresh", "POST", {}), "refresh locked failed request")
        eventually(lambda: self.request_state(third["id"])["status"] == "pending_review",
                   "failed request review reset")
        self.reject(third)
        phase("locked approver fails closed without PAM or server update")
        self.ordinary_cli_approval()
        for role in self.profiles:
            require((self.profiles[role]["home"] / "pinentry-events").read_text().splitlines().count("GETPIN") >= 1,
                    "profile never completed initial real password login")
        for role in self.profiles:
            self.profile_token(role)
        for log in self.logs:
            self.check_private(log.read_bytes())

    def ordinary_cli_approval(self):
        """Remote approvals still require PAM in an ordinary, fresh CLI session."""
        phase("fresh ordinary approver CLI approval without opening UI")
        request = self.new_request()
        profile = self.profiles["approver"]
        self.cli("approver", "stop-agent")
        eventually(lambda: profile["agent"].poll() is not None, "old approver agent exit")
        config_path = profile["home"] / ".config" / ("rbw-" + profile["name"]) / "config.json"
        config = json.loads(config_path.read_text())
        config["face_auth"] = False
        config_path.write_text(json.dumps(config))
        profile["agent"] = self.start("approver", "ordinary-agent", "rbw-agent", "--no-daemonize")
        sock = profile["runtime"] / ("rbw-" + profile["name"]) / "socket"
        eventually(lambda: sock.is_socket() if profile["agent"].poll() is None else
                   require(False, "ordinary approver agent exited"), "ordinary agent socket readiness")
        # Restarting discards in-memory keys. This is a local password unlock,
        # not another server login or a seeded User Key; no UI command is used.
        (profile["home"] / "pinentry-allow").write_text("allow\n")
        try:
            self.cli("approver", "unlock")
        finally:
            (profile["home"] / "pinentry-allow").write_text("deny\n")
        self.cli("approver", "unlocked")
        opened_before = (profile["home"] / "opened-urls").read_bytes()
        before = self.events()
        self.result("wait")
        approval = self.start("approver", "ordinary-approve", "rbw",
                              "auth-request", "approve", request["id"])
        approval_log = self.work / "approver-ordinary-approve.log"
        def native_entry():
            require(approval.poll() is None, "ordinary CLI approval exited before native PAM")
            events = self.events()
            if len(events) == len(before):
                return False
            require(events[:len(before)] == before and len(events) == len(before) + 1
                    and events[-1].startswith("entered "), "unexpected ordinary approval PAM event")
            return True
        eventually(native_entry, "ordinary CLI native PAM entry", 15)
        self.unchanged(request, self.events(), seconds=2)
        text = approval_log.read_text()
        require("Request: " + request["id"] in text and
                "Fingerprint: " + request["fingerprint"] in text,
                "ordinary CLI omitted exact explicit approval review metadata")
        require((profile["home"] / "opened-urls").read_bytes() == opened_before,
                "ordinary CLI approval unexpectedly opened a browser")
        self.result("success")
        try:
            code = approval.wait(timeout=25)
        except subprocess.TimeoutExpired:
            raise Failure("ordinary CLI approval did not complete") from None
        require(code == 0, "ordinary CLI approval failed")
        self.check_private(approval_log.read_bytes())
        events = self.events()[len(before):]
        require(len(events) == 2 and events[0].split()[0] == "entered" and
                events[1].split()[0] == "success" and events[0].split()[1] == events[1].split()[1],
                "ordinary device approval bypassed fresh native PAM")
        approved = parsed(self.server_request(request["id"]), "ordinary CLI server approval")
        require(field(approved, "requestApproved") is True and field(approved, "responseDate")
                and isinstance(field(approved, "key"), str) and field(approved, "key").startswith("4."),
                "ordinary CLI did not persist a real encrypted approval")
        self.wait_requester(request, True)
        result = self.cli("requester", "get", self.item, plaintext=True)
        require(result.stdout == self.secret + b"\n",
                "ordinary-approver round trip decrypted a different secret")
        phase("ordinary approver CLI still requires PAM and completes real decryption")

    def cleanup_account(self):
        if self.account is None:
            return
        # Authenticate only credentials generated for this invocation, never an
        # arbitrary email or pre-existing user. Works even if initial CLI login failed.
        token = self.account.get("token")
        if not token or http(self.server + "/api/accounts/profile", token=token)[0] == 401:
            login = parsed(http(self.server + "/identity/connect/token", "POST", {
                "grant_type": "password", "scope": "api offline_access", "client_id": "cli",
                "deviceType": 8, "deviceName": "rbwBio disposable cleanup",
                "deviceIdentifier": str(uuid.uuid4()), "username": self.email,
                "password": self.account["password_hash"]}, form=True), "synthetic cleanup login")
            token = login["access_token"]
            self.account["token"] = token
            self.save_recovery()
        profile = parsed(http(self.server + "/api/accounts/profile", token=token), "cleanup identity")
        require(field(profile, "email") == self.email and
                (not self.account["account_id"] or field(profile, "id") == self.account["account_id"]),
                "refusing cleanup for a different account")
        self.account["account_id"] = field(profile, "id")
        self.save_recovery()
        status, _ = http(self.server + "/api/accounts/delete", "POST",
                         {"masterPasswordHash": self.account["password_hash"]}, token)
        require(200 <= status < 300, "authenticated synthetic account deletion failed")
        # The same normal authenticated profile endpoint must now reject its token.
        require(http(self.server + "/api/accounts/profile", token=token)[0] in (400, 401, 403, 404),
                "deleted synthetic account still authenticates")
        self.recovery.unlink()
        phase("authenticated synthetic account deletion confirmed " + self.account["account_id"])

    def close(self):
        # Stop only our two profiles before deleting their account.
        for role in self.profiles:
            try:
                self.cli(role, "stop-agent", seconds=5)
            except Failure:
                pass
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        try:
            self.cleanup_account()
        finally:
            shutil.rmtree(self.work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and pathlib.Path("/.dockerenv").exists()
            and (FIXTURE / "DISPOSABLE-ONLY").is_file(), "use only the dedicated disposable Docker image")
    require(not pathlib.Path("/etc/pam.d/rbw-device-auth").exists(), "refusing to replace existing PAM policy")
    os.umask(0o077)
    CONTROL.mkdir(mode=0o755)
    CONTROL.chmod(0o755)
    events = CONTROL / "events"
    events.touch(mode=0o666)
    events.chmod(0o666)
    pathlib.Path("/etc/pam.d/rbw-device-auth").write_text(
        "#%PAM-1.0\nauth required /usr/lib/security/pam_howdy.so\naccount required pam_permit.so\n")
    pathlib.Path("/etc/pam.d/rbw-device-auth").chmod(0o644)
    harness = Harness(args.server)
    def interrupted(signum, frame):
        raise Failure("interrupted; deleting only this run's synthetic account")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    failure = None
    try:
        phase("isolated profiles and native test-only PAM; no hardware assurance")
        def ready():
            try:
                return http(args.server.rstrip("/") + "/api/config")[0] == 200
            except Failure:
                return False
        eventually(ready, "real server readiness", 60)
        harness.result("success")
        harness.prepare_profiles()
        harness.register()
        harness.exercise()
    except Exception as error:
        # Never interpolate raw HTTP, CLI, JSON or crypto exception strings.
        failure = str(error) if isinstance(error, Failure) else (
            "fixture operation failed [" + type(error).__name__ + "] (private diagnostics suppressed)")
    finally:
        try:
            harness.close()
        except Exception:
            print("device-approval: cleanup incomplete; private account-recovery.json retained", file=sys.stderr)
            failure = failure or "synthetic account cleanup failed"
    if failure:
        print("device-approval: FAIL: " + failure, file=sys.stderr)
        return 1
    phase("PASS full protocol and explicit-review negative cases")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("device-approval: FAIL: unsafe container setup or invalid arguments", file=sys.stderr)
        sys.exit(1)
