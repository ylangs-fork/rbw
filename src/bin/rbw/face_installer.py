# Offline configuration/enrollment only. rbw first authenticates the complete
# prebuilt runtime and this helper in separately checked root-owned snapshots.
import configparser
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import select
import signal
import time


RUNTIME = Path("/usr/lib/security/rbw-howdy/runtime")
BASE = Path("/usr/lib/security/rbw-howdy")
CONF = Path("/etc/rbw-howdy")
MODULE = BASE / "pam_howdy.so"
TRANSACTION = CONF / ".onboarding"
ENV = {"PATH": str(RUNTIME / "bin") + ":/usr/sbin:/usr/bin:/sbin:/bin",
       "HOME": "/root", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}

# Executed only by the authenticated private interpreter, never from a user file.
# Tap Howdy's existing recorder; do not open another camera or alter its frames.
ENROLLMENT_PREVIEW = r"""
import json
import os
import runpy
import select
import sys
import time

protocol = sys.stdout
sys.stdout = sys.stderr
HOWDY = "/usr/lib/security/rbw-howdy/howdy"
if HOWDY not in sys.path:
    sys.path.insert(0, HOWDY)

# Match add.py's import order for the bundled native libraries.
import dlib
import cv2
from recorders.video_capture import VideoCapture
from rotation import rotate_frame


def check_cancelled():
    descriptor = sys.stdin.fileno()
    if select.select([descriptor], [], [], 0)[0] and os.read(descriptor, 1) == b"":
        raise RuntimeError("face enrollment cancelled")


original_read_frame = VideoCapture.read_frame


def preview_read_frame(self, frame_number=None):
    check_cancelled()
    result = original_read_frame(self)
    check_cancelled()
    if frame_number is None:
        frame_number = getattr(self, "_rbw_preview_frame_number", 0) + 1
    self._rbw_preview_frame_number = frame_number
    now = time.monotonic()
    preview_due = now - getattr(self, "_rbw_preview_last_frame", float("-inf")) >= 0.1
    # Use the same one-based frame number as Howdy, including rotation modes 1/2.
    frame = rotate_frame(result[0], self.config.getint("video", "rotate", fallback=0),
                         frame_number)
    grayscale = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    if not hasattr(self, "_rbw_preview_clahe"):
        self._rbw_preview_clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    histogram = cv2.calcHist([self._rbw_preview_clahe.apply(grayscale)],
                             [0], None, [8], [0, 256])
    darkness = float(histogram[0, 0] / histogram.sum() * 100)
    threshold = self.config.getfloat("video", "dark_threshold", fallback=60.0)
    self._rbw_enrollment_darkness = darkness
    if not preview_due:
        return result

    # Pulsed IR can alternate lit/black at 15 fps. A 10 Hz telemetry cap can
    # repeatedly select black frames; leave the next lit frame eligible instead.
    # Still publish sustained blackouts once a second rather than freeze.
    if darkness == 100.0 and now - getattr(self, "_rbw_preview_last_frame", float("-inf")) < 1.0:
        return result

    message = "RBWBIO_PREVIEW " + json.dumps(
        {"darkness": darkness, "threshold": threshold},
        separators=(",", ":"), allow_nan=False)
    if len(message.encode("utf-8")) + 1 > 4096:
        raise RuntimeError("face enrollment telemetry exceeds protocol limit")
    print(message, file=protocol, flush=True)
    self._rbw_preview_last_frame = time.monotonic()
    return result


def enrollment_read_frame(self):
    # Howdy add's 60-frame limit must count usable frames, not IR-off pulses.
    # Keep its detector, single-face check, encoder and model format unchanged.
    if not hasattr(self, "_rbw_enrollment_deadline"):
        self._rbw_enrollment_deadline = time.monotonic() + 30.0
        self._rbw_enrollment_frames = 0
        self._rbw_enrollment_black = 0
        self._rbw_enrollment_dark = 0
    number = self._rbw_enrollment_frames + 1
    while time.monotonic() < self._rbw_enrollment_deadline:
        result = preview_read_frame(self, number)
        if time.monotonic() >= self._rbw_enrollment_deadline:
            break
        darkness = self._rbw_enrollment_darkness
        if darkness == 100.0:
            self._rbw_enrollment_black += 1
        elif darkness > self.config.getfloat("video", "dark_threshold", fallback=60.0):
            self._rbw_enrollment_dark += 1
        else:
            self._rbw_enrollment_frames += 1
            return result
    check_cancelled()
    if self._rbw_enrollment_frames:
        reason = "not enough usable frames"
    elif self._rbw_enrollment_dark:
        reason = "all illuminated frames were too dark"
    else:
        reason = "camera yielded only black frames"
    raise RuntimeError("face enrollment timed out after 30 seconds: " + reason)


VideoCapture.read_frame = enrollment_read_frame
sys.argv = [HOWDY + "/cli.py"] + sys.argv[1:]
check_cancelled()
runpy.run_path(HOWDY + "/cli.py", run_name="__main__")
# A cancellation during encoding/model writing must still roll the model back.
check_cancelled()
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def trusted(path):
    path = Path(path)
    require(path.is_absolute(), "non-absolute system path")
    for entry in [*reversed(path.parents), path]:
        metadata = entry.lstat()
        require(metadata.st_uid == 0, str(entry) + " is not root-owned")
        require(stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & 0o022 == 0,
                str(entry) + " is writable by a non-root user")
    resolved = path.resolve(strict=True)
    if resolved != path:
        trusted(resolved)
    return resolved


def run(*args, timeout=1200, capture=False, cwd=None, preview=False):
    trusted(args[0])
    if not preview:
        return subprocess.run(args, check=True, env=ENV, stdin=sys.stdin,
                              stdout=subprocess.PIPE if capture else sys.stderr,
                              stderr=sys.stderr, timeout=timeout, text=capture, cwd=cwd).stdout
    # The privileged supervisor watches cancellation independently of camera
    # reads. A blocked driver must not leave a recorder or its children alive.
    with subprocess.Popen(args, env=ENV, stdin=sys.stdin, stdout=sys.stdout,
                          stderr=sys.stderr, cwd=cwd, start_new_session=True) as child:
        deadline = time.monotonic() + timeout
        try:
            while True:
                if select.select([sys.stdin], [], [], 0)[0] and os.read(sys.stdin.fileno(), 1) == b"":
                    raise RuntimeError("face enrollment cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    status = child.wait(timeout=min(0.05, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
            if status:
                raise RuntimeError("face enrollment failed (exit status: " + str(status) + ")")
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            raise


def configure():
    # The archive is authenticated before extraction, without executing Python.
    # Existing source-only markers do not authorize changing a foreign install.
    trusted(BASE / "bundle-manifest.json")
    trusted(BASE / ".rbw-bundle-sha256")
    trusted(BASE / ".rbw-managed")
    manifest = json.loads((BASE / "bundle-manifest.json").read_text())
    checksum = (BASE / ".rbw-bundle-sha256").read_text().strip()
    require(manifest.get("schema") == 1 and manifest.get("platform") == "linux-x86_64-ubuntu22.04"
            and isinstance(manifest.get("version"), str) and
            re.fullmatch(r"[a-f0-9]{64}", checksum), "invalid installed prebuilt face runtime identity")
    marker = json.dumps({"version": manifest["version"], "platform": manifest["platform"],
                         "sha256": checksum}, sort_keys=True) + "\n"
    for path in (MODULE, RUNTIME / "bin/python3", RUNTIME / "bin/v4l2-ctl",
                 RUNTIME / "bin/notify-send", BASE / "default-config.ini"):
        trusted(path)
    def regular(path):
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                "unsafe managed configuration file: " + str(path))
    if CONF.exists() or CONF.is_symlink():
        require(not CONF.is_symlink() and CONF.is_dir(),
                "foreign isolated configuration directory")
        trusted(CONF / ".rbw-managed")
        require((CONF / ".rbw-managed").read_text() == marker,
                "foreign or different-version Howdy configuration; refusing to overwrite it")
        trusted(CONF / "config.ini")
        trusted(CONF / "models")
        regular(CONF / ".rbw-managed")
        regular(CONF / "config.ini")
        require(not (CONF / "models").is_symlink() and (CONF / "models").is_dir(),
                "foreign isolated model directory")
        return False
    trusted("/etc")
    CONF.mkdir(mode=0o755)
    try:
        shutil.copyfile(BASE / "default-config.ini", CONF / "config.ini")
        os.chmod(CONF / "config.ini", 0o644)
        (CONF / "models").mkdir(mode=0o755)
        (CONF / ".rbw-managed").write_text(marker)
        os.chmod(CONF / ".rbw-managed", 0o644)
    except BaseException:
        shutil.rmtree(CONF)
        raise
    return True


def camera():
    candidates = []
    for sysdevice in sorted(Path("/sys/class/video4linux").glob("video*")):
        device = Path("/dev") / sysdevice.name
        require(stat.S_ISCHR(device.stat().st_mode), "camera path is not a character device")
        try:
            formats = run(str(RUNTIME / "bin/v4l2-ctl"), "--device=" + str(device), "--list-formats-ext", capture=True)
        except subprocess.CalledProcessError:
            continue
        formats = re.findall(r"'(.{4})'", formats)
        # Never fall back to an ordinary RGB/YUYV webcam or metadata node.
        monochrome = [value for value in formats if value in ("GREY", "Y8  ", "Y10 ", "Y12 ", "Y16 ")]
        if not monochrome:
            continue
        stable = next((path for path in sorted(Path("/dev/v4l/by-path").glob("*"))
                       if path.resolve() == device.resolve()), device)
        pixel_format = monochrome[0].strip()
        candidates.append((str(stable), pixel_format if pixel_format.startswith(("Y10", "Y12", "Y16")) else ""))
    require(len(candidates) == 1,
            "cannot select one unambiguous monochrome/IR camera (found " + str(len(candidates)) +
            "); RGB fallback and guessing are unsafe; unsupported camera configuration")
    return candidates[0]


def rollback():
    trusted(TRANSACTION)
    state = json.loads((TRANSACTION / "state.json").read_text())
    for name, destination in (("config", CONF / "config.ini"),
                              ("model", CONF / "models" / (state["user"] + ".dat"))):
        backup = TRANSACTION / name
        if backup.exists():
            shutil.copy2(backup, destination)
            os.chown(destination, 0, state["model_gid"] if name == "model" else state["config_gid"])
        elif name == "model" and destination.exists():
            destination.unlink()
    shutil.rmtree(TRANSACTION)
    if state.get("created_config"):
        # Only this transaction's new isolated configuration is removed.
        shutil.rmtree(CONF)


def desktop_camera_access(device, account, owner_pid):
    # Check with the running desktop process's actual groups, not root's camera
    # access or a group assignment that would require a new login to take effect.
    status = dict(line.split(":", 1) for line in
                  Path("/proc", str(owner_pid), "status").read_text().splitlines()
                  if ":" in line)
    require(all(int(uid) == account.pw_uid for uid in status["Uid"].split()),
            "enrollment owner is not the ordinary desktop user")
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([int(group) for group in status["Groups"].split()])
            os.setgid(int(status["Gid"].split()[0]))
            os.setuid(account.pw_uid)
            descriptor = os.open(device, os.O_RDWR | os.O_NONBLOCK)
            os.close(descriptor)
            os._exit(0)
        except BaseException:
            os._exit(1)
    _, result = os.waitpid(child, 0)
    require(os.WIFEXITED(result) and os.WEXITSTATUS(result) == 0,
            "your active desktop user cannot access the camera; no permissions or groups were changed")


def prepare(user, owner_pid):
    account = pwd.getpwnam(user)
    require(account.pw_uid > 0 and account.pw_uid == int(sys.argv[3]), "invalid enrollment account")
    created_config = configure()
    trusted(CONF)
    if TRANSACTION.exists():
        trusted(TRANSACTION / "state.json")
        previous = json.loads((TRANSACTION / "state.json").read_text())
        # Automatically recover an interrupted wizard, but never steal a live one.
        require(not Path("/proc", str(previous["pid"])).exists(), "another face setup is still running")
        rollback()
        created_config = configure()
    model = CONF / "models" / (user + ".dat")
    trusted(CONF / "config.ini")
    trusted(CONF / "models")
    if model.exists() or model.is_symlink():
        trusted(model)
        require(not model.is_symlink() and model.is_file() and model.stat().st_nlink == 1,
                "unsafe existing face model")
    TRANSACTION.mkdir(mode=0o700)
    state = {"user": user, "pid": owner_pid, "config_gid": (CONF / "config.ini").stat().st_gid,
             "model_gid": model.stat().st_gid if model.exists() else account.pw_gid,
             "created_config": created_config}
    (TRANSACTION / "state.json").write_text(json.dumps(state))
    shutil.copy2(CONF / "config.ini", TRANSACTION / "config")
    if model.exists():
        shutil.copy2(model, TRANSACTION / "model")
    try:
        device, pixel_format = camera()
        desktop_camera_access(device, account, owner_pid)
        print("Selected monochrome/IR camera: " + device + ". Look into the camera for enrollment.", file=sys.stderr, flush=True)
        config = configparser.ConfigParser()
        config.read(CONF / "config.ini")
        for section, key, value in [
            ("video", "device_path", device), ("video", "pixel_format", pixel_format),
            ("video", "timeout", "10"), ("core", "workaround", "off"),
            ("core", "disabled", "false"), ("core", "use_cnn", "false"),
            ("snapshots", "save_failed", "false"), ("snapshots", "save_successful", "false"),
        ]:
            config.set(section, key, value)
        with open(CONF / "config.ini", "w") as output:
            config.write(output)
        old_umask = os.umask(0o077)
        try:
            trusted(BASE / "howdy")
            trusted(BASE / "howdy" / "cli.py")
            deadline = time.monotonic() + 90
            for sample in range(5):
                remaining = deadline - time.monotonic()
                require(remaining > 0, "face enrollment timed out")
                print("Recording face sample " + str(sample + 1) + "/5. Keep looking at the camera.",
                      file=sys.stderr, flush=True)
                run(str(RUNTIME / "bin/python3"), "-B", "-s", "-E", "-c", ENROLLMENT_PREVIEW,
                    "-U", user, "-y", "add", "rbw face", timeout=remaining, preview=True)
        finally:
            os.umask(old_umask)
        trusted(model)
        os.chown(model, 0, account.pw_gid)
        os.chmod(model, 0o640)
        print(device)
    except BaseException:
        rollback()
        raise


def main():
    require(os.geteuid() == 0, "installer requires explicit system privilege")
    os.umask(0o022)
    require(len(sys.argv) == 5, "invalid installer invocation")
    action, user, uid, pid = sys.argv[1:]
    require(re.fullmatch(r"[a-zA-Z0-9_.-]+", user) is not None and not user.startswith("-"), "invalid login user")
    require(pwd.getpwnam(user).pw_uid == int(uid) and int(uid) > 0, "invalid normal user")
    trusted("/etc")
    lock_fd = os.open("/etc/.rbw-face-setup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    lock_metadata = os.fstat(lock_fd)
    require(stat.S_ISREG(lock_metadata.st_mode) and lock_metadata.st_uid == 0 and
            lock_metadata.st_mode & 0o077 == 0 and lock_metadata.st_nlink == 1, "unsafe setup lock")
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if action == "prepare":
        prepare(user, int(pid))
    elif action in ("rollback", "commit"):
        trusted(TRANSACTION / "state.json")
        state = json.loads((TRANSACTION / "state.json").read_text())
        require(state["user"] == user and state["pid"] == int(pid), "setup transaction owner changed")
        if action == "rollback":
            rollback()
        else:
            shutil.rmtree(TRANSACTION)
    else:
        raise RuntimeError("unknown installer operation")


try:
    main()
except BaseException as error:
    print("rbw face activation failed: " + str(error), file=sys.stderr)
    sys.exit(1)
