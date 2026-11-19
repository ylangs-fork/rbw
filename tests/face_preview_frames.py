#!/usr/bin/python3
"""Exercise the embedded enrollment adapter without root, hardware, or model data."""
import ast
import configparser
import io
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import cv2
import numpy as np


HELPER = Path(__file__).resolve().parents[1] / "src/bin/rbw/face_installer.py"
ADAPTER = next(
    ast.literal_eval(node.value)
    for node in ast.parse(HELPER.read_text()).body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "ENROLLMENT_PREVIEW"
            for target in node.targets)
)
HOWDY = "/usr/lib/security/rbw-howdy/howdy"


def rotated(frame, mode, number):
    # The pinned Howdy rotation modes, including their one-based read counter.
    code = None
    if mode == 1:
        code = {1: cv2.ROTATE_90_COUNTERCLOCKWISE,
                2: cv2.ROTATE_90_CLOCKWISE}.get(number % 3)
    elif mode == 2:
        code = (cv2.ROTATE_90_COUNTERCLOCKWISE if number % 2 == 0
                else cv2.ROTATE_90_CLOCKWISE)
    elif mode == 3:
        code = cv2.ROTATE_90_COUNTERCLOCKWISE
    elif mode == 4:
        code = cv2.ROTATE_90_CLOCKWISE
    return frame if code is None else cv2.rotate(frame, code)


def expected_darkness(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    histogram = cv2.calcHist([gray], [0], None, [8], [0, 256])
    return float(histogram[0, 0] / np.sum(histogram) * 100)


class AdapterHarness:
    def __init__(self, results, rotate=0, threshold=None):
        self.results = results
        self.reads = 0
        self.captures = []
        self.clock = 0.0
        self.rotations = []
        self.before_return = None
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.config = configparser.ConfigParser()
        self.config["video"] = {"rotate": str(rotate)}
        if threshold is not None:
            self.config.set("video", "dark_threshold", str(threshold))
        read_fd, self.write_fd = os.pipe()
        self.stdin = os.fdopen(read_fd)
        harness = self

        class VideoCapture:
            def __init__(self, config):
                self.config = config
                harness.captures.append(self)

            def read_frame(self):
                result = harness.results[harness.reads]
                harness.reads += 1
                if harness.before_return:
                    harness.before_return()
                return result

        self.capture_type = VideoCapture

    def cancel(self):
        if self.write_fd is not None:
            os.close(self.write_fd)
            self.write_fd = None

    def messages(self):
        messages = []
        for line in self.output.getvalue().splitlines():
            assert line.startswith("RBWBIO_PREVIEW "), line
            assert len(line.encode("utf-8")) + 1 <= 4096
            messages.append(json.loads(line.removeprefix("RBWBIO_PREVIEW ")))
            assert set(messages[-1]) == {"darkness", "threshold"}
        return messages

    def run(self, body, *, enrollment=False):
        def rotate(frame, mode, number):
            self.rotations.append((mode, number))
            return rotated(frame, mode, number)

        def run_path(path, run_name):
            print("Howdy console output")
            capture = self.capture_type(self.config)
            if not enrollment:
                capture.read_frame = types.MethodType(namespace["preview_read_frame"], capture)
            body(capture)

        recorders = types.ModuleType("recorders")
        recorders.__path__ = []
        modules = {
            "dlib": types.ModuleType("dlib"),
            "recorders": recorders,
            "recorders.video_capture": types.SimpleNamespace(VideoCapture=self.capture_type),
            "rotation": types.SimpleNamespace(rotate_frame=rotate),
            "runpy": types.SimpleNamespace(run_path=run_path),
            "time": types.SimpleNamespace(monotonic=lambda: self.clock),
        }
        namespace = {"__name__": "__main__"}
        try:
            with mock.patch.dict(sys.modules, modules), \
                    mock.patch.object(sys, "stdin", self.stdin), \
                    mock.patch.object(sys, "stdout", self.output), \
                    mock.patch.object(sys, "stderr", self.errors), \
                    mock.patch.object(sys, "argv", ["-c", "-U", "example", "-y", "add", "rbw face"]), \
                    mock.patch.object(sys, "path", ["/trusted/private-stdlib", HOWDY]):
                exec(compile(ADAPTER, "<enrollment-preview-test>", "exec"), namespace)
        finally:
            self.cancel()
            self.stdin.close()


class PreviewFramesTest(unittest.TestCase):
    def test_same_result_identity_darkness_and_unmodified_source(self):
        source = np.full((96, 160, 3), 9, dtype=np.uint8)
        source[:, 120:] = 180
        gray = cv2.cvtColor(source, cv2.COLOR_BGR2GRAY)
        original_source, original_gray = source.copy(), gray.copy()
        result = (source, gray)
        harness = AdapterHarness([result], threshold=57.5)

        def enroll(capture):
            self.assertIs(capture.read_frame(), result)

        harness.run(enroll)
        self.assertEqual(len(harness.captures), 1)
        self.assertEqual(harness.reads, 1)
        np.testing.assert_array_equal(source, original_source)
        np.testing.assert_array_equal(gray, original_gray)
        message, = harness.messages()
        self.assertIsInstance(message["darkness"], float)
        self.assertIsInstance(message["threshold"], float)
        self.assertEqual(message["darkness"], expected_darkness(source))
        self.assertEqual(message["threshold"], 57.5)
        self.assertIn("Howdy console output", harness.errors.getvalue())
        self.assertNotIn("Howdy console output", harness.output.getvalue())

    def test_dark_bright_and_default_threshold(self):
        for value, darkness in ((0, 100.0), (220, 0.0)):
            with self.subTest(value=value):
                frame = np.full((96, 128, 3), value, dtype=np.uint8)
                result = (frame, frame[:, :, 0])
                harness = AdapterHarness([result])
                harness.run(lambda capture: capture.read_frame())
                message, = harness.messages()
                self.assertEqual(message["darkness"], darkness)
                self.assertEqual(message["threshold"], 60.0)
                self.assertIsInstance(message["threshold"], float)

    def test_all_rotations_and_unpreviewed_frame_counter(self):
        source = np.zeros((64, 96, 3), dtype=np.uint8)
        source[:32, :48] = 180
        result = (source, source[:, :, 0])
        for mode in range(5):
            with self.subTest(mode=mode):
                harness = AdapterHarness([result] * 3, rotate=mode)

                def enroll(capture):
                    self.assertIs(capture.read_frame(), result)
                    harness.clock = 0.05
                    self.assertIs(capture.read_frame(), result)
                    harness.clock = 0.11
                    self.assertIs(capture.read_frame(), result)

                harness.run(enroll)
                self.assertEqual(harness.rotations, [(mode, 1), (mode, 2), (mode, 3)])
                messages = harness.messages()
                self.assertEqual(len(messages), 2)
                for number, message in zip((1, 3), messages):
                    expected = rotated(source, mode, number)
                    self.assertEqual(message["darkness"], expected_darkness(expected))
                np.testing.assert_array_equal(source[:32, :48], 180)
                np.testing.assert_array_equal(source[32:], 0)

    def test_pulsed_ir_does_not_lock_preview_to_black_phase(self):
        black = np.zeros((64, 96, 3), dtype=np.uint8)
        lit = np.full_like(black, 180)
        results = [(frame, frame[:, :, 0]) for frame in (black, lit) * 30]
        harness = AdapterHarness(results)

        def enroll(capture):
            for number, result in enumerate(results):
                harness.clock = number / 15
                self.assertIs(capture.read_frame(), result)

        harness.run(enroll)
        messages = harness.messages()
        self.assertTrue(any(message["darkness"] == 0.0 for message in messages))
        self.assertEqual(sum(message["darkness"] == 100.0 for message in messages), 1)

    def test_sustained_blackout_replaces_last_lit_preview(self):
        lit = np.full((64, 96, 3), 180, dtype=np.uint8)
        black = np.zeros_like(lit)
        results = [(lit, lit[:, :, 0])] + [(black, black[:, :, 0])] * 30
        harness = AdapterHarness(results)

        def enroll(capture):
            for number, result in enumerate(results):
                harness.clock = number / 15
                self.assertIs(capture.read_frame(), result)

        harness.run(enroll)
        messages = harness.messages()
        self.assertEqual(messages[0]["darkness"], 0.0)
        self.assertEqual(messages[-1]["darkness"], 100.0)

    def test_eof_before_start_opens_no_recorder(self):
        harness = AdapterHarness([])
        harness.cancel()
        with self.assertRaisesRegex(RuntimeError, "enrollment cancelled"):
            harness.run(lambda capture: self.fail("enrollment started after cancellation"))
        self.assertEqual(harness.reads, 0)
        self.assertEqual(harness.captures, [])
        self.assertEqual(harness.messages(), [])

    def test_eof_before_next_read_or_during_read_prevents_model_save(self):
        source = np.full((64, 96, 3), 180, dtype=np.uint8)
        result = (source, source[:, :, 0])
        for during_read in (False, True):
            with self.subTest(during_read=during_read):
                harness = AdapterHarness([result, result])
                saved = []

                def enroll(capture):
                    self.assertIs(capture.read_frame(), result)
                    if during_read:
                        harness.before_return = harness.cancel
                    else:
                        harness.cancel()
                    capture.read_frame()
                    saved.append("model")

                with self.assertRaisesRegex(RuntimeError, "enrollment cancelled"):
                    harness.run(enroll)
                self.assertEqual(harness.reads, 2 if during_read else 1)
                self.assertEqual(len(harness.messages()), 1)
                self.assertEqual(saved, [])

    def test_eof_after_cli_returns_still_fails_prepare(self):
        harness = AdapterHarness([])
        with self.assertRaisesRegex(RuntimeError, "enrollment cancelled"):
            harness.run(lambda capture: harness.cancel())
        self.assertEqual(harness.messages(), [])



class EnrollmentBudgetTest(unittest.TestCase):
    def setUp(self):
        self.black = np.zeros((64, 96, 3), dtype=np.uint8)
        self.lit = np.full_like(self.black, 180)
        self.dark = self.black.copy()
        self.dark[:, -24:] = 180

    def harness(self, frames, step=1 / 15):
        harness = AdapterHarness([(frame, frame[:, :, 0]) for frame in frames])
        def advance():
            harness.clock += step
        harness.before_return = advance
        return harness

    def test_sixty_usable_frames_survive_ir_off_pulses_and_dark_frames(self):
        frames = [self.black, self.dark, self.lit] * 60
        harness = self.harness(frames)
        seen = []
        harness.run(lambda capture: seen.extend(capture.read_frame() for _ in range(60)),
                    enrollment=True)
        self.assertEqual(harness.reads, 180)
        for result in seen:
            self.assertIs(result[0], self.lit)

    def test_black_and_dark_streams_fail_within_wall_clock_limit(self):
        for frame, reason in ((self.black, "only black"), (self.dark, "too dark")):
            with self.subTest(reason=reason):
                harness = self.harness([frame] * 40, step=1)
                with self.assertRaisesRegex(RuntimeError, reason):
                    harness.run(lambda capture: capture.read_frame(), enrollment=True)
                self.assertLessEqual(harness.clock, 30)

    def test_frame_must_return_before_deadline_to_be_enrolled(self):
        for elapsed in (29.99, 30.0, 31.0):
            with self.subTest(elapsed=elapsed):
                harness = self.harness([self.lit], step=elapsed)
                if elapsed < 30:
                    seen = []
                    harness.run(lambda capture: seen.append(capture.read_frame()), enrollment=True)
                    self.assertIs(seen[0][0], self.lit)
                else:
                    with self.assertRaisesRegex(RuntimeError, "timed out"):
                        harness.run(lambda capture: capture.read_frame(), enrollment=True)

    def test_darkness_equal_to_threshold_is_usable(self):
        harness = self.harness([self.dark])
        harness.config.set("video", "dark_threshold", str(expected_darkness(self.dark)))
        seen = []
        harness.run(lambda capture: seen.append(capture.read_frame()), enrollment=True)
        self.assertIs(seen[0][0], self.dark)

    def test_cancel_while_skipping_dark_frames_aborts_before_next_sample(self):
        harness = self.harness([self.black] * 5)
        def cancel_after_two():
            harness.clock += 1 / 15
            if harness.reads == 2:
                harness.cancel()
        harness.before_return = cancel_after_two
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            harness.run(lambda capture: capture.read_frame(), enrollment=True)
        self.assertEqual(harness.reads, 2)

    def test_skipped_frames_do_not_change_howdy_rotation_parity(self):
        harness = self.harness([self.black, self.lit, self.black, self.lit])
        harness.config.set("video", "rotate", "1")
        harness.run(lambda capture: [capture.read_frame(), capture.read_frame()], enrollment=True)
        self.assertEqual(harness.rotations, [(1, 1), (1, 1), (1, 2), (1, 2)])


class EnrollmentRollbackTest(unittest.TestCase):
    def test_five_sample_budget_and_partial_failure_rollback(self):
        functions = [node for node in ast.parse(HELPER.read_text()).body
                     if isinstance(node, ast.FunctionDef)
                     and node.name in ("require", "rollback", "prepare")]
        original_config = "[video]\n[core]\n[snapshots]\n"
        for outcome in ("cancelled", "timeout"):
            for existing in (False, True):
                with self.subTest(outcome=outcome, existing_model=existing), \
                        tempfile.TemporaryDirectory() as directory:
                    config_dir = Path(directory)
                    (config_dir / "models").mkdir()
                    (config_dir / "config.ini").write_text(original_config)
                    model = config_dir / "models/example.dat"
                    if existing:
                        model.write_bytes(b"original private model")
                    clock = types.SimpleNamespace(value=0.0)
                    samples = []

                    def enroll(*args, **kwargs):
                        remaining = kwargs["timeout"]
                        samples.append(remaining)
                        model.write_bytes(b"replacement model")
                        duration = 31.0 if outcome == "timeout" else 10.0
                        clock.value += min(duration, remaining)
                        if duration > remaining:
                            raise subprocess.TimeoutExpired(args, remaining)
                        if outcome == "cancelled" and len(samples) == 3:
                            raise RuntimeError("sample cancelled")

                    namespace = dict(
                        CONF=config_dir, TRANSACTION=config_dir / ".onboarding",
                        BASE=Path("/unused"), RUNTIME=Path("/unused"), json=json,
                        shutil=shutil, configparser=configparser,
                        time=types.SimpleNamespace(monotonic=lambda: clock.value),
                        pwd=types.SimpleNamespace(getpwnam=lambda user:
                            types.SimpleNamespace(pw_uid=1000, pw_gid=os.getgid())),
                        sys=types.SimpleNamespace(argv=["installer", "prepare", "example", "1000"],
                                                  stderr=io.StringIO()),
                        os=types.SimpleNamespace(umask=os.umask, chmod=os.chmod, chown=lambda *args: None),
                        trusted=lambda path: path, configure=lambda: False,
                        camera=lambda: ("/dev/null", ""), desktop_camera_access=lambda *args: None,
                        ENROLLMENT_PREVIEW=ADAPTER, run=enroll)
                    exec(compile(ast.Module(body=functions, type_ignores=[]), str(HELPER), "exec"), namespace)
                    error = subprocess.TimeoutExpired if outcome == "timeout" else RuntimeError
                    with self.assertRaises(error):
                        namespace["prepare"]("example", os.getpid())
                    self.assertEqual((config_dir / "config.ini").read_text(), original_config)
                    self.assertFalse((config_dir / ".onboarding").exists())
                    if existing:
                        self.assertEqual(model.read_bytes(), b"original private model")
                    else:
                        self.assertFalse(model.exists())
                    self.assertLessEqual(clock.value, 90.0)


class PreviewSupervisorTest(unittest.TestCase):
    def test_cancel_reaps_a_blocked_camera_process(self):
        import concurrent.futures
        import select
        import signal
        import subprocess
        import time

        functions = [node for node in ast.parse(HELPER.read_text()).body
                     if isinstance(node, ast.FunctionDef)
                     and node.name in ("require", "trusted", "run")]
        cancel_read, cancel_write = os.pipe()
        output_read, output_write = os.pipe()
        with os.fdopen(cancel_read, "rb") as stdin, os.fdopen(output_write, "wb") as stdout:
            namespace = {"Path": Path, "stat": __import__("stat"), "os": os,
                         "sys": types.SimpleNamespace(stdin=stdin, stdout=stdout, stderr=sys.stderr),
                         "subprocess": subprocess, "select": select, "signal": signal,
                         "time": time, "ENV": {"PATH": "/usr/bin:/bin"}}
            exec(compile(ast.Module(body=functions, type_ignores=[]), str(HELPER), "exec"), namespace)
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    task = executor.submit(
                        namespace["run"], "/usr/bin/python3", "-u", "-c",
                        "import os,time; print(os.getpid(),flush=True); time.sleep(60)",
                        timeout=5, preview=True)
                    self.assertTrue(select.select([output_read], [], [], 3)[0],
                                    "camera process did not start")
                    pid = int(os.read(output_read, 64).strip())
                    os.close(cancel_write)
                    cancel_write = None
                    with self.assertRaisesRegex(RuntimeError, "cancelled"):
                        task.result(timeout=3)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                if cancel_write is not None:
                    os.close(cancel_write)
                os.close(output_read)


if __name__ == "__main__":
    unittest.main()
