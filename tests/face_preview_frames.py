#!/usr/bin/python3
"""Exercise the embedded enrollment adapter without root, hardware, or model data."""
import ast
import base64
import configparser
import io
import json
import os
from pathlib import Path
import sys
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
            assert len(line) + 1 <= 512 * 1024
            messages.append(json.loads(line.removeprefix("RBWBIO_PREVIEW ")))
        return messages

    def run(self, body):
        def rotate(frame, mode, number):
            self.rotations.append((mode, number))
            return rotated(frame, mode, number)

        def run_path(path, run_name):
            assert path == HOWDY + "/cli.py"
            assert run_name == "__main__"
            assert sys.argv == [HOWDY + "/cli.py", "-U", "example", "-y", "add", "rbw face"]
            assert sys.path == ["/trusted/private-stdlib", HOWDY]
            print("Howdy console output")
            body(self.capture_type(self.config))

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
        try:
            with mock.patch.dict(sys.modules, modules), \
                    mock.patch.object(sys, "stdin", self.stdin), \
                    mock.patch.object(sys, "stdout", self.output), \
                    mock.patch.object(sys, "stderr", self.errors), \
                    mock.patch.object(sys, "argv", ["-c", "-U", "example", "-y", "add", "rbw face"]), \
                    mock.patch.object(sys, "path", ["/trusted/private-stdlib", HOWDY]):
                exec(compile(ADAPTER, "<enrollment-preview-test>", "exec"), {"__name__": "__main__"})
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
        jpeg = base64.b64decode(message["jpeg"], validate=True)
        self.assertLessEqual(len(jpeg), 200 * 1024)
        preview = cv2.imdecode(np.frombuffer(jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
        self.assertEqual(preview.shape, source.shape)
        self.assertLess(np.abs(preview.astype(float) - source).mean(), 2)
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
                self.assertEqual(harness.rotations, [(mode, 1), (mode, 3)])
                messages = harness.messages()
                self.assertEqual(len(messages), 2)
                for number, message in zip((1, 3), messages):
                    expected = rotated(source, mode, number)
                    self.assertEqual(message["darkness"], expected_darkness(expected))
                    preview = cv2.imdecode(np.frombuffer(base64.b64decode(message["jpeg"]),
                                                        dtype=np.uint8), cv2.IMREAD_COLOR)
                    self.assertEqual(preview.shape, expected.shape)
                    self.assertLess(np.abs(preview.astype(float) - expected).mean(), 2)
                np.testing.assert_array_equal(source[:32, :48], 180)
                np.testing.assert_array_equal(source[32:], 0)

    def test_preview_dimensions_and_oversized_jpeg_are_bounded(self):
        frame = np.random.default_rng(1).integers(0, 256, (800, 1200, 3), dtype=np.uint8)
        original = frame.copy()
        harness = AdapterHarness([(frame, frame[:, :, 0])])
        encode = cv2.imencode
        sizes = []

        def oversized_once(extension, image, options):
            sizes.append(image.shape[:2])
            if len(sizes) == 1:
                return True, np.zeros(200 * 1024 + 1, dtype=np.uint8)
            return encode(extension, image, options)

        with mock.patch.object(cv2, "imencode", side_effect=oversized_once):
            harness.run(lambda capture: capture.read_frame())
        self.assertEqual(sizes, [(426, 640), (213, 320)])
        message, = harness.messages()
        jpeg = base64.b64decode(message["jpeg"], validate=True)
        self.assertLessEqual(len(jpeg), 200 * 1024)
        preview = cv2.imdecode(np.frombuffer(jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
        self.assertLessEqual(preview.shape[0], 480)
        self.assertLessEqual(preview.shape[1], 640)
        self.assertEqual(message["darkness"], expected_darkness(frame))
        np.testing.assert_array_equal(frame, original)

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

    def test_unencodable_preview_fails_instead_of_silently_succeeding(self):
        frame = np.full((64, 96, 3), 180, dtype=np.uint8)
        harness = AdapterHarness([(frame, frame[:, :, 0])])
        with mock.patch.object(cv2, "imencode", return_value=(False, None)):
            with self.assertRaisesRegex(RuntimeError, "cannot encode"):
                harness.run(lambda capture: capture.read_frame())
        self.assertEqual(harness.messages(), [])


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
