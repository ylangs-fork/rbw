#!/usr/bin/env python3
"""Exercise the shipped runtime on a clean, offline OS; never enroll a person."""
import ctypes
from pathlib import Path
import subprocess
import sys

import cv2
import dlib
import numpy as np

root = Path("/usr/lib/security/rbw-howdy")
assert Path(sys.prefix).resolve().is_relative_to(root), "Python escaped its private runtime"
image = np.zeros((32, 32, 3), dtype=np.uint8)
gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
assert gray.shape == (32, 32)
assert not dlib.get_frontal_face_detector()(image, 0), "blank fixture unexpectedly matched a face"
dlib.face_recognition_model_v1(str(root / "dlib-data/dlib_face_recognition_resnet_model_v1.dat"))
dlib.shape_predictor(str(root / "dlib-data/shape_predictor_5_face_landmarks.dat"))
ctypes.CDLL(str(root / "pam_howdy.so"))


python = root / "runtime/bin/python3"
help_result = subprocess.run(
    [str(python), "-B", "-s", "-E", str(root / "howdy/cli.py"), "--help"],
    capture_output=True, text=True,
)
assert help_result.returncode == 0, help_result.stderr
comparison = subprocess.run(
    [str(python), "-B", "-s", "-E", str(root / "howdy/compare.py"), "rbw-smoke-no-model"],
    capture_output=True, text=True,
)
assert comparison.returncode == 10, comparison.stdout + comparison.stderr
for line in Path("/proc/self/maps").read_text().splitlines():
    columns = line.split(maxsplit=5)
    if len(columns) != 6:
        continue
    path = columns[5]
    if path.startswith("/") and ".so" in Path(path).name:
        assert Path(path).is_relative_to(root), "loaded an external shared library: " + path

print("Private runtime passed:", sys.version.split()[0], "dlib", dlib.__version__, "OpenCV", cv2.__version__, "NumPy", np.__version__)
