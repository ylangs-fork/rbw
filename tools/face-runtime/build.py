#!/usr/bin/python3
"""Build-time only. Produce a root-scoped, offline Howdy runtime and tarball."""
import argparse
import bz2
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

BASE = Path("/usr/lib/security/rbw-howdy")
RUNTIME = BASE / "runtime"
WORK = Path("/build")
TOOLS = Path(__file__).resolve().parent
HOWDY_COMMIT = "7998959b0c36909a90619fd0904b622000df8354"
HOWDY_SHA256 = "785f5099b9bdb830529385fea56571971f4ac9cf51c838cfb576f31e003657b8"
DLIB_VERSION = "20.0.1"
DLIB_URL = "https://files.pythonhosted.org/packages/25/1e/17570a07f9db19014f5df9cc5de2b4acfb47834e9921e019372b51d7cc03/dlib-20.0.1.tar.gz"
DLIB_SHA256 = "7cb2a09467de032332c743bc967007f016598c66c9c9ebc54a5b66d3d9e46d54"
MODELS_COMMIT = "fd81b6308a6a73d4ce08859eb2f4b628a21e27a2"
MODELS = {
    "shape_predictor_5_face_landmarks.dat": "6e787bbebf5c9efdb793f6cd1f023230c4413306605f24f299f12869f95aa472",
    "dlib_face_recognition_resnet_model_v1.dat": "abb1f61041e434465855ce81c2bd546e830d28bcbed8d27ffbe5bb408b11553a",
    "mmod_human_face_detector.dat": "db9e9e40f092c118d5eb3e643935b216838170793559515541c56a2b50d9fc84",
}
PLATFORM = "linux-x86_64-ubuntu22.04"
MARKER = "rbw isolated Howdy " + HOWDY_COMMIT + " dlib " + DLIB_VERSION + "\n"
# These must bind to the process's existing host ABI in a dlopened PAM module.
HOST_ABI = re.compile(r"^(?:ld-linux.*|lib(?:c|m|pthread|dl|rt|resolv|util|anl)\.so\..*|libpam\.so\..*|libaudit\.so\..*|libcap-ng\.so\..*)$")


def run(*args, **kwargs):
    subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url, name, expected=None):
    destination = Path("/root/.cache/face-runtime") / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists() or (expected and sha256(destination) != expected):
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with urllib.request.urlopen(url, timeout=120) as source, open(temporary, "wb") as output:
            shutil.copyfileobj(source, output)
        if expected and sha256(temporary) != expected:
            raise RuntimeError("download SHA256 mismatch: " + url)
        temporary.replace(destination)
    return destination


def unpack(archive):
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("unsafe source archive member: " + member.name)
            if not (member.isdir() or member.isfile() or member.issym()):
                raise RuntimeError("unexpected source archive member: " + member.name)
            if member.issym():
                target = Path(member.linkname)
                if target.is_absolute() or ".." in target.parts:
                    raise RuntimeError("unsafe source archive link: " + member.name)
        source.extractall(WORK)


def copy(source, target):
    source, target = Path(source), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, target, symlinks=False,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    else:
        shutil.copy2(source.resolve(), target)


def elf(path):
    with open(path, "rb") as source:
        return source.read(4) == b"\x7fELF"


def dependencies(path):
    result = subprocess.run(["/usr/bin/ldd", str(path)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        # Only the deliberately static launchers may lack dynamic dependencies.
        headers = subprocess.check_output(["/usr/bin/readelf", "-l", str(path)], text=True)
        dynamic = subprocess.check_output(["/usr/bin/readelf", "-d", str(path)], text=True)
        if "INTERP" in headers or "(NEEDED)" in dynamic:
            raise RuntimeError("cannot resolve ELF dependencies: " + str(path) + "\n" + result.stdout + result.stderr)
        return []
    if "not found" in result.stdout:
        raise RuntimeError("unresolved ELF dependency: " + str(path) + "\n" + result.stdout)
    return [Path(value) for value in re.findall(r"(?:=>\s+|^\s*)(/\S+)", result.stdout, re.M)]


def closure(seeds, directory, exclude=None):
    directory.mkdir(parents=True, exist_ok=True)
    pending = list(seeds)
    seen = set()
    while pending:
        source = pending.pop()
        resolved = source.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        for dependency in dependencies(resolved):
            if exclude and exclude.fullmatch(dependency.name):
                continue
            target = directory / dependency.name
            if target.exists():
                if sha256(target) != sha256(dependency):
                    raise RuntimeError("colliding runtime library: " + dependency.name)
            else:
                copy(dependency, target)
            pending.append(dependency)


def patch_runtime():
    for path in sorted(RUNTIME.rglob("*")):
        if not path.is_file() or not elf(path) or path.name in ("python3", "notify-send", "v4l2-ctl"):
            continue
        headers = subprocess.check_output(["/usr/bin/readelf", "-l", str(path)], text=True)
        if "INTERP" in headers:
            run("/usr/bin/patchelf", "--set-interpreter", RUNTIME / "lib/ld-linux-x86-64.so.2", path)
        dynamic = subprocess.check_output(["/usr/bin/readelf", "-d", str(path)], text=True)
        if "(NEEDED)" in dynamic:
            # Fail closed on a missing library instead of searching host default dirs.
            run("/usr/bin/patchelf", "--no-default-lib", path)
            if path.name not in ("ld-linux-x86-64.so.2", "libc.so.6"):
                run("/usr/bin/patchelf", "--force-rpath", "--set-rpath", RUNTIME / "lib", path)


def build(version):
    if os.uname().machine != "x86_64":
        raise RuntimeError("face runtime builder requires Linux x86_64")
    if BASE.exists():
        raise RuntimeError("builder requires a pristine root payload directory")
    WORK.mkdir(exist_ok=True)
    unpack(download("https://codeload.github.com/boltgolt/howdy/tar.gz/" + HOWDY_COMMIT,
                    "howdy-" + HOWDY_COMMIT + ".tar.gz", HOWDY_SHA256))
    unpack(download(DLIB_URL, "dlib-" + DLIB_VERSION + ".tar.gz", DLIB_SHA256))
    howdy = WORK / ("howdy-" + HOWDY_COMMIT)
    dlib = WORK / ("dlib-" + DLIB_VERSION)
    site = RUNTIME / "lib/python3.10/site-packages"
    copy("/usr/lib/python3.10", RUNTIME / "lib/python3.10")
    site.mkdir(parents=True, exist_ok=True)
    copy("/usr/lib/python3/dist-packages/numpy", site / "numpy")
    opencv = sorted(Path("/usr/lib/python3/dist-packages").glob("cv2*"))
    if not opencv:
        raise RuntimeError("builder OpenCV module is missing")
    for module in opencv:
        copy(module, site / module.name)
    # Direct CMake avoids setuptools argument parsing and pins a generic x86_64 CPU.
    run("/usr/bin/cmake", "-S", dlib / "tools/python", "-B", WORK / "dlib-build",
        "-DCMAKE_BUILD_TYPE=Release", "-DPYTHON_EXECUTABLE=/usr/bin/python3",
        "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=" + str(site), "-DDLIB_USE_CUDA=OFF",
        "-DDLIB_NO_GUI_SUPPORT=ON", "-DDLIB_USE_FFMPEG=OFF",
        "-DUSE_AVX_INSTRUCTIONS=OFF", "-DUSE_SSE4_INSTRUCTIONS=OFF",
        "-DUSE_SSE2_INSTRUCTIONS=ON")
    run("/usr/bin/cmake", "--build", WORK / "dlib-build", "--parallel", "2")
    copy(dlib / "tools/python/dlib", site / "dlib")
    copy("/usr/bin/python3.10", RUNTIME / "bin/python3.real")
    for name in ("notify-send", "v4l2-ctl"):
        copy("/usr/bin/" + name, RUNTIME / ("bin/" + name + ".real"))
    copy(TOOLS / "python-entry.py", RUNTIME / "python-entry.py")
    run("/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-Os", "-static", "-s",
        "-Wl,--build-id=none", TOOLS / "launcher.c", "-o", RUNTIME / "bin/python3")
    for name in ("notify-send", "v4l2-ctl"):
        copy(RUNTIME / "bin/python3", RUNTIME / ("bin/" + name))
    seeds = [path for path in RUNTIME.rglob("*") if path.is_file() and elf(path)]
    # These are dlopened, so DT_NEEDED alone cannot discover them. Private libpam
    # also permits module inspection inside private Python without host ABI mixing;
    # rbw itself still binds libpam/libc from its existing host process namespace.
    dlopen_modules = list(Path("/lib/x86_64-linux-gnu").glob("libnss_*.so.2"))
    dlopen_modules += list(Path("/lib/x86_64-linux-gnu").glob("libpam.so.*"))
    closure(seeds + dlopen_modules, RUNTIME / "lib")
    for module in dlopen_modules:
        copy(module, RUNTIME / "lib" / module.name)
    patch_runtime()
    run("/usr/bin/meson", "setup", WORK / "howdy-build", howdy / "howdy", "--prefix=/usr",
        "--datadir=" + str(BASE / "share"), "-Dlog_path=/etc/rbw-howdy/logs",
        "--buildtype=release", "--wrap-mode=nofallback", "-Dinstall_pam_config=false",
        "-Dinstall_selinux_module=false", "-Dinstall_config=false", "-Dpam_dir=" + str(BASE),
        "-Dpy_sources_dir=" + str(BASE), "-Dconfig_dir=/etc/rbw-howdy",
        "-Ddlib_data_dir=" + str(BASE / "dlib-data"), "-Duser_models_dir=/etc/rbw-howdy/models",
        "-Dpython_path=" + str(RUNTIME / "bin/python3"))
    run("/usr/bin/meson", "compile", "-C", WORK / "howdy-build", "-j", "2")
    run("/usr/bin/meson", "install", "-C", WORK / "howdy-build", "--no-rebuild",
        "--tags", "pam_module,py_sources,meta")
    copy(howdy / "howdy/src/config.ini", BASE / "default-config.ini")
    # Product-supported capture is OpenCV only; unused optional upstream plugins
    # must never introduce enrollment/authentication-time dependency installation.
    from configparser import ConfigParser
    default_config = ConfigParser()
    default_config.read(BASE / "default-config.ini")
    if (default_config.get("video", "recording_plugin") != "opencv" or
            default_config.getboolean("rubberstamps", "enabled") or
            default_config.getboolean("snapshots", "save_failed") or
            default_config.getboolean("snapshots", "save_successful")):
        raise RuntimeError("pinned Howdy defaults enable unsupported plugins or snapshots")
    closure([BASE / "pam_howdy.so"], BASE / "pam-libs", exclude=HOST_ABI)
    for path in [BASE / "pam_howdy.so"] + sorted((BASE / "pam-libs").iterdir()):
        run("/usr/bin/patchelf", "--force-rpath", "--set-rpath", BASE / "pam-libs", path)
    for name, checksum in MODELS.items():
        archive = download("https://raw.githubusercontent.com/davisking/dlib-models/" +
                           MODELS_COMMIT + "/" + name + ".bz2", name + ".bz2", checksum)
        target = BASE / "dlib-data" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with bz2.open(archive, "rb") as source, open(target, "wb") as output:
            shutil.copyfileobj(source, output)
    licenses = BASE / "licenses"
    copy(howdy / "LICENSE", licenses / "howdy-LICENSE")
    copy(dlib / "LICENSE.txt", licenses / "dlib-LICENSE.txt")
    # dlib vendors pybind11 and other code with additional license notices.
    for path in sorted(dlib.rglob("*")):
        if path.is_file() and re.search(r"(?:license|copying|copyright)", path.name, re.I):
            copy(path, licenses / "dlib-source-notices" / path.relative_to(dlib))
    copy(download("https://raw.githubusercontent.com/davisking/dlib-models/" + MODELS_COMMIT +
                  "/README.md", "models-" + MODELS_COMMIT + "-README.md"), licenses / "models-README.md")
    copy("/usr/share/common-licenses", licenses / "common-licenses")
    # Include package notices and exact source/binary provenance, not only top-level Python licenses.
    for document in sorted(Path("/usr/share/doc").glob("*/copyright")):
        copy(document, licenses / "ubuntu" / document.parent.name / "copyright")
    provenance = subprocess.check_output([
        "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n"
    ], text=True)
    (licenses / "ubuntu-packages.tsv").write_text(provenance)
    (licenses / "ubuntu-sources.list").write_text(Path("/etc/apt/sources.list").read_text())
    (BASE / ".rbw-managed").write_text(MARKER)
    # Copying and packaging must not ship mutable bytecode, link escapes or biometric material.
    for path in BASE.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("unexpected payload symlink: " + str(path))
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    BASE.chmod(0o755)
    inventory = {str(path.relative_to(BASE)): sha256(path)
                 for path in sorted(BASE.rglob("*")) if path.is_file()}
    manifest = {"schema": 1, "version": version, "platform": PLATFORM,
                "howdy_commit": HOWDY_COMMIT, "dlib_version": DLIB_VERSION, "files": inventory}
    (BASE / "bundle-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    package(version)


def package(version):
    output = Path("/out")
    output.mkdir(exist_ok=True)
    archive = output / ("rbw-face-runtime-" + version + "-" + PLATFORM + ".tar.gz")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1735689600"))
    with open(archive, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                                 mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.GNU_FORMAT) as bundle:
            for path in [BASE] + sorted(BASE.rglob("*")):
                entry = bundle.gettarinfo(str(path), arcname="rbw-howdy" +
                                          ("/" + str(path.relative_to(BASE)) if path != BASE else ""))
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = "root"
                entry.mtime = epoch
                if entry.isfile():
                    with open(path, "rb") as source:
                        bundle.addfile(entry, source)
                elif entry.isdir():
                    bundle.addfile(entry)
                else:
                    raise RuntimeError("nonregular bundle member: " + str(path))
    checksum = sha256(archive)
    (output / (archive.name + ".sha256")).write_text(checksum + "  " + archive.name + "\n")
    # Publication supplies the real URL later; no placeholder source manifest is generated.
    (output / "artifact.json").write_text(json.dumps({"version": version, "platform": PLATFORM,
                                                    "filename": archive.name, "sha256": checksum},
                                                   indent=2) + "\n")
    print(checksum + "  " + str(archive), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    build(parser.parse_args().version)
