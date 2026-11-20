#!/usr/bin/python3
"""Container-only packaging checks. No camera, enrollment, unlock, or desktop claims."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


RUNTIME_SHA256 = 'c93f0aa8022b79f401228764bd49a836d1ef3ce5f827166b2f6247a979850676'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def snapshot(paths):
    result = {}
    for top in paths:
        top = Path(top)
        for path in [top] + (sorted(top.rglob('*')) if top.is_dir() else []):
            if not path.exists() and not path.is_symlink():
                result[str(path)] = None
                continue
            info = path.lstat()
            value = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            if path.is_symlink():
                value['target'] = os.readlink(path)
            elif path.is_file():
                value['sha256'] = digest(path)
            result[str(path)] = value
    return result


def policies():
    return snapshot(['/etc/pam.d', '/etc/sudoers', '/etc/sudoers.d', '/home/rbw-smoke'])


def command(*args, expected=0):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15, stdin=subprocess.DEVNULL)
    print('$ ' + ' '.join(args), flush=True)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    require(result.returncode == expected,
            'unexpected exit status for ' + ' '.join(args) + ': ' + str(result.returncode))
    return result.stdout + result.stderr


def probe():
    require(os.getuid() != 0, 'CLI probes must run as an ordinary unprivileged user')
    before = policies()
    share = Path('/usr/share/rbwbio')
    build = json.loads((share / 'build.json').read_text())
    manifest = json.loads((share / 'face-runtime.json').read_text())
    require(manifest['sha256'] == RUNTIME_SHA256 and manifest['version'] == '1.17.0',
            'unexpected face runtime metadata')
    require(digest(share / 'face-runtime.tar.gz') == RUNTIME_SHA256, 'runtime archive changed')
    require((share / 'face-runtime.tar.gz.sha256').read_text()
            == RUNTIME_SHA256 + '  face-runtime.tar.gz\n', 'runtime SHA manifest mismatch')
    require(build['desktop_executable'] == '/usr/bin/rbw', 'unstable desktop executable')
    for binary in ('rbw', 'rbw-agent'):
        version = command('/usr/bin/' + binary, '--version')
        require(build['upstream_version'] in version, binary + ' reports a different version')
        help_text = command('/usr/bin/' + binary, '--help')
        require('Usage:' in help_text or 'USAGE:' in help_text, binary + ' help is missing')
    command('/usr/bin/rbw', 'ui', '--help')
    checked = command('/usr/bin/rbw', 'setup', '--check', expected=1)
    require('native Howdy is missing' in checked, 'clean system should fail closed before enrollment')
    require(not Path('/etc/pam.d/rbw-device-auth').exists(), 'package activated a PAM policy')
    require(not Path('/usr/lib/security/rbw-howdy').exists(), 'package deployed the face runtime')
    for entry, arguments in (
        ('/usr/share/applications/rbwbio.desktop', '/usr/bin/rbw ui'),
        ('/etc/xdg/autostart/rbwbio.desktop', '/usr/bin/rbw ui --background'),
    ):
        text = Path(entry).read_text()
        require('@RBW_EXEC@' not in text and 'Exec=' + arguments in text,
                'desktop template was not correctly installed: ' + entry)
    for icon in ('rbwbio.svg', 'rbwbio-symbolic.svg'):
        require((Path('/usr/share/icons/hicolor/scalable/apps') / icon).is_file(), 'missing desktop icon')
    require(before == policies(), 'read-only CLI probes changed user data or system authentication policy')
    for directory in ('.config/rbw', '.local/share/rbw', '.cache/rbw'):
        require((Path.home() / directory / 'package-smoke-sentinel').read_text() == 'preserve-user-data\n',
                'package did not preserve existing user data')
    print('Package installation and read-only CLI/agent probes passed. Desktop, camera and biometric authentication NOT VERIFIED.')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'snapshot-policy':
        Path(sys.argv[2]).write_text(json.dumps(policies(), sort_keys=True))
    elif len(sys.argv) == 3 and sys.argv[1] == 'compare-policy':
        require(json.loads(Path(sys.argv[2]).read_text()) == policies(),
                'installing the package changed authentication policies or existing user files')
    elif sys.argv[1:] == ['probe']:
        probe()
    else:
        raise SystemExit('usage: smoke.py snapshot-policy FILE|compare-policy FILE|probe')
