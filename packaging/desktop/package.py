#!/usr/bin/python3
"""Build-time only: verify the published runtime and assemble a normal Debian package."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


SOURCE = Path('/src')
RUNTIME_SHA256 = 'c93f0aa8022b79f401228764bd49a836d1ef3ce5f827166b2f6247a979850676'
RUNTIME = Path('/opt/rbwbio/face-runtime.tar.gz')
BINARIES = SOURCE / 'target/x86_64-unknown-linux-gnu/release'


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, text=True, **kwargs)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def manifest():
    result = json.loads((SOURCE / 'src/bin/rbw/face-runtime.json').read_text())
    if (result['version'] != '1.17.0'
            or result['platform'] != 'linux-x86_64-ubuntu22.04'
            or result['sha256'] != RUNTIME_SHA256
            or urllib.parse.urlsplit(result['url']).scheme != 'https'):
        raise RuntimeError('package requires the pinned published face runtime 1.17.0')
    return result


def download():
    metadata = manifest()
    cache = Path('/root/.cache/rbwbio-face') / (RUNTIME_SHA256 + '.tar.gz')
    if not cache.exists():
        temporary = cache.with_suffix('.download')
        try:
            with urllib.request.urlopen(metadata['url'], timeout=120) as response:
                if urllib.parse.urlsplit(response.url).scheme != 'https':
                    raise RuntimeError('runtime download redirected away from HTTPS')
                with temporary.open('wb') as output:
                    shutil.copyfileobj(response, output)
            if digest(temporary) != RUNTIME_SHA256:
                raise RuntimeError('published face runtime SHA-256 mismatch')
            temporary.rename(cache)
        finally:
            temporary.unlink(missing_ok=True)
    if digest(cache) != RUNTIME_SHA256:
        raise RuntimeError('cached face runtime SHA-256 mismatch; remove the corrupt cache')
    RUNTIME.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(cache, RUNTIME)


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def write(destination, content):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content)
    destination.chmod(0o644)


def package():
    commit = os.environ['SOURCE_COMMIT']
    epoch = int(os.environ['SOURCE_DATE_EPOCH'])
    if not re.fullmatch('[0-9a-f]{40}', commit) or epoch <= 0:
        raise RuntimeError('a full source commit and its positive commit timestamp are required')
    if run('dpkg', '--print-architecture', capture_output=True).stdout.strip() != 'amd64':
        raise RuntimeError('desktop package supports only amd64')
    metadata = manifest()
    if digest(RUNTIME) != RUNTIME_SHA256:
        raise RuntimeError('packaged runtime SHA-256 mismatch')
    cargo = (SOURCE / 'Cargo.toml').read_text().split('\n[', 1)[0]
    match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', cargo, re.M)
    if not match:
        raise RuntimeError('expected a stable semantic package version in Cargo.toml')
    upstream = match.group(1)
    version = upstream + '+git' + commit[:12] + '-1'
    output = Path('/out')
    output.mkdir()
    with tempfile.TemporaryDirectory(prefix='rbwbio-deb-') as temporary:
        work = Path(temporary)
        root = work / 'root'
        for name in ('rbw', 'rbw-agent'):
            binary = BINARIES / name
            versions = run('readelf', '--version-info', binary, capture_output=True).stdout
            glibc = [tuple(map(int, value.split('.'))) for value in
                     re.findall(r'\bGLIBC_([0-9]+\.[0-9]+)\b', versions)]
            if not glibc or max(glibc) > (2, 35):
                raise RuntimeError(name + ' is not compatible with glibc 2.35')
            dynamic = run('readelf', '--dynamic', binary, capture_output=True).stdout
            if 'libpam.so.0' not in dynamic:
                raise RuntimeError(name + ' must link the Ubuntu system PAM library')
            if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
                raise RuntimeError(name + ' must not override the system library lookup')
            install(binary, root / 'usr/bin' / name, 0o755)
        share = root / 'usr/share/rbwbio'
        install(RUNTIME, share / 'face-runtime.tar.gz')
        install(SOURCE / 'src/bin/rbw/face-runtime.json', share / 'face-runtime.json')
        write(share / 'face-runtime.tar.gz.sha256', RUNTIME_SHA256 + '  face-runtime.tar.gz\n')
        assets = SOURCE / 'assets/desktop'
        for template, target in (
            ('rbwbio.desktop.in', 'usr/share/applications/rbwbio.desktop'),
            ('rbwbio-autostart.desktop.in', 'etc/xdg/autostart/rbwbio.desktop'),
        ):
            text = (assets / template).read_text()
            if '@RBW_EXEC@' not in text:
                raise RuntimeError('desktop template must contain @RBW_EXEC@: ' + template)
            write(root / target, text.replace('@RBW_EXEC@', '/usr/bin/rbw'))
        for icon in ('rbwbio.svg', 'rbwbio-symbolic.svg'):
            install(assets / icon, root / 'usr/share/icons/hicolor/scalable/apps' / icon)
        install(SOURCE / 'LICENSE', root / 'usr/share/doc/rbwbio/copyright')
        install(SOURCE / 'README.md', root / 'usr/share/doc/rbwbio/README.md')
        build = {
            'source_commit': commit, 'source_date_epoch': epoch,
            'upstream_version': upstream, 'package_version': version,
            'target': 'x86_64-unknown-linux-gnu', 'minimum_glibc': '2.35',
            'desktop_executable': '/usr/bin/rbw', 'face_runtime': metadata,
            'rustc': run('rustc', '-Vv', capture_output=True).stdout.strip(),
            'cargo': run('cargo', '-V', capture_output=True).stdout.strip(),
            'builder_packages': run('dpkg-query', '-W', '-f=${binary:Package}=${Version}\n',
                                    capture_output=True).stdout.splitlines(),
        }
        write(share / 'build.json', json.dumps(build, indent=2) + '\n')
        # Let Ubuntu's symbol database account for all actual ELF dependencies.
        write(work / 'debian/control', 'Source: rbwbio\nSection: utils\nPriority: optional\n'
              'Maintainer: rbwBio maintainers <noreply@github.com>\n\n'
              'Package: rbwbio\nArchitecture: amd64\nDescription: rbwBio desktop CLI\n')
        shlibs = run('dpkg-shlibdeps', '-O', '-e' + str(root / 'usr/bin/rbw'),
                     '-e' + str(root / 'usr/bin/rbw-agent'), cwd=work, capture_output=True).stdout
        if not shlibs.startswith('shlibs:Depends='):
            raise RuntimeError('dpkg-shlibdeps did not report dependency metadata')
        dependencies = [value.strip() for value in shlibs.strip().split('=', 1)[1].split(',')]
        dependencies = [value for value in dependencies if not re.match(r'^libc6(?:\s|$)', value)]
        dependencies += ['libc6 (>= 2.35)', 'libpam0g', 'xdg-utils', 'librsvg2-common',
                         'pinentry-gnome3 | pinentry-qt | pinentry-x11']
        dependencies = list(dict.fromkeys(dependencies))
        installed_size = sum(path.stat().st_size for path in root.rglob('*') if path.is_file())
        write(root / 'DEBIAN/control',
              'Package: rbwbio\nVersion: ' + version + '\nArchitecture: amd64\n'
              'Section: utils\nPriority: optional\n'
              'Maintainer: rbwBio maintainers <noreply@github.com>\n'
              'Homepage: https://github.com/ylangs-fork/rbw\n'
              'Depends: ' + ', '.join(dependencies) + '\n'
              'Provides: rbw (= ' + version + ')\nConflicts: rbw\nReplaces: rbw\n'
              'Installed-Size: ' + str((installed_size + 1023) // 1024) + '\n'
              'Description: rbwBio Bitwarden CLI and portable desktop request inbox\n'
              ' Includes rbw, rbw-agent, desktop entrypoints and a pinned offline face runtime.\n'
              ' Face enrollment and isolated PAM activation are explicit user operations.\n')
        write(root / 'DEBIAN/conffiles', '/etc/xdg/autostart/rbwbio.desktop\n')
        for path in sorted(root.rglob('*'), reverse=True) + [root]:
            os.utime(path, (epoch, epoch))
        artifact = output / ('rbwbio_' + version + '_amd64.deb')
        run('dpkg-deb', '--root-owner-group', '-Zxz', '-z3', '--build', root, artifact)
    build.update({'filename': artifact.name, 'sha256': digest(artifact)})
    write(output / 'artifact.json', json.dumps(build, indent=2) + '\n')
    write(output / (artifact.name + '.sha256'), build['sha256'] + '  ' + artifact.name + '\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['download']:
        download()
    elif sys.argv[1:] == ['package']:
        package()
    else:
        raise SystemExit('usage: package.py download|package')
