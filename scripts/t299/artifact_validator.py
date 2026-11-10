"""Read-only, probe-configured validation of the final self-signed Mesh DMG."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

BUNDLE_ID = 'com.webdesserts.mesh'
VERSION = r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?'
MAX_OUTPUT = 8192


class ValidationError(Exception):
    pass


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def load_config(path):
    if not Path(path).is_file():
        raise ValidationError('identity configuration missing')
    try:
        cfg = json.loads(Path(path).read_text())
        require(set(cfg) == {'common_name', 'der_sha256', 'designated_requirement', 'observations'}, 'invalid identity configuration fields')
        for key in ['common_name', 'designated_requirement']:
            require(isinstance(cfg[key], str) and 0 < len(cfg[key]) <= 4096 and cfg[key] == cfg[key].strip() and '\n' not in cfg[key], 'invalid ' + key)
        require(isinstance(cfg['der_sha256'], str) and re.fullmatch('[0-9a-f]{64}', cfg['der_sha256']), 'invalid DER SHA256')
        require('identifier "' + BUNDLE_ID + '"' in cfg['designated_requirement'], 'requirement missing bundle identifier')
        require(set(cfg['observations']) == {'spctl', 'ticket'}, 'missing observation configuration')
        for record in cfg['observations'].values():
            require(set(record) == {'exit_code', 'stdout_lines', 'stderr_lines'}, 'invalid observation fields')
            require(type(record['exit_code']) is int and 1 <= record['exit_code'] <= 255, 'expected rejection exit code required')
            lines = []
            for key in ['stdout_lines', 'stderr_lines']:
                require(isinstance(record[key], list) and len(record[key]) <= 16, 'invalid observation templates')
                for line in record[key]:
                    require(isinstance(line, str) and 1 <= len(line) <= 512 and not re.search(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]', line), 'invalid observation line')
                    literal = line.replace('{path}', '')
                    require(line.count('{path}') <= 1 and '{' not in literal and '}' not in literal, 'unknown observation placeholder')
                lines.extend(record[key])
            require(lines, 'empty observation classifier')
        return cfg
    except (ValueError, TypeError, KeyError) as exc:
        raise ValidationError('invalid identity configuration') from exc


def classify(result, record, app_path):
    path = str(app_path)
    require(Path(path).is_absolute() and Path(path).name == 'Mesh.app' and
            '..' not in Path(path).parts and len(path) <= 4096 and
            not re.search(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]', path), 'invalid observation app path')
    require(result.returncode == record['exit_code'], 'unknown observation exit code')
    for stream in ['stdout', 'stderr']:
        text = getattr(result, stream)
        require(len(text) <= MAX_OUTPUT, 'observation output too large')
        require(not re.search(r'[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]', text), 'invalid observation output control')
        expected = [line.replace('{path}', path) for line in record[stream + '_lines']]
        # Only line endings and a final newline normalize; diagnostic content is exact.
        require(text.splitlines() == expected, 'unknown observation text')
    return 'expected_preapproval'


def digest(path):
    sha = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def checked(runner, argv):
    result = runner(argv)
    require(result.returncode == 0, 'command failed: ' + argv[0])
    require(len(result.stdout) + len(result.stderr) <= MAX_OUTPUT, 'command output too large')
    return result


def inside(path, root):
    require(path.resolve().is_relative_to(root.resolve()), 'app path escapes owned mount')
    return path


def validate(dmg, version, config_path, runner=run):
    cfg = load_config(config_path)
    dmg = Path(dmg).absolute()
    require(re.fullmatch(VERSION, version), 'invalid version')
    require(dmg.name == 'Mesh_{}_universal.dmg'.format(version) and dmg.is_file() and not dmg.is_symlink(), 'missing or incorrectly named DMG')
    # Do not recursively clean the owned directory if detach fails: it may be live.
    mount = Path(tempfile.mkdtemp(prefix='mesh-dmg-'))
    detached = False
    try:
        try:
            checked(runner, ['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(dmg)])
            app = inside(mount / 'Mesh.app', mount)
            info_path = inside(app / 'Contents/Info.plist', mount)
            require(info_path.is_file(), 'missing Info.plist')
            try:
                info = plistlib.loads(info_path.read_bytes())
            except (ValueError, plistlib.InvalidFileException) as exc:
                raise ValidationError('invalid Info.plist') from exc
            require(info.get('CFBundleIdentifier') == BUNDLE_ID, 'wrong bundle identifier')
            require(info.get('CFBundleShortVersionString') == version, 'wrong version')
            require(info.get('CFBundleExecutable') == 'Mesh', 'wrong executable')
            executable = inside(app / 'Contents/MacOS/Mesh', mount)
            require(executable.is_file(), 'missing executable')
            arch = checked(runner, ['lipo', '-archs', str(executable)])
            archs = arch.stdout.split()
            require(len(archs) == 2 and set(archs) == {'x86_64', 'arm64'} and not arch.stderr.strip(), 'wrong architecture')
            with tempfile.TemporaryDirectory(prefix='mesh-public-cert-') as cert_dir:
                prefix = Path(cert_dir) / 'signer'
                checked(runner, ['codesign', '-d', '--extract-certificates=' + str(prefix), str(app)])
                certs = list(Path(cert_dir).iterdir())
                require(certs == [Path(str(prefix) + '0')] and certs[0].is_file() and not certs[0].is_symlink(), 'expected one self-signed public certificate')
                require(digest(certs[0]) == cfg['der_sha256'], 'wrong certificate fingerprint')
            checked(runner, ['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
            dr_result = checked(runner, ['codesign', '-d', '-r-', str(app)])
            dr_lines = [line[len('designated => '):] for line in (dr_result.stdout + '\n' + dr_result.stderr).splitlines() if line.startswith('designated => ')]
            require(dr_lines == [cfg['designated_requirement']], 'wrong designated requirement')
            details = checked(runner, ['codesign', '-dv', '--verbose=4', str(app)])
            text = details.stdout + '\n' + details.stderr
            require(not re.search(r'adhoc|ad-hoc|linker-signed', text, re.I), 'ad-hoc or linker signature rejected')
            authorities = [line[len('Authority='):] for line in text.splitlines() if line.startswith('Authority=')]
            require(authorities == [cfg['common_name']], 'wrong signer common name')
            observations = {
                'spctl': classify(runner(['spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)]), cfg['observations']['spctl'], app),
                'ticket': classify(runner(['xcrun', 'stapler', 'validate', str(app)]), cfg['observations']['ticket'], app),
            }
        finally:
            checked(runner, ['hdiutil', 'detach', str(mount)])
            detached = True
    finally:
        if detached:
            # A real detach leaves an empty directory; fake runners may leave fixtures.
            if not any(mount.iterdir()):
                mount.rmdir()
    return dict(status='validated', version=version, arch='universal', bundle_id=BUNDLE_ID,
                asset=dmg.name, common_name=cfg['common_name'], der_sha256=cfg['der_sha256'],
                der_hash_match=True, designated_requirement=cfg['designated_requirement'],
                observations=observations, sha256=digest(dmg), size=dmg.stat().st_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dmg', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--signer-config', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.dmg, args.version, args.signer_config), sort_keys=True))
        return 0
    except (ValidationError, OSError) as exc:
        print('validation failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())