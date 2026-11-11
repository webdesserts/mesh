"""Owner-gated local build/validation; only --publish permits release access."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from artifact_validator import (VERSION, ValidationError, digest, load_config,
                                require, run, validate)

TAURI_CLI_VERSION = '2.11.4'
SIGNING_IDENTITY = 'ObsidianMemory Dev Signing'
REPOSITORY = 'webdesserts/mesh'
TARGET = 'universal-apple-darwin'
APP_BUNDLE_NAME = 'Mesh.app'
LATEST_JSON = 'latest.json'
DEFAULT_UPDATER_KEY = Path.home() / '.tauri/webdesserts-updater.key'
UPDATER_PLATFORMS = ['darwin-aarch64', 'darwin-x86_64']


def artifact_path(source, version):
    return source / 'target' / TARGET / 'release/bundle/dmg' / ('Mesh_{}_universal.dmg'.format(version))


def bundle_macos_dir(source):
    return source / 'target' / TARGET / 'release/bundle/macos'


def updater_archive_path(source):
    return bundle_macos_dir(source) / (APP_BUNDLE_NAME + '.tar.gz')


def updater_sig_path(source):
    return bundle_macos_dir(source) / (APP_BUNDLE_NAME + '.tar.gz.sig')


def latest_json_path(source):
    return bundle_macos_dir(source) / LATEST_JSON


def release_assets(source, version):
    """The three release assets, in upload order: dmg, updater archive, latest.json."""
    return [artifact_path(source, version), updater_archive_path(source), latest_json_path(source)]


def local_environment():
    return {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'CARGO_HOME', 'RUSTUP_HOME', 'SSH_AUTH_SOCK'] if key in os.environ}


def checked(runner, argv, cwd, env):
    result = runner(argv, cwd=cwd, env=env)
    require(result.returncode == 0, 'command failed: ' + ' '.join(argv[:2]))
    return result.stdout.strip()


def check_checkout(source, tag, runner, env):
    require(not checked(runner, ['git', 'status', '--porcelain', '--untracked-files=all'], source, env), 'source checkout is dirty')
    head = checked(runner, ['git', 'rev-parse', '--verify', 'HEAD'], source, env)
    tagged = checked(runner, ['git', 'rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}'], source, env)
    require(re.fullmatch('[0-9a-f]{40,64}', head) and head == tagged, 'checkout does not match exact existing tag')
    detached = runner(['git', 'symbolic-ref', '-q', 'HEAD'], cwd=source, env=env)
    require(detached.returncode == 1, 'source must be a detached tag checkout')
    return head


def check_remote_tag(source, tag, head, runner):
    """The pushed tag (peeled when annotated) must resolve to the checked-out commit."""
    ref = 'refs/tags/' + tag
    raw = checked(runner, ['git', 'ls-remote', '--tags', 'origin', ref, ref + '^{}'], source, local_environment())
    refs = {}
    for line in raw.splitlines():
        parts = line.split('\t')
        require(len(parts) == 2, 'invalid ls-remote response')
        refs[parts[1]] = parts[0]
    require(refs.get(ref + '^{}', refs.get(ref)) == head, 'remote tag missing or does not match HEAD')


def resolve_updater_key(updater_key=None):
    raw = updater_key or os.environ.get('TAURI_SIGNING_PRIVATE_KEY') or DEFAULT_UPDATER_KEY
    try:
        key = Path(raw).expanduser()
        present = key.is_file()
    except (OSError, ValueError):
        present = False
    require(present, 'updater signing key missing')
    return key


def latest_manifest(tag, signature, pub_date):
    url = 'https://github.com/{}/releases/download/{}/{}.tar.gz'.format(REPOSITORY, tag, APP_BUNDLE_NAME)
    return {
        'notes': 'Release ' + tag,
        'platforms': {platform: {'signature': signature, 'url': url} for platform in UPDATER_PLATFORMS},
        'pub_date': pub_date,
        'version': tag[1:],
    }


def build_and_validate(source, tag, config_path, runner, validator, updater_key=None):
    """No release client or credentials are reachable from this operation."""
    env = local_environment()
    commit = check_checkout(source, tag, runner, env)
    cli = checked(runner, ['cargo', 'tauri', '--version'], source, env)
    require(cli == 'tauri-cli ' + TAURI_CLI_VERSION, 'wrong pinned tauri-cli version')
    version = tag[1:]
    dmg, tar_gz, latest = release_assets(source, version)
    sig = updater_sig_path(source)
    for path in [dmg, tar_gz, sig, latest]:
        require(not path.exists() and not path.is_symlink(), 'final artifact already exists; use a fresh build checkout')
    key = resolve_updater_key(updater_key)
    # An explicit (possibly empty) password keeps tauri-cli from prompting on stdin; CI='true' makes
    # bundle_dmg.sh pass --skip-jenkins so no Finder window opens during the build.
    signing_env = dict(env, APPLE_SIGNING_IDENTITY=SIGNING_IDENTITY, CARGO_TARGET_DIR=str(source / 'target'),
                       TAURI_SIGNING_PRIVATE_KEY=str(key),
                       TAURI_SIGNING_PRIVATE_KEY_PASSWORD=os.environ.get('TAURI_SIGNING_PRIVATE_KEY_PASSWORD', ''),
                       CI='true')
    # Avoid Tauri's shell hook and duplicate frontend builds in historical checkouts.
    with tempfile.TemporaryDirectory(prefix='mesh-tauri-config-') as temp:
        override = Path(temp) / 'tauri-override.json'
        override.write_text(json.dumps({'build': {'beforeBuildCommand': ''}}))
        checked(runner, ['cargo', 'tauri', 'build', '--target', TARGET, '--bundles', 'app,dmg', '--config', str(override)], source / 'crates/desktop', signing_env)
    receipt = validator(dmg, version, config_path, runner=lambda argv: runner(argv, cwd=source, env=env))
    require(receipt.get('status') == 'validated' and receipt.get('asset') == dmg.name and
            receipt.get('sha256') == digest(dmg) and receipt.get('size') == dmg.stat().st_size,
            'validator receipt does not match final artifact')
    require(tar_gz.is_file() and not tar_gz.is_symlink(), 'updater archive missing')
    require(sig.is_file() and not sig.is_symlink(), 'updater signature missing')
    signature = sig.read_text().strip()
    require(signature, 'updater signature missing')
    pub_date = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with latest.open('x') as output:
        json.dump(latest_manifest(tag, signature, pub_date), output, indent=2, sort_keys=True)
        output.write('\n')
    updater = {'archive': tar_gz.name, 'archive_sha256': digest(tar_gz), 'latest_json_sha256': digest(latest)}
    return dict(validation=receipt, source_commit=commit, tag=tag, updater=updater,
                tool_versions={'tauri-cli': TAURI_CLI_VERSION}, upload={'status': 'not_requested'})


def release_state(tag, names, source, runner):
    """None when the release does not exist; refuses any already-present asset name."""
    result = runner(['gh', 'release', 'view', tag, '--repo', REPOSITORY, '--json', 'tagName,assets,isDraft'], cwd=source, env=None)
    if result.returncode != 0:
        require('release not found' in (result.stderr or '').lower(), 'release lookup failed')
        return None
    try:
        release = json.loads(result.stdout)
        present = [item['name'] for item in release['assets']]
        valid = (release['tagName'] == tag and isinstance(release['isDraft'], bool) and
                 all(isinstance(name, str) for name in present))
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError('invalid release response') from exc
    require(valid, 'wrong release response')
    require(not set(names) & set(present), 'release asset already exists')
    return {'draft': release['isDraft']}


def verify_remote_assets(tag, files, source, runner):
    raw = checked(runner, ['gh', 'release', 'view', tag, '--repo', REPOSITORY, '--json', 'assets'], source, None)
    try:
        assets = {item['name']: item for item in json.loads(raw)['assets']}
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError('invalid release response') from exc
    for path in files:
        item = assets.get(path.name)
        require(isinstance(item, dict), 'release asset missing after upload: ' + path.name)
        require(item.get('size') == path.stat().st_size, 'release asset size mismatch: ' + path.name)
        remote = item.get('digest')
        require(not remote or remote == 'sha256:' + digest(path), 'release asset digest mismatch: ' + path.name)


def attempt(runner, argv, source):
    try:
        return runner(argv, cwd=source, env=None).returncode == 0
    except OSError:
        return False


def publish_existing(source, tag, config_path, runner, validator, updater_key=None):
    """No tag creation, asset replacement, or retry path; a new release goes draft -> verified -> published."""
    head = check_checkout(source, tag, runner, local_environment())
    check_remote_tag(source, tag, head, runner)
    files = release_assets(source, tag[1:])
    names = [path.name for path in files]
    release_state(tag, names, source, runner)
    receipt = build_and_validate(source, tag, config_path, runner, validator, updater_key)
    # Recheck after the build; create/upload itself still refuses a racing same-name asset.
    try:
        state = release_state(tag, names, source, runner)
        require(digest(files[0]) == receipt['validation']['sha256'], 'artifact changed before upload')
        require(digest(files[1]) == receipt['updater']['archive_sha256'] and
                digest(files[2]) == receipt['updater']['latest_json_sha256'], 'updater artifact changed before upload')
    except (ValidationError, OSError):
        receipt['upload'] = {'status': 'not_attempted', 'reason': 'pre-upload check failed'}
        return receipt
    paths = [str(path) for path in files]
    if state is None:
        argv = ['gh', 'release', 'create', tag] + paths + ['--repo', REPOSITORY, '--draft', '--verify-tag', '--title', tag, '--generate-notes']
        upload, draft = {'release': 'created', 'published': False}, True
    else:
        argv = ['gh', 'release', 'upload', tag] + paths + ['--repo', REPOSITORY]
        upload, draft = {'release': 'existing', 'published': False}, state['draft']
    receipt['upload'] = upload
    if not attempt(runner, argv, source):
        upload['status'] = 'unknown'
        return receipt
    try:
        verify_remote_assets(tag, files, source, runner)
    except (ValidationError, OSError) as exc:
        upload.update(status='unverified', reason=str(exc))
        return receipt
    if draft and not attempt(runner, ['gh', 'release', 'edit', tag, '--repo', REPOSITORY, '--draft=false', '--latest'], source):
        upload['status'] = 'unknown'
        return receipt
    upload.update(status='uploaded', published=True)
    return receipt


def execute(source, tag, config_path, publish=False, runner=run, validator=validate, updater_key=None):
    require(re.fullmatch('v' + VERSION, tag), 'expected an explicit existing v<version> tag')
    source = Path(source).resolve()
    config_path = Path(config_path).resolve()
    cfg = load_config(config_path)
    require(cfg['common_name'] == SIGNING_IDENTITY, 'configuration does not match fixed signing identity')
    if publish:
        return publish_existing(source, tag, config_path, runner, validator, updater_key)
    return build_and_validate(source, tag, config_path, runner, validator, updater_key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--tag', required=True, help='Existing owner-authorized tag; never created or pushed')
    parser.add_argument('--signer-config', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--updater-key', type=Path, default=None,
                        help='Tauri updater private key (default: $TAURI_SIGNING_PRIVATE_KEY or ~/.tauri/webdesserts-updater.key)')
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    # Reserve the local receipt before any build or upload; never overwrite evidence.
    try:
        with args.receipt.open('x') as output:
            try:
                receipt = execute(args.source, args.tag, args.signer_config, publish=args.publish, updater_key=args.updater_key)
            except (ValidationError, OSError) as exc:
                receipt = {'status': 'failed', 'diagnostic': str(exc), 'upload': {'status': 'not_attempted'}}
            serialized = json.dumps(receipt, sort_keys=True)
            output.write(serialized + '\n')
            print(serialized)
        return 0 if 'validation' in receipt and receipt['upload']['status'] in ['not_requested', 'uploaded'] else 1
    except OSError:
        print('could not create or persist local receipt; do not infer remote outcome or retry upload', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
