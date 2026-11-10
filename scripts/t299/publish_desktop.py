"""Owner-gated local build/validation; only --publish permits release access."""
import argparse
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


def artifact_path(source, version):
    return source / 'target' / TARGET / 'release/bundle/dmg' / ('Mesh_{}_universal.dmg'.format(version))


def local_environment():
    return {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'CARGO_HOME', 'RUSTUP_HOME'] if key in os.environ}


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


def build_and_validate(source, tag, config_path, runner, validator):
    """No release client or credentials are reachable from this operation."""
    env = local_environment()
    commit = check_checkout(source, tag, runner, env)
    cli = checked(runner, ['cargo', 'tauri', '--version'], source, env)
    require(cli == 'tauri-cli ' + TAURI_CLI_VERSION, 'wrong pinned tauri-cli version')
    version = tag[1:]
    dmg = artifact_path(source, version)
    require(not dmg.exists() and not dmg.is_symlink(), 'final artifact already exists; use a fresh build checkout')
    signing_env = dict(env, APPLE_SIGNING_IDENTITY=SIGNING_IDENTITY, CARGO_TARGET_DIR=str(source / 'target'))
    # Avoid Tauri's shell hook and duplicate frontend builds in historical checkouts.
    with tempfile.TemporaryDirectory(prefix='mesh-tauri-config-') as temp:
        override = Path(temp) / 'tauri-override.json'
        override.write_text(json.dumps({'build': {'beforeBuildCommand': ''}}))
        checked(runner, ['cargo', 'tauri', 'build', '--target', TARGET, '--bundles', 'dmg', '--config', str(override)], source / 'crates/desktop', signing_env)
    receipt = validator(dmg, version, config_path, runner=lambda argv: runner(argv, cwd=source, env=env))
    require(receipt.get('status') == 'validated' and receipt.get('asset') == dmg.name and
            receipt.get('sha256') == digest(dmg) and receipt.get('size') == dmg.stat().st_size,
            'validator receipt does not match final artifact')
    return dict(validation=receipt, source_commit=commit, tag=tag,
                tool_versions={'tauri-cli': TAURI_CLI_VERSION}, upload={'status': 'not_requested'})


def release_available(tag, asset, source, runner):
    raw = checked(runner, ['gh', 'release', 'view', tag, '--repo', REPOSITORY, '--json', 'tagName,assets'], source, None)
    try:
        release = json.loads(raw)
        require(release['tagName'] == tag and isinstance(release['assets'], list), 'wrong release response')
        names = [item['name'] for item in release['assets']]
        require(all(isinstance(name, str) for name in names), 'invalid release asset response')
        require(asset not in names, 'release asset already exists')
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError('invalid release response') from exc


def publish_existing(source, tag, config_path, runner, validator):
    """No tag creation, release creation, replacement, or retry path."""
    check_checkout(source, tag, runner, local_environment())
    dmg = artifact_path(source, tag[1:])
    release_available(tag, dmg.name, source, runner)
    receipt = build_and_validate(source, tag, config_path, runner, validator)
    # Recheck after the build; upload itself still refuses a racing same-name asset.
    try:
        release_available(tag, dmg.name, source, runner)
        require(digest(dmg) == receipt['validation']['sha256'], 'artifact changed before upload')
    except (ValidationError, OSError):
        receipt['upload'] = {'status': 'not_attempted', 'reason': 'pre-upload check failed'}
        return receipt
    try:
        result = runner(['gh', 'release', 'upload', tag, str(dmg), '--repo', REPOSITORY], cwd=source, env=None)
        status = 'uploaded' if result.returncode == 0 else 'unknown'
    except OSError:
        status = 'unknown'
    receipt['upload'] = {'status': status}
    return receipt


def execute(source, tag, config_path, publish=False, runner=run, validator=validate):
    require(re.fullmatch('v' + VERSION, tag), 'expected an explicit existing v<version> tag')
    source = Path(source).resolve()
    config_path = Path(config_path).resolve()
    cfg = load_config(config_path)
    require(cfg['common_name'] == SIGNING_IDENTITY, 'configuration does not match fixed signing identity')
    if publish:
        return publish_existing(source, tag, config_path, runner, validator)
    return build_and_validate(source, tag, config_path, runner, validator)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--tag', required=True, help='Existing owner-authorized tag; never created or pushed')
    parser.add_argument('--signer-config', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    # Reserve the local receipt before any build or upload; never overwrite evidence.
    try:
        with args.receipt.open('x') as output:
            try:
                receipt = execute(args.source, args.tag, args.signer_config, publish=args.publish)
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