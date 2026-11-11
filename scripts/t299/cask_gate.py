"""Owner-operated stable cask gates; desktop prerelease casks are out of scope.

Default validation has no Git write operation. The official
`brew audit --cask --online` gate must exit 0; its output is not classified. Audit output is not evidence of Gatekeeper
preapproval: that classification belongs solely to artifact_validator's
spctl/ticket evidence.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

import artifact_validator
from artifact_validator import ValidationError, digest, require, run

REPOSITORY = 'webdesserts/mesh'
TOKEN = 'mesh'
TAP = 'webdesserts/tap'
OFFICIAL_TAP = 'homebrew/cask'
QUALIFIED = TAP + '/' + TOKEN
CASK = 'Casks/' + TOKEN + '.rb'
# Literal Homebrew interpolation, kept out of .format braces by concatenation.
CASK_URL = 'https://github.com/' + REPOSITORY + '/releases/download/v#{version}/Mesh_#{version}_universal.dmg'
FLOORS = ('big_sur', 'monterey', 'ventura', 'sonoma', 'sequoia', 'tahoe')
NONTERMINAL = ('queued', 'requested', 'waiting', 'pending', 'in_progress')
STABLE_VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
MAX_AUDIT_OUTPUT = 65536
MAX_STDERR = 4096


def checked(runner, argv, **kwargs):
    result = runner(argv, **kwargs)
    if result.returncode != 0:
        stderr = result.stderr if isinstance(result.stderr, str) else ''
        raise ValidationError('command failed: {}; stderr={!r}'.format(' '.join(argv[:2]), stderr[-MAX_STDERR:]))
    return result.stdout


def version(tag):
    require(isinstance(tag, str) and re.fullmatch('v' + STABLE_VERSION, tag), 'explicit stable v<major.minor.patch> tag required')
    return tag[1:]


def asset_url(tag):
    return 'https://github.com/{}/releases/download/{}/Mesh_{}_universal.dmg'.format(REPOSITORY, tag, version(tag))


def resolved_cask_source_path(value, tap):
    source = Path(value)
    return (source if source.is_absolute() else Path(tap) / source).resolve()


def generate(tag, sha256, macos_floor):
    value = version(tag)
    require(isinstance(sha256, str) and re.fullmatch('[0-9a-fA-F]{64}', sha256), '64hex artifact digest required')
    require(macos_floor in FLOORS, 'explicit reviewed supported macOS floor required')
    return '''cask "mesh" do
  version "{version}"
  sha256 "{sha256}"

  url "{url}"
  name "Mesh"
  desc "Desktop companion for Mesh"
  homepage "https://github.com/webdesserts/mesh"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: :{floor}

  app "Mesh.app"

  caveats <<~EOS
    Mesh is self-signed, not Apple-notarized. On first launch, macOS may block it.
    After verifying the release, approve it once in System Settings > Privacy & Security > Open Anyway.
    Never approve an unexpected warning. An upgrade may require approval again.
    The macOS floor is a reviewed support policy, not proof on every newer macOS release.
  EOS
end
'''.format(version=value, sha256=sha256.lower(), url=CASK_URL, floor=macos_floor)


def read_git(tap, runner, *args):
    # This allowlist bounds the entire validation path, not merely CLI defaults.
    require(args[0] in ('rev-parse', 'symbolic-ref', 'status', 'ls-tree', 'show'), 'Git write unavailable during validation')
    return checked(runner, ['git', *args], cwd=tap)


def capture_baseline(tap, candidate, runner, clean=False):
    require(read_git(tap, runner, 'rev-parse', '--show-toplevel').strip() == str(tap), 'tap must be checkout root')
    require(read_git(tap, runner, 'symbolic-ref', '--short', 'HEAD').strip() == 'main', 'tap must use main')
    head = read_git(tap, runner, 'rev-parse', '--verify', 'HEAD').strip()
    upstream = read_git(tap, runner, 'rev-parse', '--verify', 'refs/remotes/origin/main').strip()
    require(re.fullmatch('[0-9a-f]{40,64}', head) and head == upstream, 'tap ref mismatch')
    path = tap / CASK
    require(not (tap / 'Casks').is_symlink() and not path.is_symlink(), 'cask path must not be a symlink')
    status = read_git(tap, runner, 'status', '--porcelain=v1', '-z', '--untracked-files=all')
    if status:
        require(not clean and status in ('?? ' + CASK + '\0', ' M ' + CASK + '\0') and
                path.is_file() and path.read_bytes() == candidate.encode(), 'unrelated dirty or staged tap changes')
    tree = read_git(tap, runner, 'ls-tree', head, '--', CASK)
    baseline = ''
    if tree:
        require(tree.startswith('100644 blob ') and tree.rstrip().endswith('\t' + CASK), 'invalid baseline cask mode')
        baseline = read_git(tap, runner, 'show', head + ':' + CASK)
    return head, baseline


def require_newer(tag, baseline):
    if baseline:
        matches = re.findall(r'^  version "(' + STABLE_VERSION + ')"$', baseline, re.M)
        require(len(matches) == 1, 'published cask version unrecognized')
        require(tuple(map(int, version(tag).split('.'))) > tuple(map(int, matches[0].split('.'))), 'candidate must be strictly newer than published version; equal-version replacement refused')


def tap_trusted(runner, env):
    try:
        taps = json.loads(checked(runner, ['brew', 'trust', '--json=v1'], env=env))['taps']
        require(isinstance(taps, list), 'invalid tap trust list')
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError('invalid tap trust list') from exc
    return TAP in taps


@contextmanager
def mapped_tap(tap, runner, env):
    repository = Path(checked(runner, ['brew', '--repository'], env=env).strip())
    require(repository.is_absolute() and (repository / 'Library/Taps').is_dir(), 'invalid Homebrew repository')
    owner = repository / 'Library/Taps/webdesserts'
    owner_exists = owner.exists() or owner.is_symlink()
    require(not owner_exists or (not owner.is_symlink() and owner.is_dir()), 'tap owner must be a real directory, not a file or symlink')
    created_owner = not owner_exists
    owner.mkdir(exist_ok=True)
    mapping = owner / 'homebrew-tap'
    created_mapping = False
    added_trust = False
    try:
        require(not mapping.exists() and not mapping.is_symlink(), 'isolated runner required: tap mapping already exists')
        mapping.symlink_to(tap, target_is_directory=True)
        created_mapping = True
        # Homebrew refuses casks from untrusted non-official taps by default; trust
        # only for the gate's lifetime and never revoke trust the user already had.
        if not tap_trusted(runner, env):
            checked(runner, ['brew', 'trust', '--tap', TAP], env=env)
            added_trust = True
        yield
    finally:
        try:
            if added_trust:
                checked(runner, ['brew', 'untrust', '--tap', TAP], env=env)
        finally:
            if created_mapping:
                require(mapping.is_symlink() and mapping.resolve() == tap, 'owned tap mapping changed; cleanup refused')
                mapping.unlink()
            if created_owner:
                owner.rmdir()


def candidate_gates(tap, tag, sha256, runner):
    # Preserve tool lookup, user/cache/temp locations, locale and CI behavior only.
    # Queue authentication stays in the separate gh path. The dedicated read-only
    # Homebrew token is exposed only to online audit, not Ruby or other brew steps.
    env = {key: os.environ[key] for key in (
        'PATH', 'HOME', 'TMPDIR', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'CI',
    ) if key in os.environ}
    env.update(HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_ENV_HINTS='1', HOMEBREW_NO_ANALYTICS='1', HOMEBREW_COLOR='0', HOMEBREW_NO_COLOR='1')
    audit_env = dict(env)
    if 'HOMEBREW_GITHUB_API_TOKEN' in os.environ:
        audit_env['HOMEBREW_GITHUB_API_TOKEN'] = os.environ['HOMEBREW_GITHUB_API_TOKEN']
    path = tap / CASK
    with mapped_tap(tap, runner, env):
        checked(runner, ['ruby', '-c', str(path)], env=env)
        raw = checked(runner, ['brew', 'info', '--json=v2', '--cask', QUALIFIED], env=env)
        try:
            casks = json.loads(raw)['casks']
            require(len(casks) == 1, 'wrong cask resolution count')
            cask = casks[0]
            require(resolved_cask_source_path(cask['ruby_source_path'], tap) == path.resolve() and
                    cask['token'] == TOKEN and cask['full_token'] == QUALIFIED and cask['tap'] == 'webdesserts/tap' and
                    cask['version'] == version(tag) and cask['sha256'] == sha256.lower() and cask['url'] == asset_url(tag), 'wrong candidate resolution')
        except (ValueError, KeyError, TypeError) as exc:
            raise ValidationError('invalid candidate resolution') from exc
        checked(runner, ['brew', 'fetch', '--cask', QUALIFIED], env=env)
        cache = Path(checked(runner, ['brew', '--cache', '--cask', QUALIFIED], env=env).strip())
        require(cache.is_absolute() and cache.is_file() and digest(cache) == sha256.lower(), 'candidate fetched SHA mismatch')
        checked(runner, ['brew', 'style', '--cask', QUALIFIED], env=env)
        result = runner(['brew', 'search', '--casks', '/^' + TOKEN + '$/'], env=env)
        # Only the exact no-color no-match diagnostic or an exact own-tap result
        # is understood; every other exit code or diagnostic is a collision or
        # lookup failure, never availability. No text is stripped or normalized.
        if result.returncode == 1 and result.stdout == '' and result.stderr == 'Error: No formulae or casks found for "/^mesh$/".\n':
            tokens = []
        else:
            require(result.returncode == 0 and result.stderr == '', 'cask token collision lookup failed unexpectedly')
            tokens = result.stdout.split()
        if tokens == [TOKEN]:
            own = checked(runner, ['brew', 'info', '--json=v2', '--cask', TOKEN], env=env)
            try:
                matches = json.loads(own)['casks']
                require(len(matches) == 1, 'invalid collision resolution')
                resolved = matches[0]
                # An official Homebrew cask may legitimately own the bare token
                # (e.g. homebrew/cask/mesh); we always install via QUALIFIED, so
                # that shadowing is expected and not a failure. Any other tap
                # resolving the bare token must be our own qualified cask.
                if resolved['tap'] == OFFICIAL_TAP:
                    require(resolved['token'] == TOKEN, 'invalid official collision resolution')
                else:
                    require(resolved['full_token'] == QUALIFIED and
                            resolved_cask_source_path(resolved['ruby_source_path'], tap) == path.resolve(), 'unqualified token resolves elsewhere')
            except (ValueError, KeyError, TypeError) as exc:
                raise ValidationError('invalid collision resolution') from exc
        else:
            require(tokens in ([], [QUALIFIED]), 'cask token collision or ambiguous lookup')
        result = runner(['brew', 'audit', '--cask', '--online', QUALIFIED], env=audit_env)
        require(isinstance(result.stdout, str) and isinstance(result.stderr, str) and
                len(result.stdout) + len(result.stderr) <= MAX_AUDIT_OUTPUT,
                'invalid or excessive brew audit output')
        if result.returncode != 0:
            raise ValidationError(
                'command failed: brew audit; stdout={!r}; stderr={!r}'.format(
                    result.stdout, result.stderr
                )
            )
        audit = 'passed'
    return audit, cache


def _validate_candidate(tap, tag, sha256, macos_floor, runner):
    candidate = generate(tag, sha256, macos_floor)
    tap = Path(tap).resolve()
    head, baseline = capture_baseline(tap, candidate, runner)
    require_newer(tag, baseline)
    path = tap / CASK
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(candidate.encode())
    audit, cache = candidate_gates(tap, tag, sha256, runner)
    require(path.read_bytes() == candidate.encode(), 'candidate changed during gates')
    require(capture_baseline(tap, candidate, runner)[0] == head, 'tap baseline changed during gates')
    return {'status': 'validated', 'baseline': head, 'tag': tag, 'sha256': sha256.lower(), 'macos_floor': macos_floor, 'audit': audit}, cache


def validate(tap, tag, sha256, macos_floor, runner=run):
    receipt, _ = _validate_candidate(tap, tag, sha256, macos_floor, runner)
    return receipt


def _validate_fetched_artifact(cache, tag, sha256, signer_config, validator, runner):
    expected = sha256.lower()
    require(cache.is_file() and digest(cache) == expected, 'fetched artifact changed before signer validation')
    # Homebrew cache names need not satisfy the validator's exact asset contract.
    with tempfile.TemporaryDirectory(prefix='mesh-cask-artifact-') as directory:
        dmg = Path(directory) / ('Mesh_{}_universal.dmg'.format(version(tag)))
        shutil.copyfile(cache, dmg)
        require(digest(dmg) == expected and digest(cache) == expected, 'fetched artifact copy SHA mismatch')
        result = validator(dmg, version(tag), signer_config, runner=runner)
        require(isinstance(result, dict) and result.get('status') == 'validated' and
                result.get('sha256') == expected and result.get('version') == version(tag) and
                result.get('asset') == dmg.name and result.get('size') == dmg.stat().st_size and
                digest(dmg) == expected, 'artifact validator receipt or copied bytes mismatch')


def check_queue(run_id, runner=run):
    require(isinstance(run_id, str) and re.fullmatch('[1-9][0-9]*', run_id), 'current GitHub run ID required')
    for workflow in ('desktop-cask.yml',):
        for status in NONTERMINAL:
            endpoint = 'repos/{}/actions/workflows/{}/runs?status={}&per_page=100'.format(REPOSITORY, workflow, status)
            raw = checked(runner, ['gh', 'api', '--paginate', '--slurp', endpoint])
            try:
                pages = json.loads(raw)
                require(isinstance(pages, list) and 1 <= len(pages) <= 10, 'incomplete or excessive queue results')
                count = pages[0]['total_count']
                require(type(count) is int and 0 <= count <= 1000, 'invalid queue count')
                rows = []
                for page in pages:
                    require(page['total_count'] == count and isinstance(page['workflow_runs'], list), 'inconsistent queue pagination')
                    rows.extend(page['workflow_runs'])
                require(len(rows) == count and len({row['id'] for row in rows}) == count, 'incomplete queue results')
                for row in rows:
                    require(type(row['id']) is int and row['id'] > 0 and row['status'] == status, 'invalid queue row')
                    require(str(row['id']) == run_id, 'another release or desktop publication is nonterminal')
            except (ValueError, KeyError, TypeError) as exc:
                raise ValidationError('invalid queue response') from exc


def remote_head(tap, runner):
    raw = checked(runner, ['git', 'ls-remote', '--exit-code', 'origin', 'refs/heads/main'], cwd=tap)
    require(re.fullmatch(r'[0-9a-f]{40,64}\trefs/heads/main\n?', raw), 'invalid remote baseline response')
    return raw.split()[0]


def publish(tap, tag, sha256, macos_floor, *, run_id, signer_config=None, runner=run, validator=None):
    """Explicit publication only; callers must maintain owner-enforced no overlap."""
    require(signer_config is not None, 'explicit signer configuration required for publication')
    artifact_validator.load_config(signer_config)
    if validator is None:
        validator = artifact_validator.validate
    candidate = generate(tag, sha256, macos_floor)
    check_queue(run_id, runner)
    tap = Path(tap).resolve()
    head, baseline = capture_baseline(tap, candidate, runner, clean=True)
    require(remote_head(tap, runner) == head, 'stale remote baseline')
    require_newer(tag, baseline)
    receipt, cache = _validate_candidate(tap, tag, sha256, macos_floor, runner)
    _validate_fetched_artifact(cache, tag, sha256, signer_config, validator, runner)
    check_queue(run_id, runner)
    require(remote_head(tap, runner) == head, 'remote changed before staging')
    require(capture_baseline(tap, candidate, runner)[0] == head and (tap / CASK).read_bytes() == candidate.encode(), 'local baseline or candidate changed before staging')
    try:
        checked(runner, ['git', 'add', '--', CASK], cwd=tap)
        checked(runner, ['git', '-c', 'user.name=Mesh cask publisher', '-c', 'user.email=mesh-cask@users.noreply.github.com', 'commit', '-m', TOKEN + ' ' + version(tag)], cwd=tap)
        commit = read_git(tap, runner, 'rev-parse', '--verify', 'HEAD').strip()
    except (ValidationError, OSError):
        return dict(receipt, status='publication_failed', local='staging_or_commit_may_exist', remote='not_attempted')
    try:
        result = runner(['git', 'push', 'origin', 'HEAD:refs/heads/main'], cwd=tap)
        push_ok = result.returncode == 0
    except OSError:
        push_ok = False
    if push_ok:
        remote = 'accepted'
    else:
        try:
            observed = remote_head(tap, runner)
            remote = 'accepted' if observed == commit else ('unchanged' if observed == head else 'unknown')
        except (ValidationError, OSError):
            remote = 'unknown'
    return dict(receipt, status='published' if remote == 'accepted' else 'publication_failed', local='committed', commit=commit, remote=remote, push_exit='zero' if push_ok else 'nonzero_or_exception')


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('--operation', choices=('validate', 'publish', 'check-queue'), default='validate')
    value.add_argument('--tap', type=Path)
    value.add_argument('--tag')
    value.add_argument('--sha256')
    value.add_argument('--macos-floor')
    value.add_argument('--signer-config', type=Path, help='Required for publish; approved public signer configuration')
    value.add_argument('--run-id')
    return value


def main():
    args = parser().parse_args()
    try:
        if args.operation == 'check-queue':
            check_queue(args.run_id)
            receipt = {'status': 'queue_clear', 'atomic_lock': False}
        else:
            require(args.tap is not None, 'explicit tap directory required')
            values = (args.tap, args.tag, args.sha256, args.macos_floor)
            receipt = publish(*values, run_id=args.run_id, signer_config=args.signer_config) if args.operation == 'publish' else validate(*values)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if receipt['status'] in ('validated', 'published', 'queue_clear') else 1
    except (ValidationError, OSError) as exc:
        print(json.dumps({'status': 'failed', 'diagnostic': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
