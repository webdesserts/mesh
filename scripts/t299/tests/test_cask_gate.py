import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cask_gate as gate
from test_artifact_validator import config as signer_fixture, FixtureRunner


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mesh-cask-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tap = self.root / 'tap'
        self.tap.mkdir()
        self.calls = []
        self.command_failure = None
        self.push = 'success'
        self.queue_busy = False
        self.remote = None
        self.repo = self.root / 'brew'
        (self.repo / 'Library/Taps').mkdir(parents=True)
        self.cache = self.root / 'homebrew-cache-prefixed-download.dmg'
        self.cache.write_bytes(b'fixture dmg')
        self.sha = hashlib.sha256(self.cache.read_bytes()).hexdigest()
        self.search_output = (gate.QUALIFIED + '\n', '', 0)
        self.unqualified_info_override = None
        self.absolute_ruby_source_path = False
        self.trusted_taps = []
        self.signer_config = self.root / 'signer.json'
        self.signer_config.write_text(json.dumps(signer_fixture()))
        self.validated_paths = []
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.tap / 'README.md').write_text('fixture tap\n')
        self.git('add', '--', 'README.md')
        self.git('commit', '-m', 'baseline')
        self.baseline = self.git('rev-parse', 'HEAD').stdout.strip()
        self.git('update-ref', 'refs/remotes/origin/main', self.baseline)
        self.remote = self.baseline

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.tap, capture_output=True, text=True, check=True)

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        result = lambda out='', err='', code=0: subprocess.CompletedProcess(argv, code, out, err)
        if argv[0] == 'gh':
            rows = [{'id': 999, 'status': 'queued'}] if self.queue_busy else []
            return result(json.dumps([{'total_count': len(rows), 'workflow_runs': rows}]))
        if argv[0] == 'git':
            if argv[1] == 'ls-remote':
                if self.remote == 'error':
                    raise OSError('fixture transport error')
                return result(self.remote + '\trefs/heads/main\n')
            if argv[1] == 'push':
                if self.push in ('accepted', 'accepted-nonzero', 'success'):
                    self.remote = self.git('rev-parse', 'HEAD').stdout.strip()
                elif self.push == 'unknown':
                    self.remote = 'error'
                elif self.push == 'diverged':
                    self.remote = 'b' * 40
                if self.push in ('accepted', 'unknown', 'unchanged-exception'):
                    raise OSError('fixture transport error')
                return result(code=0 if self.push == 'success' else 1)
            if self.command_failure == 'commit' and 'commit' in argv:
                return result(code=1)
            return subprocess.run(argv, **kwargs, capture_output=True, text=True)
        if self.command_failure and self.command_failure in argv:
            return result(err='unrelated failure', code=1)
        if argv == ['brew', '--repository']:
            return result(str(self.repo) + '\n')
        if argv == ['brew', 'trust', '--json=v1']:
            return result(json.dumps({'taps': self.trusted_taps, 'formulae': [], 'casks': [], 'commands': []}))
        if argv[:2] == ['brew', 'info']:
            source = self.tap / gate.CASK
            cask = {'token': gate.TOKEN, 'full_token': gate.QUALIFIED, 'tap': 'webdesserts/tap',
                    'version': '0.5.8', 'sha256': self.sha, 'url': gate.asset_url('v0.5.8'),
                    'ruby_source_path': str(source) if self.absolute_ruby_source_path else gate.CASK}
            if self.command_failure == 'resolution':
                cask['ruby_source_path'] = '/wrong/cask.rb'
            if argv[-1] == gate.TOKEN and self.unqualified_info_override:
                for field, value in self.unqualified_info_override.items():
                    cask[field] = value
            return result(json.dumps({'casks': [cask]}))
        if argv[:2] == ['brew', '--cache']:
            return result(str(self.cache) + '\n')
        if argv[:2] == ['brew', 'search']:
            if self.command_failure == 'collision':
                return result('other/tap/mesh\n')
            out, err, code = self.search_output
            return result(out, err, code)
        if argv[0] in ('brew', 'ruby'):
            return result()
        self.fail('unexpected command: ' + repr(argv))

    def validate(self, **kw):
        return gate.validate(self.tap, 'v0.5.8', self.sha, 'sonoma', runner=self.runner, **kw)

    def artifact_validator(self, dmg, version, config_path, runner):
        self.assertEqual(dmg.name, 'Mesh_0.5.8_universal.dmg')
        self.assertNotEqual(dmg.parent, self.cache.parent)
        self.assertTrue(dmg.parent.name.startswith('mesh-cask-artifact-'))
        self.assertFalse(dmg.is_symlink())
        self.assertEqual(dmg.read_bytes(), self.cache.read_bytes())
        self.assertEqual(version, '0.5.8')
        self.assertEqual(config_path, self.signer_config)
        self.validated_paths.append(dmg)
        return dict(status='validated', version=version, asset=dmg.name,
                    sha256=gate.digest(dmg), size=dmg.stat().st_size)

    def publish(self, **overrides):
        options = dict(run_id='123', runner=self.runner, signer_config=self.signer_config,
                       validator=self.artifact_validator)
        options.update(overrides)
        return gate.publish(self.tap, 'v0.5.8', self.sha, 'sonoma', **options)

    def assert_no_staging(self):
        self.assertEqual(self.git('diff', '--cached', '--name-only').stdout, '')
        self.assertEqual(self.git('rev-parse', 'HEAD').stdout.strip(), self.baseline)

    def test_generation_exact_and_required_inputs(self):
        expected = ('cask "mesh" do\n'
                    '  version "0.5.8"\n'
                    '  sha256 "' + self.sha + '"\n\n'
                    '  url "https://github.com/webdesserts/mesh/releases/download/v#{version}/Mesh_#{version}_universal.dmg"\n'
                    '  name "Mesh"\n'
                    '  desc "Desktop companion for Mesh"\n'
                    '  homepage "https://github.com/webdesserts/mesh"\n\n'
                    '  livecheck do\n'
                    '    url :url\n'
                    '    strategy :github_latest\n'
                    '  end\n\n'
                                        '  depends_on macos: :sonoma\n\n'
                    '  app "Mesh.app"\n\n'
                    '  caveats <<~EOS\n'
                    '    Mesh is self-signed, not Apple-notarized. On first launch, macOS may block it.\n'
                    '    After verifying the release, approve it once in System Settings > Privacy & Security > Open Anyway.\n'
                    '    Never approve an unexpected warning. An upgrade may require approval again.\n'
                    '    The macOS floor is a reviewed support policy, not proof on every newer macOS release.\n'
                    '  EOS\n'
                    'end\n')
        self.assertEqual(gate.generate('v0.5.8', self.sha, 'sonoma'), expected)
        self.assertNotIn('v0.5.8/Mesh_0.5.8', expected)
        self.assertNotIn('no_check', gate.generate('v0.5.8', self.sha, 'tahoe'))
        self.assertIn('depends_on macos: :tahoe', gate.generate('v0.5.8', self.sha, 'tahoe'))
        for tag, sha, floor in [('v0.5.8', self.sha, ''), ('v0.5.8', self.sha, 'invented'), ('v0.5.8', 'bad', 'sonoma'), ('latest', self.sha, 'sonoma')]:
            with self.subTest(tag=tag, sha=sha, floor=floor), self.assertRaises(gate.ValidationError):
                gate.generate(tag, sha, floor)
        for forbidden in ['no-quarantine', 'xattr', 'postflight', 'no_check', 'spctl']:
            self.assertNotIn(forbidden, expected)

    def test_candidate_resolution_accepts_relative_and_absolute_source_paths(self):
        self.assertEqual(self.validate()['status'], 'validated')
        self.absolute_ruby_source_path = True
        self.assertEqual(self.validate()['status'], 'validated')
        self.assert_no_staging()

    def test_all_candidate_children_receive_only_allowlisted_environment(self):
        allowed = {
            'PATH': os.defpath, 'HOME': str(self.root), 'TMPDIR': str(self.root),
            'USER': 'fixture', 'LOGNAME': 'fixture', 'LANG': 'C',
            'LC_ALL': 'C', 'LC_CTYPE': 'C', 'CI': 'true',
        }
        hostile = {
            'GH_TOKEN': 'fixture-gh-secret', 'GITHUB_TOKEN': 'fixture-github-secret',
            'AWS_SECRET_ACCESS_KEY': 'fixture-unrelated-secret', 'RUBYOPT': '-rhostile',
            'HOMEBREW_NO_INSTALL_FROM_API': '1', 'HOMEBREW_DEVELOPER': '1',
            'HOMEBREW_DEVCMD_RUN': '1', 'HOMEBREW_CASK_OPTS': 'hostile',
            'HOMEBREW_NO_AUTO_UPDATE': '0', 'HOMEBREW_NO_ENV_HINTS': '0',
            'HOMEBREW_NO_ANALYTICS': '0', 'HOMEBREW_COLOR': '1',
            'HOMEBREW_GITHUB_API_TOKEN': 'fixture-homebrew-read-token',
        }
        expected = dict(allowed, HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_ENV_HINTS='1',
                        HOMEBREW_NO_ANALYTICS='1', HOMEBREW_COLOR='0', HOMEBREW_NO_COLOR='1')
        audit_expected = dict(expected, HOMEBREW_GITHUB_API_TOKEN=hostile['HOMEBREW_GITHUB_API_TOKEN'])
        seen = []
        def inspecting(argv, **kwargs):
            if argv[0] in ('ruby', 'brew'):
                command_env = audit_expected if argv[:2] == ['brew', 'audit'] else expected
                self.assertEqual(kwargs.get('env'), command_env, argv)
                seen.append(argv)
            return self.runner(argv, **kwargs)
        self.search_output = (gate.TOKEN + '\n', '', 0)
        with patch.dict(os.environ, dict(allowed, **hostile), clear=True):
            gate.validate(self.tap, 'v0.5.8', self.sha, 'sonoma', runner=inspecting)
            self.assertEqual(os.environ['GH_TOKEN'], hostile['GH_TOKEN'])
            self.assertEqual(os.environ['HOMEBREW_NO_INSTALL_FROM_API'], '1')
        self.assertEqual([argv[:2] for argv in seen], [
            ['brew', '--repository'], ['brew', 'trust'], ['brew', 'trust'],
            ['ruby', '-c'], ['brew', 'info'],
            ['brew', 'fetch'], ['brew', '--cache'], ['brew', 'style'],
            ['brew', 'search'], ['brew', 'info'], ['brew', 'audit'],
            ['brew', 'untrust'],
        ])
        self.assertIn(['brew', 'trust', '--tap', gate.TAP], seen)
        self.assertEqual(seen[-1], ['brew', 'untrust', '--tap', gate.TAP])
        self.assertIn(['brew', 'style', '--cask', gate.QUALIFIED], seen)
        self.assertNotIn(['brew', 'style', '--cask', str(self.tap / gate.CASK)], seen)
        self.assert_no_staging()

    def test_default_validate_cannot_publish_and_repeat_uses_head(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(gate, 'publish', side_effect=AssertionError('publication reached')):
            receipt = self.validate()
            self.assertEqual(receipt['status'], 'validated')
            self.assertEqual(receipt['audit'], 'passed')
            self.assertEqual(self.validate()['baseline'], self.baseline)
        self.assert_no_staging()
        self.assertFalse(any(a[0] == 'git' and a[1] in ('add', 'commit', 'push') for a in self.calls))
        self.assertFalse((self.repo / 'Library/Taps/webdesserts/homebrew-tap').exists())
        self.assertEqual(gate.parser().parse_args(['--tap', str(self.tap), '--tag', 'v0.5.8', '--sha256', self.sha, '--macos-floor', 'sonoma']).operation, 'validate')

    def test_default_cli_and_missing_floor_do_not_publish(self):
        arguments = ['cask_gate.py', '--tap', str(self.tap), '--tag', 'v0.5.8', '--sha256', self.sha,
                     '--macos-floor', 'sonoma']
        with patch.object(sys, 'argv', arguments), patch.object(gate, 'validate', return_value={'status': 'validated'}) as validate, patch.object(gate, 'publish', side_effect=AssertionError('publication reached')), patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(gate.main(), 0)
            validate.assert_called_once()
        arguments.remove('--macos-floor')
        arguments.remove('sonoma')
        with patch.object(sys, 'argv', arguments), patch.object(gate, 'publish', side_effect=AssertionError('publication reached')), patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(gate.main(), 1)
        self.assertFalse((self.tap / gate.CASK).exists())
        self.assert_no_staging()

    def test_gate_failures_never_stage_and_cleanup_mapping(self):
        for failure in ['resolution', 'fetch', 'style', 'audit', 'collision', 'search', 'ruby']:
            with self.subTest(failure=failure):
                self.command_failure = failure
                with self.assertRaises(gate.ValidationError):
                    self.validate()
                self.assert_no_staging()
                self.assertFalse((self.repo / 'Library/Taps/webdesserts/homebrew-tap').exists())
        self.command_failure = None
        self.cache.write_bytes(b'wrong digest')
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assert_no_staging()

    def test_unrelated_dirty_staged_and_ref_mismatch_refuse(self):
        (self.tap / 'other').write_text('dirty')
        with self.assertRaises(gate.ValidationError):
            self.validate()
        (self.tap / 'other').unlink()
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assert_no_staging()

    def test_stale_audit_config_flag_is_dead_as_intentional_negative(self):
        with self.assertRaises(SystemExit) as caught:
            gate.parser().parse_args(['--tap', str(self.tap), '--tag', 'v0.5.8',
                                      '--audit-config', 'irrelevant.json'])
        self.assertEqual(caught.exception.code, 2)

    def test_collision_availability_and_own_token_are_bounded(self):
        for output in ['', gate.QUALIFIED + '\n', gate.TOKEN + '\n']:
            self.search_output = (output, '', 0)
            self.assertEqual(self.validate()['status'], 'validated')
        self.search_output = (gate.QUALIFIED + '\nother/tap/' + gate.TOKEN, '', 0)
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assert_no_staging()

    def test_own_token_collision_requires_own_full_token_and_source_path(self):
        self.search_output = (gate.TOKEN + '\n', '', 0)
        for field, value in [
            ('full_token', 'other/tap/' + gate.TOKEN),
            ('ruby_source_path', str(self.root / 'foreign-cask.rb')),
        ]:
            start = len(self.calls)
            self.unqualified_info_override = {field: value}
            with self.subTest(field=field), self.assertRaises(gate.ValidationError):
                self.validate()
            calls = self.calls[start:]
            self.assertTrue(any(argv[:4] == ['brew', 'info', '--json=v2', '--cask']
                                and argv[-1] == gate.TOKEN for argv in calls))
            self.assertFalse(any(argv[:2] == ['brew', 'audit'] for argv in calls))
            self.assertFalse(any(argv[0] == 'git'
                                 and any(verb in argv for verb in ('add', 'commit', 'push'))
                                 for argv in calls))
            self.assert_no_staging()
        self.unqualified_info_override = None

    def test_official_cask_shadowing_bare_token_is_accepted(self):
        self.search_output = (gate.TOKEN + '\n', '', 0)
        self.unqualified_info_override = {'tap': 'homebrew/cask', 'full_token': gate.TOKEN}
        self.assertEqual(self.validate()['status'], 'validated')
        self.unqualified_info_override = None

    def test_collision_search_accepts_only_exact_no_color_no_match(self):
        no_match = 'Error: No formulae or casks found for "/^mesh$/".\n'
        self.search_output = ('', no_match, 1)
        self.assertEqual(self.validate()['status'], 'validated')
        for out, err, code in [
            ('', no_match + 'another line\n', 1),
            ('', '\x1b[31m' + no_match, 1),
            ('', no_match.rstrip('\n'), 1),
            ('', '', 1),
            ('', 'Error: something else\n', 1),
            ('mesh\n', no_match, 1),
            ('', no_match, 2),
            (gate.QUALIFIED + '\n', 'warning on success\n', 0),
        ]:
            self.search_output = (out, err, code)
            with self.subTest(out=out, err=err, code=code), self.assertRaises(gate.ValidationError):
                self.validate()
        self.search_output = (gate.QUALIFIED + '\n', '', 0)
        self.assert_no_staging()

    def test_published_head_is_baseline_for_repeat_validation(self):
        path = self.tap / gate.CASK
        path.parent.mkdir()
        path.write_text(gate.generate('v0.5.7', 'a' * 64, 'sonoma'))
        self.git('add', '--', gate.CASK)
        self.git('commit', '-m', 'older published cask')
        self.baseline = self.git('rev-parse', 'HEAD').stdout.strip()
        self.git('update-ref', 'refs/remotes/origin/main', self.baseline)
        self.assertEqual(self.validate()['baseline'], self.baseline)
        self.assertEqual(self.validate()['baseline'], self.baseline)
        self.assert_no_staging()
        path.write_text(path.read_text() + '# unrelated edit\n')
        with self.assertRaises(gate.ValidationError):
            self.validate()

    def test_queue_and_late_remote_changes_leave_no_staging(self):
        self.queue_busy = True
        with self.assertRaises(gate.ValidationError):
            self.publish()
        self.assertFalse((self.tap / gate.CASK).exists())
        self.assert_no_staging()
        self.queue_busy = False
        original = self.runner
        def changing(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[:2] == ['brew', 'audit']:
                self.remote = 'a' * 40
            return result
        with self.assertRaises(gate.ValidationError):
            self.publish(runner=changing)
        self.assert_no_staging()

    def test_runner_exception_always_removes_owned_mapping(self):
        original = self.runner
        def raising(argv, **kwargs):
            if argv[:2] == ['brew', 'fetch']:
                raise OSError('fixture fetch failure')
            return original(argv, **kwargs)
        with self.assertRaises(OSError):
            gate.validate(self.tap, 'v0.5.8', self.sha, 'sonoma', runner=raising)
        self.assertFalse((self.repo / 'Library/Taps/webdesserts').exists())
        self.assert_no_staging()

    def test_staged_candidate_is_not_revalidated(self):
        self.validate()
        self.git('add', '--', gate.CASK)
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assertFalse(any(a[:2] == ['git', 'push'] for a in self.calls))

    def test_validation_call_graph_excludes_publication_and_git_writes(self):
        module = ast.parse(Path(gate.__file__).read_text())
        functions = {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}
        reachable = set()
        def visit(name):
            if name in reachable or name not in functions:
                return
            reachable.add(name)
            for node in ast.walk(functions[name]):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    visit(node.func.id)
        visit('validate')
        self.assertNotIn('publish', reachable)
        self.assertNotIn('remote_head', reachable)
        self.assertNotIn('check_queue', reachable)
        for verb in ['add', 'commit', 'push', 'config', 'reset', 'update-ref']:
            with self.subTest(verb=verb), self.assertRaises(gate.ValidationError):
                gate.read_git(self.tap, self.runner, verb)

    def test_owner_symlink_cannot_create_mapping_in_external_directory(self):
        owner = self.repo / 'Library/Taps/webdesserts'
        external = self.root / 'external-owner'
        external.mkdir()
        sentinel = external / 'sentinel'
        sentinel.write_bytes(b'external state must remain untouched\x00')
        owner.symlink_to(external, target_is_directory=True)
        link_before = owner.lstat()
        target_before = external.stat()
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assertTrue(owner.is_symlink())
        self.assertEqual(os.readlink(owner), str(external))
        for key in ('st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            self.assertEqual(getattr(owner.lstat(), key), getattr(link_before, key))
            self.assertEqual(getattr(external.stat(), key), getattr(target_before, key))
        self.assertEqual(sentinel.read_bytes(), b'external state must remain untouched\x00')
        self.assertEqual(list(external.iterdir()), [sentinel])
        self.assertFalse((external / 'homebrew-tap').is_symlink())
        self.assertEqual([a for a in self.calls if a[0] in ('brew', 'ruby')], [['brew', '--repository']])
        self.assert_no_staging()

    def test_owner_file_and_dangling_symlink_are_rejected_unchanged(self):
        owner = self.repo / 'Library/Taps/webdesserts'
        missing = self.root / 'missing-owner'
        for kind in ('file', 'dangling-symlink'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    owner.write_bytes(b'owner file')
                else:
                    owner.symlink_to(missing, target_is_directory=True)
                before = owner.lstat()
                with self.assertRaises(gate.ValidationError):
                    self.validate()
                self.assertEqual(owner.lstat(), before)
                if kind == 'file':
                    self.assertEqual(owner.read_bytes(), b'owner file')
                else:
                    self.assertEqual(os.readlink(owner), str(missing))
                    self.assertFalse(missing.exists())
                owner.unlink()
        self.assert_no_staging()

    def test_existing_mapping_is_not_replaced(self):
        mapping = self.repo / 'Library/Taps/webdesserts/homebrew-tap'
        mapping.mkdir(parents=True)
        with self.assertRaises(gate.ValidationError):
            self.validate()
        self.assertTrue(mapping.is_dir())
        self.assert_no_staging()

    def test_publish_requires_signer_configuration_before_rewrite(self):
        bogus_signer = self.root / 'bogus-signer.json'
        bogus_signer.write_text(json.dumps({'exit_code': 1, 'stdout_lines': [], 'stderr_lines': ['fixture self-signed incompatibility']}))
        for config in (None, self.root / 'missing.json', bogus_signer):
            with self.subTest(config=config), self.assertRaises(gate.ValidationError):
                self.publish(signer_config=config)
            self.assertFalse((self.tap / gate.CASK).exists())
            self.assertEqual(self.calls, [])
            self.assert_no_staging()

    def test_publish_cli_requires_explicit_signer_config(self):
        args = ['cask_gate.py', '--operation', 'publish', '--tap', str(self.tap),
                '--tag', 'v0.5.8', '--sha256', self.sha, '--macos-floor', 'sonoma',
                '--run-id', '123']
        with patch.object(sys, 'argv', args), patch('sys.stderr', new_callable=io.StringIO) as output:
            self.assertEqual(gate.main(), 1)
            self.assertIn('explicit signer configuration required', output.getvalue())
        self.assertFalse((self.tap / gate.CASK).exists())
        self.assert_no_staging()

    def test_validate_only_never_loads_signer_or_validates_artifact(self):
        self.signer_config.unlink()
        with patch.object(gate.artifact_validator, 'validate', side_effect=AssertionError('artifact validation reached')), patch.object(gate.artifact_validator, 'load_config', side_effect=AssertionError('signer config reached')):
            receipt = self.validate()
        self.assertNotIn('cache', receipt)
        self.assertNotIn(str(self.cache), json.dumps(receipt))
        self.assert_no_staging()

    def test_artifact_rejections_and_bad_receipts_never_write_git(self):
        for failure in ('wrong signer', 'ad-hoc signature', 'validation failure', 'bad-status', 'bad-digest', 'bad-version', 'bad-asset', 'bad-size', 'copy-mutation'):
            path = self.tap / gate.CASK
            if path.exists():
                path.unlink()
            self.validated_paths.clear()
            def reject(dmg, version, config_path, runner):
                receipt = self.artifact_validator(dmg, version, config_path, runner)
                if failure in ('wrong signer', 'ad-hoc signature', 'validation failure'):
                    raise gate.ValidationError(failure)
                if failure == 'copy-mutation':
                    dmg.write_bytes(b'changed during validation')
                else:
                    receipt[{'bad-status': 'status', 'bad-digest': 'sha256', 'bad-version': 'version', 'bad-asset': 'asset', 'bad-size': 'size'}[failure]] = 'wrong'
                return receipt
            with self.subTest(failure=failure), self.assertRaises(gate.ValidationError):
                self.publish(validator=reject)
            self.assert_no_staging()
            self.assertTrue(self.validated_paths)
            self.assertTrue(all(not p.parent.exists() for p in self.validated_paths))
            self.assertFalse(any(a[0] == 'git' and any(v in a for v in ('add', 'commit', 'push')) for a in self.calls))

    def test_cache_and_copy_failures_block_and_clean_temporary_directory(self):
        original_copy = gate.shutil.copyfile
        for failure in ('cache-before-copy', 'copy-corruption', 'copy-error'):
            path = self.tap / gate.CASK
            if path.exists():
                path.unlink()
            self.cache.write_bytes(b'fixture dmg')
            copies = []
            def copying(source, destination):
                self.assertEqual(source, self.cache)
                copies.append(destination)
                if failure == 'copy-error':
                    raise OSError('fixture copy failure')
                original_copy(source, destination)
                destination.write_bytes(b'corrupted copy')
            def changing(argv, **kwargs):
                result = self.runner(argv, **kwargs)
                if failure == 'cache-before-copy' and argv[:2] == ['brew', 'audit']:
                    self.cache.write_bytes(b'cache mutated after digest gate')
                return result
            with self.subTest(failure=failure), patch.object(gate.shutil, 'copyfile', side_effect=copying), self.assertRaises((gate.ValidationError, OSError)):
                self.publish(runner=changing)
            self.assertEqual(self.validated_paths, [])
            self.assertTrue(all(not p.parent.exists() for p in copies))
            self.assert_no_staging()

    def test_actual_artifact_validator_is_used_by_default_before_git_writes(self):
        for details, accepted in [('Authority=Wrong signer\n', False), ('Signature=adhoc\n', False),
                                  ('Authority=ObsidianMemory Dev Signing\nSignature size=123\n', True)]:
            path = self.tap / gate.CASK
            if path.exists():
                path.unlink()
            fixture = FixtureRunner()
            fixture.metadata['CFBundleShortVersionString'] = '0.5.8'
            fixture.details = details
            fixture.cleanup_mount = lambda mount: None
            def combined(argv, **kwargs):
                if argv[0] in ('hdiutil', 'lipo', 'codesign', 'spctl', 'xcrun'):
                    return fixture(argv, **kwargs)
                return self.runner(argv, **kwargs)
            with self.subTest(details=details):
                if accepted:
                    self.assertEqual(self.publish(validator=None, runner=combined)['remote'], 'accepted')
                else:
                    with self.assertRaises(gate.ValidationError):
                        self.publish(validator=None, runner=combined)
                    self.assert_no_staging()
            self.assertTrue(fixture.calls)
            self.assertFalse(fixture.mount.exists())
            attach = next(argv for argv in fixture.calls if argv[:2] == ['hdiutil', 'attach'])
            copied = Path(attach[-1])
            self.assertEqual(copied.name, 'Mesh_0.5.8_universal.dmg')
            self.assertFalse(copied.parent.exists())

    def test_publish_newer_success_cask_only(self):
        receipt = self.publish()
        self.assertEqual(len(self.validated_paths), 1)
        self.assertFalse(self.validated_paths[0].parent.exists())
        self.assertEqual(receipt['remote'], 'accepted')
        self.assertEqual(self.git('show', '--format=', '--name-only', 'HEAD').stdout.strip(), gate.CASK)
        self.assertEqual(self.git('status', '--porcelain').stdout, '')
        self.assertEqual([a for a in self.calls if a[:2] == ['git', 'add']], [['git', 'add', '--', gate.CASK]])

    def test_publish_equal_or_older_refuses_before_rewrite(self):
        for version in ['0.5.8', '0.5.9']:
            path = self.tap / gate.CASK
            path.parent.mkdir(exist_ok=True)
            path.write_text(gate.generate('v' + version, 'a' * 64, 'sonoma'))
            self.git('add', '--', gate.CASK)
            self.git('commit', '-m', 'published fixture')
            self.baseline = self.git('rev-parse', 'HEAD').stdout.strip()
            self.git('update-ref', 'refs/remotes/origin/main', self.baseline)
            self.remote = self.baseline
            before = path.read_bytes()
            with self.subTest(version=version), self.assertRaises(gate.ValidationError):
                self.publish()
            self.assertEqual(path.read_bytes(), before)
            self.assert_no_staging()

    def test_publish_dirty_or_stale_refuses(self):
        self.remote = 'a' * 40
        with self.assertRaises(gate.ValidationError):
            self.publish()
        self.assertFalse((self.tap / gate.CASK).exists())
        self.remote = self.baseline
        self.validate()
        with self.assertRaises(gate.ValidationError):
            self.publish()
        self.assert_no_staging()

    def test_publish_gate_failure_does_not_stage(self):
        self.command_failure = 'style'
        with self.assertRaises(gate.ValidationError):
            self.publish()
        self.assert_no_staging()

    def test_audit_failure_blocks_before_artifact_validation_and_git_write(self):
        audit_codes = []
        validated = []
        original = self.runner
        def auditing(argv, **kwargs):
            outcome = original(argv, **kwargs)
            if argv[:2] == ['brew', 'audit']:
                audit_codes.append(outcome.returncode)
            return outcome
        def validator(dmg, version, config_path, runner):
            validated.append(dmg)
            return self.artifact_validator(dmg, version, config_path, runner)
        self.command_failure = 'audit'
        with self.assertRaises(gate.ValidationError) as caught:
            self.publish(runner=auditing, validator=validator)
        self.assertEqual(
            str(caught.exception),
            "command failed: brew audit; stdout=''; stderr='unrelated failure'",
        )
        self.assertEqual(audit_codes, [1])
        self.assertEqual(validated, [])
        self.assertFalse(any(a[0] == 'git' and any(v in a for v in ('add', 'commit', 'push')) for a in self.calls))
        # Candidate file creation and temporary Homebrew mapping precede the
        # audit by design; the guarantee is no publication Git write.
        self.assert_no_staging()

    def test_audit_failure_diagnostic_is_bounded(self):
        original = self.runner
        def noisy_audit(argv, **kwargs):
            if argv[:2] == ['brew', 'audit']:
                return subprocess.CompletedProcess(
                    argv, 1, '', 'x' * (gate.MAX_AUDIT_OUTPUT + 1)
                )
            return original(argv, **kwargs)
        with self.assertRaisesRegex(
            gate.ValidationError, 'invalid or excessive brew audit output'
        ):
            self.publish(runner=noisy_audit)
        self.assertFalse(any(a[0] == 'git'
                             and any(verb in a for verb in ('add', 'commit', 'push'))
                             for a in self.calls))
        self.assert_no_staging()

    def test_commit_failure_reports_local_stage(self):
        self.command_failure = 'commit'
        receipt = self.publish()
        self.assertEqual(receipt['status'], 'publication_failed')
        self.assertEqual(receipt['local'], 'staging_or_commit_may_exist')
        self.assertFalse(any(a[:2] == ['git', 'push'] for a in self.calls))

    def test_push_failure_reports_remote_evidence_without_retry(self):
        for outcome, expected in [('rejected', 'unchanged'), ('unchanged-exception', 'unchanged'), ('accepted', 'accepted'), ('accepted-nonzero', 'accepted'), ('unknown', 'unknown'), ('diverged', 'unknown')]:
            with self.subTest(outcome=outcome):
                self.git('reset', '--hard', self.baseline)
                self.remote = self.baseline
                self.push = outcome
                self.calls.clear()
                receipt = self.publish()
                self.assertEqual(receipt['remote'], expected)
                self.assertEqual(receipt['local'], 'committed')
                self.assertNotEqual(receipt['commit'], self.baseline)
                self.assertEqual(len([a for a in self.calls if a[:2] == ['git', 'push']]), 1)
                self.assertFalse(any('--force' in a or 'rebase' in a for a in self.calls))


class AuditQueueTests(unittest.TestCase):
    def test_stable_only_numeric_ordering(self):
        for tag in ['v0.5.8-rc.1', 'v0.5.8+build.1', 'v01.5.8', '0.5.8', 'v0.5', 'v0.5.8\n']:
            with self.subTest(tag=tag), self.assertRaises(gate.ValidationError):
                gate.generate(tag, 'a' * 64, 'sonoma')
        for tag, baseline in [('v0.5.10', '0.5.9'), ('v0.6.0', '0.5.99'), ('v1.0.0', '0.99.99')]:
            gate.require_newer(tag, '  version "' + baseline + '"\n')
        for tag, baseline in [('v0.5.8', '0.5.8'), ('v0.5.9', '0.5.10'), ('v0.5.8', '0.5.7-rc.1')]:
            with self.subTest(tag=tag, baseline=baseline), self.assertRaises(gate.ValidationError):
                gate.require_newer(tag, '  version "' + baseline + '"\n')

    def test_queue_auth_remains_separate_from_candidate_environment(self):
        def runner(argv, **kwargs):
            self.assertEqual(argv[0], 'gh')
            self.assertNotIn('env', kwargs)
            self.assertEqual(os.environ['GH_TOKEN'], 'fixture-queue-auth')
            return subprocess.CompletedProcess(argv, 0, '[{"total_count": 0, "workflow_runs": []}]', '')
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-queue-auth'}, clear=True):
            gate.check_queue('123', runner=runner)

    def test_queue_self_exclusion_all_nonterminal_and_incomplete_errors(self):
        calls = []
        def runner(argv, **kw):
            calls.append(argv)
            status = argv[-1].split('status=')[1].split('&')[0]
            rows = [{'id': 123, 'status': status}]
            return subprocess.CompletedProcess(argv, 0, json.dumps([{'total_count': 1, 'workflow_runs': rows}]), '')
        gate.check_queue('123', runner=runner)
        self.assertEqual(len(calls), 2 * len(gate.NONTERMINAL))
        for state in gate.NONTERMINAL:
            def active(argv, **kw):
                status = argv[-1].split('status=')[1].split('&')[0]
                rows = [{'id': 456, 'status': state}] if status == state else []
                return subprocess.CompletedProcess(argv, 0, json.dumps([{'total_count': len(rows), 'workflow_runs': rows}]), '')
            with self.subTest(state=state), self.assertRaises(gate.ValidationError):
                gate.check_queue('123', runner=active)
        for code, payload in [(1, ''), (0, 'bad'), (0, '[]'), (0, '[{"total_count": 1, "workflow_runs": []}]')]:
            with self.subTest(payload=payload), self.assertRaises(gate.ValidationError):
                gate.check_queue('123', runner=lambda *a, **k: subprocess.CompletedProcess([], code, payload, ''))


if __name__ == '__main__':
    unittest.main()
