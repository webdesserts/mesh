import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish_desktop as pub
from test_artifact_validator import config
from artifact_validator import ValidationError

TAG = 'v0.5.7'
HEAD = 'a' * 40


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='publisher checkout ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.cfg = self.root / 'fixture-config.json'
        self.cfg.write_text(json.dumps(config()))
        self.key = self.root / 'updater.key'
        self.key.write_text('fixture updater key')
        self.calls = []
        self.fail = None
        self.dirty = False
        self.wrong_tag = False
        self.remote_tag = HEAD
        self.release = 'missing'
        self.existing = []
        self.lookup_error = False
        self.bad_remote = False
        self.no_sig = False
        self.version = 'tauri-cli 2.11.4'
        self.validated = []
        self.override = None

    def built(self):
        return pub.release_assets(self.root, '0.5.7')

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        code, out, err = 0, '', ''
        if argv[0] != 'gh':
            self.assertNotIn('GH_TOKEN', kwargs['env'])
            self.assertNotIn('GITHUB_TOKEN', kwargs['env'])
        if argv[:2] == ['git', 'status']:
            out = ' M dirty' if self.dirty else ''
        elif argv[:2] == ['git', 'rev-parse']:
            out = 'b' * 40 if self.wrong_tag and argv[-1] != 'HEAD' else HEAD
        elif argv[:2] == ['git', 'symbolic-ref']:
            code = 1
        elif argv[:2] == ['git', 'ls-remote']:
            ref = 'refs/tags/' + TAG
            out = 'd' * 40 + '\t' + ref + '\n' + self.remote_tag + '\t' + ref + '^{}'
        elif argv == ['cargo', 'tauri', '--version']:
            out = self.version
        elif argv[:3] == ['cargo', 'tauri', 'build']:
            self.override = Path(argv[argv.index('--config') + 1])
            self.assertEqual(json.loads(self.override.read_text()), {'build': {'beforeBuildCommand': ''}})
            self.assertEqual(kwargs['cwd'], self.root / 'crates/desktop')
            env = kwargs['env']
            self.assertEqual(env['APPLE_SIGNING_IDENTITY'], 'ObsidianMemory Dev Signing')
            self.assertEqual(env['TAURI_SIGNING_PRIVATE_KEY'], str(self.key))
            self.assertIn('TAURI_SIGNING_PRIVATE_KEY_PASSWORD', env)
            self.assertEqual(argv[:7], ['cargo', 'tauri', 'build', '--target', 'universal-apple-darwin', '--bundles', 'app,dmg'])
            dmg, tar_gz, _ = self.built()
            for path in [dmg, tar_gz]:
                path.parent.mkdir(parents=True, exist_ok=True)
            dmg.write_bytes(b'final dmg')
            tar_gz.write_bytes(b'final updater archive')
            if not self.no_sig:
                pub.updater_sig_path(self.root).write_text('fixture-signature\n')
        elif argv[:3] == ['gh', 'release', 'view'] and argv[-1] == 'tagName,assets,isDraft':
            if self.lookup_error:
                code, err = 1, 'HTTP 500'
            elif self.release == 'missing':
                code, err = 1, 'release not found'
            else:
                out = json.dumps({'tagName': TAG, 'isDraft': self.release == 'draft',
                                  'assets': [{'name': name} for name in self.existing]})
        elif argv[:3] == ['gh', 'release', 'view'] and argv[-1] == 'assets':
            assets = []
            for path in self.built():
                size = path.stat().st_size + (1 if self.bad_remote else 0)
                assets.append({'name': path.name, 'size': size, 'digest': 'sha256:' + pub.digest(path)})
            out = json.dumps({'assets': assets})
        if self.fail and self.fail in argv:
            code = 99
        return subprocess.CompletedProcess(argv, code, out, err)

    def validator(self, dmg, version, cfg, runner):
        self.validated.append(dmg)
        self.assertEqual(dmg, pub.artifact_path(self.root, version))
        self.assertFalse(self.override.exists())
        return {'status': 'validated', 'asset': dmg.name, 'sha256': pub.digest(dmg), 'size': dmg.stat().st_size}

    def execute(self, publish=False, validator=None, updater_key='default'):
        key = self.key if updater_key == 'default' else updater_key
        return pub.execute(self.root, TAG, self.cfg, publish=publish, runner=self.runner,
                           validator=validator or self.validator, updater_key=key)

    def gh(self, verb):
        return [argv for argv, _ in self.calls if argv[:3] == ['gh', 'release', verb]]

    def paths(self):
        return [str(path) for path in self.built()]

    def test_default_build_only_external_checkout_no_github_credentials(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-token', 'APPLE_SIGNING_IDENTITY': 'wrong'}):
            receipt = self.execute()
        self.assertEqual(receipt['upload']['status'], 'not_requested')
        self.assertFalse(any(argv[0] == 'gh' or argv[:2] == ['git', 'ls-remote'] for argv, _ in self.calls))
        self.assertEqual(len(self.validated), 1)
        builds = [argv for argv, _ in self.calls if argv[:3] == ['cargo', 'tauri', 'build']]
        self.assertEqual(len(builds), 1)
        for argv, opts in self.calls:
            self.assertNotIn('shell', opts)
            if argv[:3] != ['cargo', 'tauri', 'build']:
                self.assertNotIn('APPLE_SIGNING_IDENTITY', opts['env'])
                self.assertNotIn('TAURI_SIGNING_PRIVATE_KEY', opts['env'])

    def test_latest_json_and_updater_receipt(self):
        receipt = self.execute()
        _, tar_gz, latest = self.built()
        manifest = json.loads(latest.read_text())
        url = 'https://github.com/{}/releases/download/{}/{}.tar.gz'.format(pub.REPOSITORY, TAG, pub.APP_BUNDLE_NAME)
        self.assertEqual(manifest['version'], '0.5.7')
        self.assertEqual(manifest['notes'], 'Release ' + TAG)
        self.assertRegex(manifest['pub_date'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
        self.assertEqual(manifest['platforms'], {p: {'signature': 'fixture-signature', 'url': url}
                                                 for p in ['darwin-aarch64', 'darwin-x86_64']})
        self.assertEqual(receipt['updater'], {'archive': tar_gz.name, 'archive_sha256': pub.digest(tar_gz),
                                              'latest_json_sha256': pub.digest(latest)})

    def test_missing_config_dirty_wrong_tag_and_cli_pin_stop(self):
        for field in ['dirty', 'wrong_tag', 'version']:
            with self.subTest(field=field):
                self.calls = []
                old = getattr(self, field)
                setattr(self, field, 'tauri-cli 2.11.5' if field == 'version' else True)
                with self.assertRaises(ValidationError):
                    self.execute()
                setattr(self, field, old)
        self.cfg.unlink()
        with self.assertRaisesRegex(ValidationError, 'configuration missing'):
            self.execute()

    def test_updater_key_missing_stops_before_build(self):
        with patch.dict(os.environ, {}, clear=False), patch.object(pub, 'DEFAULT_UPDATER_KEY', self.root / 'absent.key'):
            os.environ.pop('TAURI_SIGNING_PRIVATE_KEY', None)
            with self.assertRaisesRegex(ValidationError, 'updater signing key missing'):
                self.execute(updater_key=None)
        self.assertFalse(any(argv[:3] == ['cargo', 'tauri', 'build'] for argv, _ in self.calls))

    def test_updater_key_from_environment(self):
        with patch.dict(os.environ, {'TAURI_SIGNING_PRIVATE_KEY': str(self.key)}):
            self.assertEqual(self.execute(updater_key=None)['upload']['status'], 'not_requested')

    def test_missing_updater_signature_refused(self):
        self.no_sig = True
        with self.assertRaisesRegex(ValidationError, 'updater signature missing'):
            self.execute()
        self.assertFalse(self.built()[2].exists())

    def test_failed_build_no_retry_and_override_removed(self):
        self.fail = '--bundles'
        with self.assertRaises(ValidationError):
            self.execute()
        self.assertFalse(self.override.exists())
        self.assertEqual(len([1 for argv, _ in self.calls if '--bundles' in argv]), 1)
        self.assertEqual(self.validated, [])

    def test_existing_asset_lookup_error_or_remote_tag_mismatch_blocks_build(self):
        cases = [dict(release='published', existing=['latest.json']), dict(lookup_error=True),
                 dict(remote_tag='c' * 40)]
        for case in cases:
            with self.subTest(case=case):
                self.setUp()
                for name, value in case.items():
                    setattr(self, name, value)
                with self.assertRaises(ValidationError):
                    self.execute(publish=True)
                self.assertFalse(any(argv[:3] == ['cargo', 'tauri', 'build'] for argv, _ in self.calls))

    def test_annotated_remote_tag_is_peeled(self):
        self.assertEqual(self.execute(publish=True)['upload']['status'], 'uploaded')

    def test_new_release_is_drafted_verified_then_published(self):
        receipt = self.execute(publish=True)
        self.assertEqual(receipt['upload'], {'status': 'uploaded', 'release': 'created', 'published': True})
        self.assertEqual(self.gh('create'), [['gh', 'release', 'create', TAG] + self.paths() +
                                             ['--repo', pub.REPOSITORY, '--draft', '--verify-tag', '--title', TAG, '--generate-notes']])
        self.assertEqual(self.gh('edit'), [['gh', 'release', 'edit', TAG, '--repo', pub.REPOSITORY, '--draft=false', '--latest']])
        order = [argv[2] for argv, _ in self.calls if argv[:2] == ['gh', 'release'] and argv[2] != 'view']
        self.assertEqual(order, ['create', 'edit'])
        self.assertFalse(self.gh('upload'))

    def test_existing_release_uploads_exact_files_no_clobber(self):
        for release, edits in [('published', 0), ('draft', 1)]:
            with self.subTest(release=release):
                self.setUp()
                self.release = release
                receipt = self.execute(publish=True)
                self.assertEqual(receipt['upload']['status'], 'uploaded')
                self.assertEqual(self.gh('upload'), [['gh', 'release', 'upload', TAG] + self.paths() + ['--repo', pub.REPOSITORY]])
                self.assertEqual(len(self.gh('edit')), edits)
                self.assertFalse(self.gh('create'))

    def test_ambiguous_create_or_publish_is_unknown(self):
        for fail, edits in [('create', 0), ('edit', 1)]:
            with self.subTest(fail=fail):
                self.setUp()
                self.fail = fail
                receipt = self.execute(publish=True)
                self.assertEqual(receipt['validation']['status'], 'validated')
                self.assertEqual(receipt['upload']['status'], 'unknown')
                self.assertFalse(receipt['upload']['published'])
                self.assertEqual(len(self.gh('edit')), edits)

    def test_unverified_remote_assets_never_published(self):
        self.bad_remote = True
        receipt = self.execute(publish=True)
        self.assertEqual(receipt['upload']['status'], 'unverified')
        self.assertIn('size mismatch', receipt['upload']['reason'])
        self.assertFalse(self.gh('edit'))

    def test_signature_failure_never_uploads(self):
        def reject(*args, **kwargs):
            raise ValidationError('signature invalid')
        with self.assertRaises(ValidationError):
            self.execute(publish=True, validator=reject)
        self.assertFalse(self.gh('create') or self.gh('upload'))

    def test_invalid_receipt_and_missing_artifact_never_upload(self):
        def invalid(*args, **kwargs):
            return {'status': 'validated', 'asset': 'wrong', 'sha256': '0' * 64, 'size': 0}
        with self.assertRaises(ValidationError):
            self.execute(publish=True, validator=invalid)
        self.assertFalse(self.gh('create') or self.gh('upload'))

    def test_upload_transport_exception_is_unknown(self):
        base = self.runner

        def disconnected(argv, **kwargs):
            if 'create' in argv:
                raise OSError('fixture disconnect')
            return base(argv, **kwargs)
        self.runner = disconnected
        self.assertEqual(self.execute(publish=True)['upload']['status'], 'unknown')
        self.assertFalse(self.gh('edit'))

    def test_cli_persists_diagnostic_and_never_overwrites(self):
        receipt = self.root / 'receipt.json'
        argv = ['publish_desktop.py', '--source', str(self.root), '--tag', TAG, '--signer-config', str(self.cfg), '--receipt', str(receipt)]
        with patch.object(sys, 'argv', argv), patch.object(pub, 'execute', side_effect=ValidationError('fixture refusal')) as execute, patch('builtins.print'):
            self.assertEqual(pub.main(), 1)
            self.assertEqual(json.loads(receipt.read_text())['upload']['status'], 'not_attempted')
            self.assertEqual(pub.main(), 1)
            self.assertEqual(execute.call_count, 1)

    def test_stale_artifacts_refused(self):
        stale = list(self.built()) + [pub.updater_sig_path(self.root)]
        for path in stale:
            with self.subTest(path=path.name):
                self.calls = []
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'stale')
                with self.assertRaisesRegex(ValidationError, 'already exists'):
                    self.execute()
                self.assertFalse(any(argv[:3] == ['cargo', 'tauri', 'build'] for argv, _ in self.calls))
                path.unlink()


if __name__ == '__main__':
    unittest.main()
