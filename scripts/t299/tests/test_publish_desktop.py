import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish_desktop as pub
from test_artifact_validator import config
from artifact_validator import ValidationError


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='publisher checkout ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.cfg = self.root / 'fixture-config.json'
        self.cfg.write_text(json.dumps(config()))
        self.calls = []
        self.fail = None
        self.dirty = False
        self.wrong_tag = False
        self.existing = False
        self.version = 'tauri-cli 2.11.4'
        self.validated = []
        self.override = None

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        code, out = 0, ''
        if argv[0] != 'gh':
            self.assertNotIn('GH_TOKEN', kwargs['env'])
            self.assertNotIn('GITHUB_TOKEN', kwargs['env'])
        if argv[:2] == ['git', 'status']:
            out = ' M dirty' if self.dirty else ''
        elif argv[:2] == ['git', 'rev-parse']:
            out = 'b'*40 if self.wrong_tag and argv[-1] != 'HEAD' else 'a'*40
        elif argv[:2] == ['git', 'symbolic-ref']:
            code = 1
        elif argv == ['cargo', 'tauri', '--version']:
            out = self.version
        elif argv[:3] == ['cargo', 'tauri', 'build']:
            self.override = Path(argv[argv.index('--config')+1])
            self.assertEqual(json.loads(self.override.read_text()), {'build': {'beforeBuildCommand': ''}})
            self.assertEqual(kwargs['cwd'], self.root / 'crates/desktop')
            self.assertEqual(kwargs['env']['APPLE_SIGNING_IDENTITY'], 'ObsidianMemory Dev Signing')
            self.assertEqual(argv[:7], ['cargo', 'tauri', 'build', '--target', 'universal-apple-darwin', '--bundles', 'dmg'])
            artifact = pub.artifact_path(self.root, '0.5.7')
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b'final dmg')
        elif argv[:3] == ['gh', 'release', 'view']:
            out = json.dumps({'tagName': 'v0.5.7', 'assets': [{'name': 'Mesh_0.5.7_universal.dmg'}] if self.existing else []})
        if self.fail and self.fail in argv:
            code = 99
        return subprocess.CompletedProcess(argv, code, out, '')

    def validator(self, dmg, version, cfg, runner):
        self.validated.append(dmg)
        self.assertEqual(dmg, pub.artifact_path(self.root, version))
        self.assertFalse(self.override.exists())
        return {'status': 'validated', 'asset': dmg.name, 'sha256': pub.digest(dmg), 'size': dmg.stat().st_size}

    def execute(self, publish=False, validator=None):
        return pub.execute(self.root, 'v0.5.7', self.cfg, publish=publish, runner=self.runner, validator=validator or self.validator)

    def test_default_build_only_external_checkout_no_github_credentials(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-token', 'APPLE_SIGNING_IDENTITY': 'wrong'}):
            receipt = self.execute()
        self.assertEqual(receipt['upload']['status'], 'not_requested')
        self.assertFalse(any(argv[0] == 'gh' for argv, _ in self.calls))
        self.assertEqual(len(self.validated), 1)
        builds = [argv for argv, _ in self.calls if argv[:3] == ['cargo', 'tauri', 'build']]
        self.assertEqual(len(builds), 1)
        for argv, opts in self.calls:
            self.assertNotIn('shell', opts)
            if argv[:3] != ['cargo', 'tauri', 'build']:
                self.assertNotIn('APPLE_SIGNING_IDENTITY', opts['env'])

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

    def test_failed_build_no_retry_and_override_removed(self):
        self.fail = '--bundles'
        with self.assertRaises(ValidationError):
            self.execute()
        self.assertFalse(self.override.exists())
        self.assertEqual(len([1 for argv, _ in self.calls if '--bundles' in argv]), 1)
        self.assertEqual(self.validated, [])

    def test_existing_release_asset_or_missing_release_blocks_build(self):
        for existing, fail in [(True, None), (False, 'view')]:
            self.existing, self.fail = existing, fail
            with self.assertRaises(ValidationError):
                self.execute(publish=True)

    def test_signature_failure_never_uploads(self):
        def reject(*args, **kwargs):
            raise ValidationError('signature invalid')
        with self.assertRaises(ValidationError):
            self.execute(publish=True, validator=reject)
        self.assertFalse(any('upload' in argv for argv, _ in self.calls))

    def test_explicit_publish_exact_file_no_clobber(self):
        receipt = self.execute(publish=True)
        self.assertEqual(receipt['upload']['status'], 'uploaded')
        uploads = [argv for argv, _ in self.calls if 'upload' in argv]
        self.assertEqual(uploads, [['gh', 'release', 'upload', 'v0.5.7', str(pub.artifact_path(self.root, '0.5.7')), '--repo', pub.REPOSITORY]])

    def test_ambiguous_upload_preserves_validation_not_remote_success(self):
        self.fail = 'upload'
        receipt = self.execute(publish=True)
        self.assertEqual(receipt['validation']['status'], 'validated')
        self.assertEqual(receipt['upload']['status'], 'unknown')

    def test_invalid_receipt_and_missing_artifact_never_upload(self):
        def invalid(*args, **kwargs):
            return {'status': 'validated', 'asset': 'wrong', 'sha256': '0'*64, 'size': 0}
        with self.assertRaises(ValidationError):
            self.execute(publish=True, validator=invalid)
        self.assertFalse(any('upload' in argv for argv, _ in self.calls))

    def test_upload_transport_exception_is_unknown(self):
        base = self.runner
        def disconnected(argv, **kwargs):
            if 'upload' in argv:
                raise OSError('fixture disconnect')
            return base(argv, **kwargs)
        self.runner = disconnected
        self.assertEqual(self.execute(publish=True)['upload']['status'], 'unknown')

    def test_cli_persists_diagnostic_and_never_overwrites(self):
        receipt = self.root / 'receipt.json'
        argv = ['publish_desktop.py', '--source', str(self.root), '--tag', 'v0.5.7', '--signer-config', str(self.cfg), '--receipt', str(receipt)]
        with patch.object(sys, 'argv', argv), patch.object(pub, 'execute', side_effect=ValidationError('fixture refusal')) as execute, patch('builtins.print'):
            self.assertEqual(pub.main(), 1)
            self.assertEqual(json.loads(receipt.read_text())['upload']['status'], 'not_attempted')
            self.assertEqual(pub.main(), 1)
            self.assertEqual(execute.call_count, 1)

    def test_stale_artifact_refused(self):
        dmg = pub.artifact_path(self.root, '0.5.7')
        dmg.parent.mkdir(parents=True)
        dmg.write_bytes(b'stale')
        with self.assertRaisesRegex(ValidationError, 'already exists'):
            self.execute()


if __name__ == '__main__':
    unittest.main()