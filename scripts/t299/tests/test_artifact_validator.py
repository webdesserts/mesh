import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import artifact_validator as av

CERT = b'fixture public DER bytes, not a real certificate'
DR = 'identifier "com.webdesserts.mesh" and certificate leaf = H"fixture"'


def config():
    return dict(common_name='ObsidianMemory Dev Signing', der_sha256=hashlib.sha256(CERT).hexdigest(),
                designated_requirement=DR, observations={
                    'spctl': dict(exit_code=3, stdout_lines=[], stderr_lines=['{path}: rejected: fixture self-signed']),
                    'ticket': dict(exit_code=65, stdout_lines=['fixture ticket absent: {path}'], stderr_lines=[])})


class FixtureRunner:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.metadata = {}
        self.arch = 'x86_64 arm64'
        self.certificates = 1
        self.details = 'Authority=ObsidianMemory Dev Signing\nSignature size=123\n'
        self.dr = 'designated => ' + DR
        self.mounted = False

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        out, err, code = '', '', 0
        if argv[:2] == ['hdiutil', 'attach']:
            self.mount = Path(argv[argv.index('-mountpoint') + 1])
            self.cleanup_mount(self.mount)
            app = self.mount / 'Mesh.app/Contents'
            (app / 'MacOS').mkdir(parents=True)
            (app / 'MacOS/Mesh').write_bytes(b'fixture executable')
            info = dict(CFBundleIdentifier=av.BUNDLE_ID, CFBundleShortVersionString='0.5.7', CFBundleExecutable='Mesh')
            info.update(self.metadata)
            (app / 'Info.plist').write_bytes(plistlib.dumps(info))
            self.mounted = True
        elif argv[:2] == ['hdiutil', 'detach']:
            assert argv[-1] == str(self.mount)
            self.mounted = False
            if self.fail != 'detach':
                shutil.rmtree(self.mount / 'Mesh.app')
        else:
            assert self.mounted
            assert str(self.mount) in argv[-1]
            extract = [arg for arg in argv if arg.startswith('--extract-certificates=')]
            if extract:
                assert len(extract) == 1
                prefix = extract[0].partition('=')[2]
                assert prefix
                for i in range(self.certificates):
                    Path(prefix + str(i)).write_bytes(CERT)
            elif argv[0] == 'lipo':
                out = self.arch
            elif '-r-' in argv:
                err = self.dr
            elif '-dv' in argv:
                err = self.details
            elif argv[0] == 'spctl':
                code, err = 3, argv[-1] + ': rejected: fixture self-signed'
            elif argv[0] == 'xcrun':
                code, out = 65, 'fixture ticket absent: ' + argv[-1]
        if self.fail and any(arg == self.fail or arg.startswith(self.fail) for arg in argv):
            code = 99
        return subprocess.CompletedProcess(argv, code, out, err)


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='validator tests ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dmg = self.root / 'Mesh_0.5.7_universal.dmg'
        self.dmg.write_bytes(b'fixture dmg')
        self.cfg = self.root / 'fixture.json'
        self.settings = config()
        self.runner = FixtureRunner()
        self.runner.cleanup_mount = lambda mount: self.addCleanup(shutil.rmtree, mount, True)

    def validate(self):
        self.cfg.write_text(json.dumps(self.settings))
        return av.validate(self.dmg, '0.5.7', self.cfg, runner=self.runner)

    def test_success_receipt_after_detach(self):
        original = av.digest
        def digest(path):
            if path == self.dmg:
                self.assertFalse(self.runner.mounted)
                self.assertEqual(self.runner.calls[-1][1], 'detach')
            return original(path)
        with patch.object(av, 'digest', digest):
            receipt = self.validate()
        self.assertEqual(receipt['sha256'], hashlib.sha256(b'fixture dmg').hexdigest())
        self.assertEqual(receipt['observations'], {'spctl': 'expected_preapproval', 'ticket': 'expected_preapproval'})
        attach = self.runner.calls[0]
        self.assertIn('-readonly', attach)
        self.assertIn('-nobrowse', attach)

    def test_certificate_prefix_is_attached_to_codesign_option(self):
        self.validate()
        call = next(argv for argv in self.runner.calls
                    if any(arg.startswith('--extract-certificates=') for arg in argv))
        options = [arg for arg in call if arg.startswith('--extract-certificates=')]
        self.assertEqual(len(options), 1)
        self.assertNotEqual(options[0], '--extract-certificates=')
        self.assertNotIn('--extract-certificates', call)
        self.assertEqual(call[-1], str(self.runner.mount / 'Mesh.app'))

    def test_identity_mismatches(self):
        for field, value in [('common_name', 'Other'), ('der_sha256', '0'*64), ('designated_requirement', DR + ' and false')]:
            with self.subTest(field=field):
                self.settings = config()
                self.settings[field] = value
                with self.assertRaises(av.ValidationError):
                    self.validate()
                self.assertEqual(self.runner.calls[-1][1], 'detach')

    def test_bad_metadata_and_arch(self):
        for key, value in [('CFBundleIdentifier', 'other'), ('CFBundleShortVersionString', '1.0.0'), ('CFBundleExecutable', '../Mesh'), ('CFBundleExecutable', 'other')]:
            with self.subTest(key=key, value=value):
                self.runner.metadata = {key: value}
                with self.assertRaises(av.ValidationError):
                    self.validate()
        self.runner.metadata = {}
        for arch in ['x86_64', 'arm64', 'arm64e', 'arm64 arm64', 'x86_64 arm64e', 'x86_64 arm64 arm64e']:
            self.runner.arch = arch
            with self.assertRaises(av.ValidationError):
                self.validate()

    def test_missing_multiple_certificates_and_unsigned(self):
        for count in [0, 2]:
            self.runner.certificates = count
            with self.assertRaises(av.ValidationError):
                self.validate()
        self.runner.certificates = 1
        for details in ['Signature=adhoc', 'flags=0x20002(adhoc,linker-signed)', 'Authority=Other', '']:
            self.runner.details = details
            with self.assertRaises(av.ValidationError):
                self.validate()

    def test_command_failures_always_detach_and_no_digest(self):
        for command in ['attach', '--extract-certificates=', '--verify', '-r-', '-dv', 'lipo', 'spctl', 'stapler', 'detach']:
            self.runner.fail = command
            with self.subTest(command=command), patch.object(av, 'digest', wraps=av.digest) as digest:
                with self.assertRaises(av.ValidationError):
                    self.validate()
                self.assertNotIn(unittest.mock.call(self.dmg), digest.call_args_list)
                self.assertEqual(self.runner.calls[-1][1], 'detach')

    def test_missing_config_and_invalid_config_do_not_mount(self):
        with self.assertRaisesRegex(av.ValidationError, 'identity configuration missing'):
            av.validate(self.dmg, '0.5.7', self.cfg, runner=self.runner)
        for key, value in [('common_name', ''), ('der_sha256', 'A'*64), ('designated_requirement', ''), ('observations', {})]:
            self.settings = config()
            self.settings[key] = value
            with self.assertRaises(av.ValidationError):
                self.validate()
        self.assertEqual(self.runner.calls, [])

    def test_missing_or_wrong_filename_does_not_mount(self):
        self.dmg.unlink()
        with self.assertRaises(av.ValidationError):
            self.validate()
        self.dmg = self.root / 'Other.dmg'
        self.dmg.write_bytes(b'x')
        with self.assertRaises(av.ValidationError):
            self.validate()
        self.assertEqual(self.runner.calls, [])

    def test_classifier_exact_exit_streams_and_unknown(self):
        record = config()['observations']['spctl']
        app = self.root / 'mount with spaces/Mesh.app'
        good = subprocess.CompletedProcess([], 3, '', str(app) + ': rejected: fixture self-signed')
        self.assertEqual(av.classify(good, record, app), 'expected_preapproval')
        for code, out, err in [(0, '', good.stderr), (3, good.stderr, ''), (3, '', 'unknown'), (3, '', good.stderr+'\ninternal error'), (3, '', good.stderr+'; unknown internal error'), (3, '', 'prefix '+good.stderr), (3, '', ' '+good.stderr), (3, '', good.stderr+' '), (3, '', good.stderr+'\n\n'), (3, '', 'x'*9000), (3, '', good.stderr.replace('mount with spaces', 'other mount'))]:
            with self.subTest(code=code, out=out, err=err[:40]), self.assertRaises(av.ValidationError):
                av.classify(subprocess.CompletedProcess([], code, out, err), record, app)

    def test_classifier_order_and_line_endings(self):
        app = self.root / 'mount with spaces/Mesh.app'
        record = dict(exit_code=3, stdout_lines=['first', 'second: {path}'], stderr_lines=['rejected'])
        for separator in ['\n', '\r\n', '\r']:
            result = subprocess.CompletedProcess([], 3, separator.join(['first', 'second: '+str(app)])+separator, 'rejected'+separator)
            self.assertEqual(av.classify(result, record, app), 'expected_preapproval')
        for lines in [['second: '+str(app), 'first'], ['first', 'extra', 'second: '+str(app)], ['first', '', 'second: '+str(app)]]:
            with self.assertRaises(av.ValidationError):
                av.classify(subprocess.CompletedProcess([], 3, '\n'.join(lines), 'rejected'), record, app)

    def test_classifier_rejects_raw_controls_before_line_normalization(self):
        app = self.root / 'mount with spaces/Mesh.app'
        controls = [chr(code) for code in range(32) if code not in [10, 13]]
        controls += [chr(code) for code in range(127, 160)] + ['\u2028', '\u2029']
        for stream in ['stdout', 'stderr']:
            for control in controls:
                for placement in ['trailing', 'inter-line']:
                    lines = ['first'] if placement == 'trailing' else ['first', 'second']
                    text = 'first' + control if placement == 'trailing' else control.join(lines)
                    record = dict(exit_code=3, stdout_lines=[], stderr_lines=[])
                    record[stream + '_lines'] = lines
                    output = dict(stdout='', stderr='')
                    output[stream] = text
                    result = subprocess.CompletedProcess([], 3, **output)
                    with self.subTest(stream=stream, control=repr(control), placement=placement), self.assertRaises(av.ValidationError):
                        av.classify(result, record, app)

    def test_observation_templates_reject_unknown_placeholders_and_controls(self):
        for line in ['{other}', '{path!r}', '{path.name}', '{path:20}', '{{path}}', '{path}{path}', 'bad\nline', 'bad\rline', 'bad\x00line', 'bad\u2028line']:
            self.settings = config()
            self.settings['observations']['spctl']['stderr_lines'] = [line]
            with self.subTest(line=line), self.assertRaises(av.ValidationError):
                self.validate()
        self.assertEqual(self.runner.calls, [])

    def test_invalid_classifier_path_rejected(self):
        record = config()['observations']['spctl']
        for app in ['relative/Mesh.app', '/tmp/../Mesh.app', '/tmp/Other.app', '/tmp/bad\npath/Mesh.app']:
            result = subprocess.CompletedProcess([], 3, '', app + ': rejected: fixture self-signed')
            with self.subTest(app=app), self.assertRaises(av.ValidationError):
                av.classify(result, record, app)

    def test_same_line_unknown_error_detaches_without_receipt(self):
        base = self.runner
        def corrupted(argv):
            result = base(argv)
            if argv[0] == 'spctl':
                result.stderr += '; unknown internal error'
            return result
        self.runner = corrupted
        with self.assertRaises(av.ValidationError), patch.object(av, 'digest', wraps=av.digest) as digest:
            self.validate()
        self.assertNotIn(unittest.mock.call(self.dmg), digest.call_args_list)
        self.assertEqual(base.calls[-1][1], 'detach')

    def test_unique_owned_mounts_and_exception_cleanup(self):
        self.validate()
        first = self.runner.mount
        self.validate()
        self.assertNotEqual(first, self.runner.mount)
        base = self.runner
        def raises(argv):
            if argv[0] == 'lipo':
                raise OSError('fixture tool missing')
            return base(argv)
        self.runner = raises
        with self.assertRaises(OSError):
            self.validate()
        self.assertEqual(base.calls[-1][1], 'detach')

    def test_codesign_identity_on_stdout(self):
        base = self.runner
        def stdout_runner(argv):
            result = base(argv)
            if '-dv' in argv or '-r-' in argv:
                result.stdout, result.stderr = result.stderr, result.stdout
            return result
        self.runner = stdout_runner
        self.assertEqual(self.validate()['status'], 'validated')

    def test_adhoc_reference_fixture(self):
        self.runner.details = (Path(__file__).parent / 'fixtures/adhoc-codesign.txt').read_text()
        with self.assertRaises(av.ValidationError):
            self.validate()


if __name__ == '__main__':
    unittest.main()
