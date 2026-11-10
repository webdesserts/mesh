"""Static workflow contracts, not a substitute for actionlint or a live runner."""
import ast
from pathlib import Path
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]


def python_blocks(text):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == 'run: |':
            indent = len(line) - len(line.lstrip())
            body = []
            for next_line in lines[index + 1:]:
                if next_line.strip() and len(next_line) - len(next_line.lstrip()) <= indent:
                    break
                body.append(next_line)
            yield textwrap.dedent('\n'.join(body))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.cask = (ROOT / '.github/workflows/desktop-cask.yml').read_text()
        self.tests = (ROOT / '.github/workflows/desktop-gate-tests.yml').read_text()
        self.verify, self.publish = self.cask.split('\n  publish:\n')

    def test_python_runner_blocks_compile_and_do_not_interpolate_inputs(self):
        for text in [self.cask, self.tests]:
            blocks = list(python_blocks(text))
            self.assertTrue(blocks)
            self.assertEqual(text.count('shell: python {0}'), len(blocks))
            for block in blocks:
                ast.parse(block)
                self.assertNotIn('${{', block)

    def test_verify_has_no_publication_credentials_or_permissions(self):
        self.assertIn('  workflow_dispatch:', self.cask)
        self.assertIn('        default: verify', self.cask)
        self.assertIn('\npermissions:\n  contents: read\n', self.cask)
        for forbidden in ['secrets.', 'contents: write', 'actions: write', "'--operation', 'publish'", 'concurrency:', '\n  push:', '\n  release:']:
            self.assertNotIn(forbidden, self.verify)
        self.assertIn('persist-credentials: false', self.verify)
        self.assertIn('HOMEBREW_GITHUB_API_TOKEN: ${{ github.token }}', self.verify)
        self.assertIn('signer_config.json', self.verify)
        self.assertIn('load_config(config)', self.verify)
        self.assertLess(self.verify.index('load_config(config)'), self.verify.index('urllib.request.urlopen'))
        self.assertIn('digest(artifact) == expected', self.verify)
        self.assertIn("receipt['sha256'] == expected", self.verify)
        self.assertNotIn('--audit-config', self.cask)
        candidate = list(python_blocks(self.verify))[-1]
        self.assertLess(candidate.index('], check=True)'), candidate.index("output.write('verified=true"))

    def test_publish_requires_all_gates_and_queries_before_authenticated_checkout(self):
        self.assertIn("inputs.intent == 'publish' && needs.verify.outputs.candidate_verified == 'true' && vars.DESKTOP_CASK_PUBLISH_ENABLED == 'true'", self.publish)
        self.assertIn('environment: desktop-cask-publication', self.publish)
        self.assertIn('actions: read', self.publish)
        self.assertIn('contents: read', self.publish)
        self.assertIn('HOMEBREW_GITHUB_API_TOKEN: ${{ github.token }}', self.publish)
        self.assertEqual(self.cask.count('HOMEBREW_GITHUB_API_TOKEN: ${{ github.token }}'), 2)
        self.assertEqual(self.cask.count('secrets.HOMEBREW_TAP_TOKEN'), 1)
        self.assertLess(self.publish.index("'--operation', 'check-queue'"), self.publish.index('repository: webdesserts/homebrew-tap'))
        self.assertIn("'--operation', 'publish', '--run-id', os.environ['GITHUB_RUN_ID']", self.publish)
        self.assertIn("'--signer-config', 'tooling/scripts/t299/signer_config.json'", self.publish)
        self.assertNotIn("'--signer-config'", self.verify)
        self.assertIn('prevent NEW release OR desktop publication runs until this job completes', self.publish)
        self.assertNotIn('concurrency:', self.cask)

    def test_read_only_test_workflow_covers_new_workflow_and_suite(self):
        self.assertEqual(self.tests.count("'.github/workflows/desktop-cask.yml'"), 3)
        self.assertIn("'-s', 'scripts/t299/tests', '-v'", self.tests)
        self.assertNotIn('secrets.', self.tests)
        self.assertNotIn('contents: write', self.tests)
        release = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertNotIn('build-desktop-dmg', release)
        self.assertIn('  publish-homebrew-formula:', release)
        self.assertNotIn('desktop-cask.yml', release)


if __name__ == '__main__':
    unittest.main()
