"""The shared accessibility action is pinned, tested and part of repo layout."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def browser_image_version(workflow):
    """Accept exactly one reviewed Noble image with an immutable digest."""
    images = re.findall(r"^\s*image:\s*(\S+)\s*$", workflow, re.MULTILINE)
    if len(images) != 1:
        raise ValueError('Expected one pinned browser image')
    match = re.fullmatch(
        r'mcr\.microsoft\.com/playwright:v(\d+\.\d+\.\d+)-noble@sha256:[0-9a-f]{64}',
        images[0],
    )
    if match is None:
        raise ValueError('Expected versioned Noble image with SHA-256 digest')
    return match.group(1)


def assert_browser_versions(test, workflow, package, lock):
    """Cross-check declared, root-lock, runtime and bundled-browser versions."""
    version = browser_image_version(workflow)
    test.assertEqual(version, package['dependencies']['playwright'])
    test.assertEqual(version, lock['packages']['']['dependencies']['playwright'])
    for name in ['playwright', 'playwright-core']:
        test.assertEqual(version, lock['packages']['node_modules/' + name]['version'])


class AccessibilityContract(unittest.TestCase):
    def test_required_standard_documents(self):
        layout = json.loads((ROOT / '.repo-layout.yml').read_text())
        structure = json.loads((ROOT / 'docs/repo-structure.json').read_text())
        self.assertIn('ACCESSIBILITY.md', layout['required'])
        self.assertIn('ACCESSIBILITY.md', structure['required_root_files'])
        self.assertIn('ACCESSIBILITY_STANDARD.md', structure['required_by_directory']['docs'])

    def test_locked_free_dependencies(self):
        folder = ROOT / 'actions/a11y'
        package = json.loads((folder / 'package.json').read_text())
        lock = json.loads((folder / 'package-lock.json').read_text())
        for name in ['axe-core', 'playwright']:
            version = package['dependencies'][name]
            self.assertRegex(version, r'^\d+\.\d+\.\d+$')
            self.assertEqual(lock['packages']['node_modules/' + name]['version'], version)
            self.assertTrue(lock['packages']['node_modules/' + name]['integrity'].startswith('sha512-'))

    def test_action_never_ignores_errors_or_uses_caller_dependency_tree(self):
        action = (ROOT / 'actions/a11y/action.yml').read_text()
        self.assertNotIn('continue-on-error', action)
        self.assertIn('npm ci --ignore-scripts', action)
        self.assertIn('cd "$TRUSTED_ACTION"', action)
        self.assertIn('package-manager-cache: false', action)
        self.assertIn('playwright install --with-deps chromium webkit', action)
        self.assertNotIn('${{ inputs.', action.split('run:')[-1])

    def test_browser_regressions_run_in_ci(self):
        workflow = (ROOT / '.github/workflows/a11y.yml').read_text()
        self.assertIn('run: npm test', workflow)
        self.assertIn('timeout-minutes: 10', workflow)
        self.assertNotIn('continue-on-error', workflow)

    def test_scope_never_claims_automated_certification(self):
        doc = (ROOT / 'docs/ACCESSIBILITY_STANDARD.md').read_text()
        for boundary in ['not SI 5568 certification', 'do NOT meet that two-OS',
                         'incomplete', 'page-load states only', '2.4.10']:
            self.assertIn(boundary, doc)


class BrowserImageLockContract(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/a11y.yml').read_text()
        folder = ROOT / 'actions/a11y'
        self.package = json.loads((folder / 'package.json').read_text())
        self.lock = json.loads((folder / 'package-lock.json').read_text())

    def test_pinned_image_matches_all_locked_browser_versions(self):
        assert_browser_versions(self, self.workflow, self.package, self.lock)

    def test_version_drift_is_rejected_at_every_layer(self):
        version = self.package['dependencies']['playwright']
        with self.assertRaises(AssertionError):
            assert_browser_versions(self, self.workflow.replace('v' + version, 'v0.0.0'),
                                    self.package, self.lock)
        for name in ['', 'node_modules/playwright', 'node_modules/playwright-core']:
            with self.subTest(layer=name):
                lock = json.loads(json.dumps(self.lock))
                entry = lock['packages'][name]
                if name:
                    entry['version'] = '0.0.0'
                else:
                    entry['dependencies']['playwright'] = '0.0.0'
                with self.assertRaises(AssertionError):
                    assert_browser_versions(self, self.workflow, self.package, lock)

    def test_unpinned_or_ambiguous_images_are_rejected(self):
        valid = next(line for line in self.workflow.splitlines() if 'image:' in line)
        invalid = [valid.split('@')[0], valid.replace('-noble', '-jammy'),
                   valid[:-1], valid + 'f', valid + '\n' + valid]
        for image in invalid:
            with self.subTest(image=image):
                with self.assertRaises(ValueError):
                    browser_image_version(image)
