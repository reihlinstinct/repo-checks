"""The shared accessibility action is pinned, tested and part of repo layout."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


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
