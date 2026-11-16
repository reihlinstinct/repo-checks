"""Bootstrap CLI failure propagation; source regression vectors alone missed this."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ENGINE = Path(__file__).resolve().parents[2] / 'src/repo_checks/scorecard.py'

class SharedCliTests(unittest.TestCase):
    def test_new_finding_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / '.github/workflows').mkdir(parents=True)
            (root / '.github/workflows/example.yml').write_text('jobs: {}\n', encoding='utf-8')
            result = subprocess.run([sys.executable, str(ENGINE), '--root', d], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('top-level-permissions', result.stdout)

    def test_clean_repository_returns_zero(self):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([sys.executable, str(ENGINE), '--root', d], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
