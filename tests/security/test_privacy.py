"""Synthetic-only privacy scanner regressions. No real identifiers."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[2] / 'src/repo_checks/privacy.py'
spec = importlib.util.spec_from_file_location('privacy', MODULE)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PrivacyTests(unittest.TestCase):
    def test_email_token_exemption_not_whole_line(self):
        self.assertEqual(set(), p.text_categories('test@example.invalid'))
        self.assertEqual({'email'}, p.text_categories('test@example.invalid contact ' + 'fixture' + '@' + 'private.test'))

    def test_fictional_phone(self):
        for value in ['+1-202-555-0100', '+1-415-555-0199', '+999-123-456-7890']:
            self.assertNotIn('phone', p.text_categories(value))
        for value in ['+1-202-555-' + '0200', '+972' + '50' + '1234567', '050' + '1234567']:
            self.assertIn('phone', p.text_categories(value))

    def test_checksum(self):
        # Build a checksum-positive synthetic sequence, never a person's ID.
        prefix = '345' + '67890'
        value = next(prefix + str(n) for n in range(10) if p.checksum(prefix + str(n)))
        self.assertIn('id', p.text_categories(value))
        self.assertNotIn('id', p.text_categories('000000000'))
        self.assertNotIn('id', p.text_categories('sha' + value + 'fff'))

    def test_secrets(self):
        for value in ['ghp_' + 'X' * 36, 'github_pat_' + 'Y' * 50, '-----BEGIN ' + 'PRIVATE KEY-----']:
            self.assertIn('secret', p.text_categories(value))

    def make_repo(self, directory):
        root = Path(directory)
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        return root

    def run_cli(self, root):
        return subprocess.run(['python3', '-I', str(MODULE), '--root', str(root)], text=True, capture_output=True)

    def test_tracked_only_and_no_value_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make_repo(d)
            secret = 'ghp_' + 'Q' * 36
            (root / 'odd\n::warning::.txt').write_text(secret)
            (root / 'untracked.txt').write_text('another' + '@' + 'private.test')
            subprocess.run(['git', '-C', str(root), 'add', 'odd\n::warning::.txt'], check=True)
            r = self.run_cli(root)
            self.assertEqual(1, r.returncode)
            result = json.loads(r.stdout)
            self.assertEqual(1, result['counts']['secret'])
            self.assertEqual(0, result['counts']['email'])
            self.assertNotIn(secret, r.stdout + r.stderr)
            self.assertNotIn('::warning::', r.stdout + r.stderr)

    def test_symlink_and_oversize_fail_closed(self):
        for kind in ['symlink', 'oversize']:
            with tempfile.TemporaryDirectory() as d:
                root = self.make_repo(d)
                target = root / 'item'
                if kind == 'symlink':
                    target.symlink_to('/etc/passwd')
                else:
                    target.write_bytes(b'x' * (p.MAX_FILE + 1))
                subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
                r = self.run_cli(root)
                self.assertEqual(2, r.returncode)
                self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(r.stdout))

    def test_sensitive_binary_filename_not_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make_repo(d)
            (root / 'creds.json').write_bytes(b'\0opaque')
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            result = p.scan(root)
            self.assertEqual(1, result['counts']['sensitive_filename'])
            self.assertEqual(1, result['binary_files_unscanned'])

    def test_clean_repo(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make_repo(d)
            (root / 'clean.md').write_text('synthetic@example.invalid +1-202-555-0100')
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            self.assertEqual(0, self.run_cli(root).returncode)


if __name__ == '__main__':
    unittest.main()
