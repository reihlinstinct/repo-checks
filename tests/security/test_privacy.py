"""Synthetic-only privacy scanner regressions. No real identifiers."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[2] / 'src/repo_checks/privacy.py'
import sys
sys.path.insert(0, str(MODULE.parents[1]))
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
        return subprocess.run(['python3', '-I', str(MODULE.parents[2] / 'tools/privacy_scan.py'), '--root', str(root)], text=True, capture_output=True)

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



class HardenedPrivacyTests(unittest.TestCase):
    make_repo = PrivacyTests.make_repo
    run_cli = PrivacyTests.run_cli
    def test_parentheses_and_id_punctuation(self):
        for value in ['+972 (50) ' + '123-4567', '(050) ' + '123-4567']:
            self.assertIn('phone', p.text_categories(value))
        prefix = '345' + '67890'
        value = next(prefix + str(n) for n in range(10) if p.checksum(prefix + str(n)))
        self.assertIn('id', p.text_categories('ID: ' + value + '.'))
        self.assertNotIn('id', p.text_categories('1.' + value))
        self.assertNotIn('id', p.text_categories(value + '.123'))

    def test_every_secret_family(self):
        samples = ['gh' + k + '_' + 'X' * 36 for k in 'pousr']
        samples += ['github_' + 'pat_' + 'Y' * 50, 'AK' + 'IA' + 'Z' * 16]
        samples += ['xox' + k + '-' + 'Z' * 24 for k in 'baprs']
        samples += ['-----BEGIN ' + k + 'PRIVATE KEY-----' for k in ['', 'RSA ', 'EC ', 'OPENSSH ']]
        for value in samples:
            self.assertIn('secret', p.text_categories(value))
        for value in ['ghp_short', 'AKIAshort', 'xoxb-short', 'BEGIN PUBLIC KEY']:
            self.assertNotIn('secret', p.text_categories(value))

    def test_adversarial_runtime(self):
        import time
        start = time.monotonic()
        for char in ['.', '-', '@', '9']:
            try:
                p.text_categories(char * 100000)
            except p.ScanError:
                pass
        self.assertLess(time.monotonic() - start, 1.5)

    def test_malformed_arguments_value_free(self):
        result = subprocess.run(['python3', '-I', str(MODULE.parents[2] / 'tools/privacy_scan.py'), '--SYNTHETIC_PRIVATE_ARGUMENT'], capture_output=True, text=True)
        self.assertEqual(2, result.returncode)
        self.assertEqual('', result.stderr)
        self.assertNotIn('SYNTHETIC_PRIVATE_ARGUMENT', result.stdout)

    def test_fifo_ancestor_symlink_and_missing(self):
        for kind in ['fifo', 'ancestor', 'missing']:
            with tempfile.TemporaryDirectory() as d:
                root = self.make_repo(d)
                (root/'docs').mkdir(); target = root/'docs/item'; target.write_text('safe')
                subprocess.run(['git','-C',str(root),'add','.'],check=True)
                target.unlink()
                if kind == 'fifo': os.mkfifo(target)
                elif kind == 'ancestor':
                    (root/'docs').rmdir(); (root/'other').mkdir(); (root/'other/item').write_text('safe'); (root/'docs').symlink_to(root/'other')
                self.assertEqual(2,self.run_cli(root).returncode)

    def test_submodule_unmerged_inventory(self):
        from unittest.mock import patch
        for entry in [b'160000 ' + b'a'*40 + b' 0\tmodule\0', b'100644 ' + b'a'*40 + b' 2\tfile\0']:
            with tempfile.TemporaryDirectory() as d:
                root=self.make_repo(d)
                with patch.object(p,'git_output',return_value=entry), self.assertRaises(p.ScanError): p.scan(root)

    def test_candidate_fsmonitor_and_git_env_do_not_execute(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root=self.make_repo(d);(root/'item').write_text('safe')
            subprocess.run(['git','-C',str(root),'add','.'],check=True)
            marker=root/'EXECUTED';helper=root/'helper'
            helper.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');helper.chmod(0o700)
            subprocess.run(['git','-C',str(root),'config','core.fsmonitor',str(helper)],check=True)
            with patch.dict(os.environ, {'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'core.fsmonitor','GIT_CONFIG_VALUE_0':str(helper),'GIT_DIR':'/not-a-repository'}):
                self.assertEqual(0,self.run_cli(root).returncode)
            self.assertFalse(marker.exists())

    def test_scan_deadline(self):
        from unittest.mock import patch, MagicMock
        boundary = MagicMock()
        boundary.__enter__.return_value.paths = ['item']
        with patch.object(p, 'Inputs', return_value=boundary), patch.object(p, 'git_output', return_value=b''), patch.object(p.time, 'monotonic', side_effect=[0, 100]), self.assertRaises(p.ScanError):
            p.scan(Path('.'))



class ExtraPrivacyTests(unittest.TestCase):
    make_repo = PrivacyTests.make_repo
    # Delegate helper methods only, not the inherited test methods.
    def test_phone_boundaries_and_unicode_email(self):
        for value in ['972'+'501234567', '050/'+'1234567', '050\t1234567', '050\u00a01234567', '050–'+'1234567', '+1234'+'5678', 'word050'+'1234567']:
            if value.startswith('word'):
                self.assertNotIn('phone',p.text_categories(value))
            else:
                self.assertIn('phone',p.text_categories(value))
        for value in ['fixture'+'@'+'gmail.com', 'דוגמה'+'@'+'דוגמה.ישראל']:
            self.assertIn('email',p.text_categories(value))
        self.assertFalse(p.fictional_phone('+99912'))
        with self.assertRaises(p.ScanError):p.text_categories('a'*321+'@'+'example.invalid')
        self.assertIn('secret',p.text_categories('github_'+'pat_'+'X'*40))
        self.assertNotIn('secret',p.text_categories('github_'+'pat_'+'X'*39))

    def test_alarm_and_stderr_contract(self):
        from unittest.mock import patch
        with patch.object(p.sys,'argv',['scan','--root','.']), patch.object(p,'scan',return_value={'status':'pass'}), patch.object(p.signal,'alarm') as alarm:
            self.assertEqual(0,p.main())
            self.assertIn(__import__('unittest').mock.call(30),alarm.call_args_list)
        import repo_checks.inputs as boundary
        real = subprocess.Popen; calls=[]
        def capture(*args,**kwargs):
            calls.append(kwargs);return real(*args,**kwargs)
        with tempfile.TemporaryDirectory() as d:
            root=self.make_repo(d)
            with patch.object(boundary.subprocess,'Popen',side_effect=capture):boundary.git_output(root,['ls-files'])
        self.assertTrue(all(c['stderr']==subprocess.DEVNULL for c in calls))


if __name__ == '__main__':
    unittest.main()
