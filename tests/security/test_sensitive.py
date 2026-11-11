"""Assembled synthetic values only. No calls to any provider."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from repo_checks import sensitive as scan
from repo_checks import pseudonymize as mask


def identity():
    prefix = '123' + '45078'
    for digit in '0123456789':
        if scan.checksum(prefix + digit):
            return prefix + digit
    raise AssertionError()


def mobile():
    return '05' + '4' + '234' + '5678'


def token():
    return 'gh' + 'p_' + 'Z' * 36


class DetectorTests(unittest.TestCase):
    def test_planted_patterns_block_reserved_synthetic_and_plates_pass(self):
        for value, kind in [(identity(), 'id'), (mobile(), 'phone'), ('+972' + mobile()[1:], 'phone'), ('05' + '4-234-5678', 'phone'), (token(), 'secret'), ('xx' + '@' + 'zz-domain.co.il', 'email'), ('pass' + 'word=' + 'zz-test-value', 'password')]:
            self.assertIn(kind, scan.categories(value))
        for value in ['ZZ_NAME_abcdefghijkl', 'ZZ_ID_abcdefghijkl', 'ZZ_PHONE_abcdefghijkl', 'zz@example.com', 'zz@' + 'sub.example.org', 'zz@zz.invalid', '+999 123 456 789', '+1 212 555 0101', '12-345-67', '123-45-678', '000' * 3]:
            self.assertFalse(scan.categories(value))
        self.assertNotIn('id', scan.categories(identity() + '1'))
        self.assertNotIn('phone', scan.categories(mobile() + '1'))
        self.assertNotIn('id', scan.categories('abc' + identity()))
        self.assertNotIn('password', scan.categories('password=""'))
        self.assertIn('password', scan.categories('"pass' + 'word": "zz-placeholder"'))

    def test_reserved_token_never_exempts_rest_of_line(self):
        self.assertIn('email', scan.categories('zz@example.com ' + 'zz@' + 'not-reserved.co.il'))
        self.assertIn('phone', scan.categories('+999123456789 ' + mobile()))
        self.assertIn('secret', scan.categories('ZZ_NAME_abc ' + token()))

    def test_pseudonyms_stable_separated_clean_and_canonical(self):
        key = b'Z' * 32
        name = mask.pseudonym('name', 'ZZ Invented', key)
        self.assertEqual(name, mask.pseudonym('name', '  zz  invented ', key))
        self.assertNotEqual(name, mask.pseudonym('name', 'ZZ Invented', b'Y' * 32))
        phone = mask.pseudonym('phone', mobile(), key)
        self.assertEqual(phone, mask.pseudonym('phone', '+972' + mobile()[1:], key))
        for value in [name, phone, mask.pseudonym('id', identity(), key)]:
            self.assertFalse(scan.categories(value))
            self.assertTrue(value.startswith('ZZ_'))
        for kind, value in [('other', 'ZZ'), ('name', ' '), ('id', 'bad'), ('phone', 'bad')]:
            with self.assertRaises(mask.MaskError):
                mask.pseudonym(kind, value, key)

    def test_domain_kind_and_full_digest_length(self):
        value = identity()
        # Compare the encoded payload, not just the already-distinct type prefix.
        name = mask.pseudonym('name', value, b'Z' * 32).split('_', 2)[2]
        ident = mask.pseudonym('id', value, b'Z' * 32).split('_', 2)[2]
        self.assertNotEqual(name, ident)
        self.assertEqual(64, len(name))
        self.assertEqual(64, len(ident))
        self.assertTrue(set(name + ident) <= set('abcdefghijklmnop'))


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'ZZ Synthetic')
        self.git('config', 'user.email', 'zz@example.com')
        self.commit('safe.txt', 'baseline\n')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'commit.gpgsign=false', '-C', str(self.root), *args], stderr=subprocess.DEVNULL, text=True)

    def commit(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git('add', '--', path)
        self.git('commit', '-qm', 'synthetic')

    def cli(self, *args):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'tools/repo_checks.py'), 'sensitive-scan', '--pre-merge', '--root', str(self.root), '--base', self.base, *args], capture_output=True, text=True)

    def test_diff_counts_locations_never_values(self):
        value = identity() + '\n' + mobile() + '\n' + token()
        self.commit('new.txt', value)
        result = self.cli()
        self.assertEqual(1, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual('findings', data['status'])
        for category in ('id', 'phone', 'secret'):
            self.assertEqual(1, data['counts'][category])
        self.assertEqual({1, 2, 3}, {i['line'] for i in data['locations']})
        self.assertTrue(all(i['file'] == 'new.txt' for i in data['locations']))
        self.assertEqual('', result.stderr)
        for raw in (identity(), mobile(), token()):
            self.assertNotIn(raw, result.stdout)

    def test_committed_fixtures_no_directory_bypass_and_worktree_ignored(self):
        self.commit('tests/fixtures/sample.txt', mobile())
        latest = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual('findings', scan.scan(self.root, latest)['status'])
        (self.root / 'tests/fixtures/sample.txt').write_text('ZZ_PHONE_safe')
        self.assertEqual('findings', scan.scan(self.root, latest)['status'])
        self.git('reset', '--hard', self.base)
        (self.root / 'not-committed.txt').write_text(mobile())
        self.assertEqual('pass', scan.scan(self.root, self.base)['status'])

    def test_removed_secret_in_intermediate_commit_blocks(self):
        self.commit('new.txt', token())
        self.commit('new.txt', 'safe')
        self.assertEqual(1, self.cli().returncode)

    def test_error_paths_no_values_or_partial_report(self):
        for raw in ('--bad-ref', 'not-a-reference'):
            result = self.cli('--head', raw)
            self.assertEqual(2, result.returncode)
            self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(result.stdout))
            self.assertEqual('', result.stderr)
        self.commit('a.txt', token())
        self.commit('z.txt', 'bad\0bytes')
        result = self.cli()
        self.assertEqual(2, result.returncode)
        self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(result.stdout))

    def test_key_file_local_restrictive_no_overwrite(self):
        keyfile = Path(self.temp.name) / 'local-key'
        mask.create_key(keyfile, self.root)
        key = mask.load_key(keyfile, self.root)
        self.assertEqual(32, len(key))
        with self.assertRaises(FileExistsError):
            mask.create_key(keyfile, self.root)
        keyfile.chmod(0o644)
        with self.assertRaises(mask.MaskError):
            mask.load_key(keyfile, self.root)
        with self.assertRaises(mask.MaskError):
            mask.create_key(self.root / 'key', self.root)
        link = Path(self.temp.name) / 'link'
        link.symlink_to(keyfile)
        with self.assertRaises(OSError):
            mask.load_key(link, self.root)

    def test_pseudonym_cli_never_emits_original_on_partial_failure(self):
        keyfile = Path(self.temp.name) / 'local-key'
        mask.create_key(keyfile, self.root)
        args = [sys.executable, '-I', str(ROOT / 'tools/repo_checks.py'), 'pseudonymize', '--root', str(self.root), '--key-file', str(keyfile)]
        value = [{'kind': 'phone', 'value': mobile()}, {'kind': 'id', 'value': 'bad'}]
        run = subprocess.run(args, input=json.dumps(value), capture_output=True, text=True)
        self.assertEqual((2, '{"status":"error"}\n', ''), (run.returncode, run.stdout, run.stderr))
        run = subprocess.run(args, input=json.dumps(value[:1]), capture_output=True, text=True)
        self.assertEqual(0, run.returncode)
        self.assertNotIn(mobile(), run.stdout)
        self.assertFalse(scan.categories(run.stdout))

    def test_hostile_path_and_import_no_output_leak(self):
        self.commit(token() + '.txt', 'safe')
        result = self.cli()
        self.assertEqual(1, result.returncode)
        self.assertNotIn(token(), result.stdout)
        self.assertTrue(json.loads(result.stdout)['locations'][0]['file'].startswith('[withheld-'))
        self.commit('sitecustomize.py', 'raise RuntimeError("ZZ")')
        self.assertEqual(1, self.cli().returncode)

    def test_hook_blocks_before_push_without_candidate_execution(self):
        installer = ROOT / 'tools/install_sensitive_hook.py'
        result = subprocess.run([sys.executable, '-I', str(installer), str(self.root), self.base], capture_output=True)
        self.assertEqual(0, result.returncode, result.stdout)
        hook = self.root / '.git/hooks/pre-push'
        def run_hook():
            head = self.git('rev-parse', 'HEAD').strip()
            return subprocess.run([str(hook)], input='refs/heads/main ' + head + ' refs/heads/main ' + self.base + '\n', capture_output=True, text=True)
        self.assertEqual(0, run_hook().returncode)
        self.commit('tests/fixtures/sample.txt', mobile())
        self.assertNotEqual(0, run_hook().returncode)
        # A checkout's replacement entrypoint is never used by the installed hook.
        self.commit('tools/repo_checks.py', 'raise SystemExit(0)')
        self.assertNotEqual(0, run_hook().returncode)
        repeat = subprocess.run([sys.executable, '-I', str(installer), str(self.root), self.base], capture_output=True)
        self.assertEqual(2, repeat.returncode)

    def test_binary_diff_attributes_and_replace_refs_cannot_hide_findings(self):
        self.commit('.gitattributes', '*.txt -diff\n')
        self.commit('hidden.txt', mobile())
        head = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(1, self.cli().returncode)
        self.git('replace', head, self.base)
        self.assertEqual(1, self.cli().returncode)

    def test_hook_missing_snapshot_and_multi_ref_failure_block(self):
        installer = ROOT / 'tools/install_sensitive_hook.py'
        self.assertEqual(0, subprocess.run([sys.executable, '-I', str(installer), str(self.root), self.base], capture_output=True).returncode)
        self.commit('x.txt', mobile())
        head = self.git('rev-parse', 'HEAD').strip()
        rows = 'refs/heads/a ' + self.base + ' refs/heads/a ' + self.base + '\n'
        rows += 'refs/heads/b ' + head + ' refs/heads/b ' + '0' * 40 + '\n'
        hook = self.root / '.git/hooks/pre-push'
        self.assertNotEqual(0, subprocess.run([str(hook)], input=rows, capture_output=True, text=True).returncode)
        (self.root / '.git/repo-checks-sensitive-v1/tools/repo_checks.py').unlink()
        self.assertNotEqual(0, subprocess.run([str(hook)], input=rows, capture_output=True, text=True).returncode)

    def test_hook_refuses_custom_routing_and_oversize_payload(self):
        installer = ROOT / 'tools/install_sensitive_hook.py'
        self.git('config', 'core.hooksPath', 'other-hooks')
        result = subprocess.run([sys.executable, '-I', str(installer), str(self.root), self.base], capture_output=True)
        self.assertEqual(2, result.returncode)
        self.assertFalse((self.root / '.git/hooks/pre-push').exists())
        self.git('config', '--unset', 'core.hooksPath')
        self.assertEqual(0, subprocess.run([sys.executable, '-I', str(installer), str(self.root), self.base], capture_output=True).returncode)
        hook = self.root / '.git/hooks/pre-push'
        for value in ('bad input', 'x' * 65537):
            run = subprocess.run([str(hook)], input=value, capture_output=True, text=True)
            self.assertEqual(2, run.returncode)
            self.assertNotIn(value, run.stdout + run.stderr)

    def test_literal_blob_limit_and_binary_selected_fixture_fail_closed(self):
        target = self.root / 'tests/fixtures/x'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic')
        self.assertEqual(2, self.cli().returncode)
        self.git('reset', '--hard', self.base)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'\xff')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic')
        self.assertEqual(2, self.cli().returncode)

    def test_embedded_non_lf_separators_cannot_hide_added_values(self):
        for index, sep in enumerate(('\u2028', '\x85', '\r', '\f', '\v', '\x1e', '\x1c', '\x1d', '\u2029')):
            with self.subTest(separator=index):
                self.git('reset', '--hard', self.base)
                self.commit('added.txt', 'note' + sep + identity() + '\nnext' + sep + mobile() + '\nlast' + sep + token())
                result = self.cli()
                self.assertEqual(1, result.returncode)
                found = json.loads(result.stdout)
                self.assertEqual({'id', 'phone', 'secret'}, {i['category'] for i in found['locations']})
                self.assertEqual({1, 2, 3}, {i['line'] for i in found['locations']})
                self.commit('tests/fixtures/added.txt', 'note' + sep + identity() + '\nnext' + sep + mobile())
                found = scan.scan(self.root, self.git('rev-parse', 'HEAD').strip())
                self.assertEqual({1, 2}, {i['line'] for i in found['locations']})

    def test_missing_key_cli_has_no_fallback_or_input_output(self):
        value = json.dumps([{'kind': 'phone', 'value': mobile()}])
        command = [sys.executable, '-I', str(ROOT / 'tools/repo_checks.py'), 'pseudonymize', '--root', str(self.root), '--key-file', str(Path(self.temp.name) / 'absent-key')]
        run = subprocess.run(command, input=value, capture_output=True, text=True)
        self.assertEqual((2, '{"status":"error"}\n', ''), (run.returncode, run.stdout, run.stderr))
        self.assertNotIn(mobile(), run.stdout + run.stderr)

    def test_limit_and_alarm_fail_closed(self):
        self.commit('x.txt', 'safe')
        with patch.object(scan, 'MAX_PATHS', 0):
            with self.assertRaises(Exception):
                scan.scan(self.root, self.base)
        with patch.object(scan.signal, 'signal'), patch.object(scan.signal, 'alarm') as alarm, patch.object(scan, 'scan', side_effect=ValueError()), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(2, scan.main(['--pre-merge']))
            self.assertEqual([unittest.mock.call(30), unittest.mock.call(0)], alarm.call_args_list)
            self.assertEqual('{"schema_version":1,"status":"error"}\n', out.getvalue())
