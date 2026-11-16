"""Dummy credentials only; never contact a provider or print token fixtures."""
import importlib.util
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
from repo_checks import secret_output as guard
from repo_checks import secret_scan
from repo_checks import privacy


def tokens():
    return ['gh' + family + '_' + 'Z' * 36 for family in 'pousr'] + [
        'github_' + 'pat_' + 'Z' * 50, 'xo' + 'xb-' + 'Z' * 30,
        'AK' + 'IA' + 'Z' * 16]


def key_block(kind=''):
    return '-----BEGIN ' + kind + 'PRIVATE KEY-----\nDUMMY_PRIVATE_BYTES\n-----END ' + kind + 'PRIVATE KEY-----'


class OutputTests(unittest.TestCase):
    def test_shared_pattern_identity_and_supported_families(self):
        self.assertIs(privacy.SECRET, guard.SECRET)
        for value in tokens() + [key_block(kind) for kind in ('', 'RSA ', 'EC ', 'OPENSSH ')]:
            self.assertTrue(guard.contains_secret(value))
            with self.assertRaises(guard.SecretOutputError) as caught:
                guard.protect_text(value)
            self.assertEqual('', str(caught.exception))
            self.assertEqual(guard.MARKER, guard.protect_text(value, redact=True))
            self.assertIn('secret', privacy.text_categories(value))

    def test_multiple_unicode_and_unterminated_private_key(self):
        value = 'אב ' + tokens()[0] + ' / ' + tokens()[1] + ' fin'
        self.assertEqual('אב ' + guard.MARKER + ' / ' + guard.MARKER + ' fin', guard.protect_text(value, redact=True))
        raw = key_block().split('-----END')[0]
        self.assertEqual(guard.MARKER, guard.protect_text(raw, redact=True))
        self.assertEqual('before ' + guard.MARKER + ' after', guard.protect_text('before ' + key_block() + ' after', redact=True))

    def test_json_keys_values_no_mutation_or_partial_result(self):
        value = {'nested': [tokens()[0], {tokens()[1]: 'safe'}], 'ok': 1}
        with self.assertRaises(guard.SecretOutputError):
            guard.protect_json(value)
        result = guard.protect_json(value, redact=True)
        self.assertEqual({'nested': [guard.MARKER, {guard.MARKER: 'safe'}], 'ok': 1}, result)
        self.assertEqual(tokens()[0], value['nested'][0])
        with self.assertRaises(guard.SecretOutputError):
            guard.protect_json({tokens()[0]: 1, tokens()[1]: 2}, redact=True)

    def test_json_cycles_nonjson_depth_and_size_refused(self):
        cycle = []; cycle.append(cycle)
        deep = None
        for _ in range(70):
            deep = [deep]
        for value in [cycle, deep, {1: 'safe'}, (1, 2), float('nan'), object(), 'a' * (guard.MAX_BYTES + 1)]:
            with self.assertRaises(guard.SecretOutputError):
                guard.protect_json(value)

    def test_literal_two_mib_boundary_and_bounded_read(self):
        limit = 2 * 1024 * 1024  # Deliberately independent of the implementation.
        for args in ((), ('--redact',)):
            result = self.cli(b'a' * (limit + 1), args)
            self.assertEqual((2, b'', b'Secret output refused or unavailable\n'),
                             (result.returncode, result.stdout, result.stderr))
        buffer = io.BytesIO(b'a' * (limit + 1))
        with patch.object(buffer, 'read', wraps=buffer.read) as read:
            with patch('sys.stdin') as stdin, patch('sys.stdout', new_callable=io.StringIO) as out, patch('sys.stderr', new_callable=io.StringIO) as err:
                stdin.buffer = buffer
                self.assertEqual(2, guard.main([]))
                self.assertEqual('', out.getvalue())
                self.assertEqual('Secret output refused or unavailable\n', err.getvalue())
            read.assert_called_once_with(limit + 1)
        self.assertEqual(limit, len(guard.protect_text('a' * limit)))
        with self.assertRaises(guard.SecretOutputError):
            guard.protect_text('a' * (limit + 1))

    def test_json_many_small_values_exceed_total_bound_before_copy(self):
        value = ['a' * 1024 for _ in range(2048)]
        self.assertGreater(len(json.dumps(value).encode()), 2 * 1024 * 1024)
        for redact in (False, True):
            with patch.object(guard, 'protect_text', wraps=guard.protect_text) as visit:
                with self.assertRaises(guard.SecretOutputError):
                    guard.protect_json(value, redact=redact)
                visit.assert_not_called()
        self.assertTrue(all(item == 'a' * 1024 for item in value))

    def test_clean_identity_and_invalid_text(self):
        self.assertEqual('safe עברית\n', guard.protect_text('safe עברית\n'))
        for value in [None, b'safe', '\ud800', 'a' * (guard.MAX_BYTES + 1)]:
            with self.assertRaises(guard.SecretOutputError):
                guard.protect_text(value)
        with self.assertRaises(guard.SecretOutputError):
            guard.protect_text('safe', redact=1)

    def cli(self, data, args=()):
        return subprocess.run([sys.executable, '-I', str(ROOT / 'tools/secret_output.py'), *args], input=data, capture_output=True)

    def test_cli_default_blocks_without_payload_on_either_channel(self):
        secret = tokens()[0].encode()
        result = self.cli(b'clean prefix\n' + secret)
        self.assertEqual(2, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertEqual(b'Secret output refused or unavailable\n', result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_cli_redacts_keys_tokens_before_any_output(self):
        data = ('before ' + key_block() + ' ' + tokens()[0] + ' after').encode()
        result = self.cli(data, ('--redact',))
        self.assertEqual(0, result.returncode)
        self.assertEqual(('before ' + guard.MARKER + ' ' + guard.MARKER + ' after').encode(), result.stdout)
        self.assertEqual(b'', result.stderr)
        self.assertNotIn(b'DUMMY_PRIVATE_BYTES', result.stdout)

    def test_broken_pipe_has_constant_diagnostic(self):
        run = subprocess.Popen([sys.executable, '-I', str(ROOT / 'tools/secret_output.py')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        run.stdout.close()
        run.stdin.write(b'clean')
        run.stdin.close()
        diagnostic = run.stderr.read()
        run.stderr.close()
        self.assertEqual(2, run.wait())
        self.assertEqual(b'Secret output refused or unavailable\n', diagnostic)

    def test_cli_invalid_oversize_args_and_clean(self):
        for data, args in [(b'\xff', ()), (b'a' * (guard.MAX_BYTES + 1), ('--redact',)), (b'safe', ('--unknown',))]:
            result = self.cli(data, args)
            self.assertEqual(2, result.returncode)
            self.assertEqual(b'', result.stdout)
            self.assertEqual(b'Secret output refused or unavailable\n', result.stderr)
        result = self.cli(b'clean\n')
        self.assertEqual((0, b'clean\n', b''), (result.returncode, result.stdout, result.stderr))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'candidate'; self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)

    def tearDown(self):
        self.temp.cleanup()

    def track(self, name, data):
        (self.root / name).write_bytes(data)
        subprocess.run(['git', '-C', str(self.root), 'add', '--', name], check=True)

    def cli(self, action=False):
        env = dict(os.environ, GITHUB_WORKSPACE=self.temp.name, CHECK_ROOT=str(self.root))
        args = [sys.executable, '-I', str(ROOT / ('actions/secrets/bootstrap.py' if action else 'tools/secret_scan.py'))]
        if not action:
            args += ['--root', str(self.root)]
        return subprocess.run(args, env=env, cwd=self.root, capture_output=True, text=True)

    def test_supported_finding_blocks_and_never_echoes(self):
        for value in tokens() + [key_block()]:
            self.track('x', value.encode())
            for action in (False, True):
                result = self.cli(action)
                self.assertEqual(1, result.returncode)
                self.assertEqual({'schema_version': 1, 'status': 'findings'}, json.loads(result.stdout))
                self.assertEqual('', result.stderr)
                self.assertNotIn(value, result.stdout)

    def test_other_privacy_findings_do_not_mask_token_only_clean(self):
        self.track('x', ('zz' + '@' + 'zz-domain.test').encode())
        self.assertEqual(0, self.cli().returncode)
        self.track('z', b'\0binary')
        self.assertEqual(0, self.cli().returncode)
        self.track('latin', b'\xff')
        self.assertEqual(0, self.cli().returncode)

    def test_after_match_invalid_inventory_and_size_still_error(self):
        self.track('a', tokens()[0].encode())
        self.track('z', b'x' * (2 * 1024 * 1024 + 1))
        result = self.cli()
        self.assertEqual(2, result.returncode)
        self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(result.stdout))
        (self.root / 'z').unlink()
        (self.root / 'z').symlink_to('/etc/passwd')
        self.assertEqual(2, self.cli().returncode)

    def test_hostile_candidate_imports_never_execute(self):
        marker = self.root / 'EXECUTED'
        poison = ('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()').encode()
        self.track('sitecustomize.py', poison)
        self.track('repo_checks.py', poison)
        self.assertEqual(0, self.cli(True).returncode)
        self.assertFalse(marker.exists())

    def test_action_has_no_advisory_or_candidate_code(self):
        text = (ROOT / 'actions/secrets/action.yml').read_text()
        self.assertNotIn('continue-on-error', text)
        self.assertIn('python3 -I', text)

    def test_alarm_armed_and_disarmed_success_failure_and_timeout(self):
        for mode in ('success', 'failure', 'timeout'):
            with self.subTest(mode=mode):
                with patch.object(secret_scan.signal, 'signal') as registered, patch.object(secret_scan.signal, 'alarm') as alarm:
                    def fake_scan(_):
                        if mode == 'timeout':
                            registered.call_args.args[1](secret_scan.signal.SIGALRM, None)
                        if mode == 'failure':
                            raise RuntimeError('PRIVATE')
                        return {'schema_version': 1, 'status': 'pass'}
                    with patch.object(secret_scan, 'scan', side_effect=fake_scan), patch('sys.stdout', new_callable=io.StringIO) as out:
                        self.assertEqual(0 if mode == 'success' else 2, secret_scan.main(['--root', str(self.root)]))
                        self.assertEqual({'schema_version': 1, 'status': 'pass' if mode == 'success' else 'error'}, json.loads(out.getvalue()))
                    registered.assert_called_once()
                    self.assertEqual(secret_scan.signal.SIGALRM, registered.call_args.args[0])
                    self.assertEqual([unittest.mock.call(30), unittest.mock.call(0)], alarm.call_args_list)

    def test_inventory_mutation_mid_scan_fails_without_candidate_output(self):
        self.track('first', b'safe')
        original = secret_scan.Inputs.read_bytes
        def changing(source, name):
            data = original(source, name)
            self.track('later', b'safe')
            return data
        with patch.object(secret_scan.Inputs, 'read_bytes', changing):
            with self.assertRaises(secret_scan.InputError) as caught:
                secret_scan.scan(self.root)
            self.assertEqual('inventory_changed', str(caught.exception))
        # Fresh start lets the same actual mutation exercise the public CLI path.
        subprocess.run(['git', '-C', str(self.root), 'rm', '-f', '-q', 'later'], check=True)
        with patch.object(secret_scan.Inputs, 'read_bytes', changing), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(2, secret_scan.main(['--root', str(self.root)]))
            self.assertEqual('{"schema_version":1,"status":"error"}\n', out.getvalue())

    def test_blocking_ci_entrypoint_cannot_be_advisory(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        section = workflow.split('      - name: Blocking secret-only text check\n', 1)[1].split('      - name:', 1)[0]
        self.assertEqual('        if: always()\n        run: python3 -I tools/secret_scan.py --root .\n', section)
        for entrypoint, module in [('tools/secret_output.py', 'secret_output'), ('tools/secret_scan.py', 'secret_scan')]:
            text = (ROOT / entrypoint).read_text()
            self.assertIn('from repo_checks.' + module + ' import main', text)
            self.assertIn('raise SystemExit(main())', text)
