"""Synthetic policy only. Never place actual private terms in tests."""
import importlib.util
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
from repo_checks import private_names as names
from repo_checks import inputs
from repo_checks import privacy


class PrivateNameTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'candidate'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.policy = json.dumps(['ZZAlpha', 'ZZSurname', 'זזבדיקה', 'ZZFull ZZName'])

    def tearDown(self):
        self.temp.cleanup()

    def track(self, name, content):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        subprocess.run(['git', '-C', str(self.root), 'add', '--', name], check=True)

    def cli(self, policy=None, action=False, extra=None):
        env = os.environ.copy()
        env.pop(names.ENV_KEY, None)
        if policy is not None:
            env[names.ENV_KEY] = policy
        if extra:
            env.update(extra)
        if action:
            env.update(GITHUB_WORKSPACE=self.temp.name, CHECK_ROOT=str(self.root))
            command = [sys.executable, '-I', str(ROOT / 'actions/private-names/bootstrap.py')]
        else:
            command = [sys.executable, '-I', str(ROOT / 'tools/private_name_scan.py'), '--root', str(self.root)]
        return subprocess.run(command, env=env, cwd=self.root, capture_output=True, text=True)

    def test_generic_uuid_token_is_not_phone_but_adjacent_pii_is(self):
        uuid = '00000000-0000-4000-8000-000000000102'
        self.assertEqual(set(), privacy.text_categories(uuid))
        # Generate positive scanner inputs, as in the scanner's own regressions.
        phone = '+' + '972' + '50' + '1234567'
        prefix = '345' + '67890'
        identity = next(prefix + str(n) for n in range(10) if privacy.checksum(prefix + str(n)))
        email = 'zz' + '@' + 'zz-domain.test'
        self.assertIn('phone', privacy.text_categories(uuid + ' ' + phone))
        self.assertIn('id', privacy.text_categories(uuid + ' ' + identity))
        self.assertIn('email', privacy.text_categories(uuid + ' ' + email))
        self.assertIn('phone', privacy.text_categories('0' * 9 + '102'))
        self.assertIn('phone', privacy.text_categories('ZZ' + uuid))

    def test_normalized_boundaries_not_substrings(self):
        pattern = names.load_policy(self.policy)
        for text in ['zzalpha', 'ZZSURNAME.', '(זזבדיקה)', 'ＺＺＡｌｐｈａ', 'ZZFull ZZName']:
            self.assertIsNotNone(pattern.search(names.normalize(text)))
        for text in ['ZZAlphaProject', 'myZZSurname', 'prefix_zzalpha', 'ZZFull ZZNames']:
            self.assertIsNone(pattern.search(names.normalize(text)))

    def test_locations_only_and_terms_never_echoed(self):
        self.track('fixture.txt', 'safe\nZZAlpha value\nזזבדיקה\n')
        result = self.cli(self.policy)
        self.assertEqual(1, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(2, data['findings'])
        self.assertNotIn('file', data)
        self.assertNotIn('line', data)
        self.assertNotIn('fixture.txt', result.stdout)
        for term in json.loads(self.policy):
            self.assertNotIn(term, result.stdout + result.stderr)
        self.assertNotIn('value', result.stdout + result.stderr)
        self.assertEqual('', result.stderr)

    def test_filename_itself_fails_without_public_location(self):
        self.track('ZZAlpha.txt', 'safe')
        result = self.cli(self.policy)
        self.assertEqual(1, result.returncode)
        self.assertEqual(1, json.loads(result.stdout)['findings'])
        self.assertNotIn('ZZAlpha', result.stdout + result.stderr)
        self.assertNotIn('line', result.stdout)

    def test_policy_missing_invalid_empty_or_wrong_shape_errors(self):
        for policy in [None, '', '[]', '{}', 'null', '[1]', '[true]', '[" "]', '["ZZBad\\nTerm"]', '["ZZBad\\u0000Term"]', self.policy * 500]:
            with self.subTest(policy_type=type(policy).__name__):
                result = self.cli(policy)
                self.assertEqual(2, result.returncode)
                self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(result.stdout))
                self.assertEqual('', result.stderr)

    def test_candidate_python_git_and_env_never_execute(self):
        marker = self.root / 'EXECUTED'
        poison = 'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n'
        self.track('sitecustomize.py', poison)
        self.track('repo_checks.py', poison)
        helper = self.root / 'helper'
        helper.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        helper.chmod(0o700)
        subprocess.run(['git', '-C', str(self.root), 'config', 'core.fsmonitor', str(helper)], check=True)
        result = self.cli(self.policy, action=True, extra={'PYTHONPATH': str(self.root), 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.fsmonitor', 'GIT_CONFIG_VALUE_0': str(helper)})
        self.assertEqual(0, result.returncode)
        self.assertFalse(marker.exists())

    def test_inventory_children_never_receive_policy(self):
        self.track('safe.txt', 'safe')
        original = inputs.subprocess.Popen
        seen = []
        def launch(*args, **kwargs):
            seen.append(kwargs['env'])
            return original(*args, **kwargs)
        with patch.dict(os.environ, {names.ENV_KEY: self.policy}), patch.object(inputs.subprocess, 'Popen', side_effect=launch):
            with inputs.Inputs(self.root):
                pass
        self.assertTrue(seen)
        self.assertTrue(all(names.ENV_KEY not in env for env in seen))

    def test_binary_encoding_and_size_probes_fail_closed(self):
        probes = [b'\0ZZAlpha', b'\0ZZAlpha' + b'x' * (privacy.MAX_FILE + 1),
                  b'\x89PNG\r\n\x1a\nZZAlpha' + b'x' * (privacy.MAX_FILE + 1),
                  b'caf\xe9 ZZAlpha', 'ZZAlpha'.encode('utf-16'),
                  b'Salted__\0\xff' + b'x' * (privacy.MAX_FILE + 1),
                  b'x' * (privacy.MAX_FILE + 1), b'x' * 9000 + b'\0ZZAlpha']
        for content in probes:
            self.track('opaque.enc', content)
            result = self.cli(self.policy)
            self.assertEqual(2, result.returncode)
            self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(result.stdout))
            self.assertEqual('', result.stderr)

    def test_generic_binary_does_not_waive_size_cap(self):
        self.track('creds.json', b'\0' + b'x' * (privacy.MAX_FILE + 100))
        with self.assertRaises(inputs.InputError):
            privacy.scan(self.root)

    def test_binary_bytes_count_toward_aggregate_budget(self):
        self.track('one', b'\0' + b'x' * 5)
        self.track('two', b'\0' + b'x' * 5)
        with patch.object(inputs, 'MAX_TOTAL', 10), inputs.Inputs(self.root) as source:
            self.assertEqual(6, len(source.read_bytes('one', binary_aware=True)))
            self.assertEqual(6, source.total)
            with self.assertRaises(inputs.InputError):
                source.read_bytes('two', binary_aware=True)

    def test_main_removes_secret_from_python_environment(self):
        import contextlib, io
        with patch.dict(os.environ, {names.ENV_KEY: self.policy}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, names.main(['--root', str(self.root)]))
            self.assertNotIn(names.ENV_KEY, os.environ)

    def test_action_contract_requires_isolated_python(self):
        self.assertIn('python3 -I ', (ROOT / 'actions/private-names/action.yml').read_text())

    def test_invalid_utf8_even_without_nul_errors(self):
        self.track('latin', b'caf\xe9')
        self.assertEqual(2, self.cli(self.policy).returncode)

    def test_nonzero_inventory_stage_is_rejected(self):
        self.track('item', 'safe')
        original = names.git_output
        def staged(root, args, *rest):
            if args == ['ls-files', '--stage', '-z']:
                return b'100644 ' + b'a' * 40 + b' 1\titem\0'
            return original(root, args, *rest)
        with patch.object(names, 'git_output', side_effect=staged):
            with self.assertRaises(inputs.InputError):
                names.scan(self.root, names.load_policy(self.policy))

    def test_utf8_prefix_boundary_not_false_binary(self):
        self.track('boundary.txt', 'a' * 8191 + 'é' + ' ZZAlpha')
        self.assertEqual(1, self.cli(self.policy).returncode)

    def test_matching_path_redacted_and_hostile_path_json_escaped(self):
        self.track('ZZSurname.txt', 'ZZAlpha')
        self.track('odd\n::warning::.txt', 'ZZAlpha')
        result = self.cli(self.policy)
        self.assertEqual(1, result.returncode)
        self.assertNotIn('ZZSurname', result.stdout)
        self.assertEqual(1, len(result.stdout.splitlines()))
        self.assertEqual(3, json.loads(result.stdout)['findings'])
        self.assertNotIn('file', json.loads(result.stdout))
        self.assertNotIn('line', json.loads(result.stdout))

    def test_symlink_missing_and_unmerged_fail_closed(self):
        self.track('item', 'safe')
        (self.root / 'item').unlink()
        self.assertEqual(2, self.cli(self.policy).returncode)
        (self.root / 'item').symlink_to('/etc/passwd')
        self.assertEqual(2, self.cli(self.policy).returncode)

    def test_action_fails_on_missing_policy_and_finding(self):
        self.assertEqual(2, self.cli(action=True).returncode)
        self.track('item', 'ZZAlpha')
        self.assertEqual(1, self.cli(self.policy, action=True).returncode)
        self.assertNotIn('continue-on-error', (ROOT / 'actions/private-names/action.yml').read_text())


if __name__ == '__main__':
    unittest.main()
