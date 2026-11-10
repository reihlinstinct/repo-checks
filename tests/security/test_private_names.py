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
        self.assertIn('phone', privacy.text_categories(uuid + ' +972501234567'))
        self.assertIn('id', privacy.text_categories(uuid + ' 000000018'))
        self.assertIn('email', privacy.text_categories(uuid + ' zz@zz-domain.test'))
        self.assertIn('phone', privacy.text_categories('000000000102'))
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
        self.assertEqual([{'file': 'fixture.txt', 'line': 2}, {'file': 'fixture.txt', 'line': 3}], data['locations'])
        for term in json.loads(self.policy):
            self.assertNotIn(term, result.stdout + result.stderr)
        self.assertNotIn('value', result.stdout + result.stderr)
        self.assertEqual('', result.stderr)

    def test_filename_itself_fails_for_clean_and_binary_contents(self):
        for content in ['safe', b'\x00binary']:
            self.track('ZZAlpha.txt', content)
            result = self.cli(self.policy)
            self.assertEqual(1, result.returncode)
            self.assertEqual([{'file': '[redacted-path]', 'line': 0}],
                             json.loads(result.stdout)['locations'])
            self.assertNotIn('ZZAlpha', result.stdout + result.stderr)

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

    def test_large_binary_probe_and_oversize_text(self):
        self.track('opaque.enc', b'Salted__\x00\xff' + b'x' * (privacy.MAX_FILE + 100))
        result = self.cli(self.policy)
        self.assertEqual(0, result.returncode)
        self.assertEqual(1, json.loads(result.stdout)['binary_files_unscanned'])
        self.assertEqual(1, privacy.scan(self.root)['binary_files_unscanned'])
        self.track('large.txt', b'x' * (privacy.MAX_FILE + 1))
        self.assertEqual(2, self.cli(self.policy).returncode)

    def test_sensitive_large_binary_still_flagged(self):
        self.track('creds.json', b'\x00' + b'x' * (privacy.MAX_FILE + 100))
        self.assertEqual(1, privacy.scan(self.root)['counts']['sensitive_filename'])

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
        self.assertIn({'file': '[redacted-path]', 'line': 1}, json.loads(result.stdout)['locations'])

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
