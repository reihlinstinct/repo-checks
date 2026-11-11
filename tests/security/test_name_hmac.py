"""Synthetic-only regressions for authenticated bounded two-pass matching."""
import base64
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import random
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from repo_checks import private_names as names
from repo_checks import name_hmac_policy as policy
from repo_checks import name_hmac_work as work
import test_private_names as fixture
from test_private_names import ENCODED_KEY, SYNTHETIC_KEY, synthetic_policy


def resign(value):
    value = copy.deepcopy(value)
    value.pop('policy_mac', None)
    value['policy_mac'] = hmac.digest(SYNTHETIC_KEY, policy.POLICY_LABEL + policy.canonical(value), hashlib.sha256).hex()
    return json.dumps(value)


class PolicyTests(unittest.TestCase):
    def test_valid_policy_authenticates_and_returns_length_index(self):
        key, targets = policy.load_policy(synthetic_policy(['ZZAlpha']), ENCODED_KEY)
        self.assertEqual(SYNTHETIC_KEY, key)
        self.assertEqual({7: frozenset({policy.term_digest(key, 'zzalpha')})}, targets)

    def test_wrong_missing_malformed_noncanonical_keys(self):
        raw = synthetic_policy(['ZZAlpha'])
        for key in [None, '', ENCODED_KEY[:-1], ENCODED_KEY + '\n',
                    base64.b64encode(b'Y' * 32).decode(),
                    base64.b64encode(b'Z' * 31).decode(), ENCODED_KEY[:-2] + 'p=']:
            with self.subTest(kind=type(key).__name__):
                with self.assertRaises(Exception):
                    policy.load_policy(raw, key)

    def test_each_authenticated_field_tamper_fails(self):
        original = json.loads(synthetic_policy(['ZZAlpha', 'ZZBeta']))
        mutations = []
        for key, value in [('schema', 'other'), ('unicode_version', 'other'),
                           ('entries', original['entries'][:1]), ('policy_mac', '0' * 64)]:
            item = copy.deepcopy(original)
            item[key] = value
            mutations.append(item)
        for field, value in [('length', 1), ('digest', '0' * 64)]:
            item = copy.deepcopy(original)
            item['entries'][0][field] = value
            mutations.append(item)
        item = copy.deepcopy(original)
        item['entries'].reverse()
        mutations.append(item)
        for value in mutations:
            with self.assertRaises(policy.PolicyError):
                policy.load_policy(json.dumps(value), ENCODED_KEY)

    def test_even_resigned_invalid_shapes_fail(self):
        original = json.loads(synthetic_policy(['ZZAlpha']))
        for field, value in [('length', True), ('length', 0), ('length', 65),
                             ('length', 1.0), ('digest', 'F' * 64), ('digest', '0' * 63)]:
            item = copy.deepcopy(original)
            item['entries'][0][field] = value
            with self.assertRaises(policy.PolicyError):
                policy.load_policy(resign(item), ENCODED_KEY)
        for entries in [[], original['entries'] * 257, [original['entries'][0]] * 2,
                        [{'length': 7, 'digest': '0' * 64, 'extra': 1}]]:
            item = copy.deepcopy(original)
            item['entries'] = entries
            with self.assertRaises(policy.PolicyError):
                policy.load_policy(resign(item), ENCODED_KEY)
        for field, value in [('extra', 1), ('schema', 'other'), ('unicode_version', 'other')]:
            item = copy.deepcopy(original)
            item[field] = value
            with self.assertRaises(policy.PolicyError):
                policy.load_policy(resign(item), ENCODED_KEY)

    def test_duplicate_json_keys_plaintext_arrays_and_oversize_rejected(self):
        for raw in ['["ZZAlpha"]', 'null', '{}', '{"schema":1,"schema":2}', ' ' * 32769]:
            with self.assertRaises(Exception):
                policy.load_policy(raw, ENCODED_KEY)

    def test_raw_and_normalized_term_bounds(self):
        for raw in ['ZZ' + 'a' * 62, 'ＺＺＡｌｐｈａ', 'ZZ' + '\u0130' * 31]:
            self.assertLessEqual(len(policy.validate_term(raw)), 64)
        for raw in ['Z', 'ZZ' + 'a' * 63, 'ZZ' + '\u0130' * 32, '\ufdfa' * 4,
                    ' ZZ', 'ZZ ', 'ZZ\0', '1234', 'Z' * 129]:
            with self.assertRaises(policy.PolicyError):
                policy.validate_term(raw)
        # Raw bound remains 2 even where normalization contracts the text.
        self.assertEqual('zz', policy.validate_term('ZZ'))

    def test_mac_uses_constant_time_comparison(self):
        original = policy.hmac.compare_digest
        with patch.object(policy.hmac, 'compare_digest', wraps=original) as compare:
            policy.load_policy(synthetic_policy(['ZZAlpha']), ENCODED_KEY)
            self.assertEqual(1, compare.call_count)
            left, right = compare.call_args.args
            self.assertEqual(32, len(left))
            self.assertEqual(32, len(right))

    def test_entry_cap_independent_of_order_and_duplicates(self):
        entries = [{'length': 7, 'digest': f'{index:064x}'} for index in range(257)]
        value = {'schema': policy.SCHEMA, 'unicode_version': __import__('unicodedata').unidata_version,
                 'entries': entries[:256]}
        policy.load_policy(resign(value), ENCODED_KEY)
        value['entries'] = entries
        with self.assertRaises(policy.PolicyError):
            policy.load_policy(resign(value), ENCODED_KEY)

    def test_domain_separation_and_length_encoding(self):
        text = 'zzalpha'
        digest = policy.term_digest(SYNTHETIC_KEY, text)
        self.assertEqual(hmac.digest(SYNTHETIC_KEY, policy.TERM_LABEL + b'\0\0\0\x07zzalpha', 'sha256'), digest)
        self.assertNotEqual(hashlib.sha256(text.encode()).digest(), digest)
        self.assertNotEqual(hmac.digest(SYNTHETIC_KEY, text.encode(), 'sha256'), digest)


class WorkTests(unittest.TestCase):
    def test_fixed_and_fuzz_differential_against_exact_regex(self):
        rng = random.Random(43)
        alphabet = 'ZZabאב .-_\u0301\u0130\ufdfa\u2028\u2029\u200b\t'
        terms = ['A\u030a\u0301', '1b', '.y', 'ZZAlpha', 'ZZFull ZZName', 'ZZאב', 'ZZ.a', 'ZZ\u2028ZZ', 'ZZ\u0301', 'ZZ\ufdfa']
        targets = [policy.validate_term(t) for t in terms]
        pattern = re.compile(r'(?<!\w)(?:' + '|'.join(map(re.escape, targets)) + r')(?!\w)')
        lengths = work.prepare_lengths(map(len, targets))
        for raw in terms + [rng.choice(terms) + ''.join(rng.choices(alphabet, k=40)) for _ in range(500)]:
            for text in [policy.normalize(raw), *map(policy.normalize, raw.splitlines())]:
                stats = {'examined_pairs': 0}
                candidates = [text[i:j] for i, j in work.pruned_candidates(text, lengths, stats)]
                self.assertEqual(bool(pattern.search(text)), any(x in targets for x in candidates))
                count, byte_work = work.work_counts(text, 64)
                self.assertLessEqual(stats['examined_pairs'], count)
                self.assertLessEqual(len(candidates), count)
                self.assertLessEqual(sum(len(x.encode()) for x in candidates), byte_work)

    def test_full_public_range_counter_matches_naive(self):
        rng = random.Random(19)
        alphabet = 'aאב -._\u0301\u0130\u2028\u200b'
        for _ in range(300):
            text = policy.normalize(''.join(rng.choices(alphabet, k=35)))
            candidates = []
            for i in range(len(text)):
                for j in range(i + 1, min(i + 64, len(text)) + 1):
                    piece = text[i:j]
                    if ((i == 0 or not re.fullmatch(r'\w', text[i-1]))
                            and (j == len(text) or not re.fullmatch(r'\w', text[j]))
                            and piece == piece.strip() and any(c.isalpha() for c in piece)
                            and not any(__import__('unicodedata').category(c).startswith('C') for c in piece)):
                        candidates.append(piece)
            self.assertEqual((len(candidates), sum(len(x.encode()) for x in candidates)), work.work_counts(text, 64))


class BoundedScanTests(unittest.TestCase):
    setUp = fixture.PrivateNameTests.setUp
    tearDown = fixture.PrivateNameTests.tearDown
    track = fixture.PrivateNameTests.track
    cli = fixture.PrivateNameTests.cli

    def test_single_point_and_first_alpha_at_end_cli_findings(self):
        # The first raw term composes to one normalized code point.
        for raw, content in [('A\u030a\u0301', '(ǻ)'), ('1b', '1b'), ('.y', '.y')]:
            self.track('x', content)
            run = self.cli(synthetic_policy([raw]))
            self.assertEqual(1, run.returncode)
            self.assertEqual({'schema_version': 1, 'status': 'findings'}, json.loads(run.stdout))
            self.assertEqual('', run.stderr)

    def test_alarm_armed_before_policy_and_inventory_then_cancelled(self):
        events = []
        original = names.load_policy
        def load(*args):
            events.append('policy')
            return original(*args)
        def alarm(seconds):
            events.append(seconds)
        with patch.dict(os.environ, {names.ENV_KEY: self.policy, names.KEY_ENV: ENCODED_KEY}), patch.object(names.signal, 'alarm', alarm), patch.object(names, 'load_policy', load), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, names.main(['--root', str(self.root)]))
        self.assertEqual([30, 'policy', 0], events)

    def test_wrong_key_fails_before_inventory(self):
        with patch.object(names, 'scan', side_effect=AssertionError('inventory reached')) as scanned:
            with patch.dict(os.environ, {names.ENV_KEY: self.policy, names.KEY_ENV: base64.b64encode(b'Y'*32).decode()}), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(2, names.main(['--root', str(self.root)]))
            scanned.assert_not_called()
            self.assertEqual({'schema_version': 1, 'status': 'error'}, json.loads(out.getvalue()))

    def test_all_sensitive_keys_removed_on_success_and_legacy_error(self):
        for legacy in (False, True):
            env = {names.ENV_KEY: self.policy, names.KEY_ENV: ENCODED_KEY}
            if legacy:
                env[policy.LEGACY_ENV] = '["ZZAlpha"]'
            with patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(2 if legacy else 0, names.main(['--root', str(self.root)]))
                self.assertTrue(all(key not in os.environ for key in policy.SENSITIVE_ENV_KEYS))

    def test_public_caps_checked_before_any_hash_even_with_early_match(self):
        self.track('a.txt', 'ZZAlpha\n')
        self.track('z.txt', 'a a a a a a a a')
        limits = [('MAX_LINE_POINTS', 5), ('MAX_FILE_POINTS', 10), ('MAX_TOTAL_POINTS', 15),
                  ('MAX_FILE_SEGMENTS', 1), ('MAX_TOTAL_SEGMENTS', 2),
                  ('MAX_FILE_CANDIDATES', 1), ('MAX_TOTAL_CANDIDATES', 2),
                  ('MAX_FILE_CANDIDATE_BYTES', 1), ('MAX_TOTAL_CANDIDATE_BYTES', 2)]
        for field, limit in limits:
            with patch.object(names, field, limit), patch.object(names, 'term_digest') as hashed:
                with self.assertRaises(names.InputError):
                    names.scan(self.root, policy.load_policy(self.policy, ENCODED_KEY))
                hashed.assert_not_called()

    def test_exact_boundaries_equal_pass_over_fails(self):
        self.track('x', 'ZZsafe')
        points, segments, calls, byte_work = 7, 2, 2, 7
        # Whole path x plus one content segment ZZsafe.
        limits = [('MAX_LINE_POINTS', 6), ('MAX_FILE_POINTS', points), ('MAX_TOTAL_POINTS', points),
                  ('MAX_FILE_SEGMENTS', segments), ('MAX_TOTAL_SEGMENTS', segments),
                  ('MAX_FILE_CANDIDATES', calls), ('MAX_TOTAL_CANDIDATES', calls),
                  ('MAX_FILE_CANDIDATE_BYTES', byte_work), ('MAX_TOTAL_CANDIDATE_BYTES', byte_work)]
        loaded = policy.load_policy(self.policy, ENCODED_KEY)
        for field, limit in limits:
            with patch.object(names, field, limit):
                self.assertEqual('pass', names.scan(self.root, loaded)['status'])
            with patch.object(names, field, limit-1):
                with self.assertRaises(names.InputError):
                    names.scan(self.root, loaded)

    def test_file_change_between_passes_fails(self):
        self.track('x', 'ZZAlpha')
        original = names.Inputs.read_bytes
        count = 0
        def changed(source, name, *args):
            nonlocal count
            count += 1
            if count == 2:
                (self.root / name).write_text('ZZOther')
            return original(source, name, *args)
        with patch.object(names.Inputs, 'read_bytes', changed):
            with self.assertRaises(names.InputError):
                names.scan(self.root, policy.load_policy(self.policy, ENCODED_KEY))

    def test_inventory_change_between_passes_fails(self):
        self.track('x', 'safe')
        original = names.inventory
        count = 0
        def changed(root):
            nonlocal count
            count += 1
            result = original(root)
            return result + b'changed' if count >= 3 else result
        with patch.object(names, 'inventory', changed):
            with self.assertRaises(names.InputError):
                names.scan(self.root, policy.load_policy(self.policy, ENCODED_KEY))

    def test_match_does_not_skip_hashing_later_candidates(self):
        self.track('x', 'ZZAlpha ZZOther ZZAlpha')
        loaded = policy.load_policy(self.policy, ENCODED_KEY)
        with patch.object(names, 'term_digest', wraps=policy.term_digest) as hashed:
            self.assertEqual('findings', names.scan(self.root, loaded)['status'])
            self.assertEqual(3, hashed.call_count)

    def test_all_splitlines_separators_and_whole_paths(self):
        for separator in ('\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'):
            self.track('x', 'ZZFull' + separator + 'ZZName')
            self.assertEqual(0, self.cli(self.policy).returncode)
        raw = synthetic_policy(['ZZ\u2028ZZ'])
        self.track('ZZ\u2028ZZ', 'safe')
        self.assertEqual(1, self.cli(raw).returncode)

    def test_children_strip_all_sensitive_keys(self):
        self.track('x', 'safe')
        from repo_checks import inputs
        launch = inputs.subprocess.Popen
        observed = []
        def call(*args, **kwargs):
            observed.append(kwargs['env'])
            return launch(*args, **kwargs)
        with patch.dict(os.environ, dict.fromkeys(policy.SENSITIVE_ENV_KEYS, 'ZZdummy')), patch.object(inputs.subprocess, 'Popen', call):
            with inputs.Inputs(self.root):
                pass
        self.assertTrue(observed)
        self.assertTrue(all(not (set(env) & set(policy.SENSITIVE_ENV_KEYS)) for env in observed))


class IntegrationScopeTests(unittest.TestCase):
    def test_benchmark_has_no_secrets_and_uses_actual_isolated_cli(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / '.github/workflows/hmac-bounded-name-scan.yml').read_text()
        for forbidden in ('pull_request_target', 'environment:', 'secrets:', 'id-token:', 'schedule:', 'push:'):
            self.assertNotIn(forbidden, text)
        self.assertIn('contents: read', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('python3 -I tools/benchmark_bounded_name_scan.py', text)
        script = (root / 'tools/benchmark_bounded_name_scan.py').read_text()
        self.assertIn("sys.executable, '-I'", script)
        self.assertNotIn('sys.argv', script)

    def test_bootstrap_fallback_sensitive_names_match_shared_constant(self):
        root = Path(__file__).resolve().parents[2]
        import ast
        tree = ast.parse((root / 'actions/private-names/bootstrap.py').read_text())
        tuples = [ast.literal_eval(node) for node in ast.walk(tree)
                  if isinstance(node, ast.Tuple) and all(isinstance(n, ast.Constant) for n in node.elts)]
        self.assertIn(policy.SENSITIVE_ENV_KEYS, tuples)

    def test_documented_constants_match_engine(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / 'docs/PRIVATE_NAME_GUARD.md').read_text()
        for number in (names.MAX_LINE_POINTS, names.MAX_FILE_POINTS, names.MAX_TOTAL_POINTS,
                       names.MAX_FILE_SEGMENTS, names.MAX_TOTAL_SEGMENTS):
            self.assertIn(str(number), text)
        self.assertIn('64 MiB', text)
        self.assertIn('128 MiB', text)
