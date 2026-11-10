"""Synthetic benchmark math and isolation contracts, not actual policy tests."""
from pathlib import Path
import random
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from repo_checks import hmac_benchmark as b


def naive(text, maximum):
    values = []
    for i in range(len(text)):
        for length in range(1, maximum + 1):
            j = i + length
            if j > len(text) or (i and re.fullmatch(r'\w', text[i-1])) or (j < len(text) and re.fullmatch(r'\w', text[j])):
                continue
            if b.admissible(text[i:j]):
                values.append(text[i:j])
    return len(values), sum(len(v.encode('utf-8')) for v in values)


class BenchmarkTests(unittest.TestCase):
    def test_prefix_counter_matches_naive_full_range(self):
        rng = random.Random(17)
        alphabet = 'aZ. _-\n\t\u05d0\u05b0\u200b\u2028\ufdfa\u0130'
        for _ in range(300):
            text = b.normalize(''.join(rng.choice(alphabet) for _ in range(rng.randrange(25))))
            maximum = rng.randrange(1, 30)
            self.assertEqual(naive(text, maximum), b.work_counts(text, maximum))

    def test_invalid_bound_refused(self):
        for maximum in (0, -1, True, '1'):
            with self.assertRaises(ValueError):
                b.work_counts('a', maximum)

    def test_public_count_not_secret_length_dependent(self):
        self.assertEqual(b.work_counts('a.a a', 4), naive('a.a a', 4))
        self.assertEqual((0, 0), b.work_counts('... ---', 32))

    def test_hash_sample_never_matches_or_reads_policy(self):
        sample = b.sampled_hash_work('a.a.' * 30, [1, 3, 5], limit=20)
        self.assertEqual(20, sample['examined_pairs'])
        self.assertTrue(sample['pair_cap_reached'])
        self.assertGreaterEqual(sample['utf8_bytes'], sample['calls'])
        self.assertGreaterEqual(sample['filter_seconds'], 0)
        self.assertGreaterEqual(sample['hmac_seconds'], 0)
        source = (ROOT / 'src/repo_checks/hmac_benchmark.py').read_text()
        for forbidden in ('os.environ', 'getenv(', 'subprocess', 'open(', 'read_text(', 'PRIVATE_NAME_'):
            self.assertNotIn(forbidden, source)

    def test_workflow_has_no_secret_or_write_permission(self):
        text = (ROOT / '.github/workflows/hmac-benchmark.yml').read_text()
        self.assertIn('permissions:\n  contents: read\n', text)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('workflow_dispatch', text)
        self.assertNotIn(' write', text)
        self.assertIn('python3 -I tools/benchmark_name_hmac.py', text)
        self.assertIn('timeout-minutes: 5', text)


class MeasurementContractTests(unittest.TestCase):
    def test_punctuation_pair_cap_fires_without_any_hash(self):
        from unittest.mock import patch
        with patch.object(b.hmac, 'digest') as digest:
            sample = b.sampled_hash_work('.-' * 100, range(1, 50), limit=20)
        self.assertEqual(20, sample['examined_pairs'])
        self.assertEqual(20, sample['rejected_pairs'])
        self.assertEqual(0, sample['calls'])
        self.assertTrue(sample['pair_cap_reached'])
        digest.assert_not_called()

    def test_digest_loop_runs_after_all_filtering(self):
        from unittest.mock import patch
        events = []
        original = b.admissible
        def filtered(text):
            events.append('filter')
            return original(text)
        def hashed(*args):
            events.append('hash')
        with patch.object(b, 'admissible', side_effect=filtered), patch.object(b.hmac, 'digest', side_effect=hashed):
            b.sampled_hash_work('a.a.a.', [1, 3], limit=5)
        self.assertIn('hash', events)
        first_hash = events.index('hash')
        self.assertNotIn('filter', events[first_hash:])

    def test_whole_normalized_path_count_upper_bounds_content(self):
        rng = random.Random(29)
        alphabet = 'ab. _-\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029\ufdfa\u0130\u0301'
        for _ in range(400):
            raw = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(35)))
            maximum = rng.randrange(1, 35)
            whole = b.work_counts(b.normalize(raw), maximum)
            content = b.content_work_counts(raw, maximum)
            self.assertGreaterEqual(whole[0], content['candidates'])
            self.assertGreaterEqual(whole[1], content['candidate_utf8_bytes'])
        for separator in ('\n', '\r\n', '\u2028', '\u2029'):
            result = b.content_work_counts('ab' + separator + 'cd', 10)
            self.assertEqual(2, result['lines'])
            self.assertEqual(2, result['candidates'])
        self.assertEqual(3, b.work_counts('ab\u2028cd', 10)[0])

    def test_rules_equal_current_scanner_on_synthetic_cases(self):
        from repo_checks import private_names
        for raw in ['ZZAlpha', 'ZZFull ZZName', '\ufdfa', '\u0130', ' a', 'a\u200b', 'ab\u2028cd']:
            self.assertEqual(private_names.normalize(raw), b.normalize(raw))
            try:
                private_names.load_policy(__import__('json').dumps([raw]))
                valid = True
            except Exception:
                valid = False
            self.assertEqual(valid, 2 <= len(raw) <= 128 and b.admissible(b.normalize(raw)))

    def test_workflow_is_exact_read_only_synthetic_lane(self):
        text = (ROOT / '.github/workflows/hmac-benchmark.yml').read_text()
        for forbidden in ('pull_request_target', 'environment:', 'secrets:', 'id-token:', 'schedule:', 'push:'):
            self.assertNotIn(forbidden, text)
        uses = [line.strip() for line in text.splitlines() if 'uses:' in line]
        self.assertEqual(['- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7'], uses)
        self.assertIn('persist-credentials: false', text)
