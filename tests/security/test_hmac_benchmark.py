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
        calls, byte_work, seconds = b.sampled_hash_work('a.a.' * 30, [1, 3, 5], limit=20)
        self.assertEqual(20, calls)
        self.assertGreaterEqual(byte_work, calls)
        self.assertGreaterEqual(seconds, 0)
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
