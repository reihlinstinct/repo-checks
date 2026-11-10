"""Synthetic differential enumeration and fixed-work invariant tests."""
from pathlib import Path
import random
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from repo_checks import hmac_benchmark as base
from repo_checks import hmac_pruned_benchmark as pruned


class PrunedTests(unittest.TestCase):
    def test_pruner_equals_naive_and_work_is_publicly_bounded(self):
        rng = random.Random(71)
        alphabet = 'aZ. _-\n\t\u05d0\u05b0\u200b\u2028\ufdfa\u0130'
        for _ in range(400):
            text = base.normalize(''.join(rng.choice(alphabet) for _ in range(rng.randrange(35))))
            lengths = sorted({rng.randrange(1, 40) for _ in range(10)})
            expected = set()
            for i in range(len(text)):
                for length in lengths:
                    j = i + length
                    if j > len(text) or (i and base.WORD.fullmatch(text[i-1])) or (j < len(text) and base.WORD.fullmatch(text[j])):
                        continue
                    if base.admissible(text[i:j]):
                        expected.add((i, j))
            stats = {'examined_pairs': 0}
            actual = list(pruned.pruned_candidates(text, lengths, stats))
            self.assertEqual(expected, set(actual))
            self.assertEqual(len(actual), len(set(actual)))
            self.assertLessEqual(stats['examined_pairs'], base.work_counts(text, max(lengths))[0])

    def test_punctuation_has_zero_second_pass_pairs(self):
        stats = {'examined_pairs': 0}
        self.assertEqual([], list(pruned.pruned_candidates('.-' * 1000, range(1, 257), stats)))
        self.assertEqual(0, stats['examined_pairs'])

    def test_complete_pass_covers_content_and_repeated_work(self):
        for content in (False, True):
            a = pruned.complete_pass('a.a\na.a', [1, 3], 5, content)
            b = pruned.complete_pass('a.a\na.a', [1, 3], 5, content)
            for field in ('calls', 'examined_pairs', 'utf8_bytes', 'public_candidates'):
                self.assertEqual(a[field], b[field])
            self.assertLessEqual(a['calls'], a['public_candidates'])

    def test_temporary_read_decode_exact_bytes(self):
        results = pruned.read_decode_measurement(1024, 256)
        self.assertEqual(3, len(results))
        self.assertTrue(all(r['bytes'] == 1024 for r in results))

    def test_workflow_is_read_only_and_has_no_secrets(self):
        text = (ROOT / '.github/workflows/hmac-pruned-benchmark.yml').read_text()
        self.assertIn('permissions:\n  contents: read\n', text)
        for unsafe in ('secrets.', 'secrets:', 'environment:', 'pull_request_target', 'workflow_dispatch', ' write'):
            self.assertNotIn(unsafe, text)
        uses = [s.strip() for s in text.splitlines() if 'uses:' in s]
        self.assertEqual(['- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7'], uses)
        source = (ROOT / 'src/repo_checks/hmac_pruned_benchmark.py').read_text()
        for unsafe in ('os.environ', 'getenv(', 'subprocess', 'PRIVATE_NAME_'):
            self.assertNotIn(unsafe, source)
