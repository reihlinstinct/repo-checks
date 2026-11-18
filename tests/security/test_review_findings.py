import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from repo_checks.review_findings import InvalidEvidence, read_json, safe_file, validate
spec = importlib.util.spec_from_file_location('review_adapter', ROOT / 'tools/review_findings.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('tests/test_bug.py', '.github/workflows/ci.yml'):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('synthetic fixture')
        self.entry = dict(issue=7, mode='automated', review_url='https://github.com/example/project/pull/1#discussion_r7',
                          affected_head='a' * 40, summary='Reject malformed synthetic input',
                          regression_paths=['tests/test_bug.py'], workflow='.github/workflows/ci.yml',
                          command='python -m unittest discover -s tests',
                          negative_control='Original implementation rejects no malformed input; negative fixture fails.',
                          pass_evidence='Fixed implementation passes the same synthetic fixture in CI.')
        self.doc = dict(version=1, repository='example/project', pull_request=9, findings=[self.entry])

    def check(self, doc=None, expected=(7,)):
        return validate(self.root, 'example/project', 9, expected, self.doc if doc is None else doc)

    def test_automated_positive(self):
        self.assertEqual({'findings': 1, 'manual_limits': 0}, self.check())

    def test_manual_positive_and_missing_rationale(self):
        e = {k: self.entry[k] for k in ('issue', 'mode', 'review_url', 'affected_head', 'summary')}
        e.update(mode='manual-limit', reason='Actual native screen reader behavior needs a device.',
                 checklist=['Read synthetic state using actual screen reader.'], owner='Repository maintainer',
                 remaining_automation='Synthetic semantic-state assertions remain in normal CI.')
        self.doc['findings'] = [e]
        self.assertEqual(1, self.check()['manual_limits'])
        for field in ('reason', 'owner', 'remaining_automation'):
            bad = copy.deepcopy(self.doc)
            bad['findings'][0][field] = ' '
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                self.check(bad)

    def test_missing_extra_duplicate_issue_fails(self):
        for expected, entries in [((7,), []), ((), [self.entry]), ((7,), [self.entry, self.entry])]:
            doc = copy.deepcopy(self.doc)
            doc['findings'] = entries
            with self.subTest(expected=expected, count=len(entries)), self.assertRaises(InvalidEvidence):
                self.check(doc, expected)

    def test_schema_identity_and_evidence_negative_controls(self):
        cases = []
        for key, value in [('repository', 'other/project'), ('pull_request', True), ('version', 2), ('findings', {})]:
            doc = copy.deepcopy(self.doc)
            doc[key] = value
            cases.append(doc)
        for key, value in [('issue', True), ('mode', 'waived'), ('review_url', 'https://invalid.example/7'),
                           ('affected_head', 'short'), ('regression_paths', []), ('command', 'true'),
                           ('negative_control', ''), ('pass_evidence', ''), ('workflow', 'tests/test_bug.py'),
                           ('regression_paths', ['tests/missing.py']), ('extra', 'not allowed')]:
            doc = copy.deepcopy(self.doc)
            doc['findings'][0][key] = value
            cases.append(doc)
        for doc in cases:
            with self.subTest(doc=doc), self.assertRaises(InvalidEvidence):
                self.check(doc)

    def test_path_traversal_and_symlink_rejected(self):
        for path in ('/etc/passwd', '../outside', 'tests/../test.py', 'tests\\test.py', 'tests//test_bug.py'):
            with self.subTest(path=path), self.assertRaises(InvalidEvidence):
                safe_file(self.root, path)
        (self.root / 'alias').symlink_to(self.root / 'tests', target_is_directory=True)
        with self.assertRaises(InvalidEvidence):
            safe_file(self.root, 'alias/test_bug.py')

    def test_duplicate_json_keys_and_size_fail(self):
        p = self.root / 'input.json'
        for data in ('{"a":1,"a":2}', 'x' * 262145, '{'):
            p.write_text(data)
            with self.assertRaises(InvalidEvidence):
                read_json(p)

    def test_reference_extraction_and_bounds(self):
        self.assertEqual({7, 8}, adapter.issue_references('example/project', ['#7 https://github.com/example/project/issues/8 https://github.com/other/project/issues/9']))
        with self.assertRaises(InvalidEvidence):
            adapter.issue_references('example/project', [' '.join('#' + str(n) for n in range(1, 32))])

    def test_collects_labeled_issues_from_review_bodies(self):
        class Fake:
            repository = 'example/project'
            def get(self, path):
                if path == '/pulls/9': return {'body': 'Fix #7', 'head': {'sha': 'a' * 40}}
                if '/comments?' in path: return [{'body': '#8 also needs a regression'}]
                if '/reviews?' in path: return [{'body': '#10'}]
                return {'labels': [{'name': 'review-finding'}] if path.endswith(('/7', '/10')) else []}
        found, _ = adapter.collect(Fake(), 9)
        self.assertEqual({7, 10}, found)

    def test_missing_token_fails_without_network(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(adapter.Github, 'get', side_effect=AssertionError('network forbidden')):
            self.assertEqual(1, adapter.main(['--root', str(self.root), '--repository', 'example/project', '--pr', '9', '--head', 'a' * 40]))

    def test_no_consumer_command_execution(self):
        self.entry['command'] = 'never execute this consumer-controlled command'
        with patch('subprocess.run', side_effect=AssertionError('execution forbidden')):
            self.check()


if __name__ == '__main__':
    unittest.main()
