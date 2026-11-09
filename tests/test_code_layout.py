"""Tests for the in-file code-layout engine and result schema."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))
from repo_checks import code_layout  # noqa: E402


def make_repo(files: dict) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    subprocess.run(['git', 'add', '-A'], cwd=root, check=True)
    return tmp


def body(lines: int) -> str:
    return '\n'.join('x = %d' % i for i in range(lines)) + '\n'


class ScanTests(unittest.TestCase):
    def test_clean_small_file_passes(self):
        with make_repo({'a.py': 'print(1)\n'}) as tmp:
            result = code_layout.scan(Path(tmp))
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['files_scanned'], 1)

    def test_too_long_flagged_with_path_and_lines(self):
        with make_repo({'big.py': body(450)}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, header_threshold=250)
        self.assertEqual(result['status'], 'findings')
        rules = {f['rule'] for f in result['findings']}
        self.assertEqual(rules, {'file_too_long', 'missing_section_headers'})
        item = result['findings'][0]
        self.assertEqual(item['path'], 'big.py')
        self.assertEqual(item['lines'], 450)
        self.assertEqual(result['counts'], {'file_too_long': 1, 'missing_section_headers': 1})

    def test_long_file_with_header_only_missing_size(self):
        text = '# Section: Things\n' + body(300)
        with make_repo({'mid.py': text}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, header_threshold=250)
        self.assertEqual(result['counts'], {'file_too_long': 0, 'missing_section_headers': 0})
        self.assertEqual(result['status'], 'pass')

    def test_header_styles_recognized(self):
        for header in ('# Section: A', '#Section: A', '    // Section: B', '// section: c'):
            text = header + '\n' + body(260)
            with make_repo({'mid.py': text}) as tmp:
                result = code_layout.scan(Path(tmp), max_lines=400, header_threshold=250)
            self.assertEqual(result['status'], 'pass', header)

    def test_non_source_and_excluded_ignored(self):
        files = {'README.md': body(900), 'data.json': body(900),
                 'vendor/lib.py': body(900), 'gen.min.js': body(900)}
        with make_repo(files) as tmp:
            result = code_layout.scan(Path(tmp))
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['files_scanned'], 0)
        self.assertEqual(result['files_excluded'], 2)

    def test_extra_excludes(self):
        with make_repo({'tools/gen.py': body(900)}) as tmp:
            result = code_layout.scan(Path(tmp), extra_excludes=('tools/gen.py',))
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['files_excluded'], 1)

    def test_bad_limits_raise(self):
        with make_repo({'a.py': 'x\n'}) as tmp:
            with self.assertRaises(code_layout.ScanError):
                code_layout.scan(Path(tmp), max_lines=100, header_threshold=250)

    def test_main_error_path_is_value_free(self):
        code = code_layout.main(['--root=/nonexistent-xyz'])
        self.assertEqual(code, 2)

    def test_main_findings_exit_1(self):
        with make_repo({'big.py': body(450)}) as tmp:
            code = code_layout.main(['--root=' + tmp])
        self.assertEqual(code, 1)


class SchemaTests(unittest.TestCase):
    def test_result_shape(self):
        with make_repo({'big.py': body(450), 'ok.py': 'y\n'}) as tmp:
            result = code_layout.scan(Path(tmp))
        self.assertEqual(set(result), {'schema_version', 'status', 'max_lines',
                                       'max_lines_test', 'header_threshold',
                                       'files_scanned', 'files_excluded',
                                       'counts', 'findings'})
        self.assertEqual(result['schema_version'], 1)
        json.dumps(result)


if __name__ == '__main__':
    unittest.main()

class RegressionAndPolicyTests(unittest.TestCase):
    def test_header_below_first_line_counts(self):
        # Regression: a section header after docstring/imports must be found.
        text = '"""Module docstring."""\nimport os\n\n# Section: API\n' + body(260)
        with make_repo({'mod.py': text}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, header_threshold=250)
        self.assertEqual(result['counts']['missing_section_headers'], 0)

    def test_test_files_use_higher_cap(self):
        with make_repo({'tests/test_big.py': body(500)}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, max_lines_test=600)
        self.assertEqual(result['counts']['file_too_long'], 0)
        # but headers still required above the threshold
        self.assertEqual(result['counts']['missing_section_headers'], 1)

    def test_test_cap_still_enforced(self):
        with make_repo({'tests/test_big.py': body(650)}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, max_lines_test=600)
        self.assertEqual(result['counts']['file_too_long'], 1)

    def test_source_cap_unchanged_by_test_cap(self):
        with make_repo({'src/big.py': body(450)}) as tmp:
            result = code_layout.scan(Path(tmp), max_lines=400, max_lines_test=600)
        self.assertEqual(result['counts']['file_too_long'], 1)
