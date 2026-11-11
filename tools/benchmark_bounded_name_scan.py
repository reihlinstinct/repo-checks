"""Synthetic end-to-end runner measurements, including secure reads twice."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import base64
import hashlib
import hmac
import json
import os
import platform
import subprocess
import tempfile
import time
import unicodedata

from repo_checks import name_hmac_policy as policy

KEY = b'Z' * 32  # Public synthetic bytes, never a policy key.
ROOT = Path(__file__).resolve().parents[1]


def synthetic_policy(terms):
    normalized = {policy.validate_term(term) for term in terms}
    entries = sorted([{'length': len(text), 'digest': policy.term_digest(KEY, text).hex()}
                      for text in normalized], key=lambda entry: entry['digest'])
    value = {'schema': policy.SCHEMA, 'unicode_version': unicodedata.unidata_version,
             'entries': entries}
    value['policy_mac'] = hmac.digest(KEY, policy.POLICY_LABEL + policy.canonical(value), hashlib.sha256).hex()
    return json.dumps(value)


def main():
    print(json.dumps({'kind': 'runtime', 'python': platform.python_version(),
                      'unicode': unicodedata.unidata_version}), flush=True)
    shapes = {'minimum': ['A\u030a\u0301'], 'maximum': ['ZZ' + 'a' * 62],
              'dense': ['A\u030a\u0301'] + ['ZZ' + 'a' * (n-2) for n in range(2, 65)]}
    # Every byte below is generated here. Never accept an external corpus path.
    corpora = {
        'dense_words': ['a a ' * 15000] * 2,
        # Approximately 2m candidates and 2m normalized points together.
        'near_caps': ['a a ' * 15632] * 2 + ['😀' * 234300] * 8,
        # Two near-1MB files: dense endpoints, alphabetic character at line end.
        'at_cap_starts': [('.' * 30 + 'a\n') * 32000] * 2,
        'single_point_finding': ['(ǻ)'],
        'prose': ['ZZAlpha met ZZBeta. ' * 10000] * 2,
        'nonascii_points': ['😀' * 249900] * 8,
        'many_lines': ['a\n' * 49000] * 2,
        'expansion': ['\ufdfa' * 7000],
        'over_budget': ['a a ' * 100000],
    }
    for corpus, files in corpora.items():
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            for index, data in enumerate(files):
                (root / ('synthetic-' + str(index) + '.txt')).write_text(data, encoding='utf-8')
            subprocess.run(['git', '-C', str(root), 'add', '--all'], check=True)
            for shape, terms in shapes.items():
                env = {k: v for k, v in os.environ.items() if k not in policy.SENSITIVE_ENV_KEYS}
                env.update({policy.POLICY_ENV: synthetic_policy(terms),
                            policy.KEY_ENV: base64.b64encode(KEY).decode('ascii')})
                for repeat in range(3):
                    start = time.perf_counter()
                    run = subprocess.run([sys.executable, '-I', str(ROOT / 'tools/private_name_scan.py'),
                                          '--root', str(root)], env=env, capture_output=True, text=True, timeout=35)
                    elapsed = time.perf_counter() - start
                    expected = (2 if corpus == 'over_budget' else
                                1 if corpus == 'single_point_finding' and shape in ('minimum', 'dense') else 0)
                    if run.returncode != expected or run.stderr or json.loads(run.stdout) != {
                            'schema_version': 1, 'status': {0: 'pass', 1: 'findings', 2: 'error'}[expected]}:
                        raise RuntimeError('Synthetic end-to-end benchmark failed')
                    print(json.dumps({'kind': 'end_to_end', 'corpus': corpus, 'shape': shape,
                                      'repeat': repeat, 'seconds': elapsed,
                                      'expected_exit': expected}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
