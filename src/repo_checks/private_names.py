"""Two-pass trusted HMAC name gate. Public output is fixed and value-free."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

from repo_checks.inputs import Inputs, InputError, git_output
from repo_checks.name_hmac_policy import (
    KEY_ENV, LEGACY_ENV, MAX_LENGTH, POLICY_ENV, SENSITIVE_ENV_KEYS,
    PolicyError, load_policy, normalize, term_digest,
)
from repo_checks.name_hmac_work import prepare_lengths, pruned_candidates, work_counts

ENV_KEY = POLICY_ENV
MAX_LINE_POINTS = 262144
MAX_FILE_POINTS = 1000000
MAX_TOTAL_POINTS = 2000000
MAX_FILE_SEGMENTS = 50000
MAX_TOTAL_SEGMENTS = 100000
MAX_FILE_CANDIDATES = 1000000
MAX_TOTAL_CANDIDATES = 2000000
MAX_FILE_CANDIDATE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_CANDIDATE_BYTES = 128 * 1024 * 1024


def inventory(root):
    staged = git_output(root, ['ls-files', '--stage', '-z'])
    if staged and not staged.endswith(b'\0'):
        raise InputError('invalid_inventory')
    for entry in staged.split(b'\0'):
        if not entry:
            continue
        metadata, _ = entry.split(b'\t', 1)
        mode, _, stage = metadata.split()
        if mode not in (b'100644', b'100755') or stage != b'0':
            raise InputError('invalid_inventory')
    return staged


def segments(name, data):
    # Split decoded content before normalization, but never split whole paths.
    if b'\0' in data:
        raise InputError('unscannable_content')
    text = data.decode('utf-8', errors='strict')
    yield normalize(name)
    for line in text.splitlines():
        yield normalize(line)


def _within(values, limits):
    if any(value > limit for value, limit in zip(values, limits)):
        raise InputError('work_limit')


def scan(root, policy):
    key, targets = policy
    prepared = prepare_lengths(targets)
    totals = [0, 0, 0, 0]
    aggregate_limits = (MAX_TOTAL_POINTS, MAX_TOTAL_SEGMENTS,
                        MAX_TOTAL_CANDIDATES, MAX_TOTAL_CANDIDATE_BYTES)
    file_limits = (MAX_FILE_POINTS, MAX_FILE_SEGMENTS,
                   MAX_FILE_CANDIDATES, MAX_FILE_CANDIDATE_BYTES)
    fingerprints = {}
    with Inputs(root) as source:
        baseline = inventory(root)
        root_stat = os.fstat(source.fd)
        identity = (root_stat.st_dev, root_stat.st_ino)
        paths = source.paths
        # No matching or policy-length work occurs in the public-budget pass.
        for name in sorted(paths):
            data = source.read_bytes(name)
            fingerprints[name] = hashlib.sha256(data).digest()
            values = [0, 0, 0, 0]
            for text in segments(name, data):
                _within((len(text),), (MAX_LINE_POINTS,))
                # Cheap point/segment refusal before building candidate indexes.
                values[0] += len(text)
                values[1] += 1
                _within(values, file_limits)
                _within([a + b for a, b in zip(totals, values)], aggregate_limits)
                calls, byte_work = work_counts(text, MAX_LENGTH)
                values[2] += calls
                values[3] += byte_work
                _within(values, file_limits)
                _within([a + b for a, b in zip(totals, values)], aggregate_limits)
            totals = [a + b for a, b in zip(totals, values)]
        if inventory(root) != baseline:
            raise InputError('inventory_changed')
    found = False
    with Inputs(root) as source:
        current = os.fstat(source.fd)
        if ((current.st_dev, current.st_ino) != identity or source.paths != paths
                or inventory(root) != baseline):
            raise InputError('inventory_changed')
        for name in sorted(paths):
            data = source.read_bytes(name)
            if hashlib.sha256(data).digest() != fingerprints[name]:
                raise InputError('file_changed')
            for text in segments(name, data):
                for i, j in pruned_candidates(text, prepared, {'examined_pairs': 0}):
                    # Saturate the result, never short-circuit hashing after a hit.
                    digest = term_digest(key, text[i:j])
                    found |= digest in targets[j-i]
        if inventory(root) != baseline:
            raise InputError('inventory_changed')
    return {'schema_version': 1, 'status': 'findings' if found else 'pass'}


def main(argv=None):
    secrets = {key: os.environ.pop(key, None) for key in SENSITIVE_ENV_KEYS}
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise PolicyError()
        parser = Parser(add_help=False)
        parser.add_argument('--root', required=True)
        args = parser.parse_args(argv)
        # Policy parsing and inventory are both covered by the backstop.
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(PolicyError()))
        signal.alarm(30)
        if secrets[LEGACY_ENV] is not None:
            raise PolicyError()
        policy = load_policy(secrets[POLICY_ENV], secrets[KEY_ENV])
        del secrets
        result = scan(Path(args.root), policy)
    except Exception:
        print('{"schema_version":1,"status":"error"}')
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 1 if result['status'] == 'findings' else 0


if __name__ == '__main__':
    sys.exit(main())
