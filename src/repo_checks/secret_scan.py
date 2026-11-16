"""Blocking secret-only tracked-text check, with fixed public output."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import sys

from repo_checks.inputs import Inputs, InputError
from repo_checks.private_names import inventory
from repo_checks.secret_output import SECRET


def scan(root):
    found = False
    with Inputs(root) as source:
        baseline = inventory(root)
        for name in sorted(source.paths):
            data = source.read_bytes(name)
            # This lane explicitly checks text, not binary privacy certification.
            # File/inventory budgets still apply before any binary classification.
            if b'\0' in data:
                continue
            try:
                text = data.decode('utf-8', errors='strict')
            except UnicodeError:
                continue
            found |= bool(SECRET.search(text))
        if inventory(root) != baseline:
            raise InputError('inventory_changed')
    return {'schema_version': 1, 'status': 'findings' if found else 'pass'}


def main(argv=None):
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise InputError('arguments')
        parser = Parser(add_help=False)
        parser.add_argument('--root', required=True)
        args = parser.parse_args(argv)
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(InputError('timeout')))
        signal.alarm(30)
        result = scan(Path(args.root))
    except Exception:
        print('{"schema_version":1,"status":"error"}')
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 1 if result['status'] == 'findings' else 0


if __name__ == '__main__':
    sys.exit(main())
