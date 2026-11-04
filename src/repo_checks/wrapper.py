"""Counts-only public interface. Never print candidate paths, values or exceptions."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import urlsplit

from .inputs import Inputs, InputError, valid_path
from . import scorecard as engine

MAX_FINDINGS = 1000
MAX_POLICY = 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError('invalid_policy')
        result[key] = value
    return result


def document(text):
    try:
        return json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise InputError('invalid_policy') from None


def baseline(value):
    if not isinstance(value, dict) or set(value) != {'version', 'findings'} or type(value['version']) is not int or value['version'] != 1:
        raise InputError('invalid_baseline')
    entries = value['findings']
    if not isinstance(entries, list) or len(entries) > MAX_FINDINGS:
        raise InputError('invalid_baseline')
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'path', 'rule', 'scope', 'evidence', 'issue', 'reason'}:
            raise InputError('invalid_baseline')
        if any(not isinstance(x, str) or not x or len(x) > 8192 for x in entry.values()):
            raise InputError('invalid_baseline')
        valid_path(entry['path'])
        link = urlsplit(entry['issue'])
        if link.scheme != 'https' or not link.hostname or link.username or link.password:
            raise InputError('invalid_baseline')
    return value


def selected(name):
    p = PurePosixPath(name)
    if any(x in {'.git', '.venv', 'venv', 'node_modules', 'vendor', 'build', 'dist'} for x in p.parts):
        return False
    return ((len(p.parts) == 3 and p.parts[:2] == ('.github', 'workflows') and p.suffix in ('.yml', '.yaml'))
            or p.name.startswith('Dockerfile') or p.suffix == '.dockerfile'
            or (p.suffix == '.sh' and 'scripts' in p.parts))


def scan(inputs):
    findings = []
    def add(items):
        for finding in items:
            if len(findings) >= MAX_FINDINGS:
                raise InputError('findings_limit')
            findings.append(finding)
    for path in sorted(inputs.paths):
        if not selected(path):
            continue
        text = inputs.read(path)
        add(engine.scan_text(path, text))
        joined = re.sub(r'\\\s*\n\s*', ' ', text)
        for line in joined.splitlines():
            if line.lstrip().startswith('#'):
                continue
            for req in engine.requirement_refs(line):
                if '$' in req:
                    raise InputError('invalid_requirement_path')
                valid_path(req)
                if req not in inputs.paths:
                    add([engine.Finding(path, 'requirements-missing', 'dependencies', req)])
                    continue
                content = re.sub(r'\\\s*\n\s*', ' ', inputs.read(req))
                for requirement in content.splitlines():
                    requirement = requirement.strip()
                    if not requirement or requirement.startswith('#'):
                        continue
                    if not re.match(r'^[A-Za-z0-9_.-]+(?:\[[\w,.-]+\])?==[^\s;]+', requirement) or not re.search(r'--hash=sha256:[a-f0-9]{64}(?:\s|$)', requirement):
                        add([engine.Finding(req, 'unhashed-requirement', 'dependencies', requirement)])
    return list(dict.fromkeys(findings))


def check(root, policy_path):
    valid_path(policy_path)
    with Inputs(root) as inputs:
        policy = document(inputs.read(policy_path, cap=MAX_POLICY))
        if not isinstance(policy, dict) or set(policy) != {'version', 'checks'} or type(policy['version']) is not int or policy['version'] != 1:
            raise InputError('invalid_policy')
        checks = policy['checks']
        if not isinstance(checks, dict) or set(checks) != {'scorecard'}:
            raise InputError('invalid_policy')
        config = checks['scorecard']
        if not isinstance(config, dict) or set(config) != {'baseline'} or not isinstance(config['baseline'], str):
            raise InputError('invalid_policy')
        valid_path(config['baseline'])
        allowed = baseline(document(inputs.read(config['baseline'], cap=MAX_POLICY)))
        findings = scan(inputs)
        try:
            new, stale = engine.evaluate(findings, allowed)
        except (ValueError, KeyError, TypeError):
            raise InputError('invalid_baseline') from None
        return len(findings), len(new), len(stale)


def main(argv=None):
    result = {'schema_version': 1, 'check_id': 'scorecard', 'engine_version': '0.1.0',
              'status': 'error', 'counts': {'current': 0, 'new': 0, 'stale': 0}, 'error_category': None}
    code = 2
    # argparse and all internal diagnostics stay private; emit one controlled record only.
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument('--root', required=True, type=Path)
            parser.add_argument('--policy', default='.repo-checks.json')
            args = parser.parse_args(argv)
            current, new, stale = check(args.root, args.policy)
        result['counts'] = {'current': current, 'new': new, 'stale': stale}
        code = int(bool(new or stale))
        result['status'] = 'fail' if code else 'pass'
    except InputError:
        result['error_category'] = 'input_unavailable_or_invalid'
    except (Exception, SystemExit):
        result['error_category'] = 'check_unavailable'
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
