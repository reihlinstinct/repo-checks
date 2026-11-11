"""Offline committed-diff boundary. No matched values enter the report."""
from __future__ import annotations

import argparse
import json
import re
import signal
import time
from pathlib import Path

from repo_checks.inputs import git_output, InputError, MAX_FILE, MAX_TOTAL, MAX_PATHS
from repo_checks.privacy import EMAIL_CANDIDATE, UUID_TOKEN, checksum, fictional_phone
from repo_checks.secret_output import SECRET

ID = re.compile(r'(?<![\w.\-])[0-9]{9}(?![\w\-]|\.[0-9])')
PHONE = re.compile(r'(?<![\w+])(?:05[0-9](?:[ .()/-]?[0-9]){7}|\+972[ .()/-]?5[0-9](?:[ .()/-]?[0-9]){7})(?!\w)')
ASSIGNMENT = re.compile(r'''(?ix)(?<!\w)["']?(?:password|passwd|pwd)["']?\s*[:=]\s*(?:["']([^"'\r\n]+)["']|([^\s,"';#}\]]+))''')
CATEGORIES = ('id', 'phone', 'email', 'password', 'secret')
RESERVED = {'example.com', 'example.net', 'example.org', 'test', 'invalid', 'localhost'}
FIXTURE_DIRS = {'fixtures', 'fixture', 'testdata', 'test-data', '__fixtures__'}


def categories(text):
    found = set()
    numbers = UUID_TOKEN.sub(lambda m: ' ' * len(m[0]), text)
    if any(checksum(m[0]) for m in ID.finditer(numbers)):
        found.add('id')
    if any(not fictional_phone(m[0]) for m in PHONE.finditer(numbers)):
        found.add('phone')
    for match in EMAIL_CANDIDATE.finditer(text):
        token = match[0]
        if len(token) > 320 and '@' in token:
            raise InputError('email_limit')
        parts = token.split('@')
        for local, domain in zip(parts, parts[1:]):
            domain = domain.lower().rstrip('.')
            if local and re.fullmatch(r'[\w.\-]+\.[^\W\d_]{2,}', domain):
                if domain not in RESERVED and not any(domain.endswith('.' + suffix) for suffix in RESERVED):
                    found.add('email')
    # No arbitrary dummy-looking password exceptions. Empty values are safe;
    # placeholders/assignments with non-empty values are intentionally flagged.
    if ASSIGNMENT.search(text):
        found.add('password')
    if SECRET.search(text):
        found.add('secret')
    return found


def resolve(root, ref):
    if not ref or ref.startswith('-') or len(ref) > 256:
        raise InputError('ref')
    value = git_output(root, ['rev-parse', '--verify', ref + '^{commit}'], 256).strip().decode('ascii')
    if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', value):
        raise InputError('ref')
    return value


def scan_tree(root, ancestor, after):
    root = Path(root)
    deadline = time.monotonic() + 25
    raw = git_output(root, ['ls-tree', '-r', '-z', '--full-tree', after])
    entries = {}
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, kind, oid = meta.split()
        path = name.decode('utf-8', errors='strict')
        if not path or any(p in ('', '.', '..') for p in path.split('/')) or '\\' in path:
            raise InputError('path')
        entries[path] = (mode, kind, oid.decode('ascii'))
    if len(entries) > MAX_PATHS:
        raise InputError('paths')
    changed = git_output(root, ['diff', '--no-ext-diff', '--no-textconv', '--name-only', '-z', '--no-renames', '--diff-filter=ACMRT', ancestor, after]).split(b'\0')
    changed = {p.decode('utf-8', errors='strict') for p in changed if p}
    fixtures = {p for p in entries if any(part.lower() in FIXTURE_DIRS for part in p.split('/')[:-1])}
    selected = changed | fixtures
    counts = dict.fromkeys(CATEGORIES, 0)
    locations = []
    total = 0
    for index, path in enumerate(sorted(selected), 1):
        if time.monotonic() > deadline:
            raise InputError("timeout")
        mode, kind, oid = entries[path]
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise InputError('nontext')
        data = git_output(root, ['cat-file', 'blob', oid], MAX_FILE)
        total += len(data)
        if total > MAX_TOTAL or b'\0' in data:
            raise InputError('content')
        text = data.decode('utf-8', errors='strict')
        # A pathname is itself output-bearing. Withhold suspicious/nonportable
        # paths instead of allowing a token or control character into diagnostics.
        path_findings = categories(path)
        display = path if not path_findings and re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', path) else '[withheld-path-' + str(index) + ']'
        findings = [(0, path_findings)] if path_findings else []
        if path in fixtures:
            findings.extend((n, categories(line)) for n, line in enumerate(text.splitlines(), 1))
        else:
            patch = git_output(root, ['-c', 'core.quotePath=true', 'diff', '--no-ext-diff', '--no-textconv', '--no-color', '--text', '--unified=0', '--no-renames', ancestor, after, '--', path], 2 * MAX_FILE)
            line_number = None
            for line in patch.decode('utf-8', errors='strict').splitlines():
                hunk = re.match(r'^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@', line)
                if hunk:
                    line_number = int(hunk[1])
                elif line_number is not None and line.startswith('+'):
                    findings.append((line_number, categories(line[1:])))
                    line_number += 1
                elif line_number is not None and line.startswith(' '):
                    line_number += 1
        for number, found in findings:
            for category in sorted(found):
                counts[category] += 1
                if len(locations) >= 10000:
                    raise InputError('report_limit')
                locations.append({'file': display, 'line': number, 'category': category})
    # Immutable objects, resolved commit hashes and no worktree reads. A moving
    # ref cannot change which content was scanned or smuggle unchecked bytes in.
    return {'schema_version': 1, 'status': 'findings' if locations else 'pass', 'counts': counts, 'locations': locations}


def scan(root, base='origin/main', head='HEAD'):
    root = Path(root)
    before, after = resolve(root, base), resolve(root, head)
    ancestor = git_output(root, ['merge-base', before, after], 256).strip().decode('ascii')
    if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', ancestor):
        raise InputError('base')
    commits = git_output(root, ['rev-list', '--reverse', ancestor + '..' + after], 65536).decode('ascii').splitlines()
    if len(commits) > 256:
        raise InputError('commit_limit')
    locations = {}
    # Inspect every introduced commit, not only the final tree. A secret added
    # then removed before push remains in history and must still block.
    for commit in commits:
        parents = git_output(root, ['rev-list', '--parents', '-n', '1', commit], 512).decode('ascii').split()
        if len(parents) < 2:
            raise InputError('parents')
        result = scan_tree(root, parents[1], commit)
        for item in result['locations']:
            locations[(item['file'], item['line'], item['category'])] = item
        if len(locations) > 10000:
            raise InputError('report_limit')
    if not commits:
        result = scan_tree(root, after, after)
        locations = {(i['file'], i['line'], i['category']): i for i in result['locations']}
    counts = dict.fromkeys(CATEGORIES, 0)
    for item in locations.values():
        counts[item['category']] += 1
    return {'schema_version': 1, 'status': 'findings' if locations else 'pass', 'counts': counts, 'locations': list(locations.values())}


def main(argv=None):
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise InputError('arguments')
        parser = Parser(add_help=False)
        parser.add_argument('--root', default='.')
        parser.add_argument('--base', default='origin/main')
        parser.add_argument('--head', default='HEAD')
        parser.add_argument('--pre-merge', action='store_true', required=True)
        args = parser.parse_args(argv)
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(InputError("timeout")))
        signal.alarm(30)
        result = scan(Path(args.root), args.base, args.head)
    except Exception:
        print('{"schema_version":1,"status":"error"}')
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return int(result['status'] == 'findings')
