"""Isolated action launcher. Inputs and candidate code are never executable."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys


CATEGORIES = {None, 'input_unavailable_or_invalid', 'check_unavailable'}


def validate(value, code):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'check_id', 'engine_version', 'status', 'counts', 'error_category'}:
        raise ValueError()
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['check_id'] != 'scorecard' or value['engine_version'] != '0.1.0':
        raise ValueError()
    if code not in (0, 1, 2) or type(code) is not int or value['status'] != {0:'pass',1:'fail',2:'error'}[code]:
        raise ValueError()
    counts = value['counts']
    if not isinstance(counts, dict) or set(counts) != {'current', 'new', 'stale'}:
        raise ValueError()
    if any(type(x) is not int or not 0 <= x <= 1000 for x in counts.values()):
        raise ValueError()
    if counts['new'] > counts['current'] or value['error_category'] not in CATEGORIES:
        raise ValueError()
    if code == 0 and (counts['new'] or counts['stale'] or value['error_category'] is not None):
        raise ValueError()
    if code == 1 and (not (counts['new'] or counts['stale']) or value['error_category'] is not None):
        raise ValueError()
    if code == 2 and (value['error_category'] is None or any(counts.values())):
        raise ValueError()
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def unrelated(a, b):
    return a != b and a not in b.parents and b not in a.parents


def safe_root(value, workspace, action):
    supplied = Path(value)
    if not supplied.is_absolute() or not supplied.is_dir() or supplied.is_symlink():
        raise ValueError()
    resolved = supplied.resolve(strict=True)
    # Reject lexical aliases and all symlink ancestors, not only final symlink.
    if supplied != resolved or resolved == action or not unrelated(resolved, action):
        raise ValueError()
    resolved.relative_to(workspace)
    return resolved


def main():
    try:
        action = Path(__file__).resolve().parent
        workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        root = safe_root(os.environ['CHECK_ROOT'], workspace, action)
        source = action.parents[1] / 'src'
        if source.is_symlink() or not source.is_dir() or source.resolve() != source:
            raise ValueError()
        # -I ignores cwd, PYTHONPATH and user-site. Insert only trusted pinned action source.
        sys.path.insert(0, str(source))
        from repo_checks.wrapper import main as check
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = check(['--root=' + str(root), '--policy=' + os.environ['CHECK_POLICY']])
        text = output.getvalue()
        if len(text) > 2048:
            raise ValueError()
        record = validate(json.loads(text), code)
        destination = os.environ.get('GITHUB_OUTPUT')
        if destination:
            fd = os.open(destination, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError()
                os.write(fd, ('result=' + record + '\n').encode('utf-8'))
            finally:
                os.close(fd)
        print(record)
        return code
    except Exception:
        print('{"error_category":"action_unavailable","status":"error"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
