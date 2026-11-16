"""Isolated action launcher. Inputs and candidate code are never executable."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys


COUNT_KEYS = {'email', 'phone', 'id', 'secret', 'sensitive_filename'}


def validate(value, code):
    if not isinstance(value, dict) or type(code) is not int or code not in (0, 1, 2):
        raise ValueError()
    if code == 2:
        if value != {'schema_version': 1, 'status': 'error'}:
            raise ValueError()
    else:
        if set(value) != {'schema_version', 'status', 'counts', 'text_files', 'binary_files_unscanned'}:
            raise ValueError()
        if type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError()
        counts = value['counts']
        if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
            raise ValueError()
        numbers = [*counts.values(), value['text_files'], value['binary_files_unscanned']]
        if any(type(n) is not int or not 0 <= n <= 20000 for n in numbers):
            raise ValueError()
        if value['text_files'] + value['binary_files_unscanned'] > 20000:
            raise ValueError()
        if value['status'] != {0: 'pass', 1: 'findings'}[code] or bool(any(counts.values())) != bool(code):
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
        from repo_checks.privacy import main as check
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = check(['--root=' + str(root)])
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
