"""Opt-in local hook installation. Refuse replacement or external hook routing."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.inputs import git_output
from repo_checks.sensitive import resolve


def install(root, base):
    root = Path(root).resolve(strict=True)
    resolve(root, base)
    # Read routing from ordinary Git configuration, including global settings.
    # This read-only command executes neither hooks nor candidate scripts.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    result = subprocess.run(['git', '--no-pager', '-c', 'core.fsmonitor=false', 'config', '--get', 'core.hooksPath'], cwd=root, env=env, capture_output=True, timeout=5)
    if result.returncode != 1:  # zero means a route exists; other errors refuse.
        raise ValueError()
    gitdir = Path(os.fsdecode(git_output(root, ['rev-parse', '--absolute-git-dir'], 4096)).strip())
    if not gitdir.is_dir() or gitdir.resolve() != gitdir:
        raise ValueError()
    hooks = gitdir / 'hooks'
    if hooks.is_symlink():
        raise ValueError()
    hooks.mkdir(exist_ok=True)
    target = hooks / 'pre-push'
    snapshot = gitdir / 'repo-checks-sensitive-v1'
    if target.exists() or target.is_symlink() or snapshot.exists() or snapshot.is_symlink():
        raise ValueError()
    source = Path(__file__).resolve().parents[1]
    snapshot.mkdir(mode=0o700)
    try:
        (snapshot / 'src/repo_checks').mkdir(parents=True)
        (snapshot / 'tools').mkdir()
        for name in ('__init__.py', 'sensitive.py', 'inputs.py', 'privacy.py', 'secret_output.py', 'name_hmac_policy.py', 'pseudonymize.py'):
            shutil.copyfile(source / 'src/repo_checks' / name, snapshot / 'src/repo_checks' / name)
        shutil.copyfile(source / 'tools/repo_checks.py', snapshot / 'tools/repo_checks.py')
        # The hook executes a local snapshot, not checked-out candidate code.
        script = '''#!/usr/bin/env python3
import json, re, subprocess, sys
ROOT = %s
COMMAND = %s
BASE = %s
try:
    data = sys.stdin.buffer.read(65537)
    if len(data) > 65536:
        raise ValueError()
    for line in data.decode('ascii').splitlines():
        fields = line.split()
        if len(fields) != 4 or not all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', fields[i]) for i in (1,3)):
            raise ValueError()
        local, remote = fields[1], fields[3]
        if not local.strip('0'):
            continue
        base = remote if remote.strip('0') else BASE
        rc = subprocess.run([sys.executable, '-I', COMMAND, 'sensitive-scan', '--pre-merge', '--root', ROOT, '--base', base, '--head', local]).returncode
        if rc:
            raise ValueError()
except Exception:
    print('{"schema_version":1,"status":"error"}')
    sys.exit(2)
''' % (repr(str(root)), repr(str(snapshot / 'tools/repo_checks.py')), repr(base))
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        with os.fdopen(fd, 'w') as out:
            out.write(script)
    except Exception:
        shutil.rmtree(snapshot)
        raise


def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError()
        install(sys.argv[1], sys.argv[2])
    except Exception:
        print('{"status":"error"}')
        return 2
    print('{"status":"installed"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
