"""Run only trusted source; candidate files are inert input."""
import os
from pathlib import Path
import sys


def main():
    try:
        action = Path(__file__).resolve().parent
        workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        root = Path(os.environ['CHECK_ROOT'])
        resolved = root.resolve(strict=True)
        if not root.is_absolute() or root != resolved or not root.is_dir():
            raise ValueError()
        resolved.relative_to(workspace)
        if root == action or root in action.parents or action in root.parents:
            raise ValueError()
        source = action.parents[1] / 'src'
        if source.is_symlink() or not source.is_dir() or source.resolve() != source:
            raise ValueError()
        sys.path.insert(0, str(source))
        from repo_checks.secret_scan import main as check
        return check(['--root=' + str(root)])
    except Exception:
        for key in ('PRIVATE_NAME_TERMS_JSON', 'PRIVATE_NAME_HMAC_POLICY_JSON', 'PRIVATE_NAME_HMAC_KEY_B64'):
            os.environ.pop(key, None)
        print('{"schema_version":1,"status":"error"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
