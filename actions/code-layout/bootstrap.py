"""Isolated action launcher. Inputs and candidate code are never executable."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import stat
import sys


RULES = ("file_too_long", "missing_section_headers")
SAFE_PATH = re.compile(r"[\w./\-]{1,200}\Z")


def validate(value, code):
    if not isinstance(value, dict) or type(code) is not int or code not in (0, 1, 2):
        raise ValueError()
    if code == 2:
        if value != {"schema_version": 1, "status": "error"}:
            raise ValueError()
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    keys = {"schema_version", "status", "max_lines", "max_lines_test", "header_threshold",
            "files_scanned", "files_excluded", "counts", "findings"}
    if set(value) != keys:
        raise ValueError()
    if value["schema_version"] != 1 or value["status"] != {0: "pass", 1: "findings"}[code]:
        raise ValueError()
    numbers = [value["max_lines"], value["max_lines_test"], value["header_threshold"],
               value["files_scanned"], value["files_excluded"]]
    if any(type(n) is not int or not 0 <= n <= 20000 for n in numbers):
        raise ValueError()
    if not 50 <= value["header_threshold"] < value["max_lines"] <= 10000:
        raise ValueError()
    if not value["max_lines"] <= value["max_lines_test"] <= 10000:
        raise ValueError()
    counts = value["counts"]
    if not isinstance(counts, dict) or set(counts) != set(RULES):
        raise ValueError()
    if any(type(n) is not int or not 0 <= n <= 20000 for n in counts.values()):
        raise ValueError()
    findings = value["findings"]
    if not isinstance(findings, list) or len(findings) > 200:
        raise ValueError()
    for item in findings:
        if (not isinstance(item, dict) or set(item) != {"path", "rule", "lines"}
                or item["rule"] not in RULES
                or type(item["lines"]) is not int or not 0 <= item["lines"] <= 100000
                or not isinstance(item["path"], str) or not SAFE_PATH.fullmatch(item["path"])):
            raise ValueError()
    if sum(counts.values()) != len(findings) or bool(findings) != bool(code):
        raise ValueError()
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unrelated(a, b):
    return a != b and a not in b.parents and b not in a.parents


def safe_root(value, workspace, action):
    supplied = Path(value)
    if not supplied.is_absolute() or not supplied.is_dir() or supplied.is_symlink():
        raise ValueError()
    resolved = supplied.resolve(strict=True)
    if supplied != resolved or resolved == action or not unrelated(resolved, action):
        raise ValueError()
    resolved.relative_to(workspace)
    return resolved


def _limit(name, lo, hi):
    raw = os.environ.get(name, "")
    if not re.fullmatch(r"\d{1,5}", raw):
        raise ValueError()
    value = int(raw)
    if not lo <= value <= hi:
        raise ValueError()
    return value


def _exclude():
    raw = os.environ.get("CHECK_EXCLUDE", "")
    if len(raw) > 4000 or (raw and not re.fullmatch(r"[\w./?*\-, ]+", raw)):
        raise ValueError()
    return ",".join(p for p in (x.strip() for x in raw.split(",")) if p)


def main():
    try:
        action = Path(__file__).resolve().parent
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        root = safe_root(os.environ["CHECK_ROOT"], workspace, action)
        max_lines = _limit("CHECK_MAX_LINES", 50, 10000)
        threshold = _limit("CHECK_HEADER_THRESHOLD", 50, 9999)
        test_cap = _limit("CHECK_MAX_LINES_TEST", 50, 10000)
        source = action.parents[1] / "src"
        if source.is_symlink() or not source.is_dir() or source.resolve() != source:
            raise ValueError()
        # -I ignores cwd, PYTHONPATH and user-site. Insert only trusted pinned action source.
        sys.path.insert(0, str(source))
        from repo_checks.code_layout import main as check
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = check(["--root=" + str(root),
                          "--max-lines=" + str(max_lines),
                          "--header-threshold=" + str(threshold),
                          "--max-lines-test=" + str(test_cap),
                          "--exclude=" + _exclude()])
        text = output.getvalue()
        if len(text) > 65536:
            raise ValueError()
        record = validate(json.loads(text), code)
        destination = os.environ.get("GITHUB_OUTPUT")
        if destination:
            fd = os.open(destination, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError()
                os.write(fd, ("result=" + record + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        print(record)
        return code
    except Exception:
        print('{"error_category":"action_unavailable","status":"error"}')
        return 2


if __name__ == "__main__":
    sys.exit(main())
