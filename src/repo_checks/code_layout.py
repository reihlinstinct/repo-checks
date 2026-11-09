"""In-file code layout: size cap and section headers for long source files.

Fixed-schema result; findings carry safe paths and line counts only.
Exit codes: 0 pass, 1 findings, 2 error. Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

from repo_checks.inputs import Inputs, InputError

VERSION = 1
SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".kt", ".kts",
                     ".java", ".swift", ".sh", ".bash")
DEFAULT_EXCLUDES = ("vendor/*", "third_party/*", "node_modules/*",
                    "generated/*", "*.min.js", "package-lock.json",
                    "Podfile.lock", "Pods/*")
HEADER = re.compile(r"^\s*(?:#|//)\s*Section:\s*\S", re.IGNORECASE | re.MULTILINE)
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__)/|(^|/)(test_|spec_)|(_test|_spec|\.test|\.spec)\.\w+\Z", re.IGNORECASE)
RULES = ("file_too_long", "missing_section_headers")
MAX_FINDINGS = 200
MIN_LIMIT = 50
MAX_LIMIT = 10_000


class ScanError(Exception):
    """Input could not be fully checked within the documented boundary."""


def _excluded(path: str, patterns: list[str]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(name, p)
               for p in patterns)


def scan(root: Path, max_lines: int = 400, header_threshold: int = 250,
         extra_excludes: tuple[str, ...] = (), max_lines_test: int = 600) -> dict:
    """Read bounded Git-tracked source files, without following symlinks."""
    if not MIN_LIMIT <= header_threshold < max_lines <= MAX_LIMIT or not max_lines <= max_lines_test <= MAX_LIMIT:
        raise ScanError()
    patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes)
    deadline = time.monotonic() + 15
    findings: list[dict] = []
    scanned = skipped = 0
    with Inputs(root) as inputs:
        for name in sorted(inputs.paths):
            if time.monotonic() > deadline:
                raise ScanError()
            if Path(name).suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if _excluded(name, patterns):
                skipped += 1
                continue
            data = inputs.read_bytes(name)
            if b"\0" in data:
                skipped += 1
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue
            scanned += 1
            lines = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            cap = max_lines_test if TEST_PATH.search(name) else max_lines
            if lines > cap and len(findings) < MAX_FINDINGS:
                findings.append({"path": name, "rule": "file_too_long", "lines": lines})
            if lines > header_threshold and not HEADER.search(text) and len(findings) < MAX_FINDINGS:
                findings.append({"path": name, "rule": "missing_section_headers", "lines": lines})
    counts = {rule: sum(1 for f in findings if f["rule"] == rule) for rule in RULES}
    return {"schema_version": VERSION,
            "status": "findings" if findings else "pass",
            "max_lines": max_lines,
            "max_lines_test": max_lines_test,
            "header_threshold": header_threshold,
            "files_scanned": scanned,
            "files_excluded": skipped,
            "counts": counts,
            "findings": findings}


def main(argv=None) -> int:
    """Emit one fixed-schema result; errors never echo input."""
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ScanError()
    parser = Parser(add_help=False)
    parser.add_argument("--root", default=".")
    parser.add_argument("--max-lines", default="400")
    parser.add_argument("--header-threshold", default="250")
    parser.add_argument("--exclude", default="")
    parser.add_argument("--max-lines-test", default="600")
    try:
        args = parser.parse_args(argv)
        max_lines = int(args.max_lines)
        header_threshold = int(args.header_threshold)
        max_lines_test = int(args.max_lines_test)
        extra = tuple(p for p in (x.strip() for x in args.exclude.split(","))
                      if p and len(p) <= 200 and re.fullmatch(r"[\w./?*\-]+", p))[:50]
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(ScanError()))
        signal.alarm(30)
        result = scan(Path(args.root), max_lines, header_threshold, extra, max_lines_test)
    except (OSError, ValueError, subprocess.SubprocessError, InputError, ScanError):
        print(json.dumps({"schema_version": VERSION, "status": "error"}))
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "findings" else 0


if __name__ == "__main__":
    raise SystemExit(main())
