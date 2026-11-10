"""Trusted secret-sourced name gate. Never emit policy values or source excerpts."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys
import unicodedata

from repo_checks.inputs import Inputs, InputError, git_output

ENV_KEY = "PRIVATE_NAME_TERMS_JSON"
MAX_TERMS = 256
MAX_FINDINGS = 1000


class PolicyError(Exception):
    """Fixed, value-free policy refusal."""


def normalize(text):
    return unicodedata.normalize("NFKC", text).casefold()


def load_policy(raw):
    if not isinstance(raw, str) or not 0 < len(raw) <= 32768:
        raise PolicyError()
    values = json.loads(raw)
    if not isinstance(values, list) or not 0 < len(values) <= MAX_TERMS:
        raise PolicyError()
    terms = set()
    for value in values:
        if type(value) is not str or not 2 <= len(value) <= 128:
            raise PolicyError()
        value = normalize(value)
        if value != value.strip() or not any(c.isalpha() for c in value):
            raise PolicyError()
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise PolicyError()
        terms.add(value)
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t in sorted(terms)) + r")(?!\w)")


def scan(root, pattern):
    findings = text_files = 0
    with Inputs(root) as inputs:
        staged = git_output(root, ["ls-files", "--stage", "-z"])
        for entry in staged.split(b"\0"):
            if not entry:
                continue
            metadata, _ = entry.split(b"\t", 1)
            mode, _, stage = metadata.split()
            if mode not in (b"100644", b"100755") or stage != b"0":
                raise InputError("invalid_inventory")
        for name in sorted(inputs.paths):
            findings += bool(pattern.search(normalize(name)))
            data = inputs.read_bytes(name)
            # No binary/encoding bypass: uncertain content is never certified.
            if b"\0" in data:
                raise InputError("unscannable_content")
            text = data.decode("utf-8", errors="strict")
            text_files += 1
            findings += sum(bool(pattern.search(normalize(line))) for line in text.splitlines())
            if findings > MAX_FINDINGS:
                raise PolicyError()
    return {"schema_version": 1, "status": "findings" if findings else "pass",
            "findings": findings, "text_files": text_files,
            "binary_files_unscanned": 0}


def main(argv=None):
    # Remove before even the first inventory subprocess. No child receives it.
    raw = os.environ.pop(ENV_KEY, None)
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise PolicyError()
        parser = Parser(add_help=False)
        parser.add_argument("--root", required=True)
        args = parser.parse_args(argv)
        pattern = load_policy(raw)
        del raw
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(PolicyError()))
        signal.alarm(30)
        result = scan(Path(args.root), pattern)
    except Exception:
        # Neither traceback, input, error message, path nor policy is exposed.
        print('{"schema_version":1,"status":"error"}')
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 1 if result["status"] == "findings" else 0


if __name__ == "__main__":
    sys.exit(main())
