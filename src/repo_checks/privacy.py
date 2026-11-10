"""Bounded, offline tracked-text privacy checks. Never prints matched values.

This is a pattern gate, not proof that a tree contains no private information.
Binary files and names of people need separate review. No automatic baselines,
whole-line exemptions or arbitrary consumer code/configuration are accepted.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
import signal
import sys
from repo_checks.inputs import Inputs, InputError, git_output, MAX_FILE, MAX_TOTAL, MAX_PATHS
from pathlib import Path

VERSION = 1
MAX_FILES = MAX_PATHS
EMAIL_CANDIDATE = re.compile(r"[\w._%+@\-]+", re.UNICODE)
UUID_TOKEN = re.compile(r"(?<![\w-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\w-])")
PHONE = re.compile(r"(?<![\w+])(?:972(?:[\s/–—.()-]{0,3}\d){9}|\+\d(?:[\s/–—.()-]{0,3}\d){7,14}\)?|00\d(?:[\s/–—.()-]{0,3}\d){7,14}\)?|\(?0[2-9](?:[\s/–—.()-]{0,3}\d){7,8}\)?)(?!\w)")
ID = re.compile(r"(?<![\w.\-])\d{9}(?![\w\-]|\.\d)")
SECRET = re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
SENSITIVE = re.compile(r"(?:^|/)(?:creds\.json|credentials\.json|app-state-sync-key[^/]*|session\.(?:json|db)|\.env|id_rsa|id_ed25519)$", re.I)
CATEGORIES = ("email", "phone", "id", "secret", "sensitive_filename")


class ScanError(Exception):
    """Input could not be fully checked within the documented text boundary."""


def checksum(value: str) -> bool:
    """Check a nine-digit Israeli-style identity number without storing it."""
    parts = [int(ch) * (1 + i % 2) for i, ch in enumerate(value)]
    return len(set(value)) > 1 and sum(n if n < 10 else n - 9 for n in parts) % 10 == 0


def fictional_phone(value: str) -> bool:
    """Allow only reserved +999 forms and NANPA 555-0100 through 0199."""
    digits = re.sub(r"\D", "", value)
    if value.startswith("+") and digits.startswith("999"):
        return 8 <= len(digits) <= 15
    if value.startswith("00"):
        digits = digits[2:]
    return len(digits) == 11 and digits.startswith("1") and digits[4:9] == "55501"


def text_categories(text: str) -> set[str]:
    """Return category labels only. Exempt exact safe tokens, never whole lines."""
    found = set()
    for candidate in EMAIL_CANDIDATE.finditer(text):
        token = candidate[0]
        if "@" not in token:
            continue
        if len(token) > 320:
            raise ScanError()
        parts = token.split("@")
        for local, domain in zip(parts, parts[1:]):
            domain = domain.lower().rstrip(".")
            if local and re.fullmatch(r"[\w.\-]+\.[^\W\d_]{2,}", domain, re.UNICODE):
                if domain not in {"example.com", "example.org", "example.net", "users.noreply.github.com", "noreply.github.com"} and not domain.endswith(".invalid"):
                    found.add("email")
    # Canonical whole UUID tokens are identifiers, not phone/ID substrings.
    # Mask only that token; adjacent or same-line PII stays fully scanned.
    number_text = UUID_TOKEN.sub(lambda match: " " * len(match[0]), text)
    if any(not fictional_phone(m[0]) for m in PHONE.finditer(number_text)):
        found.add("phone")
    if any(checksum(m[0]) for m in ID.finditer(number_text)):
        found.add("id")
    if SECRET.search(text):
        found.add("secret")
    return found


def scan(root: Path) -> dict:
    """Read bounded Git-tracked regular UTF8 text, without following symlinks."""
    deadline = time.monotonic() + 15
    counts = {key: 0 for key in CATEGORIES}
    text_files = binary_files = 0
    with Inputs(root) as inputs:
        staged = git_output(root, ["ls-files", "--stage", "-z"])
        for entry in staged.split(b"\0"):
            if not entry:
                continue
            metadata, _ = entry.split(b"\t", 1)
            mode, _, stage = metadata.split()
            if mode not in (b"100644", b"100755") or stage != b"0":
                raise ScanError()
        for name in sorted(inputs.paths):
            if time.monotonic() > deadline:
                raise ScanError()
            data = inputs.read_bytes(name, binary_aware=True)
            found = {"sensitive_filename"} if SENSITIVE.search(name) else set()
            if data is None or b"\0" in data:
                binary_files += 1
            else:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    binary_files += 1
                else:
                    text_files += 1
                    found.update(text_categories(text))
            for category in found:
                counts[category] += 1
    return {"schema_version": VERSION, "status": "findings" if any(counts.values()) else "pass", "counts": counts, "text_files": text_files, "binary_files_unscanned": binary_files}


def main(argv=None) -> int:
    """Emit one fixed-schema counts-only result; errors never echo input."""
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ScanError()
    parser = Parser(add_help=False)
    parser.add_argument("--root", default=".")
    try:
        args = parser.parse_args(argv)
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(ScanError()))
        signal.alarm(30)
        result = scan(Path(args.root))
    except (OSError, ValueError, subprocess.SubprocessError, InputError, ScanError):
        print(json.dumps({"schema_version": VERSION, "status": "error"}))
        return 2
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "findings" else 0


if __name__ == "__main__":
    raise SystemExit(main())
