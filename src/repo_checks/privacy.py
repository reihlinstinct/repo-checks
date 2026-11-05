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
from pathlib import Path

VERSION = 1
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 30000
EMAIL = re.compile(r"(?<![\w@])([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?![\w@])")
PHONE = re.compile(r"(?<![\w+])(?:\+\d(?:[ .()-]?\d){7,14}|00\d(?:[ .()-]?\d){7,14}|0[2-9](?:[ .()-]?\d){7,8})(?!\w)")
ID = re.compile(r"(?<![\w.\-])\d{9}(?![\w.\-])")
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
    for match in EMAIL.finditer(text):
        domain = match[2].lower()
        if domain not in {"example.com", "example.org", "example.net", "users.noreply.github.com", "noreply.github.com"} and not domain.endswith(".invalid"):
            found.add("email")
    if any(not fictional_phone(m[0]) for m in PHONE.finditer(text)):
        found.add("phone")
    if any(checksum(m[0]) for m in ID.finditer(text)):
        found.add("id")
    if SECRET.search(text):
        found.add("secret")
    return found


def scan(root: Path) -> dict:
    """Read bounded Git-tracked regular UTF8 text, without following symlinks."""
    root = root.resolve(strict=True)
    proc = subprocess.run(["git", "-C", str(root), "ls-files", "--stage", "-z"], capture_output=True, timeout=20, check=False)
    if proc.returncode:
        raise ScanError()
    entries = [e for e in proc.stdout.split(b"\0") if e]
    if len(entries) > MAX_FILES:
        raise ScanError()
    counts = {key: 0 for key in CATEGORIES}
    text_files = binary_files = total = 0
    for entry in entries:
        metadata, raw_name = entry.split(b"\t", 1)
        mode, _, stage = metadata.split()
        if mode not in (b"100644", b"100755") or stage != b"0":
            raise ScanError()  # symlinks, submodules and unresolved entries fail closed
        name = raw_name.decode("utf-8", errors="strict")
        path = root / name
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
            raise ScanError()
        if path.stat().st_size > MAX_FILE:
            raise ScanError()
        data = path.read_bytes()
        total += len(data)
        if len(data) > MAX_FILE or total > MAX_TOTAL:
            raise ScanError()
        found = {"sensitive_filename"} if SENSITIVE.search(name) else set()
        if b"\0" in data:
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


def main() -> int:
    """Emit one fixed-schema counts-only result; errors never echo input."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    try:
        result = scan(Path(args.root))
    except (OSError, ValueError, subprocess.SubprocessError, ScanError):
        print(json.dumps({"schema_version": VERSION, "status": "error"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "findings" else 0


if __name__ == "__main__":
    raise SystemExit(main())
