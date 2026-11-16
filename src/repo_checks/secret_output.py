"""Secret-only text boundary for controlled producers, never a secret store."""
from __future__ import annotations

import re

# Shared with repository scanning. Recognition is intentionally format-based.
TOKEN = re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16}')
KEY_HEADER = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
SECRET = re.compile(TOKEN.pattern + '|' + KEY_HEADER.pattern)
KEY_BLOCK = re.compile(r'-----BEGIN (?P<kind>RSA |EC |OPENSSH |)PRIVATE KEY-----.*?(?:-----END (?P=kind)PRIVATE KEY-----|\Z)', re.DOTALL)
MARKER = '[REDACTED_SECRET]'
MAX_BYTES = 2 * 1024 * 1024


class SecretOutputError(Exception):
    """Constant error type with no input in its message."""


def _text(value):
    try:
        if type(value) is not str or len(value.encode('utf-8', errors='strict')) > MAX_BYTES:
            raise SecretOutputError()
        return value
    except Exception:
        raise SecretOutputError() from None


def contains_secret(text):
    return bool(SECRET.search(_text(text)))


def protect_text(text, *, redact=False):
    """Block by default, or redact recognized tokens and complete PEM payloads.

    This must run before any print, logging, transcript save or send. It cannot
    retract bytes an upstream producer already emitted. Unknown/split/encoded
    secrets and binary content are outside this pattern boundary.
    """
    _text(text)
    if type(redact) is not bool:
        raise SecretOutputError()
    if not redact:
        if SECRET.search(text):
            raise SecretOutputError()
        return text
    # Consume the entire key payload, not only its recognizable header. An
    # unterminated block consumes the remainder instead of exposing key bytes.
    text = KEY_BLOCK.sub(MARKER, text)
    text = TOKEN.sub(MARKER, text)
    if SECRET.search(text):
        raise SecretOutputError()
    return text


def protect_json(value, *, redact=False):
    """Return a checked copy of a bounded JSON value, including string keys.

    Reject cycles, non-JSON values, excessive nesting and redacted key collisions.
    No partial result is returned when any part fails.
    """
    import json
    try:
        # Validate the full size before constructing a recursive copy.
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        _text(encoded)
        def visit(item, depth=0):
            if depth > 64:
                raise SecretOutputError()
            if type(item) is str:
                return protect_text(item, redact=redact)
            if item is None or type(item) in (bool, int, float):
                return item
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            if type(item) is dict and all(type(key) is str for key in item):
                result = {}
                for key, child in item.items():
                    checked = protect_text(key, redact=redact)
                    if checked in result:
                        raise SecretOutputError()
                    result[checked] = visit(child, depth + 1)
                return result
            raise SecretOutputError()
        return visit(value)
    except Exception:
        raise SecretOutputError() from None


def main(argv=None):
    """Bounded stdin to stdout; default block, explicit --redact replacement."""
    import argparse
    import sys
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise SecretOutputError()
        parser = Parser(add_help=False)
        parser.add_argument('--redact', action='store_true')
        args = parser.parse_args(argv)
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise SecretOutputError()
        result = protect_text(data.decode('utf-8', errors='strict'), redact=args.redact)
        # All validation completes before any input-derived output is emitted.
        import os
        remaining = memoryview(result.encode('utf-8'))
        while remaining:
            written = os.write(sys.stdout.fileno(), remaining)
            if written <= 0:
                raise SecretOutputError()
            remaining = remaining[written:]
        return 0
    except Exception:
        print('Secret output refused or unavailable', file=sys.stderr)
        return 2
