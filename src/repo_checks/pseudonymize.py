"""Explicit typed pseudonyms. Local key only; no automatic name discovery."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import unicodedata


class MaskError(Exception):
    """Value-free refusal."""


def key_path(path, root):
    path = Path(path).absolute()
    root = Path(root).resolve(strict=True)
    # Refuse symlinked parents and repository-local keys, including .git.
    if path.parent.resolve(strict=True) != path.parent or path.is_relative_to(root):
        raise MaskError()
    return path


def create_key(path, root):
    path = key_path(path, root)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = secrets.token_bytes(32)
        if os.write(fd, data) != len(data):
            raise MaskError()
        os.fsync(fd)
    finally:
        os.close(fd)


def load_key(path, root):
    path = key_path(path, root)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise MaskError()
        data = os.read(fd, 33)
        if len(data) != 32:
            raise MaskError()
        return data
    finally:
        os.close(fd)


def pseudonym(kind, value, key):
    if type(key) is not bytes or len(key) != 32 or type(value) is not str or not value or len(value.encode('utf-8')) > 4096:
        raise MaskError()
    if kind == 'name':
        value = ' '.join(unicodedata.normalize('NFC', value).casefold().split())
    elif kind == 'id':
        if not re.fullmatch(r'[0-9]{9}', value):
            raise MaskError()
    elif kind == 'phone':
        value = re.sub(r'[ .()/-]', '', value)
        if re.fullmatch(r'05[0-9]{8}', value):
            value = '+972' + value[1:]
        elif not re.fullmatch(r'\+9725[0-9]{8}', value):
            raise MaskError()
    else:
        raise MaskError()
    if not value:
        raise MaskError()
    digest = hmac.new(key, b'repo-checks:pseudonym:v1\0' + kind.encode() + b'\0' + value.encode(), hashlib.sha256).digest()
    # Letters only: output cannot resemble a phone, ID, email or provider token.
    alphabet = 'abcdefghijklmnop'
    encoded = ''.join(alphabet[b >> 4] + alphabet[b & 15] for b in digest)
    return 'ZZ_' + kind.upper() + '_' + encoded


def main(argv=None):
    import argparse
    try:
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise MaskError()
        parser = Parser(add_help=False)
        parser.add_argument('--key-file', required=True)
        parser.add_argument('--root', default='.')
        parser.add_argument('--create-key', action='store_true')
        args = parser.parse_args(argv)
        if args.create_key:
            create_key(args.key_file, args.root)
            print('{"status":"key-created"}')
            return 0
        key = load_key(args.key_file, args.root)
        data = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise MaskError()
        value = json.loads(data.decode('utf-8'))
        if type(value) is not list or len(value) > 10000:
            raise MaskError()
        result = []
        for item in value:
            if type(item) is not dict or set(item) != {'kind', 'value'}:
                raise MaskError()
            result.append(pseudonym(item['kind'], item['value'], key))
        # The entire request validates before any output; never emit originals.
        print(json.dumps(result))
        return 0
    except Exception:
        print('{"status":"error"}')
        return 2
