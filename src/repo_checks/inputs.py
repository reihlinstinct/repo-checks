"""Bounded read-only Git inventory. Candidate code and config are never executed."""
from __future__ import annotations

import os
from pathlib import Path
import select
import stat
import subprocess
import time


class InputError(Exception):
    """Fixed, value-free input refusal."""


MAX_PATHS = 20_000
MAX_INVENTORY = 4 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def git_output(root: Path, args: list[str], cap: int = MAX_INVENTORY) -> bytes:
    # Do not inherit repository routing, external diff/pager or injected config.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k != 'PRIVATE_NAME_TERMS_JSON'}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0')
    command = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull,
               '-c', 'core.pager=cat', '-c', 'core.untrackedCache=false',
               '-c', 'core.sshCommand=false', '--no-pager', *args]
    try:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except OSError:
        raise InputError('inventory_unavailable') from None
    assert process.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + 10
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InputError('inventory_timeout')
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                raise InputError('inventory_timeout')
            chunk = os.read(process.stdout.fileno(), min(65536, cap + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > cap:
                raise InputError('inventory_limit')
        if process.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
            raise InputError('inventory_unavailable')
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired):
        raise InputError('inventory_unavailable') from None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def valid_path(path: str) -> list[str]:
    parts = path.split('/')
    if not path or '\\' in path or any(p in ('', '.', '..') for p in parts) or '\x00' in path:
        raise InputError('invalid_path')
    return parts


class Inputs:
    """Own one root descriptor; every file read walks relative directory FDs."""
    def __init__(self, root: Path):
        self.root = root
        self.total = 0
        self.fd: int | None = None
        self.paths: frozenset[str] = frozenset()

    def __enter__(self):
        if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
            raise InputError('secure_open_unavailable')
        try:
            self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            root_stat = os.fstat(self.fd)
            top = git_output(self.root, ['rev-parse', '--show-toplevel'], 4096)
            # Git emits a terminal LF, not a path delimiter in this command.
            top_path = Path(os.fsdecode(top[:-1] if top.endswith(b'\n') else top))
            current = os.stat(top_path, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (root_stat.st_dev, root_stat.st_ino):
                raise InputError('not_repository_root')
            raw = git_output(self.root, ['ls-files', '-z', '--cached'])
            if raw and not raw.endswith(b'\x00'):
                raise InputError('invalid_inventory')
            names = raw[:-1].split(b'\x00') if raw else []
            if len(names) > MAX_PATHS:
                raise InputError('inventory_limit')
            decoded = [x.decode('utf-8', errors='strict') for x in names]
            for name in decoded:
                valid_path(name)
            if len(set(decoded)) != len(decoded):
                raise InputError('duplicate_inventory')
            self.paths = frozenset(decoded)
            return self
        except InputError:
            self.close()
            raise
        except (OSError, ValueError, UnicodeError):
            self.close()
            raise InputError('inventory_unavailable') from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __exit__(self, *_):
        self.close()

    def read_bytes(self, path: str, cap: int = MAX_FILE) -> bytes:
        parts = valid_path(path)
        if self.fd is None or path not in self.paths or not 0 < cap <= MAX_FILE:
            raise InputError('untracked_or_closed')
        directory = os.dup(self.fd)
        handle = None
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            handle = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(handle)
            if not stat.S_ISREG(before.st_mode):
                raise InputError('not_regular_file')
            # A binary marker never waives file or aggregate byte limits.
            if before.st_size > cap or self.total + before.st_size > MAX_TOTAL:
                raise InputError('file_limit')
            data = bytearray()
            while True:
                chunk = os.read(handle, min(65536, cap + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > cap or self.total + len(data) > MAX_TOTAL:
                    raise InputError('file_limit')
            after = os.fstat(handle)
            linked = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(linked):
                raise InputError('file_changed')
            self.total += len(data)
            return bytes(data)
        except InputError:
            raise
        except (OSError, UnicodeError):
            raise InputError('file_unavailable') from None
        finally:
            if handle is not None:
                os.close(handle)
            os.close(directory)

    def read(self, path: str, cap: int = MAX_FILE) -> str:
        try:
            return self.read_bytes(path, cap).decode('utf-8', errors='strict')
        except UnicodeError:
            raise InputError('file_unavailable') from None
