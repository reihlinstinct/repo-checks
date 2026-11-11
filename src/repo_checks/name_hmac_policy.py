"""Authenticated keyed policy. Never serialize actual policies in this module."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unicodedata

LEGACY_ENV = 'PRIVATE_NAME_TERMS_JSON'
POLICY_ENV = 'PRIVATE_NAME_HMAC_POLICY_JSON'
KEY_ENV = 'PRIVATE_NAME_HMAC_KEY_B64'
SENSITIVE_ENV_KEYS = (LEGACY_ENV, POLICY_ENV, KEY_ENV)
SCHEMA = 'repo-checks.private-names.hmac/v1'
TERM_LABEL = b'repo-checks/private-names/v1/term\0'
POLICY_LABEL = b'repo-checks/private-names/v1/policy\0'
MAX_LENGTH = 64
MAX_TERMS = 256


class PolicyError(Exception):
    """Value-free refusal, including malformed or unauthenticated policies."""


def normalize(text):
    return unicodedata.normalize('NFKC', text).casefold()


def validate_term(raw):
    """Shared converter contract only; this function performs no conversion."""
    if type(raw) is not str or not 2 <= len(raw) <= 128:
        raise PolicyError()
    text = normalize(raw)
    if (not 1 <= len(text) <= MAX_LENGTH or text != text.strip()
            or not any(c.isalpha() for c in text)
            or any(unicodedata.category(c).startswith('C') for c in text)):
        raise PolicyError()
    return text


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def term_digest(key, text):
    return hmac.digest(key, TERM_LABEL + len(text).to_bytes(4, 'big')
                       + text.encode('utf-8'), hashlib.sha256)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError()
        result[key] = value
    return result


def _hex(value):
    return (type(value) is str and len(value) == 64
            and all(c in '0123456789abcdef' for c in value))


def load_policy(raw, encoded_key):
    if (type(raw) is not str or not 0 < len(raw) <= 32768
            or type(encoded_key) is not str or len(encoded_key) != 44):
        raise PolicyError()
    key = base64.b64decode(encoded_key, validate=True)
    if len(key) != 32 or base64.b64encode(key).decode('ascii') != encoded_key:
        raise PolicyError()
    value = json.loads(raw, object_pairs_hook=_object)
    if type(value) is not dict or set(value) != {'schema', 'unicode_version', 'entries', 'policy_mac'}:
        raise PolicyError()
    if not _hex(value['policy_mac']):
        raise PolicyError()
    signed = {k: v for k, v in value.items() if k != 'policy_mac'}
    expected = hmac.digest(key, POLICY_LABEL + canonical(signed), hashlib.sha256)
    if not hmac.compare_digest(expected, bytes.fromhex(value['policy_mac'])):
        raise PolicyError()
    # No policy field steers inventory or matching until authentication succeeds.
    if value['schema'] != SCHEMA or value['unicode_version'] != unicodedata.unidata_version:
        raise PolicyError()
    entries = value['entries']
    if type(entries) is not list or not 1 <= len(entries) <= MAX_TERMS:
        raise PolicyError()
    previous = ''
    targets = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'length', 'digest'}:
            raise PolicyError()
        length, digest = entry['length'], entry['digest']
        if type(length) is not int or not 1 <= length <= MAX_LENGTH or not _hex(digest):
            raise PolicyError()
        if digest <= previous:
            raise PolicyError()
        previous = digest
        targets.setdefault(length, set()).add(bytes.fromhex(digest))
    return key, {length: frozenset(values) for length, values in targets.items()}
