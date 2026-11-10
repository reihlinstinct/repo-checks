"""Synthetic-only digest-work measurements, never a production privacy scanner."""
from __future__ import annotations

from array import array
import bisect
import hashlib
import hmac
import json
import platform
import re
import sys
import time
import unicodedata

WORD = re.compile(r'\w')
LABEL = b'repo-checks/private-names/v1/term\0'
SYNTHETIC_KEY = b'Z' * 32  # Public dummy bytes, never an actual policy key.


def normalize(text):
    return unicodedata.normalize('NFKC', text).casefold()


def admissible(text):
    return (bool(text) and text == text.strip() and any(c.isalpha() for c in text)
            and not any(unicodedata.category(c).startswith('C') for c in text))


def work_counts(text, max_length):
    """Count all public-range candidates and UTF-8 bytes without HMAC matching.

    Endpoint prefix sums avoid enumerating every candidate. Alpha/category-C
    indexes implement the existing term rules; all boundaries are normalized.
    """
    if type(max_length) is not int or max_length < 1:
        raise ValueError()
    n = len(text)
    byte_offsets = array('Q', [0])
    alpha = array('Q')
    controls = array('Q')
    ends = array('Q')
    end_bytes = array('Q', [0])
    for i, c in enumerate(text):
        byte_offsets.append(byte_offsets[-1] + len(c.encode('utf-8')))
        if c.isalpha():
            alpha.append(i)
        if unicodedata.category(c).startswith('C'):
            controls.append(i)
        end = i + 1
        if not c.isspace() and (end == n or WORD.fullmatch(text[end]) is None):
            ends.append(end)
            end_bytes.append(end_bytes[-1] + byte_offsets[-1])
    count = byte_work = 0
    for start, c in enumerate(text):
        if c.isspace() or (start and WORD.fullmatch(text[start - 1]) is not None):
            continue
        ai = bisect.bisect_left(alpha, start)
        if ai == len(alpha):
            continue
        ci = bisect.bisect_left(controls, start)
        upper = min(n, start + max_length, controls[ci] if ci < len(controls) else n)
        lo = bisect.bisect_left(ends, alpha[ai] + 1)
        hi = bisect.bisect_right(ends, upper)
        if hi > lo:
            count += hi - lo
            byte_work += end_bytes[hi] - end_bytes[lo] - (hi - lo) * byte_offsets[start]
    return count, byte_work


def sampled_hash_work(text, lengths, limit=20000):
    """Time bounded synthetic work only. This sample cap is NOT a scan budget."""
    calls = byte_work = 0
    started = time.perf_counter()
    for i in range(len(text)):
        if i and WORD.fullmatch(text[i - 1]) is not None:
            continue
        for length in lengths:
            j = i + length
            if j > len(text) or (j < len(text) and WORD.fullmatch(text[j]) is not None):
                continue
            candidate = text[i:j]
            if not admissible(candidate):
                continue
            encoded = candidate.encode('utf-8')
            hmac.digest(SYNTHETIC_KEY, LABEL + length.to_bytes(4, 'big') + encoded, hashlib.sha256)
            calls += 1
            byte_work += len(encoded)
            if calls == limit:
                return calls, byte_work, time.perf_counter() - started
    return calls, byte_work, time.perf_counter() - started


def expansion_bound():
    maximum = 0
    for point in range(sys.maxunicode + 1):
        maximum = max(maximum, len(normalize(chr(point))))
    return maximum


def main():
    expansion = expansion_bound()
    maximum = 128 * expansion
    print(json.dumps({'kind': 'runtime', 'python': platform.python_version(),
                      'unicode': unicodedata.unidata_version,
                      'max_single_expansion': expansion, 'public_max_length': maximum}))
    patterns = {'short_words': 'a a ', 'punctuated': 'a.a.', 'punctuation_only': '.-! ',
                'prose': 'ZZAlpha met ZZBeta. ZZGamma stayed nearby. ',
                'expansion': '\ufdfa'}
    for corpus, pattern in patterns.items():
        for raw_size in (32768, 2 * 1024 * 1024):
            repetitions = raw_size // len(pattern.encode('utf-8'))
            raw = pattern * repetitions
            started = time.perf_counter()
            text = normalize(raw)
            normalize_seconds = time.perf_counter() - started
            started = time.perf_counter()
            candidates, byte_work = work_counts(text, maximum)
            print(json.dumps({'kind': 'count', 'corpus': corpus, 'raw_bytes': len(raw.encode('utf-8')), 'raw_codepoints': len(raw),
                              'normalized_codepoints': len(text), 'candidates': candidates,
                              'candidate_utf8_bytes': byte_work, 'normalize_seconds': normalize_seconds,
                              'count_seconds': time.perf_counter() - started}), flush=True)
            if raw_size == 32768:
                # Single short/long lengths plus dense and sparse policy length sets.
                for shape, lengths in [('short', [1]), ('long', [maximum]),
                                       ('sparse', [1, 4, 8, 16, 32, 64, 128, 256, 512, maximum]),
                                       ('dense', list(range(1, 257)))]:
                    for repeat in range(3):
                        calls, hashed, seconds = sampled_hash_work(text, lengths)
                        print(json.dumps({'kind': 'hmac_sample', 'corpus': corpus,
                                          'shape': shape, 'repeat': repeat, 'calls': calls,
                                          'utf8_bytes': hashed, 'seconds': seconds}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
