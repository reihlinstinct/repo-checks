"""Synthetic complete pruned passes and aggregate read/decode measurements only."""
from array import array
import bisect
import hashlib
import hmac
import json
import platform
from pathlib import Path
import statistics
import tempfile
import time
import unicodedata

from repo_checks import hmac_benchmark as base


def pruned_candidates(text, lengths, stats):
    """Reuse admissibility indexes; examined pairs never exceed public count."""
    lengths = sorted(set(lengths))
    if not lengths or any(type(n) is not int or n < 1 for n in lengths):
        raise ValueError()
    alpha, controls, ends = array('Q'), array('Q'), array('Q')
    for i, c in enumerate(text):
        if c.isalpha():
            alpha.append(i)
        if unicodedata.category(c).startswith('C'):
            controls.append(i)
        j = i + 1
        if not c.isspace() and (j == len(text) or base.WORD.fullmatch(text[j]) is None):
            ends.append(j)
    length_set = set(lengths)
    for start, c in enumerate(text):
        if c.isspace() or (start and base.WORD.fullmatch(text[start - 1]) is not None):
            continue
        ai = bisect.bisect_left(alpha, start)
        if ai == len(alpha):
            continue
        ci = bisect.bisect_left(controls, start)
        lower = alpha[ai] + 1
        upper = min(len(text), start + lengths[-1], controls[ci] if ci < len(controls) else len(text))
        lo, hi = bisect.bisect_left(ends, lower), bisect.bisect_right(ends, upper)
        if hi <= lo:
            continue
        ll, lh = bisect.bisect_left(lengths, lower - start), bisect.bisect_right(lengths, upper - start)
        if hi - lo <= lh - ll:
            for k in range(lo, hi):
                end = ends[k]
                stats['examined_pairs'] += 1
                if end - start in length_set:
                    yield start, end
        else:
            for k in range(ll, lh):
                end = start + lengths[k]
                stats['examined_pairs'] += 1
                position = bisect.bisect_left(ends, end, lo, hi)
                if position < hi and ends[position] == end:
                    yield start, end


def complete_pass(raw, lengths, maximum, content=False):
    started = time.perf_counter()
    lines = [base.normalize(s) for s in raw.splitlines()] if content else [base.normalize(raw)]
    normalize_seconds = time.perf_counter() - started
    started = time.perf_counter()
    public_calls = public_bytes = 0
    for text in lines:
        calls, byte_work = base.work_counts(text, maximum)
        public_calls += calls
        public_bytes += byte_work
    count_seconds = time.perf_counter() - started
    stats = {'examined_pairs': 0}
    calls = byte_work = 0
    started = time.perf_counter()
    for text in lines:
        for i, j in pruned_candidates(text, lengths, stats):
            encoded = text[i:j].encode('utf-8')
            digest = hmac.digest(base.SYNTHETIC_KEY, base.LABEL + (j-i).to_bytes(4, 'big') + encoded, hashlib.sha256)
            # Synthetic set lookup, with no match-dependent stop or work change.
            _ = digest in {b'Z' * 32}
            calls += 1
            byte_work += len(encoded)
    second_seconds = time.perf_counter() - started
    if stats['examined_pairs'] > public_calls or calls > public_calls or byte_work > public_bytes:
        raise ValueError('Synthetic invariant breach')
    return {**stats, 'calls': calls, 'utf8_bytes': byte_work,
            'public_candidates': public_calls, 'public_utf8_bytes': public_bytes,
            'normalized_codepoints': sum(map(len, lines)), 'lines': len(lines),
            'normalize_seconds': normalize_seconds, 'count_seconds': count_seconds,
            'pruned_second_seconds': second_seconds,
            'total_seconds': normalize_seconds + count_seconds + second_seconds}


def read_decode_measurement(total=32 * 1024 * 1024, chunk=2 * 1024 * 1024):
    """Read only a temporary file created here with repeated public dummy bytes."""
    if total <= 0 or chunk <= 0 or total % chunk:
        raise ValueError()
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'synthetic.bin'
        with path.open('wb') as stream:
            for _ in range(total // chunk):
                stream.write(b'a' * chunk)
        repeats = []
        for repeat in range(3):
            started = time.perf_counter()
            seen = 0
            with path.open('rb') as stream:
                while True:
                    data = stream.read(chunk)
                    if not data:
                        break
                    if b'\0' in data:
                        raise ValueError()
                    seen += len(data.decode('utf-8', errors='strict'))
            if seen != total:
                raise ValueError()
            repeats.append({'repeat': repeat, 'bytes': total, 'seconds': time.perf_counter()-started})
    return repeats


def main():
    print(json.dumps({'kind': 'runtime', 'python': platform.python_version(),
                      'unicode': unicodedata.unidata_version}), flush=True)
    maximum = 2304  # Public benchmark range, not a production policy limit.
    patterns = {'short_words': 'a a ', 'punctuated': 'a.a.', 'punctuation_only': '.-! ',
                'prose': 'ZZAlpha met ZZBeta. ', 'expansion': '\ufdfa', 'many_lines': 'a\n'}
    shapes = {'minimum': [1], 'maximum': [maximum], 'dense': list(range(1, 257)),
              'long_dense': list(range(2049, 2305)), 'sparse': [1, 4, 8, 32, 128, 512, maximum]}
    for corpus, pattern in patterns.items():
        for size in (1024, 4096):
            raw = pattern * (size // len(pattern.encode('utf-8')))
            for shape, lengths in shapes.items():
                timings = []
                for repeat in range(3):
                    record = complete_pass(raw, lengths, maximum, content=corpus == 'many_lines')
                    timings.append(record['total_seconds'])
                    print(json.dumps({'kind': 'complete_pruned', 'corpus': corpus, 'shape': shape,
                                      'raw_bytes': len(raw.encode('utf-8')), 'repeat': repeat, **record}), flush=True)
                print(json.dumps({'kind': 'variance', 'corpus': corpus, 'shape': shape,
                                  'raw_bytes': len(raw.encode('utf-8')), 'minimum_seconds': min(timings),
                                  'median_seconds': statistics.median(timings), 'maximum_seconds': max(timings)}), flush=True)
    for record in read_decode_measurement():
        print(json.dumps({'kind': 'synthetic_read_decode', **record}), flush=True)
    return 0
