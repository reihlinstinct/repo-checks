"""Public-range work accounting and indexed normalized candidate traversal."""
from array import array
import bisect
import re
import unicodedata

WORD = re.compile(r'\w')


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



def prepare_lengths(lengths):
    """Validate/sort/index once per pass, never once per content line."""
    values = tuple(lengths)
    if not values or any(type(n) is not int or n < 1 for n in values):
        raise ValueError()
    ordered = tuple(sorted(set(values)))
    return ordered, frozenset(ordered)


def pruned_candidates(text, prepared, stats):
    """Build per-text admissibility indexes and traverse bounded windows."""
    lengths, length_set = prepared
    alpha, controls, ends = array('Q'), array('Q'), array('Q')
    for i, c in enumerate(text):
        if c.isalpha():
            alpha.append(i)
        if unicodedata.category(c).startswith('C'):
            controls.append(i)
        j = i + 1
        if not c.isspace() and (j == len(text) or WORD.fullmatch(text[j]) is None):
            ends.append(j)
    for start, c in enumerate(text):
        if c.isspace() or (start and WORD.fullmatch(text[start - 1]) is not None):
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
