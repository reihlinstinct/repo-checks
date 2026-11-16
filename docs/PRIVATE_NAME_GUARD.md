# Authenticated private-name guard

The current source is a synthetic-only HMAC implementation for
[design issue 33](https://github.com/reihlinstinct/repo-checks/issues/33).
The reusable workflow pins this landed HMAC scanner and forwards the two
protected values explicitly. This does not install the scanner for any consumer
or run actual-list conversion. Conversion needs its own reviewed execution path.

## Protected policy

The scanner requires `PRIVATE_NAME_HMAC_POLICY_JSON` and
`PRIVATE_NAME_HMAC_KEY_B64`. The old `PRIVATE_NAME_TERMS_JSON` must be absent.
The two new values belong only in an exact-default-branch restricted environment,
never repository or organization secrets. This source change installs no secrets.

The key is exactly 32 bytes, in canonical padded base64. The JSON has exactly
`schema`, `unicode_version`, `entries` and `policy_mac`. Schema is
`repo-checks.private-names.hmac/v1`; Unicode version must equal the runtime's
`unicodedata.unidata_version`. Entries are 1..256 strict `length`/`digest` objects,
sorted by distinct lowercase 64-character hexadecimal digest. Length is a strict
integer from 1 through 64. Duplicate JSON keys, unknown fields, legacy arrays,
booleans as lengths and JSON longer than 32768 characters error.

Term HMAC-SHA-256 input is ASCII `repo-checks/private-names/v1/term`, NUL,
uint32-big-endian normalized length, then normalized UTF-8 text. Policy MAC input
is ASCII `repo-checks/private-names/v1/policy`, NUL, then canonical JSON of all
fields except `policy_mac`: sorted keys, comma/colon separators, ASCII escaping
and no NaN. The policy MAC is checked with `hmac.compare_digest` before inventory.
A wrong key cannot silently pass. Keys and policies are never printed.

`name_hmac_policy.validate_term` defines the future converter's shared validation:
raw length 2..128, then NFKC and casefold, normalized length 1..64, no leading or
trailing whitespace, at least one alphabetic character and no category-C
character. Overlength terms error instead of being skipped or shortened. The
converter itself is not included or executed. No variants are inferred.

## Matching and public work bounds

Content is decoded strictly as UTF-8 and split with `str.splitlines()` before
each line is normalized. Paths are normalized whole. A normalized candidate
starts at text start or after a non-`\w` character, and ends at text end or before
a non-`\w` character, using Python Unicode regex semantics. No names-only-line
mode, fuzzy matching, niqqud removal or invisible-character stripping exists.
Ordinary code and prose are scanned. Split phrases do not join across lines.

The first pass securely reads and validates all files and counts admissible
candidates over every public length 1..64, independent of protected lengths.
All limits below are inclusive. Exceeding any limit errors before candidate
hashing. Counts include the path and all content segments; an empty decoded
file contributes its path but no content segments. Empty content lines count
as segments even though they contain no candidates.

| Work | Per segment | Per file including path | Aggregate |
| --- | ---: | ---: | ---: |
| Normalized code points | 262144 | 1000000 | 2000000 |
| Segments | - | 50000 | 100000 |
| Public admissible candidates | - | 1000000 | 2000000 |
| Candidate UTF-8 bytes | - | 64 MiB | 128 MiB |

Existing raw limits remain 2 MiB per file, 32 MiB aggregate, 20000 tracked paths
and 4 MiB inventory output. Each read pass independently applies them. NUL,
invalid UTF-8, symlinks, submodules, unmerged stages, missing/changed files and
unscannable content error. Binary signatures or extensions grant no exemption.
This is not proof about encoded, obfuscated or image-based text.

The second pass uses indexed pruning at authenticated protected lengths, hashing
every eligible candidate without stopping after a hit. Transient SHA-256 file
fingerprints compare each second read with its first read; inventory bytes,
tracked path sets and root identity must remain unchanged. These fingerprints
are not a replacement for HMAC policy protection and are never emitted. An
isolated job with an exact-SHA clean checkout is still required. This is not an
atomic snapshot against arbitrary concurrent modifications after a file's
second read. No candidate code may run in the job.

The 30-second alarm covers policy parsing and scanning; the five-minute workflow
job remains a separate backstop. Proposed constants require repeated actual
ubuntu-24.04 runner evidence and exact-head independent review before merge.
Local timing on a different interpreter is not that evidence. Repository-fit
counts are not timing proof or rollout authorization.

## Output and isolation

Public output is exactly `schema_version` (1) and `status` (`pass`, `findings` or
`error`); exits are 0, 1 and 2 respectively. No paths, line numbers, counts,
excerpts, terms, lengths, digests or keys are exposed. Error output is constant
and exception values/tracebacks are suppressed. Pass/fail is still a membership
oracle; fork candidates must be denied before access to a protected environment.

All three sensitive environment keys are popped as scanner main's first
operation. Shared Git children strip all three; bootstrap errors remove them.
Python runs with `-I` and trusted source, with no candidate imports. This cannot
erase process startup memory or the parent shell's environment. The future
integration must explicitly forward both new secret names to the trusted scan
step only. No outputs, summaries, caches or artifacts may contain either value.

## Verification

Synthetic tests cover authenticated policy mutation, wrong-key errors before
inventory, strict schema/base64 handling, old-array rejection, normalization
and regex differential tests, public cap boundaries, all line separators,
whole-path matches, between-pass changes, no match short-circuit, fixed output
and all sensitive environment keys. Single-normalized-code-point and first-alpha-at-end
terms have CLI finding regressions. Differential fuzz asserts examined second-pass
pairs never exceed the first-pass public candidate count. Direct regressions cover
constant-time MAC comparison, the entry-count cap independently of ordering, and
the armed/cancelled alarm. Existing secure-reader regressions remain.

`python3 -I tools/benchmark_bounded_name_scan.py` generates temporary Git
repositories and public dummy policies in memory, then runs the actual isolated
CLI repeatedly. It covers dense words, prose, near-aggregate normalized non-ASCII
text, many lines, normalization expansion, combined near-candidate/normalized-point
caps, two near-1MB dense-dot/line-final-letter files, one-normalized-code-point
findings and over-budget errors. The dense-dot shape uses two files, each 32000 repeats of 30 dots, an ASCII
letter and a newline. It reproduces the independently reported synthetic recipe
on the actual runner, without treating the earlier local timing as runner proof. Output contains
synthetic corpus identifiers, runtime/Unicode versions, elapsed times and expected
exit codes only. Each repetition starts a fresh interpreter; OS caches are not
flushed. The benchmark neither reads actual policies nor changes configuration.

[Trusted integration requirements](PRIVATE_NAME_WORKFLOW.md) describe explicit
HMAC forwarding and landed pins. Required-status changes, binary policy and
actual-list migration remain separate execution stages.
