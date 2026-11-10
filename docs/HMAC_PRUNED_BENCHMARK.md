# Complete synthetic pruned-pass measurements

Follow-up to issue #33 and the first synthetic benchmark. No production policy,
matching deployment, secret, consumer, settings or budget constant changes.

This read-only pull-request lane measures complete synthetic normalization,
public-range counting and a complete indexed second pass, with no sampling or
match-dependent short-circuit. Each corpus/size/length-shape combination runs
three times and reports minimum, median and maximum. Runtime and Unicode version
are reported; the job log records the runner image. These are repeats within one
runner job, not independent-machine variance. Compare separate CI runs before
setting production headroom.

Synthetic corpus sizes are 1 KiB and 4 KiB, rounded to whole UTF-8 patterns.
Shapes include minimum, maximum, sparse, dense short and dense long lengths.
Larger complete dense passes are deliberately not guessed to fit the five-minute
measurement job. Counted work and the measured range must accompany any
projection; a small measurement is not certification of a large input envelope.

Length validation, sorting and set preparation happen exactly once per complete
pass, before normalization or second-pass timing. Preparation time is reported
separately and included in the total; lengths over the public maximum are refused.
A regression counts one preparation call across many content lines.

The pruner builds alphabetic/control/boundary endpoint indexes for each line. For each eligible
start, it finds the admissible endpoint window, then traverses the shorter of
that window and protected-length candidates within it. Every examined pair is
counted, including a nonmember endpoint/length. No repeated per-substring
admissibility scan is used. Differential tests compare the full candidate set
with naive enumeration and require examined pairs, HMAC calls and hashed bytes
to stay below the first pass's public figures. Punctuation-only content examines
zero second-pass pairs. The second pass also has linear per-normalized-code-point index construction
and start scanning with bisects, even when examined pairs are zero. These costs
are not represented by the pair count; production budgets must also count lines
and normalized code points. Indexes are rebuilt, not shared with the first pass.
All measured passes complete and are never truncated.

Content mode is exercised with many short lines. Other synthetic corpora are
single-line inputs treated as whole strings. The complete measurement includes
normalization, counting, pruner index construction, enumeration, encoding,
HMAC and synthetic set lookup. It excludes inventory, I/O and production policy
authentication. A separate temporary-file test generates exactly 32 MiB of ASCII
dummy bytes, then reads, NUL-checks and strictly decodes it three times in bounded
chunks. Those reads may be page-cache hot; no cold-disk or real repository
throughput is claimed. No user file is opened or downloaded.

No benchmark value is a production limit. After actual-runner measurements,
options must state public per-line/file/aggregate normalized, line-count,
candidate and byte-work caps; phase time limits/headroom; constant fail-closed
over-budget behavior; and likely consumer adoption impact. Smaller public caps,
phase-separated backstops or infeasibility are choices for review, not silent
changes. Real-list conversion/installation and the frozen app remain held.
