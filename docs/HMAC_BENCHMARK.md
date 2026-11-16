# Synthetic keyed-digest benchmark

This slice measures work. It does not implement or replace the privacy scanner,
read any policy, access a secret, configure a consumer or choose production
limits. The design is tracked in issue #33.

The pull-request-only benchmark runs on ubuntu-24.04 with the same system python3
as the trusted action. It reports the interpreter/Unicode version, exhaustive
single-character normalization expansion, synthetic candidate counts/UTF-8 byte
work, and repeated bounded HMAC timing samples. Dummy key bytes are public test
data, not an actual policy key. No candidate repository text is measured.

The counter uses the full public normalized-length range derived from the raw
128-character term limit and measured maximum single-character expansion. It
compares normalized-space Unicode word boundaries and existing term admissibility
rules. Prefix sums and indexed endpoints avoid hashing every public-range
candidate just to count them. Differential tests compare the optimized counter
with naive enumeration on random synthetic text. This is benchmark scaffolding,
not the production two-pass reader or budget enforcement.

Corpora cover repeated short words, punctuation-separated words, punctuation-only
text, prose and normalization expansion. Input sizes target 32 KiB and 2 MiB of
UTF-8, rounded down to whole repeated patterns. Only the smaller corpus receives
repeated short/long/sparse/dense length samples. The sample stops at a fixed number
of examined boundary-eligible pairs, including rejected pairs. It builds the
admissible encoded messages first and reports filtering and HMAC-loop timing
separately. The HMAC timer includes only digest calls on prepared messages. The
pair cap bounds synthetic measurement work, not production truncation. Every
sample reports examined/rejected pairs, calls, bytes and whether the cap fired.

No production budget is asserted from local timings. Actual-runner results must
be reviewed, with enough margin for normalization, counting, file validation and
matching under the existing scanner alarm. The future scanner must fail closed
at deterministic public budgets, never truncate or short-circuit on a match.
Aggregate 32 MiB projections and exact-limit tests remain work for the next
reviewed implementation slice. Missing or failed measurements are not approval
to guess a budget or weaken matching.

## Content mode and conservative whole-text counts

Separate many-line corpora use LF, CRLF and U+2028 at both sizes. Their content
records splitlines before normalizing each line and report line count,
normalization time and per-line count time. They exercise per-line overhead,
which a single-line corpus does not measure.

Whole-normalized-text counting is exact for paths. For content it is a
conservative upper bound, not an exact content count: U+2028/U+2029 can create
extra spanning candidates in path mode; control-category separators prevent
spanning matches, while splitlines removes those separators in content mode.
Line-edge matches retain valid surrounding non-word boundaries in whole text.
Synthetic fixed and randomized tests check both candidate and byte upper bounds,
including normalization expansion and every separator. Production code must
still implement the actual line-local path, not treat this tested property as a
license to join lines or change matching semantics.

## Budget implications and remaining work

A public budget must cover filtering and endpoint/length enumeration, not only
admissible candidates or bytes hashed. The production second pass must either
reuse indexed pruning so rejected-substring validation cannot dominate, or count
examined work explicitly. A punctuation-only input can have zero candidates but
many rejected pairs; the pair-capped sample exposes that cost honestly.

Initial runner evidence at the previous PR head showed that counting a 2 MiB
normalization-expansion corpus took about 9.35 seconds, before hashing. A simple
16-file projection to the existing 32 MiB raw aggregate is about 150 seconds,
already beyond the 30-second scanner backstop but below the 5-minute job before
other work. This is a projection, not a measured aggregate run or chosen budget.
Revised per-line and filtering-separated samples must be read alongside it.
Normalized-code-point and enumeration limits will need to be much lower, or the
feasibility tradeoff must return for review. Actual aggregate measurements,
repeated end-to-end implementation timings and exact-limit tests remain the next
slice. No constants are approved by this benchmark.
