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
of calls to bound benchmark time; that sample cap must never become production
truncation. Counting and HMAC timing are reported separately.

No production budget is asserted from local timings. Actual-runner results must
be reviewed, with enough margin for normalization, counting, file validation and
matching under the existing scanner alarm. The future scanner must fail closed
at deterministic public budgets, never truncate or short-circuit on a match.
Aggregate 32 MiB projections and exact-limit tests remain work for the next
reviewed implementation slice. Missing or failed measurements are not approval
to guess a budget or weaken matching.
