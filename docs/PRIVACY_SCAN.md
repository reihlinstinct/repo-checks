# Value-free privacy pattern gate

The stdlib-only scanner runs offline on Git-tracked regular files, with no
consumer imports, hooks, baseline, network or credentials. Public output contains
only fixed category counts and coverage counts, never finding text or paths.
Exit 0 means no matched patterns in the scanned text, 1 means findings, 2 means
the input could not be checked within its limits. Missing files, symlinks,
submodules, unresolved entries and oversized inputs fail closed.

Patterns cover phone-shaped strings (including bare Israeli country code and common Unicode whitespace/dash/slash separators), Unicode/IDN email candidates, Israeli-style nine-digit
checksum-positive IDs, common token/private-key markers and credential/session
filenames. Exact example email domains, GitHub noreply domains, reserved +999
phone forms and NANPA +1-NPA-555-0100 through 0199 are fictional exceptions.
Exceptions apply to individual matched tokens, never whole lines or directories.
Fixtures assemble non-reserved shapes at runtime; they contain no real identifiers.

Limits: 20,000 tracked files, 2 MiB per file, 32 MiB total, 10-second Git listing with capped streaming output; 15-second scan deadline and 30-second CLI alarm.
Binary/non-UTF8 files are counted as unscanned. PDFs, images, OCR, compressed
archives, encoded secrets, personal names and arbitrary secrets require separate
review. Pattern matches can be public official contacts, synthetic test data,
geometry or other harmless numeric data. Do not call a candidate a confirmed leak
without triage. Never auto-baseline or allowlist an existing hit simply to go green.

This first slice enables the check in this repository only. Next slice: isolated,
immutable-SHA-pinned composite action with a real shadow consumer retaining its
existing guard. Each consumer needs a separate reviewed PR and green checks.
Existing required checks, source-specific privacy review and security scanning
remain in place. No historical rewriting or consumer settings changes are included.

The checks intentionally avoid private-token lists or fingerprints. Short personal
identifier hashes can be guessed. A scan has no authority to disclose source data,
remove public source documents, revoke credentials or rewrite repository history.

Unicode email support is best-effort candidate recognition, not full RFC/EAI
validation. Obfuscated addresses, mixed-script confusables, encoded identifiers,
country-specific phone formats outside the advertised forms and text hidden in
binary files may be missed. Unicode normalization/OCR is not a substitute for
review. Long email-shaped candidates fail closed rather than being skipped.
