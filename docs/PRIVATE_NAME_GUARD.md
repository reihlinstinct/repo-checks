# Secret-sourced name guard

The private policy is a JSON array in the `PRIVATE_NAME_TERMS_JSON` Actions
secret. It is never committed, hashed, cached, passed as a command-line argument,
printed or included in an artifact. Missing, empty or malformed policy fails
with exit 2. Matches fail with exit 1. Scanner failures also fail with exit 2.

Matching uses NFKC normalization, Unicode case-folding and exact word boundaries.
No whole-line allowlists, consumer policy files or automatic baselines are used.
Each matching line reports only its JSON-escaped file path and line number.
Paths containing policy terms are redacted. No excerpts or matching terms are
reported. Binary contents are explicitly counted as unscanned, not certified.
Encoded/obfuscated names and OCR remain outside this text gate's scope.

## Trusted workflow boundary

Run the immutable-SHA-pinned `actions/private-names` action only from a trusted
base-branch `pull_request_target` workflow. Check out the candidate head into a
separate directory using a pinned checkout with `persist-credentials: false`,
no submodules and no LFS. Use a read-only token. Do not execute candidate code,
install candidate dependencies, run candidate tests or restore candidate caches
in this job. Other test jobs must never receive the policy secret. Do not run
the secret-bearing action under a candidate-controlled `pull_request` workflow.
The first installation becomes effective only after landing on the base branch;
PR CI alone does not prove a newly added target workflow runs.

Set the secret only on the trusted scanner step. The scanner pops it from its
inherited environment before any Git subprocess and strips it from inventory
child environments as defense in depth. Isolated Python loads only pinned
trusted source, never cwd/PYTHONPATH/sitecustomize. Candidate paths, symlinks,
Git configuration and inventory are treated as hostile input.

Keep the existing generic privacy scanner as a separate failing step. Neither
step may use `continue-on-error`. Required branch-check configuration must be
verified separately; a red workflow is not evidence that protection requires it.

## Bounded binary classification

The shared reader classifies at most the first 8 KiB before applying the 2 MiB
text limit. NUL or invalid UTF-8 identifies binary input, which is counted as
unscanned after descriptor/identity checks. Encrypted image artifacts are not
text and do not become text-limit errors merely due to size. Oversize UTF-8
text still fails closed; symlinks, missing files and changed files still fail.
The 32 MiB aggregate budget counts bytes actually read, including binary probes.
Sensitive filename checks still apply to binary files. This does not inspect
image, encrypted, compressed or PDF contents.

All regression policies use invented test terms. Existing findings need private
triage; never delete intentional private-source content or waive collisions just
to turn a public-export check green.
