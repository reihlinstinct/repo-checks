# Secret-sourced name guard

The private policy is a JSON array in the `PRIVATE_NAME_TERMS_JSON` Actions
secret in a dedicated environment restricted to the exact default branch. It
must not exist at repository or organization scope, where same-repository PR
workflows could access it. It is never committed, hashed, cached, passed as a command-line argument,
printed or included in an artifact. Missing, empty or malformed policy fails
with exit 2. Matches fail with exit 1. Scanner failures also fail with exit 2.

Matching uses NFKC normalization, Unicode case-folding and exact word boundaries.
No whole-line allowlists, consumer policy files or automatic baselines are used.
Each matching line reports only its JSON-escaped file path and line number.
Paths containing policy terms are redacted and fail even when their contents
are clean or binary; line zero denotes a filename finding. No excerpts or matching terms are
reported. Binary contents are explicitly counted as unscanned, not certified.
Encoded/obfuscated names and OCR remain outside this text gate's scope.

## Trusted workflow boundary

Run the immutable-SHA-pinned `actions/private-names` action only from a trusted
default-branch `workflow_run` workflow. A separate secret-free `pull_request`
request workflow triggers it. Require the completed source event to be
`pull_request`, validate the original run's repository binding and 40-character
head SHA, and scan that exact immutable SHA as inert data. Never use an artifact
or a caller-supplied branch name as executable code or as authority for the SHA.
Check out the candidate into a separate directory using pinned checkout with
`persist-credentials: false`, no submodules and no LFS. The scanner job uses
`contents: read` and the restricted environment. Do not execute candidate code,
install candidate dependencies, run candidate tests or restore candidate caches
in this job. Other test jobs must never receive the policy secret.

A separate final job has only `statuses: write`, no checkout and no policy
secret. It attaches a fixed pass/fail status to the validated scanned head SHA,
not the default-branch SHA of the trusted workflow. Source request failures and
scanner failures must never post success. A missing request leaves the required
head status missing, rather than claiming a clean scan.

Environment branch rules must allow only the exact default branch, with no tag
rules, wildcard, pull-request merge refs, or administrator bypass. Prove with a
synthetic PR that a candidate job requesting this environment is blocked before
accessing any secret. A policy at repository scope is not sufficient isolation.
The first installation is effective only after landing on the default branch;
PR CI alone does not prove a newly added workflow runs. Private-source exporters
need their own separate public-output scanning boundary; do not scan or remove
intentional private source names to force a green result.

`pull_request_target` was considered, but GitHub's announced December 2, 2026
public default-policy enforcement would require an explicit opt-out. The
`workflow_run` separation avoids that opt-out. It still requires the same strict
rule: fetched candidate data is never executed in a privileged job.

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

## Consumer installation

The reviewed `.github/workflows/private-name-guard.yml` reusable workflow owns
binding, fetch, scan and reporting. Pin callers to its full reviewed immutable
commit SHA, never a branch or tag. The caller's `privacy-request.yml` is a
secret-free `pull_request` workflow named `Private name scan request`, with no
checkout and one fixed echo step. The caller's trusted `workflow_run` listener
matches that exact name and completed type, then calls the pinned reusable
workflow with only `actions: read`, `contents: read` and `statuses: write`.
Permissions are reduced per job: binding gets actions read, scanning gets
contents read, reporting gets statuses write. Do not pass `secrets: inherit`.
The caller explicitly passes only `PRIVATE_NAME_TERMS_JSON`; the reusable
workflow declares that named secret required. Set the exact-default-branch-only
`privacy-policy` environment in each CALLER repository, not merely this shared
repository. The scan job selects that caller environment, whose secret takes
precedence. GitHub requires explicit named forwarding even for environment-only
secrets; omission otherwise resolves empty. Never use a repository-scoped copy
as a workaround. Verify the first consumer end to end before widening. No token or policy
is passed to Git fetch, and candidate fetch/checkouts suppress all output to
avoid accidentally printing a commit subject containing private text.

The binding job re-reads the original workflow run through GitHub and requires
the expected request path, event, completed state, repository ID, source head
repository ID, immutable head SHA and conclusion to agree with the wake payload.
No candidate text is interpolated into executable JavaScript or shell source.
A failed source request or any failed/skipped/cancelled scan posts failure, never
success. The head status context is exactly `private-name-guard`; require it in
branch settings only after verifying installation on the default branch.
Environment restrictions do not establish branch-required checks by themselves.

The own-repository Scorecard baseline names only the intended report-job
`statuses: write` capability with issue and reason. It is not a name-policy or
privacy waiver. Changed capabilities, jobs or evidence invalidate that baseline.
