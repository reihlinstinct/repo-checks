# Secret-sourced name guard

This prerequisite provides the scanner and action only. The trusted workflow
is documented separately in [PRIVATE_NAME_WORKFLOW.md](PRIVATE_NAME_WORKFLOW.md)
and pins the landed scanner commit.
No consumer rollout or branch-required status is installed by this change.

Policy is a mandatory JSON array in PRIVATE_NAME_TERMS_JSON, stored only in an
exact-default-branch restricted environment. Missing/malformed policy errors
with exit 2; findings exit 1. No consumer baseline or whole-line waiver exists.
NFKC normalization, case folding and exact Unicode word boundaries apply.
Attached letters, underscores, digits, niqqud and split phrases are not extra
matches. Changing these semantics requires a separate reviewed decision.

Public output has exactly two keys: schema_version (1) and status (pass,
findings or error). There are no counts, including coverage or per-file counts.
Never report file paths, line numbers, excerpts, policy terms or hashes in public
logs. Pass/fail can still reveal policy membership to chosen inputs; the future
workflow must refuse fork candidates before accessing policy. Only trusted
same-repository maintainers may submit candidates. Matching saturates to a
boolean without a policy-dependent findings limit; all files still undergo
input validation even after a match. Private local triage may
inspect source, but its detailed output must not be published.

Every file has a 2 MiB cap and all bytes read count toward the 32 MiB aggregate
budget, regardless of prefix. NUL bytes or invalid UTF-8 make the name scan fail
closed, including encrypted images, UTF-16 and binary-magic-prefixed text. No
binary signature, extension or filename grants an exemption. An encrypted-blob
policy is a separate unresolved decision, not implemented here. Symlinks,
submodules, nonzero stages, missing/changed files and other input errors fail.

Only the trusted scan step may receive the secret. Python runs with -I, loads
only pinned trusted source and never executes candidate code. main removes
the key from Python's os.environ before Git runs; child environments also strip
it. This does not erase process startup memory or the parent shell environment.
No candidate process may run in that job. No outputs, artifacts, caches or
step summaries receive the policy. Regression policies are synthetic only.

Generic privacy findings retain their existing caller policy; scanner errors
must never be masked as success. Complete canonical UUID tokens are parsed as
identifiers, while adjacent phone/ID/email data remains checked. This scanner
is not proof that encoded, obfuscated or image-based text contains no names.

## Integration binding required in the follow-up

The scanner reads the tracked working-tree files, not committed blobs. It does
not bind its result to a commit. The integration must freshly check out the exact
candidate SHA, verify HEAD equals it and the working tree/index are clean before
scanning, and report status only for that exact SHA. It must reject forks before
policy access and pin the action to the full landed scanner commit on main,
never an intermediate PR commit. These requirements are not installed here.
