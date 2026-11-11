# Local pre-merge sensitive-data scan

Offline, free and local-first. No API calls, account access, licence-plate detector,
encryption or real-data import. Synthetic fixtures are the default. Encryption
for a task that truly needs real data requires a separate user decision.

## Command and scope

From a trusted, reviewed checkout of this tool:

```sh
python3 -I /trusted/repo-checks/tools/repo_checks.py sensitive-scan \
  --pre-merge --root /path/to/candidate --base origin/main --head HEAD
```

Resolve both commits, find their merge base, then inspect each introduced commit
(up to 256), not only the final tree. A secret added then removed before push
still blocks. For each commit, scan added diff lines against its first parent
and all committed text under fixture/fixtures/testdata/test-data/__fixtures__
directories. Also scan selected pathnames. No worktree files or candidate code
are executed. Unstaged/untracked content is outside this committed-content check.
Unchanged non-fixture baseline files and older history are not audited.

Output is a JSON status, category counts and file:line locations, never matched
values, excerpts or source exceptions. Counts are unique file/line/category
locations across inspected commits. Path-only findings use the explicit sentinel line 0, not a content line. Suspicious or
nonportable paths are withheld. Exit0 means no supported finding in this scope;
exit1 means findings; exit2 means an incomplete/error scan and must block.
No partial findings are emitted on an error. Never interpret an error as pass.

Budgets: inherited 20,000 paths, 4 MiB inventory, 2 MiB/file, 32 MiB selected raw bytes
per tree, 10,000 report locations, 256 introduced commits and a 30-second CLI alarm.
Any binary/NUL/invalidUTF-8 selected blob, symlink/submodule, missing object,
invalid ref, overflow or unsupported input fails closed. No fixture-directory,
inline-comment or arbitrary path allowlist bypass exists. Diff text is forced
so attributes cannot hide text as a binary patch. Git replacement objects are
disabled in the shared Git reader; hooks, textconv and external diff are disabled.

## Detectors and limits

- Israeli ID: bounded ASCII 9-digit candidates with the alternating 1/2 checksum.
  Repeated-digit sentinels are excluded by the existing shared checksum helper.
  No numeric ID of a real person is used in the tests; check-valid shapes are
  assembled from synthetic pieces at runtime.
- Israeli mobile phones: 05x plus 7 remaining digits or +9725x plus 7 digits, with
  optional single ASCII separators. These are shape checks, not subscriber
  lookup. There is no assumed safe Israeli mobile range. Existing reserved
  +999 and NANPA 555-0100..0199 fixture forms do not match this Israeli detector.
- Emails: non-reserved domains. example.com/.net/.org and their subdomains,
  .test/.invalid/.localhost forms are safe fixture domains. Whole safe email
  tokens never exempt another same-line address.
- Password assignments: nonempty password/passwd/pwd keys with = or : syntax,
  quoted or unquoted. Even dummy-looking nonempty assignments block. Empty
  values pass. This intentionally produces false positives in literal examples;
  assemble detection fixtures at runtime instead of adding bypass comments.
- Existing shared provider-token and supported PEM-header patterns. Their
  documented unknown/encoded/split-write/unsupported-PEM gaps remain.

No licence plates are detected. Canonical UUIDs are masked only within the ID
candidate pass. This is not arbitrary-name discovery, OCR, a universal secret
scanner, or certification of binary/encoded/nonnormalized/obfuscated inputs.
It supplements rather than replaces existing privacy/name/secret checks.

## Opt-in pre-push hook

```sh
python3 -I /trusted/repo-checks/tools/install_sensitive_hook.py \
  /path/to/candidate origin/main
```

Run this only when you intend to install a local hook. It refuses an existing
pre-push hook, existing snapshot or custom core.hooksPath rather than replacing
someone else's setup. It copies only reviewed tool modules to a local .git
snapshot, so a candidate's checked-out replacement scanner cannot bypass it.
Each pushed ref is checked at its explicit local commit. For an existing branch,
the remote hash is the base; a new branch uses the configured base. Missing
remote objects/base refs fail closed. Deletions carry no new commits. Hook input
is bounded, multi-ref pushes are checked, and failures stop the push. A missing
snapshot blocks. Uninstall manually by removing the installed hook and snapshot
only after deciding an alternative gate.

Git hooks are not unbypassable enforcement: git push --no-verify, changing local
configuration or deleting the hook can bypass them. Run the trusted local
command before merging too. No branch protections or required-status settings
are changed here. No consumer hooks are installed by this PR.

## Explicit HMAC pseudonymization

Create one local key outside every candidate repository, with mode 0600, then
keep it private and out of commits, logs, hosted CI and CircleCI:

```sh
python3 -I /trusted/repo-checks/tools/repo_checks.py pseudonymize \
  --root /path/to/candidate --key-file /private/local-mask-key --create-key
```

No key is generated in this repository by default. Existing files are not
overwritten; symlinked paths, wrong permissions/owner/hardlinks and repository-
local key paths are refused. To mask an explicitly typed JSON request, pass a
list of objects with exactly kind and value fields through private buffered
stdin. Kinds are name, id and phone. Avoid terminal echo and command arguments
for real inputs. Only the full validated pseudonym list is emitted. Errors are
constant and never emit a partially transformed request or original values.

The reusable API is repo_checks.pseudonymize.pseudonym(kind,value,key). It uses
HMAC-SHA256 with a versioned domain and kind separator. Names use NFC/casefold
and collapsed whitespace; IDs require 9 ASCII digits; Israeli phone forms are
canonicalized. Outputs are typed ZZ_NAME_/ZZ_ID_/ZZ_PHONE_ plus letters only,
not valid IDs or dialable phones. Same local key+normalized input gives the
same value; a changed key changes results. No reversible mapping is stored.
Keep the full 256-bit digest to avoid unnecessary truncation collisions.

Pseudonyms still reveal equality/linkability within a key. HMAC is not
anonymization, encryption or automatic removal of incidental identifying text.
A CSV adapter must explicitly select sensitive columns and must not copy
unchecked columns, log originals or fall back after an error. No CSV adapter,
application output producer or hosted transcript integration is claimed here.

## Regression and mutation checks

Run python3 -m unittest discover -s tests/security -v. Synthetic tests exercise
planted check-valid ID/mobile/token/password shapes, safe fixtures, line reports,
fixture rescans, removed intermediate secrets, invalid/binary inputs, key-file
rules, deterministic normalization, buffered CLI refusal and installed-hook
candidate replacement isolation. The suite must remain green alongside existing
checks. A review and green CI at the exact head remain the merge gate.
