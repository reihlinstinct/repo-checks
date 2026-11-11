# Secret-only output and repository guard

Tracked in [design issue 37](https://github.com/reihlinstinct/repo-checks/issues/37).
This is a format-based safety layer, not proof that output contains no secrets.
It recognizes GitHub classic/fine-grained tokens, Slack token patterns, AWS
access-key IDs and supported PEM private-key headers. Arbitrary passwords,
unknown formats, encoded/split credentials and binary data are outside scope.
No provider calls or paid services are used.

## Controlled output API

Import from `repo_checks.secret_output`:

- `contains_secret(text)` validates a bounded string and returns a boolean.
- `protect_text(text, redact=False)` returns clean text unchanged or raises the
  value-free `SecretOutputError`. Explicit `redact=True` replaces recognized
  tokens and entire supported PEM blocks with `[REDACTED_SECRET]`. An unterminated
  PEM block consumes the remainder of the text. Block mode is the default.
- `protect_json(value, redact=False)` returns a checked copy of a JSON value,
  checking string keys and values. It refuses cycles, non-JSON types, nonfinite
  floats, depth over 64, excessive size and key collisions after redaction.

Each text/serialized JSON value is limited to 2 MiB of strict UTF-8. All values
are validated before a result is returned. Exceptions contain no input. Callers
must not catch a refusal and fall back to printing or sending the original.

```python
from repo_checks.secret_output import protect_text

# Apply BEFORE a controlled producer writes, saves or sends this value.
checked = protect_text(message)
send_to_destination(checked)
```

The module does not intercept logging libraries, email transport or transcript
storage automatically. A call site is covered only after the producer actually
calls this boundary and tests prove no bypass. A formatter that logs its original
exception/message before this API is not protected. No project-controlled output
call sites outside this shared repository have been migrated in this PR. Hosted
agent transcripts, platform logs and unrelated mail remain outside this code's
control. Never claim blanket protection for those surfaces.

## Bounded stdin CLI

`python3 -I tools/secret_output.py` reads at most 2 MiB plus one byte from stdin,
checks the full text, and emits it only when clean. A match or any invalid input
emits no payload and returns 2 with a constant stderr diagnostic. It does not
print input, token values or paths. `--redact` explicitly selects replacement
mode; successful output exits 0. There are no file/network arguments.

Buffer output privately before passing it to this CLI. Piping a command through
it does not protect an upstream stderr, independent logs, terminal echo or
transcript capture of the command before the pipe. It is not a transparent
streaming log sanitizer. A broken output pipe produces the same fixed refusal;
no fallback writes the original text.

## Blocking tracked-text action

`actions/secrets` invokes trusted isolated source using Python `-I`. Pass an
absolute `checkout-root` within `GITHUB_WORKSPACE`, separate from the action.
Pin a reviewed landed commit. Never use `continue-on-error` for this action.
The CLI equivalent is `python3 -I tools/secret_scan.py --root /path/to/checkout`.

The shared secure reader applies the existing 20000-path, 4 MiB inventory,
2 MiB/file and 32 MiB total raw limits. Symlinks, nonregular index entries,
submodules, missing/changed files and inventory errors fail. Text is Git-tracked
strict UTF-8 without NUL. Invalid UTF-8 and NUL-bearing files are explicitly not
scanned by this text-only lane, but their bytes still consume the limits. This
means a token embedded in binary, an image or a NUL-bearing file is not certified.
The name scanner's separate fail-closed all-file policy is unchanged.

Recognized token/private-key findings return exit 1; errors return 2. Other
privacy categories do not affect this lane. Output is exactly `schema_version`
(1) and `status` (`pass`, `findings`, `error`), with no counts, paths or excerpts.
All files continue validation after a finding; no candidate code is executed.
Inventory is checked again before completion. The 30-second alarm is a backstop.
The ordinary privacy scanner imports the same secret regex, preventing drift.

The shared repository runs this blocking check in CI. Consumer adoption is a
separate pinned rollout, preserving existing checks. A failing check is not a
branch-required protection until separately configured. No settings change,
consumer migration, secret rotation or actual credential use occurs in this PR.
Already exposed credentials must be revoked/rotated independently.

## Verification

Synthetic tests assemble dummy values, never real credentials. They cover each
recognized family, Unicode context, multiple matches, whole/unterminated PEM
redaction, JSON keys/values/collisions/depth/types, no original mutation, bounded
input, invalid UTF-8, malformed arguments, broken pipes, constant diagnostics,
CLI block/redact/pass, scanner findings/errors, candidate-import isolation,
shared-pattern identity and the explicitly limited binary scope.

Run `python3 -m unittest discover -s tests/security -v`. No token is sent to a
provider to validate a test. Outputs and artifacts must never contain fixture
values except deliberately assembled synthetic source.

## Call-site inventory and no-bypass evidence

Inventory scope: this repository's tracked `src/`, `tools/`, `actions/` and
`.github/workflows/`, reviewed for `protect_text`, `protect_json`, `SECRET` and
secret CLI invocations. No consumer-repository output integration is included.

| Producer / entrypoint | Boundary and actual sink | Evidence / limit |
| --- | --- | --- |
| `tools/secret_output.py` | Isolated bootstrap calls `secret_output.main`; the full stdin buffer passes `protect_text` before any stdout bytes | CLI tests assert empty stdout on rejection, fixed stderr, explicit redaction, literal 2 MiB + 1 refusal, bounded read and broken pipe; upstream stderr/logging is outside this boundary |
| `protect_json` API | Total serialized size is checked before copying; every string key/value passes `protect_text` | Tests reject many small strings exceeding total 2 MiB before the first copied string, nesting/type errors and collisions; no production caller exists here |
| `tools/secret_scan.py` and CI `engine` | Isolated bootstrap calls `secret_scan.main`; fixed JSON result only | Tests pin the non-advisory `if: always()` CI invocation, reject candidate imports and inventory mutation, assert alarm(30) and alarm(0) on pass/error/timeout |
| `actions/secrets/bootstrap.py` | Isolated trusted bootstrap calls the same scanner | Functional synthetic bootstrap tests run, but no workflow executes the composite `action.yml` itself yet |
| `src/repo_checks/privacy.py` | Shared `SECRET` regex is used for classification, not output sanitization | Pattern-identity tests prevent regex drift; this is not an output call-site migration |

There are zero migrated application log, transcript, file-save or mail-send
producers. APIs alone do not cover those sinks. Each future producer needs a
separate inventory of every write path and failure-path tests proving it cannot
fall back to the unchecked original. Hosted output remains outside this code.

Additional limits: supported PEM headers are only PRIVATE, RSA, EC and OPENSSH.
ENCRYPTED, DSA, PGP and headerless key bodies are not recognized. Suppressed
exception chaining does not erase Python's in-memory `__context__`; callers must
not serialize raw exception objects. Split-across-writes, encoded, unknown and
binary values remain outside the claim.
