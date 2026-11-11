# repo-checks

Pinned, local checks for repositories. Initial scope: a shared offline Scorecard
regression engine and its existing synthetic test vectors. It does not replace
OpenSSF Scorecard, SAST, privacy review or language-specific tests.

Status: implementation pilot, not deployed to consumers. Engine configuration and
baselines remain local to each consumer. No credentials or network needed.

```sh
python3 -m unittest discover -s tests/security -v
python3 src/repo_checks/scorecard.py --root /path/to/consumer
```

The initial engine preserves the source behavior for shadow comparison. Its
legacy CLI prints finding evidence, so the future consumer action must call a
value-free wrapper, never use `--inventory` or echo arbitrary findings in public
CI. No action/workflow consumer rollout is included in the bootstrap.

See [design](docs/DESIGN.md) and [contributing](CONTRIBUTING.md).

## Privacy gate pilot

`python3 -I tools/privacy_scan.py --root /path/to/checkout` runs a bounded,
offline, counts-only tracked-text pattern check. CI runs it on this repository.
It does not certify privacy or inspect binary/PDF/image contents. Consumer rollout
requires a separately reviewed pinned action and shadow pilot, not copy-pasted
inline grep. See [scope, limits and exit codes](docs/PRIVACY_SCAN.md).

The [isolated privacy action](docs/PRIVACY_ACTION.md) is the consumer boundary.
Pin the reviewed action commit, retain existing guards during the first shadow
pilot, and do not treat mocked/local tests as real consumer proof.


## Authenticated name guard (staged)

The [HMAC name guard](docs/PRIVATE_NAME_GUARD.md) accepts an authenticated keyed
policy and uses deterministic public work caps and a two-pass matcher. This is a
synthetic-only implementation stage. The existing reusable workflow remains pinned
to the earlier scanner; new secret forwarding and landed pins require a separate
reviewed integration change. No actual policy conversion or consumer rollout is
included. Run the generated-corpus end-to-end measurement with:

```sh
python3 -I tools/benchmark_bounded_name_scan.py
```

## Secret-only controlled output and text gate

The [secret-output APIs and blocking text action](docs/SECRET_OUTPUT.md) provide
bounded block/redact helpers and a dedicated token-only check. They do not
intercept hosted transcripts or mail automatically. Coverage requires explicit
integration before each controlled output. Binary and unknown/encoded token
formats remain outside the text-only recognition scope. Existing privacy/name
checks are separate; no consumer settings are changed by this implementation.
