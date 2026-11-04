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
