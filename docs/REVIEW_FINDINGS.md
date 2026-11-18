# Review findings evidence gate

Tracks repo-checks issue64 and collaboration-docs issue78. Applies to non-trivial findings from every reviewer, including human and automated reviews. This implementation is a candidate until independent review, real CI and pinned consumer adoption complete.

## The rule

Track every non-trivial finding in an issue labeled `review-finding`, link that issue in the PR body or a PR issue comment/review, and record evidence in `docs/review-findings/pr-N.json`. Include automated regression paths and normal CI workflow/command, with original-behavior failure or a controlled mutation and fixed-behavior pass evidence. A follow-up PR is allowed for a genuinely nonblocking finding, with its own issue and visible partial status. Security/material findings stay blocking under the existing merge gate.

If faithful automation is impossible, declare `manual-limit` with an owner, reason, concrete checklist and remaining automatable portion. This is visible limitation tracking, not automatic risk acceptance. Maintainers still decide whether manual evidence is sufficient. No real incidents, secrets or private source material belong in fixtures or manifests.

## What is actually enforced

The stdlib action reads the current PR body, up to100 issue comments, up to100 reviews, and at most30 referenced same-repository issues. References can use `#N` or an observed GitHub issue URL. A same-repository issue carrying the `review-finding` label requires one manifest entry, whether open or closed. Duplicate/extra/missing entries, bad identity, absent files, traversal and symlink paths, malformed JSON, missing evidence text or empty manual limitations fail. A PR without labeled linked findings must explicitly state `Review-findings: none`, or carry an empty valid manifest.

The check never imports consumer modules, executes a declared test command, evaluates Markdown, checks out submodules/LFS, or follows redirects. API failure, pagination, size/request bounds and head drift fail closed. Output is counts-only. Use only the read-only `GITHUB_TOKEN`, never a personal token. Ubuntu's preinstalled Python is sufficient; no dependency install, browser or paid service. Normal run budget is two minutes with concurrency cancelling superseded PR runs.

**Limits:** this cannot prove test semantics, prove a described command is actually wired into a job, prove CI evidence text is truthful, or discover findings nobody labels/links. Files and workflow paths are checked, not their meaning. Reviewers must verify failing-before/passing-after evidence, real CI wiring and completeness. Cross-repository finding issues require a local tracking issue. Inline review-thread comments are not exhaustively fetched: link each finding issue in the PR body/issue comments/review summary. The label can be added by maintainers after review; rerun the PR check after changing metadata. Metadata edits do not automatically invalidate an already-completed check. Branch protection requiring this status is a separate settings decision, not silently changed here.

## Manifest shape

The manifest has exactly `version` (integer1), `repository` (owner/repo), `pull_request` (integerN) and `findings` (array). Each entry has `issue` (positive integer), `mode`, `review_url` (GitHub review reference), `affected_head` (40hex), and `summary`.

For mode `automated`, also include:
- `regression_paths`: one or more real relative test/lint files.
- `workflow`: an existing `.github/workflows/*.yml` or `.yaml` file.
- `command`: a description of the normal CI command. Never executed by this gate.
- `negative_control`: original-failure or controlled mutation evidence.
- `pass_evidence`: fixed-result evidence and real CI result reference.

For mode `manual-limit`, instead include:
- `reason`, `owner`, `remaining_automation`: substantive text.
- `checklist`: nonempty list of concrete manual verification steps.

No extra fields are accepted. Manifests must remain under256KiB. Do not copy external instructions or sensitive evidence into them.

## Deployment order

1. Review this action and negative tests independently; run shared-repo CI.
2. Publish its immutable implementation commit. Generate the reusable workflow from the template below, replacing `IMPLEMENTATION_SHA` with that real40hex SHA, then review/merge the workflow commit. Do not use a branch/tag or self-referential unpinned checkout.
3. Consumer owners add a cheap PR job calling the reusable workflow at its reviewed40hex commit, retain existing checks and add their explicit-none or mapped manifest.
4. Record adoption PR, exact head, real positive/negative check outcome and remaining limits for every public consumer. Never claim every repo is protected from a shared implementation alone. Private/frozen consumers require separate scope and budget review.

Reusable workflow template, to be committed as `.github/workflows/review-findings.yml` only after substituting the real implementation SHA:

```yaml
name: Review findings
on:
  workflow_call:
permissions:
  contents: read
  issues: read
  pull-requests: read
jobs:
  evidence:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-24.04
    timeout-minutes: 2
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
          submodules: false
          lfs: false
          path: consumer
      - uses: reihlinstinct/repo-checks/actions/review-findings@IMPLEMENTATION_SHA
        with:
          root: consumer
          repository: ${{ github.repository }}
          pull-request: ${{ github.event.pull_request.number }}
          head: ${{ github.event.pull_request.head.sha }}
          token: ${{ github.token }}
```

Do not use `pull_request_target`, secrets inheritance or consumer-code execution. New commits trigger checks normally; schedule no periodic polling. Re-runs after new review metadata are a required maintainer step until a separately reviewed metadata-triggered trusted workflow is added.

## Tests

`python3 -m unittest discover -s tests/security -p test_review_findings.py -v`

The normal shared CI discovers these tests in `tests/security`. Negative cases cover missing mappings, identity/schema/path failures, duplicate/oversize JSON, bad issue references, absent token, synthetic metadata discovery and non-execution of consumer commands. Mocked metadata tests are not real GitHub API proof or consumer rollout proof.
