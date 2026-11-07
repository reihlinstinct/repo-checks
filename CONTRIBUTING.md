# Contributing

Open an issue and state file placement before coding. Design/security-boundary
changes need a design note and Mermaid diagram first. Keep engines in
src/repo_checks, adapters in tools or actions, tests in tests, documentation in
docs, workflow glue in .github/workflows. No new root code files.

Use only synthetic fixtures. No personal data, secrets, copied production
baselines or payload artifacts. Do not weaken local consumer policies to pass.
Small focused commits and PRs, exact-head independent review, green real CI,
normal signed squash merge, no bypass. Do not claim skipped tests ran.

Consumer pins use full immutable commit SHAs. No mutable nested actions, remote
script execution, runtime dependencies or privileged untrusted-PR execution.

## File placement (enforced)

Decide where a file lives BEFORE creating it. The contract in `.repo-layout.yml` lists the allowed top-level directories, the file types permitted in each, and the required community-standards files; `python3 tools/check_repo_layout.py` enforces it in CI. A new kind of file means updating the contract in the same PR.
