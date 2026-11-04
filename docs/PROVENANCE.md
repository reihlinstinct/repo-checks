# Initial engine provenance

MIT engine from https://github.com/reihlinstinct/collaboration-docs,
scripts/security/scorecard_guard.py, copied byte-identically. Tests change only
import target to src/repo_checks/scorecard.py. 46 source tests pass locally.

SHA-256 of copied engine, colon-grouped hex (remove colons for digest):
`a7f2:0175:0c16:6680:2239:366f:a238:9f6e:c6ab:c7c6:b737:2912:3d79:7862:78c9:84d1`

The bootstrap engine was byte-identical at its initial PR. The later bounded
wrapper PR adds an optional finding sink and makes duplicate-key iteration lazy
to stop Finding allocation at the cap. Existing rule semantics and baseline
fingerprints stay unchanged; normalized findings were compared on three current
repository trees. The checksum above identifies the original, not the sink edit.
