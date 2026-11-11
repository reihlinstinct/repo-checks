# Isolated privacy action

Use actions/privacy at a reviewed full immutable commit SHA. The caller checks
out its own exact event commit with a pinned checkout action and
persist-credentials:false. Pass only the absolute checkout-root within
GITHUB_WORKSPACE. No credentials, token, policy, commands or baselines are inputs.

The action uses isolated Python and inserts only its own pinned source tree.
Caller PYTHONPATH, cwd modules, sitecustomize, Git helper config and GIT_* routing
cannot select code. The engine uses descriptor-relative bounded tracked reads.
Root aliases, symlink traversal, action/root overlap and workspace escapes fail.

Output is one validated JSON record with fixed category counts and coverage,
never source values, paths, error strings or fingerprints. Missing/malformed
output and invalid counts/status/schema fail closed. GITHUB_OUTPUT is written
as a single fixed-name JSON line to a regular non-symlink file. Exit status
propagates: pass0, findings1, error2. Do not swallow it in a caller pipeline.

No consumer changes in this PR. Next is one separately reviewed real shadow
consumer that keeps the old required guard. Only after remote proof should
individual public repositories adopt this gate. Findings require private
triage; never auto-baseline, loosen checks or publish source values to pass.
Binary/PDF/image contents still need review. Secret-sourced name enforcement uses the separate trusted private-names action documented in PRIVATE_NAME_GUARD.md.

The scanner includes an exact-token, exact-path public accessibility-contact
policy; see [scope and boundaries](PRIVACY_SCAN.md). Consumers cannot widen it
through action inputs. Pin the reviewed scanner version before using it.
