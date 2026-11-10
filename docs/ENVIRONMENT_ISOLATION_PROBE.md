# Synthetic environment isolation probe

Temporary unmerged verification only. The environment permits the exact default
branch and no tags. This branch tests both push/candidate and PR merge refs.

Expected result: GitHub rejects the environment deployment before a runner or
step starts. This workflow receives a synthetic probe secret only, never the
real private-name policy. No checkout, code execution from a candidate, uploads,
external calls or secret output occur. If a step starts, the proof fails even
if the workflow ultimately fails. Close without merging after recording results.
