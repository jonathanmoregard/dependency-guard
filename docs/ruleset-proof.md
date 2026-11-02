# Ruleset proof

This proof is a human/admin step. It is blocked until Jonathan creates the
`guard-merger` App and configures the two rulesets. Run it in the private
`jonathanmoregard/dependency-guard-scratch` repository, then retain the command
output and PR links under a proof record ID such as
`dependency-guard-scratch-2026-11-02-01`.

## Setup

1. Install `guard-merger` on the scratch repository with only Contents read/write
   and Pull requests read/write; leave webhooks disabled.
1. Create the reviews ruleset with `guard-merger` bypass in `pull_request` mode.
1. Create a separate required-checks ruleset with no App bypass. Require a
   controllable scratch check and the dependency gate.
1. Copy and SHA-pin the caller workflow. Start in `dry-run`, observe one full
   run, then temporarily use `live` with a provisional proof string for these
   tests.
1. Before and after each test, run
   `scripts/dump-effective-rules.sh jonathanmoregard/dependency-guard-scratch main`
   and save the JSON with the PR URL and head SHA.

## Tests

1. **Failing required check:** open an otherwise eligible dependency PR and make
   the scratch required check fail. The App may request auto-merge, but the PR
   must not merge. A direct App merge attempt must also be rejected.
1. **Stale review:** approve a PR, then push a new commit so the review is stale.
   Confirm the App's review-rules bypass works only through the PR merge path;
   required checks must still rerun and pass for the new head before merge.
1. **Workflow-file PR:** open a PR changing `.github/workflows/`. The dependency
   gate must be red or ineligible and `guard-merger` must not act. With a failing
   required check, a direct App merge attempt must fail.
1. **Direct App merge attempt:** using a short-lived App installation token,
   try to merge a PR whose required check is failing. Record GitHub's rejection.
   Then make the check pass and confirm native auto-merge merges only the exact
   evaluated head SHA.

The proof passes only if the App cannot push to the protected branch, cannot
bypass required checks, and cannot merge a different head from the one gated.
Remove the provisional live caller after the test. Deleting the scratch
repository requires separate owner approval.
