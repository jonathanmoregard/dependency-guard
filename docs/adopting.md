# Adopting dependency-guard

Use a scratch repository first. Do not enable live mode until the ruleset proof
has passed and dry-run results have been reviewed for at least seven days.

## 1. Create the merge App

Create a GitHub App named `guard-merger` with exactly these repository
permissions:

1. **Contents: Read and write**.
1. **Pull requests: Read and write**.

Give it no other account or repository permission and no webhook. Install it
only on repositories that will use dependency-guard. Generate a private key and
record the App ID.

## 2. Split the rulesets

Create two active branch rulesets for the default branch:

1. A **reviews ruleset** containing pull-request/review requirements. Add
   `guard-merger` as a bypass actor in `pull_request` mode. Do not grant an
   always-bypass or push bypass.
1. A **checks ruleset** containing every required CI and security check,
   including the dependency gate. Give `guard-merger` **no bypass** on this
   ruleset.

Require squash merging and enable repository auto-merge. Protect workflow-file
changes with the same required checks; dependency-guard itself makes those PRs
ineligible or red.

Follow [the proof procedure](ruleset-proof.md) before recording a proof ID in a
live caller workflow.

## 3. Store Dependabot secrets

Copy the App values into the adopting repository as **Dependabot secrets**:

1. `GUARD_MERGER_APP_ID`
1. `GUARD_MERGER_PRIVATE_KEY`

`pull_request` workflows started by Dependabot can read Dependabot secrets, not
ordinary Actions secrets. Do not use `pull_request_target`, `secrets: inherit`,
or any agent-accessible credential store.

Create the repository label `dependency-guard:would-merge` for dry-run results.

## 4. Allow and pin the workflows

If the repository belongs to an organization with an Actions allow-list, allow:

```text
jonathanmoregard/dependency-guard/*
```

Copy `templates/dependency-guard.yml` to
`.github/workflows/dependency-guard.yml`, replace both `TODO-PIN` values with
the reviewed release commit SHA, and copy `templates/dependabot.yml` to
`.github/dependabot.yml`. Adjust only the ecosystem directories and cooldown
inputs needed by the repository. Keep the caller's `id-token: write` permission:
the gate requests a token with audience `dependency-guard` and validates its
`job_workflow_ref` and `job_workflow_sha` claims before checking out executable
code. Its `GITHUB_TOKEN` still has read-only repository permissions.

Keep `mode: dry-run` for at least seven days. Check that every eligible PR gets
the label, every unsupported or major update stays manual, and every red result
fails the required gate. Then set `mode: live` and set `ruleset-proof` to the
proof record ID. Live mode fails if the proof ID or either App secret is empty.
