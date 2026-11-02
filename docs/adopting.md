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
record the **Client ID** (shown under About on the App page; it starts with `Iv`, and is not the numeric App ID).

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

1. `GUARD_MERGER_CLIENT_ID`
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
it is used solely to read the called workflow's OIDC `job_workflow_sha` claim
before checking out executable code. Human and fork PRs short-circuit to
`not-dependency` without requesting OIDC or checking out any repository. If a
Dependabot run cannot obtain or validate the identity token, it becomes
ineligible and the gate still revokes any stale auto-merge request. The gate's
`GITHUB_TOKEN` has issues write permission only to ensure the cooldown label
exists and pull-request write permission only to reconcile that label or revoke
stale auto-merge.

The caller retries cooldown-only verdicts every six hours and can also be run
with manual workflow dispatch. The gate auto-creates the advisory
`dependency-guard:cooldown` label used to find those PRs. Keep `actions: write`
on the caller's `retry` job so it can re-run the existing gate workflow.

Keep `mode: dry-run` for at least seven days. Check that every eligible PR gets
the label, every unsupported or major update stays manual, and every red result
fails the required gate. Then set `mode: live` and set `ruleset-proof` to the
proof record ID. Live mode fails if the proof ID or either App secret is empty.

Only npm packages resolved from `https://registry.npmjs.org/` with lockfile
integrity data are eligible. A changed or added git, file, plain-HTTP,
alternate-registry, unresolved, or integrity-free npm entry stays manual.
Unchanged npm workspace links (`"link": true`) are ignored; adding, removing,
or changing a workspace-link entry stays manual. Non-`node_modules/` workspace
target entries are also ignored only while unchanged; adding, removing, or
changing one stays manual.

Only Cargo packages from crates.io's canonical git index or sparse index are
eligible. Changed or added git and alternate-registry packages stay manual, as
does any added, removed, or changed workspace/path package without a `source`.

The shorter security cooldown is deterministic and package-specific. For an
exact package name reported by Dependabot metadata, OSV must report at least
one vulnerability for the old version that it no longer reports for the new
version, and the new version must exactly equal that vulnerability record's
`fixed` event. A later release does not inherit the shortened cooldown. GHSA
metadata fields are not used. Every other changed package keeps its normal
patch/minor cooldown, and an OSV error keeps the normal cooldown while also
making the gate ineligible.
