# Threat model

## Boundary

`dependency-guard` handles one class of change: Dependabot-authored Cargo and
npm patch/minor updates. Lockfiles from the pull request are untrusted data. The
gate implementation comes from the pinned reusable-workflow revision, never
from the pull request checkout. Human pull requests return `not-dependency`.

The `guard-merger` GitHub App is the only merge authority used by this system.
It enables GitHub native auto-merge for an exact, already evaluated head SHA.
It is not an agent identity and has no webhook. Agents must not receive its App
ID/private key or installation token.

## Controls

1. Every PR commit must be authored by `dependabot[bot]` and GitHub-verified.
1. Only configured manifests and lockfiles may change.
1. Every changed resolved package, including transitives, is checked for update
   type, registry age, and OSV findings. New packages are ineligible.
1. Registry, OSV, metadata, and parse failures fail closed.
1. npm packages that gain an install script are ineligible.
1. Third-party actions and caller references are pinned to full commit SHAs.
1. The gate validates GitHub OIDC `job_workflow_ref` and `job_workflow_sha`
   claims before it checks out executable code from the called workflow repo.
1. `--match-head-commit` prevents a verdict from being reused after the PR head
   changes.
1. The App may bypass the review ruleset only in pull-request mode. It has no
   bypass on the required-checks ruleset, so it cannot merge a failing PR.
1. Live mode requires a recorded ruleset proof. Dry-run is the default.

## Residual risk

An aged package can be healthy according to its registry and OSV while still
containing a malicious payload. A registry, maintainer, GitHub, OSV, or pinned
action compromise can also defeat assumptions outside this repository. The
cooldown reduces exposure to newly reported incidents; it does not prove code
is safe.

The gate does not inspect package source, run package code, review behavior, or
prove that CI tests are sufficient. It also does not make deployment safe.
Adopters own canaries, rollback, backups, and production release controls. For
Klaffat those controls are deferred to the ECS migration in issue #20; live
unattended production dependency merges remain blocked until that work is done.

App credential theft gives the attacker the App's installation permissions.
Keep installation scope narrow, store credentials only as GitHub Dependabot
secrets, rotate the private key, and rely on the no-bypass checks ruleset as the
independent merge boundary.
