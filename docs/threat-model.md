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

1. The workflow run actor must be `dependabot[bot]`, read directly from the
   GitHub Actions context, and the PR must have exactly one commit. That commit
   must be authored by `dependabot[bot]` and GitHub-verified.
1. Only configured manifests and lockfiles may change.
1. Every changed resolved package, including transitives, is checked for update
   type, registry age, and OSV findings. New packages are ineligible.
1. The shorter security cooldown applies only to an exact Dependabot-advised
   package when the new version exactly equals an OSV `fixed` event for a
   vulnerability reported on the old version and absent from the new version.
   GHSA/alert metadata is ignored; later releases and all other packages keep
   their normal cooldown.
1. Registry, OSV, metadata, and parse failures fail closed.
1. npm packages that gain an install script are ineligible.
1. Changed and added npm entries must resolve from the HTTPS npmjs registry and
   include lockfile integrity data; git, file, HTTP, alternate, and missing
   sources are ineligible.
1. npm workspace-link entries are ignored only while unchanged. Adding,
   removing, or changing a `link: true` entry is ineligible.
1. npm non-`node_modules/` workspace target entries are ignored only while
   unchanged. Adding, removing, or changing one is ineligible.
1. Changed and added Cargo entries must use a canonical crates.io source.
   Git/alternate-registry entries and any changed, added, or removed local
   workspace/path package are ineligible.
1. Third-party actions and caller references are pinned to full commit SHAs.
1. The gate validates GitHub OIDC `job_workflow_ref` and `job_workflow_sha`
   claims before it checks out executable code from the called workflow repo.
   `id-token: write` is used solely to read `job_workflow_sha`; non-Dependabot
   PRs return `not-dependency` before any OIDC request or checkout. Missing or
   invalid OIDC on a Dependabot PR is ineligible and still reaches disarm.
1. `--match-head-commit` prevents a verdict from being reused after the PR head
   changes. The automerge job also reads `headRefOid` immediately before
   enabling auto-merge and fails if it no longer matches the evaluated SHA.
1. The retry job only re-runs the gate already defined on the base branch for
   the PR's current head and never checks out or executes PR code; its label is
   advisory and cannot make a PR eligible.
1. The gate job alone receives `issues: write` and `pull-requests: write` on its
   `GITHUB_TOKEN`. It uses issues write only to create the advisory cooldown
   label, and pull-request write only to reconcile that label or query and
   disable an existing auto-merge request after a non-eligible Dependabot
   verdict. Label failures are warning-only. Query or revocation failure fails
   the required gate, and revocation runs inside that job so a later job cannot
   race the required check turning green. After revocation, the gate posts one
   best-effort PR comment with the verdict and first reason; comment failure
   does not hide a successful revocation or fail the job.
1. The App may bypass the review ruleset only in pull-request mode. It has no
   bypass on the required-checks ruleset, so it cannot merge a failing PR.
1. Live mode requires a recorded ruleset proof. Dry-run is the default.

## Residual risk

An actor with repository write access can still do anything that write access
allows. Requiring Dependabot as the workflow actor and a single commit closes
this gate's auto-merge-without-review path for a forged Dependabot-authored
commit; it does not reduce the actor's underlying repository authority.

An aged package can be healthy according to its registry and OSV while still
containing a malicious payload. A registry, maintainer, GitHub, OSV, or pinned
action compromise can also defeat assumptions outside this repository. The
cooldown reduces exposure to newly reported incidents; it does not prove code
is safe.

The gate does not inspect package source, run package code, review behavior, or
prove that CI tests are sufficient. It also does not make deployment safe.
Adopters own canaries, rollback, backups, and production release controls. Do
not run live mode against a production deploy path until those exist.

App credential theft gives the attacker the App's installation permissions.
Keep installation scope narrow, store credentials only as GitHub Dependabot
secrets, rotate the private key, and rely on the no-bypass checks ruleset as the
independent merge boundary.
