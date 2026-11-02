# dependency-guard

Reusable GitHub Actions for a narrow class of Dependabot updates. The gate can
queue patch and minor library updates for native GitHub auto-merge after fixed
cooldowns and required checks. It does not use AI review.

The gate reads Cargo and npm lockfiles as data. It rejects foreign or unverified
commits, unrelated files, new dependencies, major and 0.x-minor updates, young
releases, OSV findings, and newly introduced npm install scripts. Missing data
fails closed. GitHub Actions, Nix, Docker, Python, Terraform, and other update
types remain manual.

Start with [the adoption guide](docs/adopting.md), copy the templates, pin every
reference, and run dry-run mode for at least seven days. Live mode requires a
separate `guard-merger` GitHub App and a recorded [ruleset
proof](docs/ruleset-proof.md). The App only enables GitHub native auto-merge;
GitHub rulesets and required checks decide whether the PR can merge.

Run the offline test suite with:

```sh
python3 -m unittest discover -s tests -v
```

See [the threat model](docs/threat-model.md) for the boundary and residual risk.
