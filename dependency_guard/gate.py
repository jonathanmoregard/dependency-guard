"""Evaluate dependency PRs and expose the evaluator as a CLI."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path, PurePosixPath
import sys
from typing import Iterable

from .lockdiff import LockfileError, PackageChange, diff_lockfiles
from .registry import HttpRegistry, OsvVulnerability, Registry
from .rules import classify_update


DEPENDABOT = "dependabot[bot]"
SUPPORTED = {"cargo", "npm"}
ECOSYSTEM_ALIASES = {
    "cargo": "cargo",
    "npm": "npm",
    "npm_and_yarn": "npm",
}
LOCKFILES = {"cargo": "Cargo.lock", "npm": "package-lock.json"}
MANIFESTS = {"cargo": "Cargo.toml", "npm": "package.json"}


@dataclass(frozen=True)
class PackageVerdict:
    ecosystem: str
    name: str
    old: str | None
    new: str
    update_type: str | None


@dataclass(frozen=True)
class GateResult:
    verdict: str
    reasons: list[str]
    packages: list[PackageVerdict]

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "reasons": self.reasons,
            "packages": [asdict(package) for package in self.packages],
        }

    def markdown(self) -> str:
        lines = ["## dependency-guard", "", f"Verdict: **{self.verdict}**", ""]
        if self.reasons:
            lines.append("Reasons:")
            lines.extend(f"1. {reason}" for reason in self.reasons)
        else:
            lines.append("No blocking reasons.")
        if self.packages:
            lines.extend(["", "Packages:"])
            for package in self.packages:
                old = package.old or "(new)"
                lines.append(
                    f"1. `{package.ecosystem}:{package.name}` {old} → "
                    f"{package.new} ({package.update_type or 'ineligible'})"
                )
        return "\n".join(lines) + "\n"


def _flatten_api_pages(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("GitHub API data must be an array")
    if value and all(isinstance(item, list) for item in value):
        return [entry for page in value for entry in page]
    return value


def _normalized_dir(value: str) -> PurePosixPath:
    path = PurePosixPath(value or ".")
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("ecosystem directories must be relative")
    return path


def _repo_path(directory: str, filename: str) -> str:
    path = _normalized_dir(directory)
    return filename if str(path) == "." else str(path / filename)


def _metadata_names(metadata: dict[str, object]) -> set[str]:
    value = metadata.get("dependency-names", "")
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return {
        item.strip()
        for item in str(value).replace("\n", ",").split(",")
        if item.strip()
    }


def _commits_are_trusted(commits: Iterable[object]) -> bool:
    found = False
    for commit in commits:
        found = True
        if not isinstance(commit, dict):
            return False
        author = commit.get("author")
        details = commit.get("commit")
        if not isinstance(author, dict) or author.get("login") != DEPENDABOT:
            return False
        if not isinstance(details, dict):
            return False
        verification = details.get("verification")
        if not isinstance(verification, dict) or verification.get("verified") is not True:
            return False
    return found


def _osv_vulns(
    registry: Registry,
    ecosystem: str,
    name: str,
    version: str,
    red_reasons: list[str],
    ineligible_reasons: list[str],
    *,
    reject_findings: bool,
) -> dict[str, OsvVulnerability] | None:
    try:
        vulnerabilities = {
            vulnerability.vulnerability_id: vulnerability
            for vulnerability in registry.osv_vulns(ecosystem, name, version)
        }
    except Exception:
        ineligible_reasons.append(
            f"could not verify OSV for {ecosystem}:{name}@{version}"
        )
        return None
    if reject_findings and vulnerabilities:
        red_reasons.append(
            f"OSV reports {', '.join(sorted(vulnerabilities))} for "
            f"{ecosystem}:{name}@{version}"
        )
    return vulnerabilities


def evaluate_gate(
    *,
    pr_author: str,
    actor: str,
    commits: list[object],
    changed_files: list[str],
    base_root: str | Path,
    head_root: str | Path,
    ecosystem_dirs: dict[str, str],
    metadata: dict[str, object],
    registry: Registry,
    now: datetime,
    patch_days: int = 3,
    minor_days: int = 7,
    security_hours: int = 8,
) -> GateResult:
    if pr_author != DEPENDABOT:
        return GateResult("not-dependency", ["PR author is not Dependabot"], [])

    red_reasons: list[str] = []
    ineligible_reasons: list[str] = []
    package_results: list[PackageVerdict] = []
    if actor != DEPENDABOT:
        red_reasons.append(f"pushed by {actor or 'unknown'}, not Dependabot")
    if len(commits) > 1:
        red_reasons.append("more than one commit")
    if not _commits_are_trusted(commits):
        red_reasons.append("a commit is not Dependabot-authored and GitHub-verified")

    raw_ecosystem = str(metadata.get("package-ecosystem", "")).strip().lower()
    ecosystem = ECOSYSTEM_ALIASES.get(raw_ecosystem)
    if ecosystem not in SUPPORTED:
        ineligible_reasons.append(
            f"unsupported ecosystem: {raw_ecosystem or 'unknown'}"
        )
        verdict = "red" if red_reasons else "ineligible"
        return GateResult(verdict, red_reasons + ineligible_reasons, [])

    directory = ecosystem_dirs.get(ecosystem, ".")
    allowed = {
        _repo_path(directory, MANIFESTS[ecosystem]),
        _repo_path(directory, LOCKFILES[ecosystem]),
    }
    unexpected = sorted(set(changed_files) - allowed)
    if unexpected:
        red_reasons.append(
            "non-manifest/lockfile changes: " + ", ".join(unexpected)
        )

    base_path = Path(base_root) / _repo_path(directory, LOCKFILES[ecosystem])
    head_path = Path(head_root) / _repo_path(directory, LOCKFILES[ecosystem])
    try:
        lock_diff = diff_lockfiles(ecosystem, base_path, head_path)
    except (LockfileError, OSError, ValueError):
        red_reasons.append(f"could not parse {LOCKFILES[ecosystem]}")
        return GateResult("red", red_reasons + ineligible_reasons, [])

    ineligible_reasons.extend(lock_diff.ineligible_reasons)

    advised_names = _metadata_names(metadata)

    for package in lock_diff.added:
        package_results.append(
            PackageVerdict(package.ecosystem, package.name, None, package.version, None)
        )
        ineligible_reasons.append(
            f"added package: {package.ecosystem}:{package.name}@{package.version}"
        )
        _osv_vulns(
            registry,
            package.ecosystem,
            package.name,
            package.version,
            red_reasons,
            ineligible_reasons,
            reject_findings=True,
        )

    for change in lock_diff.changed:
        update_type = classify_update(change.old, change.new)
        package_results.append(
            PackageVerdict(
                change.ecosystem, change.name, change.old, change.new, update_type
            )
        )
        new_vulnerabilities = _osv_vulns(
            registry,
            change.ecosystem,
            change.name,
            change.new,
            red_reasons,
            ineligible_reasons,
            reject_findings=True,
        )
        security_update = False
        if change.name in advised_names:
            old_vulnerabilities = _osv_vulns(
                registry,
                change.ecosystem,
                change.name,
                change.old,
                red_reasons,
                ineligible_reasons,
                reject_findings=False,
            )
            security_update = (
                old_vulnerabilities is not None
                and new_vulnerabilities is not None
                and any(
                    vulnerability_id not in new_vulnerabilities
                    and change.new in vulnerability.fixed_versions
                    for vulnerability_id, vulnerability in old_vulnerabilities.items()
                )
            )
        if update_type is None:
            ineligible_reasons.append(
                f"non-semver or non-forward update: {change.name} "
                f"{change.old} → {change.new}"
            )
            continue
        if update_type == "major":
            ineligible_reasons.append(
                f"major-equivalent update: {change.name} {change.old} → {change.new}"
            )
            continue
        if (
            change.ecosystem == "npm"
            and not change.old_has_install_script
            and change.new_has_install_script
        ):
            ineligible_reasons.append(
                f"npm package gained an install script: {change.name}@{change.new}"
            )
        cooldown = timedelta(days=patch_days if update_type == "patch" else minor_days)
        if security_update:
            cooldown = timedelta(hours=security_hours)
        try:
            published = registry.publish_time(
                change.ecosystem, change.name, change.new
            )
            if published.tzinfo is None:
                raise ValueError("publish time is not timezone-aware")
            if now.astimezone(timezone.utc) - published.astimezone(timezone.utc) < cooldown:
                ineligible_reasons.append(
                    f"{change.name}@{change.new} has not completed its "
                    f"{int(cooldown.total_seconds() // 3600)}h cooldown"
                )
        except Exception:
            ineligible_reasons.append(
                f"could not verify publish time for "
                f"{change.ecosystem}:{change.name}@{change.new}"
            )

    if not lock_diff.changed and not lock_diff.added:
        ineligible_reasons.append("no changed resolved packages to verify")
    if red_reasons:
        verdict = "red"
    elif ineligible_reasons:
        verdict = "ineligible"
    else:
        verdict = "eligible"
    return GateResult(verdict, red_reasons + ineligible_reasons, package_results)


def _read_json(path: str, *, pages: bool = False) -> object:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return _flatten_api_pages(value) if pages else value


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a dependency update PR")
    parser.add_argument("--pr-author", default=os.environ.get("PR_AUTHOR"))
    parser.add_argument("--actor", default=os.environ.get("ACTOR"))
    parser.add_argument("--commits-file", default=os.environ.get("COMMITS_FILE"))
    parser.add_argument(
        "--changed-files-file", default=os.environ.get("CHANGED_FILES_FILE")
    )
    parser.add_argument("--metadata-file", default=os.environ.get("METADATA_FILE"))
    parser.add_argument("--base-root", default=os.environ.get("BASE_ROOT"))
    parser.add_argument("--head-root", default=os.environ.get("HEAD_ROOT"))
    parser.add_argument("--cargo-dir", default=os.environ.get("CARGO_DIR", "."))
    parser.add_argument("--npm-dir", default=os.environ.get("NPM_DIR", "."))
    parser.add_argument(
        "--patch-days", type=int, default=int(os.environ.get("PATCH_DAYS", "3"))
    )
    parser.add_argument(
        "--minor-days", type=int, default=int(os.environ.get("MINOR_DAYS", "7"))
    )
    parser.add_argument(
        "--security-hours",
        type=int,
        default=int(os.environ.get("SECURITY_HOURS", "8")),
    )
    parser.add_argument("--now", default=os.environ.get("NOW"))
    parser.add_argument(
        "--summary-file", default=os.environ.get("GITHUB_STEP_SUMMARY")
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    required = {
        "pr-author": args.pr_author,
        "actor": args.actor,
        "commits-file": args.commits_file,
        "changed-files-file": args.changed_files_file,
        "base-root": args.base_root,
        "head-root": args.head_root,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit("missing inputs: " + ", ".join(missing))
    commits = _read_json(args.commits_file, pages=True)
    changed_entries = _read_json(args.changed_files_file, pages=True)
    changed_files = []
    for entry in changed_entries:
        if isinstance(entry, str):
            changed_files.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("filename"), str):
            changed_files.append(entry["filename"])
        else:
            raise SystemExit("changed-files input is invalid")
    metadata: dict[str, object] = {}
    if args.metadata_file:
        loaded = _read_json(args.metadata_file)
        if not isinstance(loaded, dict):
            raise SystemExit("metadata input must be an object")
        metadata = loaded
    now = (
        datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        if args.now
        else datetime.now(timezone.utc)
    )
    result = evaluate_gate(
        pr_author=args.pr_author,
        actor=args.actor,
        commits=commits,
        changed_files=changed_files,
        base_root=args.base_root,
        head_root=args.head_root,
        ecosystem_dirs={"cargo": args.cargo_dir, "npm": args.npm_dir},
        metadata=metadata,
        registry=HttpRegistry(),
        now=now,
        patch_days=args.patch_days,
        minor_days=args.minor_days,
        security_hours=args.security_hours,
    )
    print(json.dumps(result.as_dict(), sort_keys=True))
    if args.summary_file:
        with Path(args.summary_file).open("a", encoding="utf-8") as handle:
            handle.write(result.markdown())
    return 1 if result.verdict == "red" else 0


if __name__ == "__main__":
    sys.exit(main())
