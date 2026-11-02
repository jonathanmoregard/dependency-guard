"""Parse supported lockfiles as data and produce deterministic diffs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tomllib


CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}
LOCAL_CARGO_SOURCE = "path"


class LockfileError(ValueError):
    """A lockfile could not be parsed or did not have the expected shape."""


@dataclass(frozen=True)
class LockedPackage:
    ecosystem: str
    name: str
    version: str
    identity: str
    has_install_script: bool = False
    resolved: str | None = None
    integrity: str | None = None
    workspace_link: bool = False
    workspace_package: bool = False
    entry_fingerprint: str | None = None


@dataclass(frozen=True)
class PackageChange:
    ecosystem: str
    name: str
    old: str
    new: str
    identity: str
    old_has_install_script: bool = False
    new_has_install_script: bool = False


@dataclass(frozen=True)
class LockDiff:
    changed: list[PackageChange]
    added: list[LockedPackage]
    removed: list[LockedPackage]
    ineligible_reasons: list[str]


def _read_cargo(path: Path) -> dict[tuple[str, str], list[LockedPackage]]:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
        packages = document.get("package", [])
        if not isinstance(packages, list):
            raise LockfileError("Cargo.lock package must be an array")
        result: dict[tuple[str, str], list[LockedPackage]] = {}
        for package in packages:
            if not isinstance(package, dict):
                raise LockfileError("Cargo.lock contains an invalid package")
            name = package.get("name")
            version = package.get("version")
            source = package.get("source", LOCAL_CARGO_SOURCE)
            if not all(isinstance(value, str) for value in (name, version, source)):
                raise LockfileError("Cargo.lock package identity is incomplete")
            fingerprint = json.dumps(
                {
                    key: value
                    for key, value in package.items()
                    if key != "dependencies"
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            locked = LockedPackage(
                "cargo",
                name,
                version,
                source,
                entry_fingerprint=fingerprint,
            )
            result.setdefault((name, source), []).append(locked)
        return result
    except (OSError, tomllib.TOMLDecodeError, LockfileError) as error:
        if isinstance(error, LockfileError):
            raise
        raise LockfileError(f"could not parse {path.name}") from error


def _npm_name(path: str, package: dict[str, object]) -> str:
    explicit = package.get("name")
    if isinstance(explicit, str) and explicit:
        return explicit
    if "node_modules/" not in path:
        return path
    return path.rsplit("node_modules/", 1)[-1]


def _read_npm(path: Path) -> dict[str, LockedPackage]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("lockfileVersion") not in (2, 3):
            raise LockfileError("package-lock.json must use lockfileVersion 2 or 3")
        packages = document.get("packages")
        if not isinstance(packages, dict):
            raise LockfileError("package-lock.json packages must be an object")
        result: dict[str, LockedPackage] = {}
        for package_path, package in packages.items():
            if package_path == "":
                continue
            if not isinstance(package_path, str) or not isinstance(package, dict):
                raise LockfileError("package-lock.json contains an invalid package")
            name = _npm_name(package_path, package)
            fingerprint = json.dumps(package, sort_keys=True, separators=(",", ":"))
            if "node_modules/" not in package_path:
                version = package.get("version")
                result[package_path] = LockedPackage(
                    "npm",
                    name,
                    version if isinstance(version, str) else "",
                    package_path,
                    workspace_package=True,
                    entry_fingerprint=fingerprint,
                )
                continue
            if package.get("link") is True:
                result[package_path] = LockedPackage(
                    "npm",
                    name,
                    "",
                    package_path,
                    workspace_link=True,
                    entry_fingerprint=fingerprint,
                )
                continue
            version = package.get("version")
            if not isinstance(version, str):
                raise LockfileError("package-lock entry has no version")
            resolved = package.get("resolved")
            integrity = package.get("integrity")
            result[package_path] = LockedPackage(
                "npm",
                name,
                version,
                package_path,
                has_install_script=package.get("hasInstallScript") is True,
                resolved=resolved if isinstance(resolved, str) else None,
                integrity=integrity if isinstance(integrity, str) else None,
                entry_fingerprint=fingerprint,
            )
        return result
    except (OSError, UnicodeError, json.JSONDecodeError, LockfileError) as error:
        if isinstance(error, LockfileError):
            raise
        raise LockfileError(f"could not parse {path.name}") from error


def _cargo_diff(base_path: Path, head_path: Path) -> LockDiff:
    base = _read_cargo(base_path)
    head = _read_cargo(head_path)
    changed: list[PackageChange] = []
    added: list[LockedPackage] = []
    removed: list[LockedPackage] = []
    for key in sorted(base.keys() | head.keys()):
        old_packages = sorted(base.get(key, []), key=lambda item: item.version)
        new_packages = sorted(head.get(key, []), key=lambda item: item.version)
        old_by_version = {package.version: package for package in old_packages}
        new_by_version = {package.version: package for package in new_packages}
        common = old_by_version.keys() & new_by_version.keys()
        old_remaining = [item for item in old_packages if item.version not in common]
        new_remaining = [item for item in new_packages if item.version not in common]
        pair_count = min(len(old_remaining), len(new_remaining))
        for index in range(pair_count):
            old = old_remaining[index]
            new = new_remaining[index]
            changed.append(
                PackageChange("cargo", old.name, old.version, new.version, old.identity)
            )
        removed.extend(old_remaining[pair_count:])
        added.extend(new_remaining[pair_count:])
    base_entries: dict[tuple[str, str], list[str]] = {}
    head_entries: dict[tuple[str, str], list[str]] = {}
    for packages, entries in ((base, base_entries), (head, head_entries)):
        for package_group in packages.values():
            for package in package_group:
                key = (package.name, package.version)
                entries.setdefault(key, []).append(package.entry_fingerprint or "")
    ineligible_reasons = [
        f"same-version entry changed: {name}"
        for name, version in sorted(base_entries.keys() & head_entries.keys())
        if sorted(base_entries[(name, version)])
        != sorted(head_entries[(name, version)])
    ]
    for package in [*changed, *added]:
        if package.identity not in CRATES_IO_SOURCES:
            reason = f"non-crates.io source: {package.name}"
            if reason not in ineligible_reasons:
                ineligible_reasons.append(reason)
    for package in removed:
        if package.identity == LOCAL_CARGO_SOURCE:
            reason = f"non-crates.io source: {package.name}"
            if reason not in ineligible_reasons:
                ineligible_reasons.append(reason)
    return LockDiff(changed, added, removed, ineligible_reasons)


def _npm_source_reasons(package: LockedPackage) -> list[str]:
    if not package.resolved or not package.resolved.startswith(
        "https://registry.npmjs.org/"
    ):
        return [f"non-registry source: {package.name}"]
    if not package.integrity:
        return [f"missing integrity: {package.name}"]
    return []


def _npm_diff(base_path: Path, head_path: Path) -> LockDiff:
    base = _read_npm(base_path)
    head = _read_npm(head_path)
    changed: list[PackageChange] = []
    added: list[LockedPackage] = []
    removed: list[LockedPackage] = []
    ineligible_reasons: list[str] = []
    for key in sorted(base.keys() | head.keys()):
        old = base.get(key)
        new = head.get(key)
        if old is None:
            if new.workspace_package:
                ineligible_reasons.append("workspace package changed")
            elif new.workspace_link:
                ineligible_reasons.append(f"workspace link changed: {new.name}")
            else:
                added.append(new)
                ineligible_reasons.extend(_npm_source_reasons(new))
        elif new is None:
            if old.workspace_package:
                ineligible_reasons.append("workspace package changed")
            elif old.workspace_link:
                ineligible_reasons.append(f"workspace link changed: {old.name}")
            else:
                removed.append(old)
        elif old.workspace_package or new.workspace_package:
            if old != new:
                ineligible_reasons.append("workspace package changed")
        elif old.workspace_link or new.workspace_link:
            if old != new:
                link = new if new.workspace_link else old
                ineligible_reasons.append(f"workspace link changed: {link.name}")
        elif old != new:
            ineligible_reasons.extend(_npm_source_reasons(new))
            if old.version == new.version:
                ineligible_reasons.append(
                    f"same-version entry changed: {new.name}"
                )
            else:
                changed.append(
                    PackageChange(
                        "npm",
                        new.name,
                        old.version,
                        new.version,
                        key,
                        old.has_install_script,
                        new.has_install_script,
                    )
                )
    return LockDiff(changed, added, removed, ineligible_reasons)


def diff_lockfiles(
    ecosystem: str, base_path: str | Path, head_path: str | Path
) -> LockDiff:
    base = Path(base_path)
    head = Path(head_path)
    if ecosystem == "cargo":
        return _cargo_diff(base, head)
    if ecosystem == "npm":
        return _npm_diff(base, head)
    raise LockfileError(f"unsupported ecosystem: {ecosystem}")
