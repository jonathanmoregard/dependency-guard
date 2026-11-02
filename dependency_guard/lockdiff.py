"""Parse supported lockfiles as data and produce deterministic diffs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tomllib


class LockfileError(ValueError):
    """A lockfile could not be parsed or did not have the expected shape."""


@dataclass(frozen=True)
class LockedPackage:
    ecosystem: str
    name: str
    version: str
    identity: str
    has_install_script: bool = False


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
            source = package.get("source", "path")
            if not all(isinstance(value, str) for value in (name, version, source)):
                raise LockfileError("Cargo.lock package identity is incomplete")
            locked = LockedPackage("cargo", name, version, source)
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
        raise LockfileError("package-lock entry has no package name")
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
            version = package.get("version")
            if not isinstance(version, str):
                raise LockfileError("package-lock entry has no version")
            result[package_path] = LockedPackage(
                "npm",
                _npm_name(package_path, package),
                version,
                package_path,
                package.get("hasInstallScript") is True,
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
    return LockDiff(changed, added, removed)


def _npm_diff(base_path: Path, head_path: Path) -> LockDiff:
    base = _read_npm(base_path)
    head = _read_npm(head_path)
    changed: list[PackageChange] = []
    added: list[LockedPackage] = []
    removed: list[LockedPackage] = []
    for key in sorted(base.keys() | head.keys()):
        old = base.get(key)
        new = head.get(key)
        if old is None:
            added.append(new)  # type: ignore[arg-type]
        elif new is None:
            removed.append(old)
        elif old.version != new.version:
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
    return LockDiff(changed, added, removed)


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
