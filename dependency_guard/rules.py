"""Pure version eligibility rules."""

from __future__ import annotations

from dataclasses import dataclass
import re


_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@dataclass(frozen=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: str | None = None


def parse_semver(value: str) -> SemVer | None:
    match = _SEMVER.fullmatch(value)
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    return SemVer(int(major), int(minor), int(patch), prerelease)


def classify_update(old: str, new: str) -> str | None:
    """Return patch/minor/major, or None when the update is ineligible."""

    old_version = parse_semver(old)
    new_version = parse_semver(new)
    if old_version is None or new_version is None:
        return None
    if old_version.prerelease is not None or new_version.prerelease is not None:
        return None
    old_core = (old_version.major, old_version.minor, old_version.patch)
    new_core = (new_version.major, new_version.minor, new_version.patch)
    if new_core <= old_core:
        return None
    if new_version.major != old_version.major:
        return "major"
    if new_version.minor != old_version.minor:
        return "major" if old_version.major == 0 else "minor"
    return "patch"
