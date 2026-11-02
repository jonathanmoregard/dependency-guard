"""Registry and OSV clients behind an injectable protocol."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Protocol
from urllib.parse import quote
import urllib.request


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class OsvVulnerability:
    vulnerability_id: str
    fixed_versions: tuple[str, ...]


class Registry(Protocol):
    def publish_time(
        self, ecosystem: str, name: str, version: str
    ) -> datetime: ...

    def osv_vulns(
        self, ecosystem: str, name: str, version: str
    ) -> list[OsvVulnerability]: ...


class HttpRegistry:
    def __init__(self, timeout: float = 10.0, user_agent: str = "dependency-guard/0.1"):
        self.timeout = timeout
        self.user_agent = user_agent

    def _json(self, request: urllib.request.Request) -> object:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except Exception as error:
            raise RegistryError("registry response could not be verified") from error

    @staticmethod
    def _datetime(value: object) -> datetime:
        if not isinstance(value, str):
            raise RegistryError("publish time is missing")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise RegistryError("publish time is invalid") from error
        if parsed.tzinfo is None:
            raise RegistryError("publish time has no timezone")
        return parsed.astimezone(timezone.utc)

    def publish_time(self, ecosystem: str, name: str, version: str) -> datetime:
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{quote(name, safe='@')}"
            document = self._json(urllib.request.Request(url, headers=headers))
            try:
                value = document["time"][version]
            except (KeyError, TypeError) as error:
                raise RegistryError("npm publish time is missing") from error
            return self._datetime(value)
        if ecosystem == "cargo":
            url = (
                "https://crates.io/api/v1/crates/"
                f"{quote(name, safe='')}/{quote(version, safe='')}"
            )
            document = self._json(urllib.request.Request(url, headers=headers))
            try:
                value = document["version"]["created_at"]
            except (KeyError, TypeError) as error:
                raise RegistryError("crate publish time is missing") from error
            return self._datetime(value)
        raise RegistryError(f"unsupported ecosystem: {ecosystem}")

    @staticmethod
    def _osv_fixed_versions(
        document: object, vulnerability_id: str, ecosystem: str, name: str
    ) -> tuple[str, ...]:
        try:
            if not isinstance(document, dict):
                raise TypeError
            if document["id"] != vulnerability_id:
                raise ValueError
            affected = document["affected"]
            if not isinstance(affected, list):
                raise TypeError
            fixed_versions: set[str] = set()
            for item in affected:
                if not isinstance(item, dict):
                    raise TypeError
                package = item["package"]
                if not isinstance(package, dict):
                    raise TypeError
                package_ecosystem = package["ecosystem"]
                package_name = package["name"]
                if not isinstance(package_ecosystem, str) or not isinstance(
                    package_name, str
                ):
                    raise TypeError
                ranges = item.get("ranges", [])
                if not isinstance(ranges, list):
                    raise TypeError
                for affected_range in ranges:
                    if not isinstance(affected_range, dict):
                        raise TypeError
                    events = affected_range["events"]
                    if not isinstance(events, list):
                        raise TypeError
                    for event in events:
                        if not isinstance(event, dict):
                            raise TypeError
                        fixed = event.get("fixed")
                        if fixed is not None and not isinstance(fixed, str):
                            raise TypeError
                        if (
                            package_ecosystem == ecosystem
                            and package_name == name
                            and fixed is not None
                        ):
                            fixed_versions.add(fixed)
            return tuple(sorted(fixed_versions))
        except (KeyError, TypeError, ValueError) as error:
            raise RegistryError("OSV vulnerability record is invalid") from error

    def osv_vulns(
        self, ecosystem: str, name: str, version: str
    ) -> list[OsvVulnerability]:
        osv_ecosystem = {"cargo": "crates.io", "npm": "npm"}.get(ecosystem)
        if osv_ecosystem is None:
            raise RegistryError(f"unsupported ecosystem: {ecosystem}")
        body = json.dumps(
            {
                "queries": [
                    {
                        "package": {"ecosystem": osv_ecosystem, "name": name},
                        "version": version,
                    }
                ]
            }
        ).encode()
        request = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
            method="POST",
        )
        document = self._json(request)
        try:
            result = document["results"][0]
            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                raise TypeError
            ids = [item["id"] for item in vulnerabilities]
            if not all(isinstance(item, str) for item in ids):
                raise TypeError
        except (IndexError, KeyError, TypeError, AttributeError) as error:
            raise RegistryError("OSV response is invalid") from error
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        records = []
        for vulnerability_id in ids:
            detail = self._json(
                urllib.request.Request(
                    "https://api.osv.dev/v1/vulns/"
                    f"{quote(vulnerability_id, safe='')}",
                    headers=headers,
                )
            )
            records.append(
                OsvVulnerability(
                    vulnerability_id,
                    self._osv_fixed_versions(
                        detail, vulnerability_id, osv_ecosystem, name
                    ),
                )
            )
        return records
