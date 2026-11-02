"""Registry and OSV clients behind an injectable protocol."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Protocol
from urllib.parse import quote
import urllib.request


class RegistryError(RuntimeError):
    pass


class Registry(Protocol):
    def publish_time(
        self, ecosystem: str, name: str, version: str
    ) -> datetime: ...

    def osv_vulns(self, ecosystem: str, name: str, version: str) -> list[str]: ...


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
                value = document["time"][version]  # type: ignore[index]
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
                value = document["version"]["created_at"]  # type: ignore[index]
            except (KeyError, TypeError) as error:
                raise RegistryError("crate publish time is missing") from error
            return self._datetime(value)
        raise RegistryError(f"unsupported ecosystem: {ecosystem}")

    def osv_vulns(self, ecosystem: str, name: str, version: str) -> list[str]:
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
            result = document["results"][0]  # type: ignore[index]
            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                raise TypeError
            ids = [item["id"] for item in vulnerabilities]
            if not all(isinstance(item, str) for item in ids):
                raise TypeError
            return ids
        except (IndexError, KeyError, TypeError, AttributeError) as error:
            raise RegistryError("OSV response is invalid") from error
