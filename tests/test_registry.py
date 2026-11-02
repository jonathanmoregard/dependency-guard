from datetime import datetime, timezone
import io
import json
import unittest
from unittest.mock import patch

from dependency_guard.registry import HttpRegistry, RegistryError


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RegistryTests(unittest.TestCase):
    def test_reads_npm_publish_time(self):
        payload = {"time": {"1.2.3": "2026-01-02T03:04:05.000Z"}}
        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(json.dumps(payload).encode()),
        ):
            published = HttpRegistry().publish_time("npm", "pkg", "1.2.3")

        self.assertEqual(
            published, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        )

    def test_reads_crates_publish_time_and_sets_user_agent(self):
        payload = {"version": {"created_at": "2026-01-02T03:04:05Z"}}
        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(json.dumps(payload).encode()),
        ) as urlopen:
            published = HttpRegistry().publish_time("cargo", "crate", "1.2.3")

        request = urlopen.call_args.args[0]
        self.assertTrue(request.get_header("User-agent"))
        self.assertEqual(published.tzinfo, timezone.utc)

    def test_queries_osv_batch_and_returns_ids(self):
        payload = {"results": [{"vulns": [{"id": "MAL-1"}, {"id": "GHSA-1"}]}]}
        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(json.dumps(payload).encode()),
        ) as urlopen:
            vulns = HttpRegistry().osv_vulns("npm", "pkg", "1.2.3")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.osv.dev/v1/querybatch")
        self.assertEqual(request.method, "POST")
        self.assertEqual(vulns, ["MAL-1", "GHSA-1"])

    def test_wraps_http_and_parse_errors(self):
        with patch(
            "urllib.request.urlopen", return_value=FakeResponse(b"not-json")
        ):
            with self.assertRaises(RegistryError):
                HttpRegistry().publish_time("npm", "pkg", "1.2.3")


if __name__ == "__main__":
    unittest.main()
