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

    def test_queries_osv_batch_and_fetches_fixed_versions_for_matching_package(self):
        batch = {"results": [{"vulns": [{"id": "MAL-1"}, {"id": "GHSA-1"}]}]}
        mal = {
            "id": "MAL-1",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "pkg"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}
                    ],
                },
                {
                    "package": {"ecosystem": "npm", "name": "other"},
                    "ranges": [{"events": [{"fixed": "9.9.9"}]}],
                },
            ],
        }
        ghsa = {"id": "GHSA-1", "affected": []}
        with patch(
            "urllib.request.urlopen",
            side_effect=[
                FakeResponse(json.dumps(batch).encode()),
                FakeResponse(json.dumps(mal).encode()),
                FakeResponse(json.dumps(ghsa).encode()),
            ],
        ) as urlopen:
            vulns = HttpRegistry().osv_vulns("npm", "pkg", "1.2.3")

        requests = [call.args[0] for call in urlopen.call_args_list]
        self.assertEqual(requests[0].full_url, "https://api.osv.dev/v1/querybatch")
        self.assertEqual(requests[0].method, "POST")
        self.assertEqual(
            [request.full_url for request in requests[1:]],
            [
                "https://api.osv.dev/v1/vulns/MAL-1",
                "https://api.osv.dev/v1/vulns/GHSA-1",
            ],
        )
        self.assertEqual(
            [(item.vulnerability_id, item.fixed_versions) for item in vulns],
            [("MAL-1", ("1.2.4",)), ("GHSA-1", ())],
        )

    def test_osv_detail_error_fails_the_lookup(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-1"}]}]}
        with patch(
            "urllib.request.urlopen",
            side_effect=[
                FakeResponse(json.dumps(batch).encode()),
                FakeResponse(b"not-json"),
            ],
        ):
            with self.assertRaises(RegistryError):
                HttpRegistry().osv_vulns("npm", "pkg", "1.2.3")

    def test_wraps_http_and_parse_errors(self):
        with patch(
            "urllib.request.urlopen", return_value=FakeResponse(b"not-json")
        ):
            with self.assertRaises(RegistryError):
                HttpRegistry().publish_time("npm", "pkg", "1.2.3")


if __name__ == "__main__":
    unittest.main()
