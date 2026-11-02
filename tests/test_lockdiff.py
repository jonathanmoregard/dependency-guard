import json
from pathlib import Path
import tempfile
import unittest

from dependency_guard.lockdiff import diff_lockfiles


FIXTURES = Path(__file__).parent / "fixtures"


class LockDiffTests(unittest.TestCase):
    def test_cargo_handles_multiple_versions_of_one_crate(self):
        result = diff_lockfiles(
            "cargo",
            FIXTURES / "cargo-multi-base.lock",
            FIXTURES / "cargo-multi-head.lock",
        )

        self.assertEqual(len(result.changed), 1)
        change = result.changed[0]
        self.assertEqual(
            (change.ecosystem, change.name, change.old, change.new),
            ("cargo", "multi", "2.0.0", "2.0.1"),
        )
        self.assertEqual(result.added, [])
        self.assertEqual(result.removed, [])

    def test_npm_captures_gained_install_script(self):
        result = diff_lockfiles(
            "npm",
            FIXTURES / "npm-install-base.json",
            FIXTURES / "npm-install-head.json",
        )

        self.assertEqual(len(result.changed), 1)
        self.assertFalse(result.changed[0].old_has_install_script)
        self.assertTrue(result.changed[0].new_has_install_script)

    def test_npm_rejects_non_registry_sources_on_changed_and_added_entries(self):
        registry = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
        sources = (
            "git+https://github.com/example/pkg.git",
            "file:../pkg",
            "http://registry.npmjs.org/pkg/-/pkg-1.0.1.tgz",
            "https://registry.example.com/pkg/-/pkg-1.0.1.tgz",
            None,
        )
        for mode in ("changed", "added"):
            for source in sources:
                with self.subTest(mode=mode, source=source):
                    base_packages = {
                        "": {"name": "root", "version": "1.0.0"},
                        "node_modules/pkg": {
                            "version": "1.0.0",
                            "resolved": registry,
                            "integrity": "sha512-old",
                        },
                    }
                    package_path = (
                        "node_modules/pkg" if mode == "changed" else "node_modules/new"
                    )
                    package = {
                        "version": "1.0.1",
                        "integrity": "sha512-new",
                    }
                    if source is not None:
                        package["resolved"] = source
                    head_packages = dict(base_packages)
                    head_packages[package_path] = package
                    with tempfile.TemporaryDirectory() as tempdir:
                        base = Path(tempdir) / "base.json"
                        head = Path(tempdir) / "head.json"
                        base.write_text(
                            json.dumps(
                                {"lockfileVersion": 3, "packages": base_packages}
                            ),
                            encoding="utf-8",
                        )
                        head.write_text(
                            json.dumps(
                                {"lockfileVersion": 3, "packages": head_packages}
                            ),
                            encoding="utf-8",
                        )
                        result = diff_lockfiles("npm", base, head)

                    name = "pkg" if mode == "changed" else "new"
                    self.assertIn(
                        f"non-registry source: {name}",
                        getattr(result, "ineligible_reasons", []),
                    )

    def test_npm_rejects_missing_integrity_on_changed_and_added_entries(self):
        base_packages = {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                "integrity": "sha512-old",
            },
        }
        for mode in ("changed", "added"):
            with self.subTest(mode=mode):
                package_path = (
                    "node_modules/pkg" if mode == "changed" else "node_modules/new"
                )
                name = "pkg" if mode == "changed" else "new"
                head_packages = dict(base_packages)
                head_packages[package_path] = {
                    "version": "1.0.1",
                    "resolved": (
                        f"https://registry.npmjs.org/{name}/-/"
                        f"{name}-1.0.1.tgz"
                    ),
                }
                with tempfile.TemporaryDirectory() as tempdir:
                    base = Path(tempdir) / "base.json"
                    head = Path(tempdir) / "head.json"
                    base.write_text(
                        json.dumps({"lockfileVersion": 3, "packages": base_packages}),
                        encoding="utf-8",
                    )
                    head.write_text(
                        json.dumps({"lockfileVersion": 3, "packages": head_packages}),
                        encoding="utf-8",
                    )
                    result = diff_lockfiles("npm", base, head)

                self.assertIn(
                    f"missing integrity: {name}",
                    getattr(result, "ineligible_reasons", []),
                )


if __name__ == "__main__":
    unittest.main()
