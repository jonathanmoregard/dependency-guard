import json
from pathlib import Path
import tempfile
import unittest

from dependency_guard.lockdiff import LockfileError, diff_lockfiles


FIXTURES = Path(__file__).parent / "fixtures"


def cargo_document(packages):
    sections = ["version = 3"]
    for name, version, source in packages:
        lines = [f'name = "{name}"', f'version = "{version}"']
        if source is not None:
            lines.append(f'source = "{source}"')
        sections.append("[[package]]\n" + "\n".join(lines))
    return "\n\n".join(sections) + "\n"


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

    def test_cargo_rejects_changed_or_added_non_crates_io_sources(self):
        crates_io = "registry+https://github.com/rust-lang/crates.io-index"
        unsafe_sources = (
            "git+https://github.com/example/pkg?rev=abc#abc",
            "registry+https://registry.example.com/index",
        )
        for mode in ("changed", "added"):
            for source in unsafe_sources:
                with self.subTest(mode=mode, source=source):
                    base_packages = [("root", "1.0.0", crates_io)]
                    if mode == "changed":
                        base_packages.append(("unsafe", "1.0.0", source))
                    head_packages = list(base_packages)
                    if mode == "changed":
                        head_packages[-1] = ("unsafe", "1.0.1", source)
                    else:
                        head_packages.append(("unsafe", "1.0.0", source))
                    with tempfile.TemporaryDirectory() as tempdir:
                        base = Path(tempdir) / "Cargo.base.lock"
                        head = Path(tempdir) / "Cargo.head.lock"
                        base.write_text(cargo_document(base_packages), encoding="utf-8")
                        head.write_text(cargo_document(head_packages), encoding="utf-8")
                        result = diff_lockfiles("cargo", base, head)

                    self.assertIn(
                        "non-crates.io source: unsafe", result.ineligible_reasons
                    )

    def test_cargo_rejects_any_changed_local_package(self):
        cases = {
            "changed": (
                [("workspace", "1.0.0", None)],
                [("workspace", "1.0.1", None)],
            ),
            "added": ([], [("workspace", "1.0.0", None)]),
            "removed": ([("workspace", "1.0.0", None)], []),
        }
        for mode, (base_packages, head_packages) in cases.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tempdir:
                base = Path(tempdir) / "Cargo.base.lock"
                head = Path(tempdir) / "Cargo.head.lock"
                base.write_text(cargo_document(base_packages), encoding="utf-8")
                head.write_text(cargo_document(head_packages), encoding="utf-8")
                result = diff_lockfiles("cargo", base, head)

                self.assertIn(
                    "non-crates.io source: workspace", result.ineligible_reasons
                )

    def test_cargo_ignores_unchanged_local_packages_and_allows_crates_io(self):
        allowed_sources = (
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/",
        )
        for source in allowed_sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tempdir:
                base = Path(tempdir) / "Cargo.base.lock"
                head = Path(tempdir) / "Cargo.head.lock"
                base.write_text(
                    cargo_document(
                        [("workspace", "1.0.0", None), ("crate", "1.0.0", source)]
                    ),
                    encoding="utf-8",
                )
                head.write_text(
                    cargo_document(
                        [("workspace", "1.0.0", None), ("crate", "1.0.1", source)]
                    ),
                    encoding="utf-8",
                )
                result = diff_lockfiles("cargo", base, head)

                self.assertNotIn("non-crates.io source", " ".join(result.ineligible_reasons))

    def test_npm_ignores_unchanged_workspace_link_without_version(self):
        document = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/workspace": {
                    "resolved": "packages/workspace",
                    "link": True,
                },
            },
        }
        with tempfile.TemporaryDirectory() as tempdir:
            base = Path(tempdir) / "base.json"
            head = Path(tempdir) / "head.json"
            base.write_text(json.dumps(document), encoding="utf-8")
            head.write_text(json.dumps(document), encoding="utf-8")

            try:
                result = diff_lockfiles("npm", base, head)
            except LockfileError as error:
                self.fail(f"unchanged workspace link raised: {error}")

        self.assertEqual(result.changed, [])
        self.assertEqual(result.added, [])
        self.assertEqual(result.removed, [])
        self.assertEqual(result.ineligible_reasons, [])

    def test_npm_rejects_added_removed_or_changed_workspace_link(self):
        link = {"resolved": "packages/workspace", "link": True}
        changed_link = {"resolved": "packages/renamed", "link": True}
        cases = {
            "added": ({}, {"node_modules/workspace": link}),
            "removed": ({"node_modules/workspace": link}, {}),
            "changed": (
                {"node_modules/workspace": link},
                {"node_modules/workspace": changed_link},
            ),
        }
        for mode, (base_entries, head_entries) in cases.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tempdir:
                base = Path(tempdir) / "base.json"
                head = Path(tempdir) / "head.json"
                base.write_text(
                    json.dumps(
                        {
                            "lockfileVersion": 3,
                            "packages": {
                                "": {"name": "root", "version": "1.0.0"},
                                **base_entries,
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                head.write_text(
                    json.dumps(
                        {
                            "lockfileVersion": 3,
                            "packages": {
                                "": {"name": "root", "version": "1.0.0"},
                                **head_entries,
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                try:
                    result = diff_lockfiles("npm", base, head)
                except LockfileError as error:
                    self.fail(f"{mode} workspace link raised: {error}")

                self.assertIn(
                    "workspace link changed: workspace", result.ineligible_reasons
                )

    def test_npm_workspace_target_is_ignored_only_while_unchanged(self):
        root = {
            "name": "root",
            "version": "1.0.0",
            "workspaces": ["packages/utils"],
        }
        link = {"resolved": "packages/utils", "link": True}
        target = {"version": "1.0.0"}
        common = {"": root, "node_modules/utils": link}
        cases = {
            "unchanged": (
                {**common, "packages/utils": target},
                {**common, "packages/utils": target},
                [],
            ),
            "added": (
                common,
                {**common, "packages/utils": target},
                ["workspace package changed"],
            ),
            "removed": (
                {**common, "packages/utils": target},
                common,
                ["workspace package changed"],
            ),
            "changed": (
                {**common, "packages/utils": target},
                {**common, "packages/utils": {"version": "1.0.1"}},
                ["workspace package changed"],
            ),
        }
        for mode, (base_packages, head_packages, reasons) in cases.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tempdir:
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

                try:
                    result = diff_lockfiles("npm", base, head)
                except LockfileError as error:
                    self.fail(f"{mode} workspace target raised: {error}")

                self.assertEqual(result.ineligible_reasons, reasons)


if __name__ == "__main__":
    unittest.main()
