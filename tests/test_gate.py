from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from dependency_guard.gate import _split_directories, evaluate_gate


NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
DEPENDABOT = "dependabot[bot]"
NPM_METADATA = {
    "package-ecosystem": "npm",
    "dependency-names": "pkg",
    "update-type": "version-update:semver-patch",
}


class FakeRegistry:
    def __init__(self, ages=None, vulns=None, publish_error=None, osv_error=None):
        self.ages = ages or {}
        self.vulns = vulns or {}
        self.publish_error = publish_error
        self.osv_error = osv_error

    def publish_time(self, ecosystem, name, version):
        if self.publish_error == name:
            raise RuntimeError("registry unavailable")
        return NOW - self.ages.get(name, timedelta(days=30))

    def osv_vulns(self, ecosystem, name, version):
        if self.osv_error in (name, (name, version)):
            raise RuntimeError("OSV unavailable")
        return [
            item if isinstance(item, FakeVulnerability) else FakeVulnerability(item)
            for item in self.vulns.get((name, version), self.vulns.get(name, []))
        ]


class FakeVulnerability(str):
    def __new__(cls, vulnerability_id, fixed_versions=()):
        value = super().__new__(cls, vulnerability_id)
        value.vulnerability_id = vulnerability_id
        value.fixed_versions = tuple(fixed_versions)
        return value


def verified_commits(login=DEPENDABOT, verified=True):
    return [
        {
            "author": {"login": login},
            "commit": {"verification": {"verified": verified}},
        }
    ]


def cargo_lock(packages):
    sections = ["version = 3"]
    for name, version in packages:
        sections.append(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"'
        )
    return "\n\n".join(sections) + "\n"


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "base").mkdir()
        (self.root / "head").mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    def write_cargo(self, base, head):
        (self.root / "base" / "Cargo.lock").write_text(
            cargo_lock(base), encoding="utf-8"
        )
        (self.root / "head" / "Cargo.lock").write_text(
            cargo_lock(head), encoding="utf-8"
        )

    def write_npm(self, directory, old, new):
        for side, version in (("base", old), ("head", new)):
            lockfile = {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "node_modules/pkg": {
                        "version": version,
                        "resolved": (
                            f"https://registry.npmjs.org/pkg/-/pkg-{version}.tgz"
                        ),
                        "integrity": f"sha512-{version}",
                    },
                },
            }
            target = self.root / side / directory
            target.mkdir(parents=True, exist_ok=True)
            (target / "package-lock.json").write_text(
                json.dumps(lockfile), encoding="utf-8"
            )

    def evaluate(self, registry=None, **overrides):
        values = {
            "pr_author": DEPENDABOT,
            "actor": DEPENDABOT,
            "commits": verified_commits(),
            "changed_files": ["Cargo.toml", "Cargo.lock"],
            "base_root": self.root / "base",
            "head_root": self.root / "head",
            "ecosystem_dirs": {"cargo": ".", "npm": "."},
            "metadata": {
                "package-ecosystem": "cargo",
                "dependency-names": "direct",
                "update-type": "version-update:semver-patch",
            },
            "registry": registry or FakeRegistry(),
            "now": NOW,
            "patch_days": 3,
            "minor_days": 7,
            "security_hours": 8,
        }
        values.update(overrides)
        return evaluate_gate(**values)

    def test_human_pr_is_not_dependency(self):
        result = self.evaluate(pr_author="human")
        self.assertEqual(result.verdict, "not-dependency")

    def test_foreign_or_unverified_commit_is_red(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        self.assertEqual(
            self.evaluate(commits=verified_commits("human")).verdict, "red"
        )
        self.assertEqual(
            self.evaluate(commits=verified_commits(verified=False)).verdict, "red"
        )

    def test_non_dependabot_workflow_actor_is_red(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])

        result = self.evaluate(actor="write-user")

        self.assertEqual(result.verdict, "red")
        self.assertIn("pushed by write-user, not Dependabot", result.reasons)

    def test_more_than_one_commit_is_red(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])

        result = self.evaluate(commits=verified_commits() + verified_commits())

        self.assertEqual(result.verdict, "red")
        self.assertIn("more than one commit", result.reasons)

    def test_non_manifest_file_is_red(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate(changed_files=["Cargo.lock", "src/lib.rs"])
        self.assertEqual(result.verdict, "red")

    def test_unsupported_ecosystem_is_ineligible(self):
        result = self.evaluate(
            changed_files=["flake.lock"],
            metadata={"package-ecosystem": "nix"},
        )
        self.assertEqual(result.verdict, "ineligible")

    def test_major_zero_x_minor_and_non_semver_are_ineligible(self):
        cases = [
            ("1.0.0", "2.0.0"),
            ("0.2.0", "0.3.0"),
            ("1.0.0", "release-2"),
        ]
        for old, new in cases:
            with self.subTest(old=old, new=new):
                self.write_cargo([("direct", old)], [("direct", new)])
                self.assertEqual(self.evaluate().verdict, "ineligible")

    def test_added_package_is_ineligible(self):
        self.write_cargo(
            [("direct", "1.0.0")],
            [("direct", "1.0.1"), ("new-transitive", "1.0.0")],
        )
        result = self.evaluate()
        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("added package" in reason for reason in result.reasons))

    def test_each_transitive_uses_its_own_cooldown(self):
        self.write_cargo(
            [("direct", "1.0.0"), ("transitive", "1.0.0")],
            [("direct", "1.0.1"), ("transitive", "1.1.0")],
        )
        registry = FakeRegistry(
            ages={"direct": timedelta(days=4), "transitive": timedelta(days=6)}
        )
        result = self.evaluate(registry=registry)
        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("transitive" in reason for reason in result.reasons))

    def test_cooldown_only_is_true_for_only_cooldown_reasons(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate(
            registry=FakeRegistry(ages={"direct": timedelta(days=2)})
        )

        self.assertEqual(result.verdict, "ineligible")
        self.assertIs(result.as_dict()["cooldown_only"], True)

    def test_cooldown_only_is_false_for_mixed_ineligible_reasons(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate(
            registry=FakeRegistry(
                ages={"direct": timedelta(days=2)}, osv_error="direct"
            )
        )

        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("cooldown" in reason for reason in result.reasons))
        self.assertIs(result.as_dict()["cooldown_only"], False)

    def test_cooldown_only_is_false_for_eligible_verdict(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate()

        self.assertEqual(result.verdict, "eligible")
        self.assertIs(result.as_dict()["cooldown_only"], False)

    def test_osv_hit_is_red(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate(registry=FakeRegistry(vulns={"direct": ["MAL-1"]}))
        self.assertEqual(result.verdict, "red")
        self.assertIn("MAL-1", " ".join(result.reasons))

    def test_unparseable_lockfile_is_red(self):
        (self.root / "base" / "Cargo.lock").write_text("not = [toml", encoding="utf-8")
        (self.root / "head" / "Cargo.lock").write_text("version = 3", encoding="utf-8")
        result = self.evaluate()
        self.assertEqual(result.verdict, "red")

    def test_registry_and_osv_errors_fail_closed(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        for registry in (
            FakeRegistry(publish_error="direct"),
            FakeRegistry(osv_error="direct"),
        ):
            with self.subTest(registry=registry):
                result = self.evaluate(registry=registry)
                self.assertEqual(result.verdict, "ineligible")
                self.assertTrue(
                    any("could not verify" in reason for reason in result.reasons)
                )

    def test_npm_gained_install_script_is_ineligible(self):
        fixture = Path(__file__).parent / "fixtures"
        (self.root / "base" / "package-lock.json").write_text(
            (fixture / "npm-install-base.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.root / "head" / "package-lock.json").write_text(
            (fixture / "npm-install-head.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        result = self.evaluate(
            changed_files=["package.json", "package-lock.json"],
            metadata={
                "package-ecosystem": "npm",
                "dependency-names": "safe-package",
                "update-type": "version-update:semver-patch",
            },
        )
        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("install script" in reason for reason in result.reasons))

    def test_npm_non_registry_source_is_ineligible(self):
        base = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                    "integrity": "sha512-old",
                },
            },
        }
        head = json.loads(json.dumps(base))
        head["packages"]["node_modules/pkg"] = {
            "version": "1.0.1",
            "resolved": "git+https://github.com/example/pkg.git",
            "integrity": "sha512-new",
        }
        (self.root / "base" / "package-lock.json").write_text(
            json.dumps(base), encoding="utf-8"
        )
        (self.root / "head" / "package-lock.json").write_text(
            json.dumps(head), encoding="utf-8"
        )

        result = self.evaluate(
            changed_files=["package.json", "package-lock.json"],
            metadata={
                "package-ecosystem": "npm",
                "dependency-names": "pkg",
                "update-type": "version-update:semver-patch",
            },
        )

        self.assertEqual(result.verdict, "ineligible")
        self.assertIn("non-registry source: pkg", result.reasons)

    def test_cargo_alternate_registry_is_ineligible(self):
        alternate = "registry+https://registry.example.com/index"
        base = cargo_lock([("direct", "1.0.0")]).replace(
            "registry+https://github.com/rust-lang/crates.io-index", alternate
        )
        head = cargo_lock([("direct", "1.0.1")]).replace(
            "registry+https://github.com/rust-lang/crates.io-index", alternate
        )
        (self.root / "base" / "Cargo.lock").write_text(base, encoding="utf-8")
        (self.root / "head" / "Cargo.lock").write_text(head, encoding="utf-8")

        result = self.evaluate()

        self.assertEqual(result.verdict, "ineligible")
        self.assertIn("non-crates.io source: direct", result.reasons)

    def test_npm_workspace_link_change_is_ineligible_not_red(self):
        base = {
            "lockfileVersion": 3,
            "packages": {"": {"name": "root", "version": "1.0.0"}},
        }
        head = json.loads(json.dumps(base))
        head["packages"]["node_modules/workspace"] = {
            "resolved": "packages/workspace",
            "link": True,
        }
        (self.root / "base" / "package-lock.json").write_text(
            json.dumps(base), encoding="utf-8"
        )
        (self.root / "head" / "package-lock.json").write_text(
            json.dumps(head), encoding="utf-8"
        )

        result = self.evaluate(
            changed_files=["package.json", "package-lock.json"],
            metadata={
                "package-ecosystem": "npm",
                "dependency-names": "workspace",
                "update-type": "version-update:semver-patch",
            },
        )

        self.assertEqual(result.verdict, "ineligible")
        self.assertIn("workspace link changed: workspace", result.reasons)

    def test_osv_fixed_vulnerability_uses_security_cooldown_for_advised_package(self):
        self.write_cargo(
            [("direct", "1.0.0"), ("transitive", "1.0.0")],
            [("direct", "1.0.1"), ("transitive", "1.0.1")],
        )
        metadata = {
            "package-ecosystem": "cargo",
            "dependency-names": "direct",
            "update-type": "version-update:semver-patch",
        }
        registry = FakeRegistry(
            ages={
                "direct": timedelta(hours=8, minutes=1),
                "transitive": timedelta(days=4),
            },
            vulns={
                ("direct", "1.0.0"): [
                    FakeVulnerability("GHSA-fixed", ("1.0.1",))
                ]
            },
        )

        result = self.evaluate(registry=registry, metadata=metadata)

        self.assertEqual(result.verdict, "eligible")

    def test_security_cooldown_does_not_apply_after_exact_fixed_version(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.9")])
        registry = FakeRegistry(
            ages={"direct": timedelta(hours=9)},
            vulns={
                ("direct", "1.0.0"): [
                    FakeVulnerability("GHSA-fixed", ("1.0.1",))
                ]
            },
        )

        result = self.evaluate(registry=registry)

        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("72h cooldown" in reason for reason in result.reasons))

    def test_ghsa_metadata_does_not_shorten_cooldown_without_osv_fix(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        metadata = {
            "package-ecosystem": "cargo",
            "dependency-names": "direct",
            "update-type": "version-update:semver-patch",
            "ghsa-id": "GHSA-unavailable-to-this-token",
            "alert-state": "open",
        }
        registry = FakeRegistry(
            ages={"direct": timedelta(hours=9)},
            vulns={
                ("direct", "1.0.0"): ["GHSA-still-present"],
                ("direct", "1.0.1"): ["GHSA-still-present"],
            },
        )

        result = self.evaluate(registry=registry, metadata=metadata)

        self.assertEqual(result.verdict, "red")
        self.assertTrue(any("72h cooldown" in reason for reason in result.reasons))

    def test_security_cooldown_uses_exact_advised_package_name(self):
        self.write_cargo(
            [("foo", "1.0.0"), ("foo-extra", "1.0.0")],
            [("foo", "1.0.1"), ("foo-extra", "1.0.1")],
        )
        metadata = {
            "package-ecosystem": "cargo",
            "dependency-names": "foo",
            "update-type": "version-update:semver-patch",
        }
        registry = FakeRegistry(
            ages={"foo": timedelta(hours=9), "foo-extra": timedelta(hours=9)},
            vulns={
                ("foo", "1.0.0"): [
                    FakeVulnerability("GHSA-foo", ("1.0.1",))
                ],
                ("foo-extra", "1.0.0"): ["GHSA-foo-extra"],
            },
        )

        result = self.evaluate(registry=registry, metadata=metadata)

        self.assertEqual(result.verdict, "ineligible")
        cooldown_reasons = [reason for reason in result.reasons if "cooldown" in reason]
        self.assertEqual(len(cooldown_reasons), 1)
        self.assertIn("foo-extra@1.0.1", cooldown_reasons[0])

    def test_osv_error_keeps_normal_cooldown_and_existing_ineligible_rule(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        metadata = {
            "package-ecosystem": "cargo",
            "dependency-names": "direct",
            "update-type": "version-update:semver-patch",
        }
        registry = FakeRegistry(
            ages={"direct": timedelta(hours=9)},
            osv_error=("direct", "1.0.0"),
        )

        result = self.evaluate(registry=registry, metadata=metadata)

        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(any("could not verify OSV" in reason for reason in result.reasons))
        self.assertTrue(any("72h cooldown" in reason for reason in result.reasons))

    def test_second_configured_npm_directory_is_evaluated(self):
        # Only the second directory has lockfiles, so reading the first fails.
        self.write_npm("docs/site", "1.0.0", "1.0.1")

        result = self.evaluate(
            changed_files=["docs/site/package.json", "docs/site/package-lock.json"],
            ecosystem_dirs={"cargo": ".", "npm": "tests/e2e\ndocs/site\n"},
            metadata=NPM_METADATA,
        )

        self.assertEqual(result.verdict, "eligible", result.reasons)
        self.assertEqual([package.name for package in result.packages], ["pkg"])

    def test_unconfigured_dependency_directory_is_ineligible_not_red(self):
        self.write_npm("tools/lint", "1.0.0", "1.0.1")

        result = self.evaluate(
            changed_files=["tools/lint/package.json", "tools/lint/package-lock.json"],
            ecosystem_dirs={"cargo": ".", "npm": "tests/e2e, docs/site"},
            metadata=NPM_METADATA,
        )

        self.assertNotEqual(result.verdict, "red")
        self.assertEqual(result.verdict, "ineligible")
        self.assertIn("dependency directory is not configured: tools/lint", result.reasons)

    def test_update_spanning_configured_directories_is_ineligible_not_red(self):
        self.write_npm("tests/e2e", "1.0.0", "1.0.1")
        self.write_npm("docs/site", "1.0.0", "1.0.1")

        result = self.evaluate(
            changed_files=[
                "tests/e2e/package-lock.json",
                "docs/site/package-lock.json",
            ],
            ecosystem_dirs={"cargo": ".", "npm": "tests/e2e\ndocs/site"},
            metadata=NPM_METADATA,
        )

        self.assertNotEqual(result.verdict, "red")
        self.assertEqual(result.verdict, "ineligible")
        self.assertTrue(
            any("spans several dependency directories" in r for r in result.reasons)
        )

    def test_non_manifest_file_is_red_with_several_directories(self):
        self.write_npm("tests/e2e", "1.0.0", "1.0.1")
        self.write_npm("tools/lint", "1.0.0", "1.0.1")
        cases = {
            "configured directory": "tests/e2e",
            "unconfigured directory": "tools/lint",
        }
        for case, directory in cases.items():
            with self.subTest(case=case):
                result = self.evaluate(
                    changed_files=[
                        f"{directory}/package-lock.json",
                        f"{directory}/index.js",
                    ],
                    ecosystem_dirs={"cargo": ".", "npm": "tests/e2e\ndocs/site"},
                    metadata=NPM_METADATA,
                )

                self.assertEqual(result.verdict, "red")
                self.assertIn(
                    f"non-manifest/lockfile changes: {directory}/index.js",
                    result.reasons,
                )

    def test_leading_slash_directory_matches_repository_relative_files(self):
        self.write_npm("tests/e2e", "1.0.0", "1.0.1")

        result = self.evaluate(
            changed_files=["tests/e2e/package.json", "tests/e2e/package-lock.json"],
            ecosystem_dirs={"cargo": ".", "npm": "/tests/e2e"},
            metadata=NPM_METADATA,
        )

        self.assertEqual(result.verdict, "eligible", result.reasons)

    def test_split_directories_reads_commas_newlines_blanks_and_duplicates(self):
        cases = (
            ("tests/e2e, /docs/site\n\n tests/e2e/ \n,", ["tests/e2e", "docs/site"]),
            ("", ["."]),
            (" \n , ", ["."]),
            ("/", ["."]),
            (["./tests/e2e", "tests/e2e", "."], ["tests/e2e", "."]),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_split_directories(value), expected)
        with self.assertRaises(ValueError):
            _split_directories("tests/e2e\n../outside")

    def test_old_patch_is_eligible(self):
        self.write_cargo([("direct", "1.0.0")], [("direct", "1.0.1")])
        result = self.evaluate(registry=FakeRegistry(ages={"direct": timedelta(days=3)}))
        self.assertEqual(result.verdict, "eligible")
        json.dumps(result.as_dict())


if __name__ == "__main__":
    unittest.main()
