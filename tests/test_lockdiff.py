from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
