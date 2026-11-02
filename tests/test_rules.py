import unittest

from dependency_guard.rules import classify_update


class ClassifyUpdateTests(unittest.TestCase):
    def test_classifies_patch_minor_and_major(self):
        self.assertEqual(classify_update("1.2.3", "1.2.4"), "patch")
        self.assertEqual(classify_update("1.2.3", "1.3.0"), "minor")
        self.assertEqual(classify_update("1.2.3", "2.0.0"), "major")

    def test_zero_x_minor_is_major_equivalent(self):
        self.assertEqual(classify_update("0.2.3", "0.3.0"), "major")
        self.assertEqual(classify_update("0.2.3", "0.2.4"), "patch")

    def test_non_semver_and_downgrades_are_ineligible(self):
        self.assertIsNone(classify_update("release-1", "release-2"))
        self.assertIsNone(classify_update("1.2.3", "1.2.2"))


if __name__ == "__main__":
    unittest.main()
