import unittest

from dep_evidence.versioning import compare_versions


class VersionComparisonTests(unittest.TestCase):
    def test_orders_numeric_versions(self):
        self.assertEqual(-1, compare_versions("1.0.0", "1.0.1"))
        self.assertEqual(0, compare_versions("1.2.3", "1.2.3"))
        self.assertEqual(1, compare_versions("2.0.0", "1.99.99"))

    def test_orders_common_maven_qualifiers(self):
        self.assertEqual(-1, compare_versions("1.0.0-alpha", "1.0.0"))
        self.assertEqual(-1, compare_versions("1.0.0-rc1", "1.0.0"))
        self.assertEqual(1, compare_versions("1.0.0-sp1", "1.0.0"))
        self.assertEqual(-1, compare_versions("1.0.0-rc1", "1.0.0-rc2"))

    def test_treats_trailing_zeroes_as_equivalent(self):
        self.assertEqual(0, compare_versions("1.0", "1.0.0"))
        self.assertEqual(0, compare_versions("1.0.0.0", "1.0"))

    def test_orders_additional_numeric_segments(self):
        self.assertEqual(1, compare_versions("1.0.0.1", "1.0"))
        self.assertEqual(-1, compare_versions("1.0.0.1", "1.0.1"))

    def test_preserves_maven_dash_numeric_nesting(self):
        self.assertEqual(1, compare_versions("1-1", "1.0"))
        self.assertEqual(-1, compare_versions("1-1", "1.1"))
        self.assertEqual(-1, compare_versions("1.0", "1.0-1"))
        self.assertEqual(-1, compare_versions("1-1-1", "1.1"))
        self.assertEqual(0, compare_versions("1", "1-0"))

    def test_qualifier_aliases_are_case_insensitive(self):
        self.assertEqual(-1, compare_versions("1.0-CR1", "1.0"))
        self.assertEqual(-1, compare_versions("1.0-ALPHA2", "1.0-BETA1"))

    def test_returns_none_for_ambiguous_versions(self):
        self.assertIsNone(compare_versions("", "1.0.0"))
        self.assertIsNone(compare_versions("latest", "1.0.0"))
        self.assertIsNone(compare_versions("1.0.0-customer-build", "1.0.0"))
        self.assertIsNone(compare_versions("v1.0.0", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
