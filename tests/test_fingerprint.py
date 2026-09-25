"""RED slice for the deterministic analysis fingerprint."""

import unittest

from dep_evidence.errors import DataError


class FingerprintTests(unittest.TestCase):
    def fingerprint(self, *, sbom_digest="s1", sources=None, policy_version="1", rule_version="1"):
        from dep_evidence.analysis import compute_analysis_fingerprint

        return compute_analysis_fingerprint(
            sbom_sha256=sbom_digest,
            sources=sources if sources is not None else {"osv": {"sha256": "a" * 64}},
            policy_version=policy_version,
            rule_version=rule_version,
        )

    def test_fingerprint_is_a_sha256_hex_digest(self):
        digest = self.fingerprint()
        self.assertEqual(64, len(digest))
        self.assertTrue(all(character in "0123456789abcdef" for character in digest))

    def test_fingerprint_is_stable_for_identical_input(self):
        self.assertEqual(self.fingerprint(), self.fingerprint())

    def test_changing_the_sbom_digest_changes_the_fingerprint(self):
        self.assertNotEqual(self.fingerprint(sbom_digest="s1"), self.fingerprint(sbom_digest="s2"))

    def test_changing_the_snapshot_changes_the_fingerprint(self):
        first = self.fingerprint(sources={"osv": {"sha256": "a" * 64}})
        second = self.fingerprint(sources={"osv": {"sha256": "b" * 64}})
        self.assertNotEqual(first, second)

    def test_changing_the_policy_version_changes_the_fingerprint(self):
        self.assertNotEqual(
            self.fingerprint(policy_version="1"), self.fingerprint(policy_version="2")
        )

    def test_changing_the_rule_version_changes_the_fingerprint(self):
        self.assertNotEqual(
            self.fingerprint(rule_version="1"), self.fingerprint(rule_version="2")
        )

    def test_key_order_in_sources_does_not_change_the_fingerprint(self):
        first = self.fingerprint(sources={"osv": {"sha256": "a" * 64}, "kev": {"sha256": "b" * 64}})
        second = self.fingerprint(sources={"kev": {"sha256": "b" * 64}, "osv": {"sha256": "a" * 64}})
        self.assertEqual(first, second)

    def test_malformed_input_surfaces_as_data_error(self):
        cases = {
            "empty sbom": {"sbom_digest": ""},
            "non-str sbom": {"sbom_digest": 7},
            "bad policy": {"policy_version": ""},
            "non-mapping sources": {"sources": "nope"},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(DataError):
                    self.fingerprint(**overrides)


if __name__ == "__main__":
    unittest.main()
