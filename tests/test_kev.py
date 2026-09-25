import unittest

from dep_evidence.kev import match_kev


class KevMatchingTests(unittest.TestCase):
    def test_malformed_cve_alias_requires_review_without_fuzzy_match(self):
        for alias in (
            "CVE-2026-12345-extra",
            "CVE-2026-123",
            "ＣＶＥ-2026-12345",
        ):
            with self.subTest(alias=alias):
                result = match_kev(
                    {"id": "GHSA-test-test-test", "aliases": [alias]},
                    {"CVE-2026-12345"},
                )

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_aliases", result.reason)
                self.assertIsNone(result.cve_id)

    def test_accepts_minimum_four_digit_cve_sequence(self):
        result = match_kev(
            {"id": "GHSA-test-test-test", "aliases": ["CVE-2026-1234"]},
            {"CVE-2026-1234"},
        )

        self.assertEqual("known_exploited", result.status)
        self.assertEqual("CVE-2026-1234", result.cve_id)

    def test_non_cve_alias_is_not_treated_as_malformed(self):
        result = match_kev(
            {"id": "RUSTSEC-2026-0001", "aliases": ["GHSA-other-test-test"]},
            {"CVE-2026-12345"},
        )

        self.assertEqual("not_known_exploited", result.status)
        self.assertEqual("no_exact_cve_alias", result.reason)

    def test_valid_cve_alias_does_not_hide_malformed_sibling(self):
        result = match_kev(
            {
                "id": "GHSA-test-test-test",
                "aliases": ["CVE-2026-12345", "CVE-2026-123"],
            },
            {"CVE-2026-12345"},
        )

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_aliases", result.reason)
        self.assertIsNone(result.cve_id)

    def test_normalizes_exact_cve_alias_case_and_whitespace(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": ["  cve-2026-12345  "],
        }

        result = match_kev(advisory, {"CVE-2026-12345"})

        self.assertEqual("known_exploited", result.status)
        self.assertEqual("CVE-2026-12345", result.cve_id)

    def test_matches_direct_cve_advisory_id(self):
        advisory = {
            "id": "CVE-2026-12345",
            "aliases": [],
        }

        result = match_kev(advisory, {"cve-2026-12345"})

        self.assertEqual("known_exploited", result.status)
        self.assertEqual("exact_cve_alias", result.reason)
        self.assertEqual("CVE-2026-12345", result.cve_id)

    def test_malformed_kev_id_requires_review(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": [],
        }

        result = match_kev(advisory, {"CVE-2026-12345", "not-a-cve"})

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_kev_id", result.reason)

    def test_malformed_kev_snapshot_requires_review(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": [],
        }

        for snapshot in (None, 17):
            with self.subTest(snapshot=snapshot):
                result = match_kev(advisory, snapshot)  # type: ignore[arg-type]

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_kev_snapshot", result.reason)

    def test_empty_kev_snapshot_requires_review(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": [],
        }

        for snapshot in (set(), [], (), ""):
            with self.subTest(snapshot=snapshot):
                result = match_kev(advisory, snapshot)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_kev_snapshot", result.reason)

    def test_malformed_advisory_id_requires_review(self):
        for advisory in (
            {"aliases": []},
            {"id": None, "aliases": []},
            {"id": 17, "aliases": []},
            {"id": "   ", "aliases": []},
        ):
            with self.subTest(advisory=advisory):
                result = match_kev(advisory, {"CVE-2026-12345"})

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)

    def test_malformed_aliases_require_review(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": 123,
        }

        result = match_kev(advisory, {"CVE-2026-12345"})

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_aliases", result.reason)

    def test_blank_alias_requires_review(self):
        for alias in ("", "   "):
            with self.subTest(alias=alias):
                result = match_kev(
                    {"id": "GHSA-test-test-test", "aliases": [alias]},
                    {"CVE-2026-12345"},
                )

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_aliases", result.reason)

    def test_malformed_cve_like_direct_advisory_id_requires_review(self):
        for advisory_id in ("CVE-2026-123", "CVE-2026-12345-extra"):
            with self.subTest(advisory_id=advisory_id):
                result = match_kev(
                    {"id": advisory_id, "aliases": []},
                    {"CVE-2026-12345"},
                )

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)
                self.assertIsNone(result.cve_id)

    def test_unicode_confusable_cve_lookalike_requires_review(self):
        for alias in ("СVE-2026-1234", "CVЕ-2026-1234", "СVЕ-2026-1234"):
            with self.subTest(alias=alias):
                result = match_kev(
                    {"id": "GHSA-test-test-test", "aliases": [alias]},
                    {"CVE-2026-1234"},
                )

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_aliases", result.reason)
                self.assertIsNone(result.cve_id)

    def test_lowercase_unicode_confusable_cve_lookalikes_require_review(self):
        for advisory_id, aliases, reason in (
            ("сve-2026-1234", [], "malformed_advisory"),
            ("ghsa-test-test-test", ["сve-2026-1234"], "malformed_aliases"),
            ("ghsa-test-test-test", ["cvе-2026-1234"], "malformed_aliases"),
            ("ghsa-test-test-test", ["сvе-2026-1234"], "malformed_aliases"),
        ):
            with self.subTest(advisory_id=advisory_id, aliases=aliases):
                result = match_kev(
                    {"id": advisory_id, "aliases": aliases},
                    {"CVE-2026-1234"},
                )

                self.assertEqual("review", result.status)
                self.assertEqual(reason, result.reason)
                self.assertIsNone(result.cve_id)

    def test_failing_kev_snapshot_iterator_requires_review(self):
        def exploding_ids():
            yield "CVE-2026-12345"
            raise RuntimeError("broken snapshot")

        result = match_kev(
            {"id": "GHSA-test-test-test", "aliases": []},
            exploding_ids(),
        )

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_kev_snapshot", result.reason)

    def test_aliases_container_with_failing_iterator_requires_review(self):
        class BrokenAliases(list):
            def __iter__(self):
                raise RuntimeError("broken aliases")

        result = match_kev(
            {"id": "GHSA-test-test-test", "aliases": BrokenAliases(["CVE-2026-12345"])},
            {"CVE-2026-12345"},
        )

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_aliases", result.reason)

    def test_aliases_container_is_consumed_exactly_once(self):
        class SecondIterationRaises(list):
            def __init__(self, items):
                super().__init__(items)
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                if self.iterations > 1:
                    raise RuntimeError("container must not be re-consumed")
                return super().__iter__()

        aliases = SecondIterationRaises(["CVE-2026-12345"])
        result = match_kev(
            {"id": "GHSA-test-test-test", "aliases": aliases},
            {"CVE-2026-12345"},
        )

        self.assertEqual("known_exploited", result.status)
        self.assertEqual("CVE-2026-12345", result.cve_id)
        self.assertEqual(1, aliases.iterations)

    def test_missing_or_empty_aliases_is_valid_evidence_not_review(self):
        cases = (
            ({"id": "CVE-2026-12345"}, "known_exploited"),
            ({"id": "GHSA-test-test-test", "aliases": []}, "not_known_exploited"),
            ({"id": "GHSA-test-test-test", "aliases": None}, "not_known_exploited"),
        )
        for advisory, expected_status in cases:
            with self.subTest(advisory=advisory):
                result = match_kev(advisory, {"CVE-2026-12345"})

                self.assertEqual(expected_status, result.status)

    def test_cve_prefix_without_dash_is_an_ordinary_identifier(self):
        for advisory_id in ("CVEAT-2026-1234", "CVE1-2026-1234", "CVE"):
            with self.subTest(advisory_id=advisory_id):
                result = match_kev(
                    {"id": advisory_id, "aliases": []},
                    {"CVE-2026-12345"},
                )

                self.assertEqual("not_known_exploited", result.status)
                self.assertEqual("no_exact_cve_alias", result.reason)

    def test_matches_exact_cve_alias(self):
        advisory = {
            "id": "GHSA-test-test-test",
            "aliases": ["CVE-2026-12345"],
        }

        result = match_kev(advisory, {"CVE-2026-12345"})

        self.assertEqual("known_exploited", result.status)
        self.assertEqual("exact_cve_alias", result.reason)
        self.assertEqual("CVE-2026-12345", result.cve_id)


if __name__ == "__main__":
    unittest.main()
