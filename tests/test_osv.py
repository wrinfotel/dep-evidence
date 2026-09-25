import unittest

from dep_evidence.model import Component
from dep_evidence.osv import match_osv


class OsvMatchingTests(unittest.TestCase):
    def make_component(self, version="1.0.0"):
        return Component(
            ecosystem="Maven",
            namespace="org.example",
            name="demo",
            version=version,
        )

    def test_non_dict_advisory_requires_review(self):
        for advisory in (None, []):
            with self.subTest(advisory=advisory):
                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)

    def test_missing_or_invalid_advisory_id_requires_review(self):
        for advisory_id in (None, 17, "", "   "):
            with self.subTest(advisory_id=advisory_id):
                advisory = {
                    "id": advisory_id,
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.example:demo",
                            },
                            "versions": ["1.0.0"],
                        }
                    ],
                }

                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)

    def test_matches_enumerated_affected_version(self):
        advisory = {
            "id": "OSV-2026-1",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("OSV-2026-1", result.advisory_id)
        self.assertEqual("affected", result.status)
        self.assertEqual("exact_version", result.reason)

    def test_matches_equivalent_maven_version_in_exact_list(self):
        advisory = {
            "id": "OSV-2026-8",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component("1.0"), advisory)

        self.assertEqual("affected", result.status)
        self.assertEqual("exact_version", result.reason)

    def test_evaluates_multiple_disjoint_ranges_in_one_event_list(self):
        advisory = {
            "id": "OSV-2026-9",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.0.2"},
                                {"introduced": "3.0.0"},
                                {"fixed": "3.2.5"},
                            ],
                        }
                    ],
                }
            ],
        }

        self.assertEqual("affected", match_osv(self.make_component("1.0.1"), advisory).status)
        self.assertEqual("not_affected", match_osv(self.make_component("2.0.0"), advisory).status)
        self.assertEqual("affected", match_osv(self.make_component("3.0.0"), advisory).status)
        self.assertEqual("not_affected", match_osv(self.make_component("3.2.5"), advisory).status)

    def test_limit_does_not_close_interval_before_later_introduced(self):
        advisory = {
            "id": "OSV-2026-42",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1"},
                                {"limit": "2"},
                                {"introduced": "3"},
                            ],
                        }
                    ],
                }
            ],
        }

        for version, expected in (
            ("0.5", ("not_affected", "no_match")),
            ("1.5", ("affected", "range")),
            ("2.5", ("not_affected", "no_match")),
            ("3.5", ("not_affected", "no_match")),
        ):
            with self.subTest(version=version):
                result = match_osv(self.make_component(version), advisory)
                self.assertEqual(expected, (result.status, result.reason))

    def test_unbounded_limit_does_not_close_interval_before_later_introduced(self):
        advisory = {
            "id": "OSV-2026-43",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1"},
                                {"limit": "*"},
                                {"introduced": "3"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("ambiguous_event_ordering", result.reason)

    def test_non_matching_package_is_not_affected(self):
        advisory = {
            "id": "OSV-2026-13",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:other",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("not_affected", result.status)
        self.assertEqual("package_name_mismatch", result.reason)

    def test_non_matching_ecosystem_is_not_affected(self):
        advisory = {
            "id": "OSV-2026-14",
            "affected": [
                {
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("not_affected", result.status)
        self.assertEqual("ecosystem_mismatch", result.reason)

    def test_matches_wildcard_package(self):
        advisory = {
            "id": "OSV-2026-12",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "*",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("affected", result.status)
        self.assertEqual("wildcard_package", result.reason)

    def test_matches_component_inside_introduced_fixed_range(self):
        advisory = {
            "id": "OSV-2026-2",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("affected", result.status)
        self.assertEqual("range", result.reason)

    def test_matches_exact_last_affected_version(self):
        advisory = {
            "id": "OSV-2026-3",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"last_affected": "1.5.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("affected", result.status)
        self.assertEqual("range_last_affected", result.reason)

    def test_ignores_withdrawn_advisory(self):
        advisory = {
            "id": "OSV-2026-4",
            "withdrawn": "2026-09-20T00:00:00Z",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("withdrawn", result.status)
        self.assertEqual("advisory_withdrawn", result.reason)

    def test_malformed_withdrawn_requires_review(self):
        for withdrawn in (None, 123, False, "", "   "):
            with self.subTest(withdrawn=withdrawn):
                advisory = {
                    "id": "OSV-2026-36",
                    "withdrawn": withdrawn,
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.example:demo",
                            },
                            "versions": ["1.0.0"],
                        }
                    ],
                }

                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)

    def test_malformed_withdrawn_timestamp_requires_review(self):
        for withdrawn in (
            "not-a-timestamp",
            "2026-09-20",
            "2026-02-30T00:00:00Z",
            "2026-09-20T00:00:00+03:00",
        ):
            with self.subTest(withdrawn=withdrawn):
                advisory = {
                    "id": "OSV-2026-39",
                    "withdrawn": withdrawn,
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.example:demo",
                            },
                            "versions": ["1.0.0"],
                        }
                    ],
                }

                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_advisory", result.reason)

    def test_unparseable_component_version_requires_review(self):
        advisory = {
            "id": "OSV-2026-5",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("latest"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("unparseable_component_version", result.reason)

    def test_returns_review_when_range_boundary_is_uncomparable(self):
        advisory = {
            "id": "OSV-2026-6",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0-customer-build"},
                                {"fixed": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("uncomparable_boundary", result.reason)

    def test_unsupported_ecosystem_variant_requires_review(self):
        advisory = {
            "id": "OSV-2026-16",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven:https://maven.google.com",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("unsupported_ecosystem_variant", result.reason)

    def test_repository_specific_maven_wildcard_requires_review(self):
        advisory = {
            "id": "OSV-2026-27",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven:https://maven.google.com",
                        "name": "*",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("unsupported_ecosystem_variant", result.reason)

    def test_malformed_package_identity_requires_review(self):
        packages = (
            {"name": "org.example:demo"},
            {"ecosystem": "Maven"},
            {"ecosystem": None, "name": "org.example:demo"},
            {"ecosystem": "Maven", "name": None},
            {"ecosystem": "Maven", "name": 17},
        )
        for package in packages:
            with self.subTest(package=package):
                advisory = {
                    "id": "OSV-2026-30",
                    "affected": [
                        {"package": package, "versions": ["1.0.0"]}
                    ],
                }

                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_affected", result.reason)

    def test_missing_or_empty_affected_evidence_requires_review(self):
        package = {"ecosystem": "Maven", "name": "org.example:demo"}
        advisories = (
            {"id": "OSV-2026-31"},
            {"id": "OSV-2026-32", "affected": []},
            {"id": "OSV-2026-33", "affected": [{"package": package, "versions": []}]},
            {"id": "OSV-2026-34", "affected": [{"package": package, "ranges": []}]},
            {
                "id": "OSV-2026-35",
                "affected": [{"package": package, "versions": [], "ranges": []}],
            },
        )
        for advisory in advisories:
            with self.subTest(advisory=advisory):
                result = match_osv(self.make_component(), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_affected", result.reason)

    def test_malformed_affected_requires_review(self):
        advisory = {
            "id": "OSV-2026-18",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    }
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_affected", result.reason)

    def test_malformed_affected_collection_requires_review(self):
        advisory = {
            "id": "OSV-2026-19",
            "affected": None,
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_affected", result.reason)

    def test_malformed_exact_versions_requires_review(self):
        advisory = {
            "id": "OSV-2026-20",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["latest"],
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_exact_version", result.reason)

    def test_exact_match_does_not_hide_malformed_exact_sibling(self):
        advisory = {
            "id": "OSV-2026-37",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0", "latest"],
                }
            ],
        }

        result = match_osv(self.make_component("1.0.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_exact_version", result.reason)

    def test_null_exact_versions_requires_review(self):
        advisory = {
            "id": "OSV-2026-22",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": None,
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_exact_version", result.reason)

    def test_null_ranges_requires_review(self):
        advisory = {
            "id": "OSV-2026-23",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": None,
                }
            ],
        }

        result = match_osv(self.make_component(), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_range", result.reason)

    def test_affected_range_wins_over_non_matching_sibling_range(self):
        advisory = {
            "id": "OSV-2026-24",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "3.0.0"},
                                {"fixed": "4.0.0"},
                            ],
                        },
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("affected", result.status)
        self.assertEqual("range", result.reason)

    def test_exact_match_does_not_hide_malformed_sibling_range(self):
        advisory = {
            "id": "OSV-2026-25",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "versions": ["1.0.0"],
                    "ranges": [17],
                }
            ],
        }

        result = match_osv(self.make_component("1.0.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_range", result.reason)

    def test_malformed_range_after_affected_range_requires_review(self):
        advisory = {
            "id": "OSV-2026-21",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                            ],
                        },
                        17,
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_range", result.reason)

    def test_mixed_terminators_require_review(self):
        advisory = {
            "id": "OSV-2026-17",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "2.0.0"},
                                {"last_affected": "2.5.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("mixed_terminator_events", result.reason)

    def test_reversed_interval_boundaries_require_review(self):
        advisory = {
            "id": "OSV-2026-26",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0.0"},
                                {"fixed": "1.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("ambiguous_event_ordering", result.reason)

    def test_equal_introduced_and_last_affected_boundaries_require_review(self):
        advisory = {
            "id": "OSV-2026-40",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"last_affected": "1.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.0.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("ambiguous_event_ordering", result.reason)

    def test_equal_zero_introduced_and_terminator_boundaries_require_review(self):
        for event in (
            {"fixed": "0"},
            {"last_affected": "0"},
            {"limit": "0"},
            {"fixed": "0.0"},
            {"last_affected": "0.0"},
            {"limit": "0.0"},
        ):
            with self.subTest(event=event):
                advisory = {
                    "id": "OSV-2026-41",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.example:demo",
                            },
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, event],
                                }
                            ],
                        }
                    ],
                }

                result = match_osv(self.make_component("1.0.0"), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("ambiguous_event_ordering", result.reason)

    def test_non_string_event_boundaries_require_review(self):
        event_lists = (
            [{"introduced": 0}],
            [{"introduced": "1.0.0"}, {"fixed": 2.0}],
            [{"introduced": "1.0.0"}, {"last_affected": 2.0}],
            [{"introduced": "1.0.0"}, {"limit": 2.0}],
        )
        for events in event_lists:
            with self.subTest(events=events):
                advisory = {
                    "id": "OSV-2026-29",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Maven",
                                "name": "org.example:demo",
                            },
                            "ranges": [{"type": "ECOSYSTEM", "events": events}],
                        }
                    ],
                }

                result = match_osv(self.make_component("1.5.0"), advisory)

                self.assertEqual("review", result.status)
                self.assertEqual("malformed_event", result.reason)

    def test_event_with_extra_key_requires_review(self):
        advisory = {
            "id": "OSV-2026-38",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0", "note": "unexpected"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.0.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_event", result.reason)

    def test_malformed_event_requires_review(self):
        advisory = {
            "id": "OSV-2026-10",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"introduced": "1.1.0", "fixed": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("malformed_event", result.reason)

    def test_range_without_introduced_requires_review(self):
        advisory = {
            "id": "OSV-2026-11",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"fixed": "2.0.0"}]}
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("missing_introduced", result.reason)

    def test_finite_limit_excludes_candidate_at_boundary(self):
        advisory = {
            "id": "OSV-2026-28",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"limit": "2.0.0"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("2.0.0"), advisory)

        self.assertEqual("not_affected", result.status)

    def test_limit_star_is_implicitly_unbounded(self):
        advisory = {
            "id": "OSV-2026-15",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"limit": "*"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.5.0"), advisory)

        self.assertEqual("affected", result.status)

    def test_unsupported_range_type_requires_review(self):
        advisory = {
            "id": "OSV-2026-7",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:demo",
                    },
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://example.test/repo.git",
                            "events": [
                                {"introduced": "deadbeef"},
                                {"fixed": "cafebabe"},
                            ],
                        }
                    ],
                }
            ],
        }

        result = match_osv(self.make_component("1.0.0"), advisory)

        self.assertEqual("review", result.status)
        self.assertEqual("unsupported_range_type", result.reason)


if __name__ == "__main__":
    unittest.main()
