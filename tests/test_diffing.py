"""RED slice for the deterministic local diff."""

import unittest

from dep_evidence.diffing import diff_bundles, summarize_diff


def bundle(components, findings, exceptions):
    return {
        "evidence": {
            "components": components,
            "findings": findings,
        },
        "exceptions": exceptions,
    }


BASE_COMPONENTS = [
    {"coordinate": "pkg:maven/org.example/keep@1.0.0", "name": "keep", "version": "1.0.0"},
    {"coordinate": "pkg:maven/org.example/removed@1.0.0", "name": "removed", "version": "1.0.0"},
]
BASE_FINDINGS = [
    {
        "component": "pkg:maven/org.example/keep@1.0.0",
        "advisory_id": "OSV-1",
        "status": "affected",
    }
]
BASE_EXCEPTIONS = [
    {"component": "pkg:maven/org.example/keep@1.0.0", "advisory_id": "OSV-1", "state": "ignored"}
]


class DiffTests(unittest.TestCase):
    def test_added_and_removed_components(self):
        before = bundle(BASE_COMPONENTS, [], [])
        after = bundle(
            [
                {"coordinate": "pkg:maven/org.example/keep@1.0.0", "name": "keep", "version": "1.0.0"},
                {"coordinate": "pkg:maven/org.example/new@2.0.0", "name": "new", "version": "2.0.0"},
            ],
            [],
            [],
        )
        result = diff_bundles(before, after)
        # Full records, not bare coordinates: a diff has to say what was added.
        self.assertEqual(
            ["pkg:maven/org.example/new@2.0.0"],
            [c["coordinate"] for c in result["components_added"]],
        )
        self.assertEqual(
            ["pkg:maven/org.example/removed@1.0.0"],
            [c["coordinate"] for c in result["components_removed"]],
        )
        self.assertEqual([], result["components_changed"])

    def test_new_and_resolved_findings(self):
        before = bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)
        after = bundle(
            BASE_COMPONENTS,
            [
                {
                    "component": "pkg:maven/org.example/removed@1.0.0",
                    "advisory_id": "OSV-2",
                    "status": "affected",
                }
            ],
            [],
        )
        result = diff_bundles(before, after)
        keys = [(f["component"], f["advisory_id"]) for f in result["findings_new"]]
        self.assertEqual([("pkg:maven/org.example/removed@1.0.0", "OSV-2")], keys)
        resolved = [(f["component"], f["advisory_id"]) for f in result["findings_resolved"]]
        self.assertEqual([("pkg:maven/org.example/keep@1.0.0", "OSV-1")], resolved)

    def test_exception_state_changes_are_reported(self):
        before = bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)
        after = bundle(
            BASE_COMPONENTS,
            BASE_FINDINGS,
            [{"component": "pkg:maven/org.example/keep@1.0.0", "advisory_id": "OSV-1", "state": "accepted"}],
        )
        result = diff_bundles(before, after)
        self.assertEqual(1, len(result["exceptions_changed"]))
        self.assertEqual("ignored", result["exceptions_changed"][0]["from"])
        self.assertEqual("accepted", result["exceptions_changed"][0]["to"])

    def test_diff_is_deterministic_regardless_of_input_order(self):
        shuffled_components = [BASE_COMPONENTS[1], BASE_COMPONENTS[0]]
        before = bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)
        after = bundle(shuffled_components, BASE_FINDINGS, BASE_EXCEPTIONS)
        self.assertEqual(
            diff_bundles(before, after),
            diff_bundles(before, bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)),
        )

    def test_identical_bundles_produce_an_empty_diff(self):
        same = bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)
        result = diff_bundles(same, same)
        for key, value in result.items():
            self.assertEqual([], value, f"{key} should be empty")
        self.assertEqual("no changes", summarize_diff(result))

    def test_malformed_bundle_surfaces_as_data_error(self):
        from dep_evidence.errors import DataError

        for bad in (None, [], "text", {"evidence": None}, {"evidence": {}}, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(DataError):
                    diff_bundles(bad, bundle(BASE_COMPONENTS, [], []))
                with self.assertRaises(DataError):
                    diff_bundles(bundle(BASE_COMPONENTS, [], []), bad)

    def test_component_without_coordinate_surfaces_as_data_error(self):
        from dep_evidence.errors import DataError

        bad = bundle([{"name": "no-coordinate"}], [], [])
        with self.assertRaises(DataError):
            diff_bundles(bad, bad)

    def test_summary_counts_the_human_readable_totals(self):
        before = bundle(BASE_COMPONENTS, BASE_FINDINGS, BASE_EXCEPTIONS)
        after = bundle(
            [BASE_COMPONENTS[0], {"coordinate": "pkg:maven/org.example/new@2.0.0", "name": "new", "version": "2.0.0"}],
            [],
            [],
        )
        summary = summarize_diff(diff_bundles(before, after))
        self.assertIn("1 added", summary)
        self.assertIn("1 removed", summary)
        self.assertIn("1 resolved", summary)


if __name__ == "__main__":
    unittest.main()
