import unittest

from dep_evidence.analysis import canonical_components, findings_for_component
from dep_evidence.model import Component


def make_component(name, version="1.0.0", namespace="org.example"):
    return Component(ecosystem="Maven", namespace=namespace, name=name, version=version)


ADVISORY = {
    "id": "GHSA-test-test-test",
    "aliases": ["CVE-2026-1234"],
    "modified": "2026-09-25T00:00:00Z",
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


class CanonicalOrderingTests(unittest.TestCase):
    def test_components_are_ordered_deterministically_by_identity(self):
        components = [
            make_component("zeta"),
            make_component("alpha", namespace="org.zzz"),
            make_component("alpha", version="2.0.0"),
            make_component("alpha"),
        ]

        ordered = canonical_components(components)

        self.assertEqual(
            [
                "Maven:org.example:alpha@1.0.0",
                "Maven:org.example:alpha@2.0.0",
                "Maven:org.example:zeta@1.0.0",
                "Maven:org.zzz:alpha@1.0.0",
            ],
            [component.coordinate for component in ordered],
        )

    def test_canonical_order_is_stable_across_shuffled_inputs(self):
        components = [make_component(name) for name in ("delta", "alpha", "charlie", "bravo")]

        first = canonical_components(components)
        second = canonical_components(list(reversed(components)))

        self.assertEqual(
            [component.coordinate for component in first],
            [component.coordinate for component in second],
        )


class FindingShapeTests(unittest.TestCase):
    def test_finding_records_status_reason_and_source_ids(self):
        component = make_component("demo")

        findings = findings_for_component(
            component,
            [ADVISORY],
            kev_cve_ids=("CVE-2026-1234",),
        )

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("affected", finding["status"])
        self.assertEqual("exact_version", finding["reason"])
        self.assertEqual("GHSA-test-test-test", finding["advisory_id"])
        self.assertEqual("Maven:org.example:demo@1.0.0", finding["component"])
        self.assertEqual("CVE-2026-1234", finding["kev"]["cve_id"])
        self.assertEqual("known_exploited", finding["kev"]["status"])
        self.assertEqual("exact_cve_alias", finding["kev"]["reason"])

    def test_non_affected_component_produces_no_finding(self):
        component = make_component("other")

        self.assertEqual(
            [],
            findings_for_component(component, [ADVISORY], kev_cve_ids=("CVE-2026-1234",)),
        )

    def test_findings_are_ordered_by_component_then_advisory(self):
        component = make_component("demo")
        advisories = [
            dict(ADVISORY, id="GHSA-zzzz-zzzz-zzzz"),
            dict(ADVISORY, id="GHSA-aaaa-aaaa-aaaa"),
        ]

        findings = findings_for_component(component, advisories, kev_cve_ids=())

        self.assertEqual(
            ["GHSA-aaaa-aaaa-aaaa", "GHSA-zzzz-zzzz-zzzz"],
            [finding["advisory_id"] for finding in findings],
        )
