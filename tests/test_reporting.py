import json
import unittest

from dep_evidence.reporting import render_evidence_json, render_report_html


FINDINGS = [
    {
        "component": "Maven:org.example:alpha@1.0.0",
        "ecosystem": "Maven",
        "package": "org.example:alpha",
        "version": "1.0.0",
        "advisory_id": "GHSA-aaaa-aaaa-aaaa",
        "status": "affected",
        "reason": "exact_version",
        "kev": {"status": "not_known_exploited", "reason": "no_exact_cve_alias", "cve_id": None},
    },
    {
        "component": "Maven:org.example:beta@2.0.0",
        "ecosystem": "Maven",
        "package": "org.example:beta",
        "version": "2.0.0",
        "advisory_id": "GHSA-bbbb-bbbb-bbbb",
        "status": "review",
        "reason": "unparseable_version",
        "kev": {"status": "not_known_exploited", "reason": "no_exact_cve_alias", "cve_id": None},
    },
]

COMPONENTS = [
    {
        "ecosystem": "Maven",
        "package": "org.example:alpha",
        "version": "1.0.0",
        "coordinate": "Maven:org.example:alpha@1.0.0",
        "relationship": "direct",
        "purl": "pkg:maven/org.example/alpha@1.0.0",
    },
]

SOURCES = {
    "osv": {
        "url": "https://example.invalid/all.zip",
        "sha256": "a" * 64,
        "record_count": 1,
        "etag": '"v1"',
        "last_modified": "Fri, 25 Sep 2026 00:00:00 GMT",
    },
    "kev": {
        "url": "https://example.invalid/kev.json",
        "sha256": "b" * 64,
        "record_count": 0,
        "etag": '"v1"',
        "last_modified": None,
    },
}

EXCEPTIONS = [
    {
        "ecosystem": "Maven",
        "package": "org.example:alpha",
        "advisory_id": "GHSA-aaaa-aaaa-aaaa",
        "reason": "vendor fix scheduled",
        "expires_on": "2026-12-31",
        "state": "active",
    },
]


def build_evidence():
    return {
        "schema_version": 1,
        "tool_version": "0.1.0",
        "policy_version": "1",
        "analysis_fingerprint": "f" * 64,
        "components": COMPONENTS,
        "findings": FINDINGS,
        "summary": {"affected": 1, "review": 1, "withdrawn": 0},
    }


class EvidenceJsonTests(unittest.TestCase):
    def test_evidence_json_is_byte_identical_across_runs(self):
        first = render_evidence_json(build_evidence())
        second = render_evidence_json(build_evidence())

        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    def test_evidence_json_is_parsed_and_keeps_ordered_findings(self):
        parsed = json.loads(render_evidence_json(build_evidence()))

        self.assertEqual(
            ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"],
            [finding["advisory_id"] for finding in parsed["findings"]],
        )
        self.assertEqual("f" * 64, parsed["analysis_fingerprint"])

    def test_key_order_is_stable_and_sorted(self):
        body = render_evidence_json({"b": 1, "a": 2, "c": {"z": 1, "y": 2}}).decode("utf-8")

        self.assertLess(body.index('"a"'), body.index('"b"'))
        self.assertLess(body.index('"b"'), body.index('"c"'))
        self.assertLess(body.index('"y"'), body.index('"z"'))

    def test_runtime_metadata_is_not_part_of_evidence(self):
        parsed = json.loads(render_evidence_json(build_evidence()))

        for forbidden in ("generated_at", "run_id", "hostname", "duration_ms", "started_at"):
            self.assertNotIn(forbidden, parsed)


class ReportHtmlTests(unittest.TestCase):
    def test_html_escapes_advisory_data_injecting_markup(self):
        findings = [
            {
                "component": "Maven:org.example:alpha@1.0.0",
                "ecosystem": "Maven",
                "package": "org.example:alpha",
                "version": "1.0.0",
                "advisory_id": "<script>alert('x')</script>",
                "status": "affected",
                "reason": "exact_version",
                "kev": {
                    "status": "not_known_exploited",
                    "reason": "no_exact_cve_alias",
                    "cve_id": None,
                },
            }
        ]

        html = render_report_html(build_evidence(), findings).decode("utf-8")

        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_has_no_remote_assets(self):
        html = render_report_html(build_evidence(), FINDINGS).decode("utf-8")

        for marker in ("http://", "https://", "<link", "<img", "src=", "@import"):
            self.assertNotIn(marker, html)

    def test_kev_wording_does_not_claim_component_was_exploited(self):
        findings = [
            dict(FINDINGS[0]),
            {
                **FINDINGS[0],
                "advisory_id": "GHSA-kev-kev-kev1",
                "kev": {
                    "status": "known_exploited",
                    "reason": "exact_cve_alias",
                    "cve_id": "CVE-2026-1234",
                },
            },
        ]

        html = render_report_html(build_evidence(), findings).decode("utf-8").lower()
        # The rendered paragraph wraps across a newline, so compare on collapsed
        # whitespace rather than on raw line breaks.
        flat = " ".join(html.split())

        self.assertIn("cve-2026-1234", flat)
        self.assertIn("cve appears in the cisa kev catalog", flat)
        # An affirmative claim that the component itself was exploited is a defect.
        # A negative disclaimer ("is not evidence that ... was exploited") is required.
        self.assertNotIn("component was exploited</td>", flat)
        self.assertNotIn("exploited in the wild", flat)
        self.assertIn("is not evidence that this component was exploited", flat)

    def test_review_findings_are_visible_in_html(self):
        html = render_report_html(build_evidence(), FINDINGS).decode("utf-8")

        self.assertIn("review", html)
        self.assertIn("GHSA-bbbb-bbbb-bbbb", html)

    def test_html_is_byte_identical_across_runs(self):
        self.assertEqual(
            render_report_html(build_evidence(), FINDINGS),
            render_report_html(build_evidence(), FINDINGS),
        )


class SourcesAndExceptionsTests(unittest.TestCase):
    def test_sources_preserve_snapshot_provenance_without_fetch_time(self):
        from dep_evidence.reporting import render_sources_json

        parsed = json.loads(render_sources_json(SOURCES))

        self.assertEqual("a" * 64, parsed["osv"]["sha256"])
        self.assertEqual(1, parsed["osv"]["record_count"])
        self.assertNotIn("fetched_at", parsed["osv"])
