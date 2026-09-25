"""RED slice for deterministic provenance assembly."""

import unittest

from dep_evidence.errors import DataError

MANIFEST = {
    "tool_version": "0.1.0",
    "format_version": 1,
    "fetched_at": "2026-09-25T17:20:38.299452Z",
    # sync_snapshots nests each dataset under "sources"; build_sources reads
    # this exact shape, so the fixture must match what sync really writes.
    "sources": {
        "osv": {
            "url": "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip",
            "record_count": 2,
            "sha256": "a" * 64,
            "bytes": 1234,
            "etag": "W/\"abc\"",
            "last_modified": "Thu, 25 Sep 2026 00:00:00 GMT",
        },
        "kev": {
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "record_count": 1,
            "sha256": "b" * 64,
            "bytes": 567,
            "etag": "W/\"def\"",
            "last_modified": "Fri, 26 Sep 2026 00:00:00 GMT",
        },
    },
    "files": {
        "osv/records.jsonl": {"sha256": "c" * 64, "bytes": 100},
        "kev/kev.json": {"sha256": "d" * 64, "bytes": 200},
    },
}


class BuildSourcesTests(unittest.TestCase):
    def build(self, manifest=None, policy_version="1"):
        from dep_evidence.analysis import build_sources

        return build_sources(
            MANIFEST if manifest is None else manifest, policy_version=policy_version
        )

    def test_sources_carry_url_and_digest_per_dataset(self):
        sources = self.build()
        self.assertEqual(MANIFEST["sources"]["osv"]["url"], sources["osv"]["url"])
        self.assertEqual("a" * 64, sources["osv"]["sha256"])
        self.assertEqual(2, sources["osv"]["record_count"])
        self.assertEqual("b" * 64, sources["kev"]["sha256"])

    def test_sources_are_byte_identical_across_calls(self):
        from dep_evidence.reporting import render_sources_json

        self.assertEqual(
            render_sources_json(self.build()), render_sources_json(self.build())
        )

    def test_policy_version_is_recorded(self):
        self.assertEqual("1", self.build()["policy_version"])

    def test_fetches_timestamp_field_is_absent(self):
        # The manifest may carry a fetch time; the deterministic evidence must
        # not, or two runs over the same snapshot would differ.
        manifest = {
            **MANIFEST,
            "fetched_at": "2026-09-25T12:00:00Z",
            "sources": {
                **MANIFEST["sources"],
                "osv": {**MANIFEST["sources"]["osv"], "fetched_at": "2026-09-25T12:00:00Z"},
            },
        }
        from dep_evidence.reporting import render_sources_json

        rendered = render_sources_json(self.build(manifest)).decode("utf-8")
        self.assertNotIn("2026-09-25T12:00:00Z", rendered)
        self.assertNotIn("fetched_at", rendered)

    def test_versions_are_derived_from_the_snapshot(self):
        sources = self.build()
        self.assertIn("osv", sources["versions"])
        self.assertIn("kev", sources["versions"])

    def test_missing_dataset_surfaces_as_data_error(self):
        sources = {k: v for k, v in MANIFEST["sources"].items() if k != "kev"}
        manifest = {**MANIFEST, "sources": sources}
        with self.assertRaises(DataError):
            self.build(manifest)

    def test_malformed_dataset_entry_surfaces_as_data_error(self):
        for key in ("osv", "kev"):
            for bad in (None, "string", 42, []):
                with self.subTest(dataset=key, value=bad):
                    manifest = {**MANIFEST, "sources": {**MANIFEST["sources"], key: bad}}
                    with self.assertRaises(DataError):
                        self.build(manifest)

    def test_missing_required_field_surfaces_as_data_error(self):
        for field in ("url", "record_count", "sha256"):
            broken = {k: v for k, v in MANIFEST["sources"]["osv"].items() if k != field}
            manifest = {**MANIFEST, "sources": {**MANIFEST["sources"], "osv": broken}}
            with self.subTest(field=field):
                with self.assertRaises(DataError):
                    self.build(manifest)


if __name__ == "__main__":
    unittest.main()
