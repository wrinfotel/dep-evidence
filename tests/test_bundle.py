"""RED slice for the evidence bundle writer."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dep_evidence.errors import DataError
from dep_evidence.model import Component

BUNDLE_FILES = (
    "evidence.json",
    "report.html",
    "components.csv",
    "exceptions.json",
    "sources.json",
    "run_manifest.json",
)


class WriteBundleTests(unittest.TestCase):
    def setUp(self):
        self.evidence = {
            "analysis_fingerprint": "fp-1",
            "policy_version": "1",
            "source_versions": {"osv": "2026-09-25", "kev": "2026-09-25"},
            "summary": {"components": 1, "findings": 1},
            "findings": [
                {
                    "component": "maven:g:a@1.0.0",
                    "advisory_id": "GHSA-1",
                    "status": "affected",
                    "reason": "range",
                    "kev": {
                        "status": "known_exploited",
                        "cve_id": "CVE-2024-1",
                        "reason": None,
                    },
                }
            ],
        }
        self.sources = {"osv": {"url": "https://x/o.zip", "record_count": 1}}
        self.exceptions = []
        self.components = [
            Component(
                ecosystem="maven",
                namespace="g",
                name="a",
                version="1.0.0",
                relationship="direct",
            )
        ]
        self.run_metadata = {"tool_version": "0.1.0", "started_at": "2026-09-25T00:00:00Z"}

    def write(self, out_dir=None, **overrides):
        from dep_evidence.bundle import write_bundle

        kwargs = {
            "evidence": self.evidence,
            "findings": self.evidence["findings"],
            "components": self.components,
            "sources": self.sources,
            "exceptions": self.exceptions,
            "run_metadata": self.run_metadata,
        }
        kwargs.update(overrides)
        with TemporaryDirectory() as tmp:
            target = Path(tmp) if out_dir is None else out_dir
            return write_bundle(target, **kwargs)

    def test_all_bundle_files_are_written(self):
        with TemporaryDirectory() as tmp:
            self.write(Path(tmp))
            for name in BUNDLE_FILES:
                self.assertTrue((Path(tmp) / name).is_file(), f"missing {name}")

    def test_runtime_metadata_stays_out_of_evidence_json(self):
        # The design requires runtime timestamps to never change evidence.json.
        with TemporaryDirectory() as tmp:
            self.write(Path(tmp), run_metadata={"started_at": "2020-01-01T00:00:00Z"})
            evidence = json.loads((Path(tmp) / "evidence.json").read_text("utf-8"))
            self.assertNotIn("2020-01-01", json.dumps(evidence))
            self.assertNotIn("started_at", evidence)

    def test_run_manifest_holds_the_runtime_metadata(self):
        with TemporaryDirectory() as tmp:
            self.write(Path(tmp))
            manifest = json.loads((Path(tmp) / "run_manifest.json").read_text("utf-8"))
            self.assertEqual("0.1.0", manifest["tool_version"])

    def test_evidence_json_is_byte_identical_across_runs(self):
        with TemporaryDirectory() as a, TemporaryDirectory() as b:
            self.write(Path(a), run_metadata={"started_at": "2020-01-01T00:00:00Z"})
            self.write(Path(b), run_metadata={"started_at": "2031-06-06T06:06:06Z"})
            self.assertEqual(
                (Path(a) / "evidence.json").read_bytes(),
                (Path(b) / "evidence.json").read_bytes(),
            )

    def test_components_csv_is_byte_identical_across_runs(self):
        with TemporaryDirectory() as a, TemporaryDirectory() as b:
            self.write(Path(a))
            self.write(Path(b))
            self.assertEqual(
                (Path(a) / "components.csv").read_bytes(),
                (Path(b) / "components.csv").read_bytes(),
            )

    def test_html_has_no_remote_assets(self):
        with TemporaryDirectory() as tmp:
            self.write(Path(tmp))
            html = (Path(tmp) / "report.html").read_text("utf-8")
            self.assertNotIn("http://", html)
            self.assertNotIn("https://", html)

    def test_evidence_files_are_always_written_even_with_zero_findings(self):
        with TemporaryDirectory() as tmp:
            self.write(
                Path(tmp),
                findings=[],
                evidence={
                    "analysis_fingerprint": "fp-0",
                    "summary": {"components": 0, "findings": 0},
                    "findings": [],
                },
            )
            self.assertEqual(
                [], json.loads((Path(tmp) / "evidence.json").read_text("utf-8"))["findings"]
            )
            self.assertTrue((Path(tmp) / "report.html").is_file())

    def test_unwritable_output_surfaces_as_data_error(self):
        blocker = Path(self.enterContext(TemporaryDirectory())) / "blocked"
        blocker.write_text("not a directory", encoding="utf-8")
        with self.assertRaises(DataError):
            self.write(blocker)

    def test_exceptions_json_is_written_verbatim(self):
        payload = [{"component": "maven:g:a@1.0.0", "state": "active"}]
        with TemporaryDirectory() as tmp:
            self.write(Path(tmp), exceptions=payload)
            self.assertEqual(
                payload, json.loads((Path(tmp) / "exceptions.json").read_text("utf-8"))
            )


if __name__ == "__main__":
    unittest.main()
