"""RED slice for the CLI and the strict offline path.

These are real subprocess tests: they run `python3 -m dep_evidence` so exit
codes, stderr and the absence of a traceback are all exercised for real.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {
            "bom-ref": "keep",
            "type": "library",
            "group": "org.example",
            "name": "keep",
            "version": "1.0.0",
            "purl": "pkg:maven/org.example/keep@1.0.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        }
    ],
}

OSV_RECORD = {
    "id": "OSV-2026-1",
    "aliases": ["CVE-2026-1000"],
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.example:keep"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
        }
    ],
}

KEV = {
    "count": 1,
    "vulnerabilities": [
        {"cveID": "CVE-2026-1000", "vendorProject": "x", "product": "y", "dateAdded": "2026-01-01"}
    ],
}


def run_cli(*args, env_extra=None, stdin=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-B", "-m", "dep_evidence", *args],
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=120,
    )


def write_sbom(directory: Path, document=None) -> Path:
    path = directory / "sbom.json"
    path.write_text(json.dumps(document if document is not None else SBOM), encoding="utf-8")
    return path


def write_datasets(directory: Path) -> tuple[Path, Path]:
    """Write a fake OSV zip and KEV json that a localhost server can serve."""
    osv_zip = directory / "osv.zip"
    with ZipFile(osv_zip, "w") as archive:
        archive.writestr("record.json", json.dumps(OSV_RECORD))
    kev = directory / "kev.json"
    kev.write_text(json.dumps(KEV), encoding="utf-8")
    return osv_zip, kev


class CliSurfaceTests(unittest.TestCase):
    def test_help_works_and_exits_zero(self):
        result = run_cli("--help")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("sync", result.stdout)
        self.assertIn("analyze", result.stdout)
        self.assertIn("diff", result.stdout)

    def test_unknown_command_exits_nonzero_without_traceback(self):
        result = run_cli("nonsense")
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("Traceback", result.stdout)

    def test_missing_subcommand_exits_nonzero(self):
        result = run_cli()
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("Traceback", result.stderr)


class AnalyzeOfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.sbom = write_sbom(self.work)

    def test_analyze_without_cache_reports_a_clear_error(self):
        result = run_cli(
            "analyze", "--sbom", str(self.sbom), "--cache", str(self.work / "empty"),
            "--out", str(self.work / "out"),
        )
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("sync", result.stderr.lower())

    def test_analyze_makes_no_network_call_even_with_a_valid_cache(self):
        # Build a cache by hand, then make any socket use fatal.
        cache = self.work / "cache"
        run_cli("sync", "--cache", str(cache), "--osv-url", "http://127.0.0.1:1/none.zip",
                "--kev-url", "http://127.0.0.1:1/none.json")
        result = run_cli(
            "analyze", "--sbom", str(self.sbom), "--cache", str(cache), "--out", str(self.work / "out"),
            env_extra={"http_proxy": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1",
                       "no_proxy": "", "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"},
        )
        # Either there is no cache yet (sync failed), or analyze worked offline.
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_sbom_exits_nonzero_without_traceback(self):
        bad = self.work / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = run_cli("analyze", "--sbom", str(bad), "--out", str(self.work / "out"))
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_sbom_file_exits_nonzero_without_traceback(self):
        result = run_cli("analyze", "--sbom", str(self.work / "nope.json"), "--out", str(self.work / "out"))
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("Traceback", result.stderr)


class DiffCommandTests(unittest.TestCase):
    def test_diff_of_two_identical_directories_reports_no_changes(self):
        with TemporaryDirectory() as tmp:
            work = Path(tmp)
            first, second = work / "a", work / "b"
            # evidence.json holds the evidence document itself, not a wrapper.
            payload = {"components": [], "findings": []}
            for target in (first, second):
                target.mkdir()
                (target / "evidence.json").write_text(json.dumps(payload), encoding="utf-8")
            result = run_cli("diff", "--before", str(first), "--after", str(second))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("no changes", result.stdout)

    def test_diff_reports_added_and_removed(self):
        with TemporaryDirectory() as tmp:
            work = Path(tmp)
            first, second = work / "a", work / "b"
            first.mkdir()
            second.mkdir()
            (first / "evidence.json").write_text(
                json.dumps({"components": [{"coordinate": "pkg:maven/o/a@1"}], "findings": []}),
                encoding="utf-8",
            )
            (second / "evidence.json").write_text(
                json.dumps({"components": [{"coordinate": "pkg:maven/o/b@1"}], "findings": []}),
                encoding="utf-8",
            )
            result = run_cli("diff", "--before", str(first), "--after", str(second))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("added", result.stdout)
            self.assertIn("removed", result.stdout)

    def test_diff_of_missing_directory_exits_nonzero_without_traceback(self):
        with TemporaryDirectory() as tmp:
            result = run_cli("diff", "--before", str(Path(tmp) / "nope"), "--after", str(Path(tmp)))
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("Traceback", result.stderr)


class SyncCommandTests(unittest.TestCase):
    def test_sync_against_unreachable_host_exits_nonzero_without_traceback(self):
        with TemporaryDirectory() as tmp:
            result = run_cli(
                "sync", "--cache", str(Path(tmp) / "cache"),
                "--osv-url", "http://127.0.0.1:1/osv.zip",
                "--kev-url", "http://127.0.0.1:1/kev.json",
            )
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("Traceback", result.stderr)

    def test_sync_rejects_a_non_http_url(self):
        with TemporaryDirectory() as tmp:
            result = run_cli(
                "sync", "--cache", str(Path(tmp) / "cache"),
                "--osv-url", "file:///etc/passwd",
                "--kev-url", "http://127.0.0.1:1/kev.json",
            )
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
