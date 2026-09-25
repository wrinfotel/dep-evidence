import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from dep_evidence import sync as sync_module
from dep_evidence.datasets import (
    CURRENT_POINTER,
    iter_osv_records,
    load_kev_ids,
    load_snapshot_manifest,
)
from dep_evidence.errors import DataError
from dep_evidence.sync import (
    _read_kev,
    _read_osv_zip,
    _sweep_stale_pointer_temporaries,
    _sweep_stale_staging_directories,
    sync_snapshots,
)


OSV_RECORD = {
    "id": "GHSA-test-test-test",
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

KEV_DOCUMENT = {
    "title": "Synthetic KEV fixture",
    "catalogVersion": "2026.09.25",
    "dateReleased": "2026-09-25T00:00:00.0000Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1234",
            "vendorProject": "Example",
            "product": "Demo",
            "vulnerabilityName": "Synthetic test record",
            "dateAdded": "2026-09-25T00:00:00.0000Z",
        }
    ],
}


def build_osv_zip(record=None, member_name="GHSA-test-test-test.json") -> bytes:
    if record is None:
        record = OSV_RECORD
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, json.dumps(record))
    return output.getvalue()


class SyncSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.cache_dir = Path(self.temporary_directory.name) / "cache"
        self.osv_body = build_osv_zip()
        self.kev_body = json.dumps(KEV_DOCUMENT).encode("utf-8")

    def start_server(self):
        test_case = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/osv.zip":
                    body = test_case.osv_body
                    content_type = "application/zip"
                    etag = '"osv-v1"'
                elif self.path == "/kev.json":
                    body = test_case.kev_body
                    content_type = "application/json"
                    etag = '"kev-v1"'
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("ETag", etag)
                self.send_header("Last-Modified", "Fri, 25 Sep 2026 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        return f"http://{host}:{port}"

    def test_retries_transient_http_error_then_installs_snapshot(self):
        osv_body = self.osv_body
        kev_body = self.kev_body
        osv_attempts = Counter()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/osv.zip":
                    osv_attempts["count"] += 1
                    if osv_attempts["count"] == 1:
                        self.send_response(503)
                        self.send_header("Retry-After", "0")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    body = osv_body
                    content_type = "application/zip"
                elif self.path == "/kev.json":
                    body = kev_body
                    content_type = "application/json"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        result = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=2,
            max_download_bytes=1024 * 1024,
        )

        self.assertTrue(result.snapshot_dir.is_dir())
        self.assertEqual(2, osv_attempts["count"])
        self.assertEqual(("CVE-2026-1234",), load_kev_ids(self.cache_dir))

    def test_retry_after_controls_delay_before_transient_retry(self):
        osv_body = self.osv_body
        kev_body = self.kev_body
        osv_attempts = Counter()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/osv.zip":
                    osv_attempts["count"] += 1
                    if osv_attempts["count"] == 1:
                        self.send_response(429)
                        self.send_header("Retry-After", "7")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    body = osv_body
                    content_type = "application/zip"
                elif self.path == "/kev.json":
                    body = kev_body
                    content_type = "application/json"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        base_url = f"http://{host}:{port}"

        with patch("dep_evidence.sync.sleep") as sleep_mock:
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=2,
                max_download_bytes=1024 * 1024,
            )

        sleep_mock.assert_called_once_with(7.0)
        self.assertEqual(2, osv_attempts["count"])

    def test_validation_failure_preserves_last_good_snapshot_and_cleans_staging(self):
        base_url = self.start_server()
        first = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        pointer_before = (self.cache_dir / "current.json").read_bytes()

        self.osv_body = build_osv_zip([OSV_RECORD])
        with self.assertRaises(DataError):
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )

        self.assertEqual(pointer_before, (self.cache_dir / "current.json").read_bytes())
        self.assertEqual(first.snapshot_dir, self.cache_dir / "snapshots" / first.snapshot_dir.name)
        self.assertTrue(first.snapshot_dir.is_dir())
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))
        self.assertEqual([], list((self.cache_dir / "snapshots").glob(".staging-*")))

    def test_failed_atomic_pointer_replacement_removes_orphan_and_preserves_last_good(self):
        base_url = self.start_server()
        first = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        pointer_before = (self.cache_dir / "current.json").read_bytes()
        real_replace = os.replace
        calls = 0

        def fail_pointer_replace(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated pointer replacement failure")
            return real_replace(source, destination)

        with patch("dep_evidence.sync.os.replace", side_effect=fail_pointer_replace):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )

        self.assertEqual(pointer_before, (self.cache_dir / "current.json").read_bytes())
        self.assertTrue(first.snapshot_dir.is_dir())
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))
        self.assertEqual(
            1,
            len(list((self.cache_dir / "snapshots").glob("snapshot-*"))),
        )

    def test_pointer_slot_occupied_by_directory_surfaces_as_data_error(self):
        # Sibling of the mkdir guard: a directory squatting on the pointer slot
        # must normalize like any other unusable cache layout.
        base_url = self.start_server()
        first = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        pointer_path = self.cache_dir / "current.json"
        pointer_before = pointer_path.read_bytes()
        pointer_path.unlink()
        pointer_path.mkdir()

        with patch.object(sync_module, "sleep", lambda _seconds: None):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )

        # last-good stays the only reachable snapshot, and no residue is left.
        self.assertTrue(first.snapshot_dir.is_dir())
        self.assertEqual(
            1,
            len(list((self.cache_dir / "snapshots").glob("snapshot-*"))),
            "the failed install must not leave an orphan snapshot",
        )
        self.assertEqual([], list((self.cache_dir / "snapshots").glob(".staging-*")))
        self.assertEqual(
            [],
            [p for p in self.cache_dir.glob(".*.tmp")],
            "the temporary pointer must be cleaned up",
        )
        # The squatting directory is left as-is: removing foreign data is not
        # this tool's job, but the last-good pointer must still be readable.
        pointer_path.rmdir()
        pointer_path.write_bytes(pointer_before)
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))

    def test_cleanup_failure_cannot_mask_the_pointer_data_error(self):
        # A cleanup that itself fails must not replace the real DataError, and
        # must not leave the .tmp orphan behind.
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        pointer_path = self.cache_dir / "current.json"
        pointer_before = pointer_path.read_bytes()
        pointer_path.unlink()
        pointer_path.mkdir()

        real_unlink = Path.unlink

        def failing_unlink(self, *args, **kwargs):
            if self.name.startswith(".current.json"):
                raise OSError(5, "simulated cleanup failure")
            return real_unlink(self, *args, **kwargs)

        with patch.object(Path, "unlink", failing_unlink):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )

        pointer_path.rmdir()
        pointer_path.write_bytes(pointer_before)
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))

    def test_unwritable_staging_location_surfaces_as_data_error(self):
        # NOTE: a chmod-based fixture would be useless here, since the test may
        # run as root and bypass the permission bits entirely.
        base_url = self.start_server()
        with patch(
            "dep_evidence.sync.tempfile.mkdtemp",
            side_effect=PermissionError(13, "simulated staging failure"),
        ):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )
        self.assertEqual(
            [],
            list((self.cache_dir / "snapshots").glob("snapshot-*")),
            "a staging failure must not install anything",
        )

    def test_non_http_urls_are_rejected_as_data_error(self):
        base_url = self.start_server()
        cases = {
            "None osv": (None, f"{base_url}/kev.json"),
            "empty kev": (f"{base_url}/osv.zip", ""),
            "non-str": (12345, f"{base_url}/kev.json"),
            "ftp scheme": ("ftp://example.invalid/osv.zip", f"{base_url}/kev.json"),
            "bare path": ("/etc/passwd", f"{base_url}/kev.json"),
        }
        for label, (osv_url, kev_url) in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(DataError):
                    sync_snapshots(
                        self.cache_dir,
                        osv_url=osv_url,
                        kev_url=kev_url,
                        max_attempts=1,
                        max_download_bytes=1024 * 1024,
                    )

    def test_non_pathlike_cache_dir_surfaces_as_data_error(self):
        # Every public entrypoint must normalize a bad cache_dir the same way,
        # not leak TypeError from Path().
        def call_sync(cache_dir):
            sync_snapshots(
                cache_dir,
                osv_url="https://example.invalid/osv.zip",
                kev_url="https://example.invalid/kev.json",
                max_attempts=1,
            )

        entrypoints = {
            "sync": call_sync,
            "manifest": load_snapshot_manifest,
            "osv": lambda value: list(iter_osv_records(value)),
            "kev": load_kev_ids,
        }
        bad_values = {
            "None": None,
            "int": 7,
            "object": object(),
            "bytes": b"/tmp/x",
            "list": ["/tmp/x"],
        }
        for name, call in entrypoints.items():
            for label, value in bad_values.items():
                with self.subTest(entrypoint=name, value=label):
                    with self.assertRaises(DataError):
                        call(value)

    def test_non_integer_limits_surface_as_data_error(self):
        base_url = self.start_server()
        for limit in ("max_attempts", "max_download_bytes", "max_uncompressed_bytes"):
            for label, value in (("str", "3"), ("None", None), ("bool", True), ("float", 1.5)):
                with self.subTest(limit=limit, value=label):
                    kwargs = {
                        "osv_url": f"{base_url}/osv.zip",
                        "kev_url": f"{base_url}/kev.json",
                        limit: value,
                    }
                    with self.assertRaises(DataError):
                        sync_snapshots(self.cache_dir, **kwargs)

    def test_snapshot_rename_failure_surfaces_as_data_error(self):
        base_url = self.start_server()
        real_replace = os.replace

        def failing_rename(src, dst, *args, **kwargs):
            if Path(str(dst)).name.startswith("snapshot-"):
                raise OSError(13, "simulated rename failure")
            return real_replace(src, dst, *args, **kwargs)

        with patch("dep_evidence.sync.os.replace", failing_rename):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )
        self.assertEqual([], list((self.cache_dir / "snapshots").glob("snapshot-*")))
        self.assertEqual([], list((self.cache_dir / "snapshots").glob(".staging-*")))

    def test_stale_pointer_temporaries_are_swept_on_success(self):
        base_url = self.start_server()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        stale = self.cache_dir / f".{CURRENT_POINTER}.deadbeef.tmp"
        stale.write_text("{}", encoding="utf-8")
        # Must actually look stale: a fresh temp may belong to a concurrent
        # install, so the sweep deliberately spares it.
        old = time.time() - 86400
        os.utime(stale, (old, old))
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        self.assertFalse(stale.exists(), "stale pointer temp not swept")

    def test_sweep_spares_a_fresh_pointer_temp(self):
        # A concurrent install's in-flight temp must never be swept: doing so
        # made the other install fail with a spurious DataError.
        base_url = self.start_server()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        stale = self.cache_dir / f".{CURRENT_POINTER}.old.tmp"
        fresh = self.cache_dir / f".{CURRENT_POINTER}.inflight.tmp"
        for path in (stale, fresh):
            path.write_text("{}", encoding="utf-8")
        old = time.time() - 86400
        os.utime(stale, (old, old))

        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        self.assertFalse(stale.exists(), "stale temp should be swept")
        self.assertTrue(fresh.exists(), "a fresh in-flight temp must be spared")

    def test_sweep_failure_cannot_change_a_successful_install(self):
        base_url = self.start_server()
        with patch(
            "dep_evidence.sync._sweep_stale_pointer_temporaries",
            side_effect=ValueError("sweep exploded"),
        ):
            # A committed pointer must stay committed even if the hygiene
            # sweep blows up afterwards.
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))

    def test_enormous_uncompressed_limit_surfaces_as_data_error(self):
        base_url = self.start_server()
        for label, value in (("2**63", 2**63), ("maxsize", sys.maxsize), ("above", sys.maxsize + 1)):
            with self.subTest(limit=label):
                with self.assertRaises(DataError):
                    sync_snapshots(
                        self.cache_dir,
                        osv_url=f"{base_url}/osv.zip",
                        kev_url=f"{base_url}/kev.json",
                        max_attempts=1,
                        max_download_bytes=1024 * 1024,
                        max_uncompressed_bytes=value,
                    )

    def test_write_failure_during_staging_surfaces_as_data_error(self):
        base_url = self.start_server()
        real_open = Path.open

        def failing_open(self, *args, **kwargs):
            if self.name.endswith(("records.jsonl", "kev.json", "manifest.json")):
                raise PermissionError(13, "simulated write failure")
            return real_open(self, *args, **kwargs)

        with patch.object(Path, "open", failing_open):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )
        self.assertEqual([], list((self.cache_dir / "snapshots").glob("snapshot-*")))
        self.assertEqual([], list((self.cache_dir / "snapshots").glob(".staging-*")))

    def test_future_dated_pointer_temp_is_swept(self):
        # A future mtime must not make an orphan immortal: a crashed run on a
        # host with a fast clock plants exactly this.
        with TemporaryDirectory() as tmp:
            cache = Path(tmp)
            planted = cache / f".{CURRENT_POINTER}.planted.tmp"
            planted.write_text("{}", encoding="utf-8")
            ahead = time.time() + 86400
            os.utime(planted, (ahead, ahead))

            _sweep_stale_pointer_temporaries(cache)
            self.assertFalse(planted.exists(), "future-dated temp should be swept")

    def test_orphaned_staging_directories_are_reclaimed(self):
        with TemporaryDirectory() as tmp:
            cache = Path(tmp)
            snapshots = cache / "snapshots"
            orphan = snapshots / ".staging-orphan"
            orphan.mkdir(parents=True)
            (orphan / "junk").write_bytes(b"x" * 4096)
            fresh = snapshots / ".staging-inflight"
            fresh.mkdir(parents=True)
            old = time.time() - 86400
            os.utime(orphan, (old, old))

            _sweep_stale_staging_directories(snapshots)
            self.assertFalse(orphan.exists(), "stale staging dir should be reclaimed")
            self.assertTrue(fresh.exists(), "in-flight staging dir must be spared")

    def test_result_construction_failure_is_not_reported_as_a_failed_install(self):
        base_url = self.start_server()
        original = Path.resolve

        def failing_resolve(self, *args, **kwargs):
            if self.name.startswith("snapshot-"):
                raise OSError("resolve failed after commit")
            return original(self, *args, **kwargs)

        with patch.object(Path, "resolve", failing_resolve):
            # The install already committed, so a resolve failure must not turn
            # it into a reported failure: the result simply carries the
            # unresolved paths.
            result = sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )
        self.assertTrue(result.snapshot_dir.name.startswith("snapshot-"))
        # Whatever the reporting, the committed pointer must still be readable
        # and must not have been rolled back.
        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))

    def test_kev_install_stores_canonical_cve_ids(self):
        base_url = self.start_server()
        self.kev_body = json.dumps(
            dict(
                KEV_DOCUMENT,
                vulnerabilities=[
                    {"cveID": "cve-2026-1234 "},
                    {"cveID": "CVE-2026-5678"},
                ],
                count=2,
            )
        ).encode("utf-8")

        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        self.assertEqual(
            ("CVE-2026-1234", "CVE-2026-5678"),
            load_kev_ids(self.cache_dir),
        )

    def test_manifest_records_digests_of_installed_files(self):
        base_url = self.start_server()

        result = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        files = manifest["files"]

        for name, entry in files.items():
            digest = hashlib.sha256((result.snapshot_dir / name).read_bytes()).hexdigest()
            self.assertEqual(digest, entry["sha256"], name)

        self.assertIn("osv/records.jsonl", files)
        self.assertIn("kev/kev.json", files)

    def test_unsupported_zip_compression_surfaces_as_data_error(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("a.json", json.dumps({"id": "X"}))
        corrupted = bytearray(output.getvalue())
        header = corrupted.find(b"PK\x01\x02")
        corrupted[header + 10 : header + 12] = (99).to_bytes(2, "little")

        with self.assertRaises(DataError):
            _read_osv_zip(bytes(corrupted), 1024 * 1024)

    def test_corrupted_deflate_payload_surfaces_as_data_error(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("a.json", json.dumps({"id": "X" * 3000}))
        raw = bytearray(output.getvalue())
        local = raw.find(b"PK\x03\x04")
        name_len = int.from_bytes(raw[local + 26 : local + 28], "little")
        extra_len = int.from_bytes(raw[local + 28 : local + 30], "little")
        compressed_size = int.from_bytes(raw[local + 18 : local + 22], "little")
        central = int.from_bytes(output.getvalue()[-22:-16], "little")
        start = local + 30 + name_len + extra_len + 4
        # Corrupt only the DEFLATE payload, so the central directory still parses.
        for offset in range(start, min(start + compressed_size - 8, central)):
            raw[offset] ^= 0xA5

        with self.assertRaises(DataError):
            _read_osv_zip(bytes(raw), 1024 * 1024)

    def test_zip_member_named_dot_does_not_crash_the_drive_check(self):
        # PurePosixPath(".").parts is empty; indexing it used to raise IndexError
        # out of _read_osv_zip. The member name is never used as an extraction
        # target (records always land in osv/records.jsonl), so accepting it is
        # fine — what matters is that it surfaces no unexpected exception type.
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(".", json.dumps({"id": "X"}))

        try:
            _read_osv_zip(output.getvalue(), 1024 * 1024)
        except DataError:
            pass
        except Exception as exc:  # noqa: BLE001 - the point is the type
            self.fail(f"unexpected {type(exc).__name__}: {exc}")

    def test_huge_integer_field_surfaces_as_data_error(self):
        big = "1" * 5000
        document = '{"id":"A","n":' + big + "}"

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("a.json", document)

        with self.assertRaises(DataError):
            _read_osv_zip(output.getvalue(), 1024 * 1024)

        with self.assertRaises(DataError):
            _read_kev(
                (
                    '{"count":1,"vulnerabilities":['
                    '{"cveID":"CVE-2026-1234","n":' + big + "}]}"
                ).encode("utf-8")
            )

    def test_non_ascii_digest_surfaces_as_data_error(self):
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        snapshot = next((self.cache_dir / "snapshots").glob("snapshot-*"))
        manifest_path = snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["kev/kev.json"]["sha256"] = "диgест"
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        pointer_path = self.cache_dir / "current.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        pointer_path.write_text(json.dumps(pointer), encoding="utf-8")

        with self.assertRaises(DataError):
            load_kev_ids(self.cache_dir)

    def test_unusable_cache_dir_surfaces_as_data_error(self):
        # A tampered cache layout must normalize the same way as any other
        # bad input, not leak the raw OSError from mkdir.
        base_url = self.start_server()
        with TemporaryDirectory() as parent:
            blockers = {
                "regular file": Path(parent) / "as_file",
                "file at snapshots": Path(parent) / "as_dir" / "snapshots",
            }
            Path(parent, "as_file").write_bytes(b"x")
            Path(parent, "as_dir").mkdir()
            Path(parent, "as_dir", "snapshots").write_bytes(b"x")
            for label, cache_dir in blockers.items():
                with self.subTest(case=label), patch.object(
                    sync_module, "sleep", lambda _seconds: None
                ):
                    with self.assertRaises(DataError):
                        sync_snapshots(
                            cache_dir,
                            osv_url=f"{base_url}/osv.zip",
                            kev_url=f"{base_url}/kev.json",
                            max_attempts=1,
                            max_download_bytes=1024 * 1024,
                        )

    def test_deeply_nested_json_surfaces_as_data_error(self):
        # RecursionError is not a ValueError: deep nesting must not escape.
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )
        pointer_path = self.cache_dir / "current.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        snapshot = self.cache_dir / pointer["snapshot"]
        deep = b"[" * 100_000 + b"]" * 100_000
        for relative in ("kev/kev.json", "manifest.json"):
            (snapshot / relative).write_bytes(deep)
        # Re-point with fresh digests so the bytes are what the readers verify.
        manifest_bytes = (snapshot / "manifest.json").read_bytes()
        pointer["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        pointer_path.write_text(json.dumps(pointer), encoding="utf-8")

        with self.assertRaises(DataError):
            load_kev_ids(self.cache_dir)

        # And through the sync path, where the payload is remote input.
        with patch.object(sync_module, "urlopen", self._deep_nesting_urlopen):
            with self.assertRaises(DataError):
                sync_snapshots(
                    self.cache_dir,
                    osv_url=f"{base_url}/osv.zip",
                    kev_url=f"{base_url}/kev.json",
                    max_attempts=1,
                    max_download_bytes=1024 * 1024,
                )

    def _deep_nesting_urlopen(self, request, timeout=None):
        deep = b"[" * 100_000 + b"]" * 100_000

        class _Response:
            headers: dict[str, str] = {}

            def read(self, _amount=None):
                return deep if request.full_url.endswith("kev.json") else self.osv_body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        response = _Response()
        response.osv_body = self.osv_body
        return response

    def test_overlong_content_length_fails_fast(self):
        attempts = []

        class OverlongLengthHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                attempts.append(self.path)
                self.send_response(200)
                # Passes [0-9]+ but int() cannot parse it: permanently malformed.
                self.send_header("Content-Length", "9" * 5000)
                self.end_headers()
                self.wfile.write(b"x" * 32)
                self.wfile.flush()

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), OverlongLengthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with patch.object(sync_module, "sleep", lambda _seconds: None):
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with self.assertRaises(DataError):
                    sync_snapshots(
                        self.cache_dir,
                        osv_url=f"{base_url}/osv.zip",
                        kev_url=f"{base_url}/kev.json",
                        max_attempts=3,
                        max_download_bytes=1024 * 1024,
                    )
            finally:
                server.shutdown()
                server.server_close()

        self.assertEqual(1, len(attempts), "a malformed header must fail fast")

    def test_manifest_with_huge_digit_string_surfaces_as_data_error(self):
        # A digest-valid manifest is still attacker-controlled content: the 3.11
        # int-str digit limit must not escape the readers either.
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        snapshot = next((self.cache_dir / "snapshots").glob("snapshot-*"))
        manifest_path = snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        # Build raw bytes: the over-long digit run must reach the parser, and
        # json.dumps() cannot even encode it because int() fails first.
        manifest_bytes = json.dumps(manifest).encode("utf-8")[:-1]
        manifest_bytes += b', "n": ' + b"9" * 5000 + b"}"
        manifest_path.write_bytes(manifest_bytes)
        pointer_path = self.cache_dir / "current.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        pointer_path.write_text(json.dumps(pointer), encoding="utf-8")

        for call in (
            load_snapshot_manifest,
            load_kev_ids,
            lambda cache: list(iter_osv_records(cache)),
        ):
            with self.assertRaises(DataError):
                call(self.cache_dir)

    def test_signed_content_length_is_rejected_without_wasting_attempts(self):
        attempts = []

        class SignedLengthHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                attempts.append(self.path)
                self.send_response(200)
                # Permanently malformed: no retry can ever make this valid.
                self.send_header("Content-Length", "-1")
                self.end_headers()
                self.wfile.write(self.server.test_case.osv_body)
                self.wfile.flush()

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), SignedLengthHandler)
        server.test_case = self
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with patch.object(sync_module, "sleep", lambda _seconds: None):
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with self.assertRaises(DataError):
                    sync_snapshots(
                        self.cache_dir,
                        osv_url=f"{base_url}/osv.zip",
                        kev_url=f"{base_url}/kev.json",
                        max_attempts=3,
                        max_download_bytes=1024 * 1024,
                    )
            finally:
                server.shutdown()
                server.server_close()

        self.assertEqual(1, len(attempts), "a malformed header must fail fast")

    def test_pointer_with_huge_digit_string_surfaces_as_data_error(self):
        # json.JSONDecodeError is a ValueError subclass, but Python 3.11 raises a
        # plain ValueError for an over-long int-str; that must not escape.
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        (self.cache_dir / "current.json").write_text(
            '{"snapshot": ' + "9" * 5000 + "}", encoding="utf-8"
        )

        for call in (
            load_snapshot_manifest,
            load_kev_ids,
            lambda cache: list(iter_osv_records(cache)),
        ):
            with self.assertRaises(DataError):
                call(self.cache_dir)

    def test_truncated_response_body_is_retried_then_reported_as_data_error(self):
        attempts = []

        class TruncatingHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                attempts.append(self.path)
                body = self.server.test_case.osv_body
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                # Send fewer bytes than promised, then drop the connection.
                self.wfile.write(body[: len(body) // 2])
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), TruncatingHandler)
        server.test_case = self
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # Only the backoff delay is faked; the HTTP attempts stay real.
        with patch.object(sync_module, "sleep", lambda _seconds: None):
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with self.assertRaises(DataError):
                    sync_snapshots(
                        self.cache_dir,
                        osv_url=f"{base_url}/osv.zip",
                        kev_url=f"{base_url}/kev.json",
                        max_attempts=3,
                        max_download_bytes=1024 * 1024,
                    )
            finally:
                server.shutdown()
                server.server_close()

        self.assertEqual(3, len(attempts), "a truncated body must be retried")

    def test_pointer_with_nul_byte_surfaces_as_data_error(self):
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        pointer_path = self.cache_dir / "current.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["snapshot"] = "snapshots/snap\x00shot-1"
        pointer_path.write_text(json.dumps(pointer), encoding="utf-8")

        with self.assertRaises(DataError):
            load_snapshot_manifest(self.cache_dir)

    def test_kev_reader_rejects_malformed_entry_instead_of_dropping_it(self):
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        kev_path = self.cache_dir / "snapshots"
        snapshot = next(kev_path.glob("snapshot-*"))
        (snapshot / "kev" / "kev.json").write_text(
            json.dumps(
                {
                    "count": 2,
                    "vulnerabilities": [
                        {"cveID": "CVE-2026-1234"},
                        {"cveID": None},
                    ],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(DataError):
            load_kev_ids(self.cache_dir)

    def test_kev_reader_rejects_edited_records_file(self):
        base_url = self.start_server()
        sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        snapshot = next((self.cache_dir / "snapshots").glob("snapshot-*"))
        (snapshot / "osv" / "records.jsonl").write_text('{"id":"TAMPERED"}\n', encoding="utf-8")

        with self.assertRaises(DataError):
            list(iter_osv_records(self.cache_dir))

    def test_manifest_reader_rejects_tampered_manifest(self):
        base_url = self.start_server()
        result = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        manifest["sources"]["osv"]["record_count"] = 999
        result.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(DataError):
            load_snapshot_manifest(self.cache_dir)

    def test_manifest_reader_rejects_pointer_escaping_the_cache(self):
        base_url = self.start_server()
        result = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        outside = Path(self.temporary_directory.name) / "outside"
        shutil.copytree(result.snapshot_dir, outside)
        pointer_path = self.cache_dir / "current.json"
        pointer_path.write_text(
            json.dumps(
                {
                    "snapshot": "../outside",
                    "manifest_sha256": json.loads(pointer_path.read_text())[
                        "manifest_sha256"
                    ],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(DataError):
            load_snapshot_manifest(self.cache_dir)

    def test_kev_vulnerability_with_malformed_cve_id_is_rejected(self):
        base_url = self.start_server()
        invalid_kev = dict(
            KEV_DOCUMENT,
            vulnerabilities=[dict(KEV_DOCUMENT["vulnerabilities"][0], cveID="bad-id")],
        )
        self.kev_body = json.dumps(invalid_kev).encode("utf-8")

        with self.assertRaises(DataError):
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )

        self.assertFalse((self.cache_dir / "current.json").exists())

    def test_kev_count_mismatch_is_rejected_before_snapshot_install(self):
        base_url = self.start_server()
        invalid_kev = dict(KEV_DOCUMENT, count=2)
        self.kev_body = json.dumps(invalid_kev).encode("utf-8")

        with self.assertRaises(DataError):
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )

        self.assertFalse((self.cache_dir / "current.json").exists())
        self.assertEqual([], list((self.cache_dir / "snapshots").glob("snapshot-*")))

    def test_osv_zip_with_excessive_decompressed_size_is_rejected(self):
        base_url = self.start_server()
        padding = "A" * (4 * 1024 * 1024)
        self.osv_body = build_osv_zip(record=dict(OSV_RECORD, padding=padding))

        with self.assertRaises(DataError):
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
                max_uncompressed_bytes=1024 * 1024,
            )

        self.assertFalse((self.cache_dir / "current.json").exists())
        self.assertEqual([], list((self.cache_dir / "snapshots").glob("snapshot-*")))

    def test_unsafe_osv_zip_member_is_rejected_before_snapshot_install(self):
        base_url = self.start_server()
        self.osv_body = build_osv_zip(member_name="../outside.json")

        with self.assertRaises(DataError):
            sync_snapshots(
                self.cache_dir,
                osv_url=f"{base_url}/osv.zip",
                kev_url=f"{base_url}/kev.json",
                max_attempts=1,
                max_download_bytes=1024 * 1024,
            )

        self.assertFalse((self.cache_dir / "current.json").exists())
        self.assertEqual([], list((self.cache_dir / "snapshots").glob("snapshot-*")))

    def test_sync_installs_validated_snapshot_with_manifest_and_current_pointer(self):
        base_url = self.start_server()

        result = sync_snapshots(
            self.cache_dir,
            osv_url=f"{base_url}/osv.zip",
            kev_url=f"{base_url}/kev.json",
            max_attempts=1,
            max_download_bytes=1024 * 1024,
        )

        self.assertTrue(result.snapshot_dir.is_dir())
        self.assertTrue(result.manifest_path.is_file())
        self.assertEqual(result.snapshot_dir, result.snapshot_dir.resolve())

        manifest = load_snapshot_manifest(self.cache_dir)
        self.assertEqual(1, manifest["format_version"])
        self.assertEqual("0.1.0", manifest["tool_version"])
        self.assertRegex(manifest["fetched_at"], r"\A\d{4}-\d{2}-\d{2}T")

        osv_source = manifest["sources"]["osv"]
        self.assertEqual(f"{base_url}/osv.zip", osv_source["url"])
        self.assertEqual(
            hashlib.sha256(self.osv_body).hexdigest(), osv_source["sha256"]
        )
        self.assertEqual(1, osv_source["record_count"])
        self.assertEqual('"osv-v1"', osv_source["etag"])
        self.assertEqual(
            "Fri, 25 Sep 2026 00:00:00 GMT", osv_source["last_modified"]
        )

        kev_source = manifest["sources"]["kev"]
        self.assertEqual(f"{base_url}/kev.json", kev_source["url"])
        self.assertEqual(
            hashlib.sha256(self.kev_body).hexdigest(), kev_source["sha256"]
        )
        self.assertEqual(1, kev_source["record_count"])
        self.assertEqual('"kev-v1"', kev_source["etag"])

        self.assertEqual([OSV_RECORD], list(iter_osv_records(self.cache_dir)))
        self.assertEqual(("CVE-2026-1234",), load_kev_ids(self.cache_dir))

        pointer = json.loads((self.cache_dir / "current.json").read_text(encoding="utf-8"))
        self.assertEqual("snapshots", pointer["snapshot"].split("/", 1)[0])
        self.assertEqual(
            result.snapshot_dir.name,
            pointer["snapshot"].split("/", 1)[1],
        )
        self.assertEqual(
            hashlib.sha256(result.manifest_path.read_bytes()).hexdigest(),
            pointer["manifest_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
