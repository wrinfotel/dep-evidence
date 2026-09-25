"""Bounded public snapshot synchronization with staged atomic installation."""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from time import sleep
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import __version__
from .datasets import (
    CURRENT_POINTER,
    KEV_NAME,
    MANIFEST_NAME,
    OSV_RECORDS_NAME,
    _cache_path,
)
from .errors import DataError


_CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z", re.IGNORECASE)
_CONTENT_LENGTH_RE = re.compile(r"[0-9]+\Z")


@dataclass(frozen=True)
class SyncResult:
    snapshot_dir: Path
    manifest_path: Path


def _retry_delay(error: HTTPError, attempt: int, max_delay: float = 30.0) -> float:
    retry_after = error.headers.get("Retry-After") if error.headers else None
    if retry_after is not None:
        try:
            return max(0.0, min(float(retry_after), max_delay))
        except ValueError:
            try:
                target = parsedate_to_datetime(retry_after)
                if target.tzinfo is None:
                    target = target.replace(tzinfo=timezone.utc)
                seconds = (target - datetime.now(timezone.utc)).total_seconds()
                return max(0.0, min(seconds, max_delay))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(2.0 ** (attempt - 1), max_delay)


class _TruncatedDownload(Exception):
    """Internal signal: the body was shorter than the promised Content-Length."""


def _download_with_retries(
    url: str,
    max_bytes: int,
    max_attempts: int,
) -> tuple[bytes, str | None, str | None]:
    transient_statuses = {408, 425, 429, 500, 502, 503, 504}
    for attempt in range(1, max_attempts + 1):
        request = Request(url, headers={"User-Agent": f"dep-evidence/{__version__}"})
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - explicit public URLs
                content_length = response.headers.get("Content-Length")
                promised: int | None = None
                if content_length is not None:
                    # Fail fast on a permanently malformed header: no retry can
                    # ever fix it. The length cap also keeps int() away from the
                    # 3.11 int-str digit limit, which would raise a ValueError
                    # the transient-retry handler would swallow as retryable.
                    declared = content_length.strip()
                    if len(declared) > 19 or not _CONTENT_LENGTH_RE.fullmatch(declared):
                        raise DataError(f"invalid Content-Length from {url}")
                    promised = int(declared)
                    if promised > max_bytes:
                        raise DataError(f"download exceeds {max_bytes} bytes: {url}")
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise DataError(f"download exceeds {max_bytes} bytes: {url}")
                if promised is not None and len(body) != promised:
                    # HTTPResponse.read(amt) returns a short body without raising
                    # when the connection drops mid-transfer, so a truncated
                    # download would otherwise be accepted as if it were complete.
                    raise _TruncatedDownload(
                        f"truncated body: got {len(body)} of {promised} bytes"
                    )
                etag = response.headers.get("ETag")
                last_modified = response.headers.get("Last-Modified")
                return body, etag, last_modified
        except HTTPError as exc:
            if exc.code not in transient_statuses or attempt == max_attempts:
                raise DataError(f"cannot download {url}: HTTP {exc.code}") from exc
            sleep(_retry_delay(exc, attempt))
            continue
        except DataError:
            raise
        except (OSError, ValueError, http.client.HTTPException, _TruncatedDownload) as exc:
            # A short body from a dropped connection is a normal transient network
            # outcome, not a corrupt snapshot: retry it, and only report failure
            # once the attempts are exhausted.
            if attempt == max_attempts:
                raise DataError(f"cannot download {url}: {exc}") from exc
            sleep(min(2.0 ** (attempt - 1), 30.0))
    raise DataError(f"cannot download {url}: exhausted attempts")


def _download(url: str, max_bytes: int) -> tuple[bytes, str | None, str | None]:
    return _download_with_retries(url, max_bytes, max_attempts=1)


def _read_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo, remaining: int) -> bytes:
    """Read one member while enforcing the uncompressed budget on real bytes."""
    with archive.open(member) as stream:
        data = stream.read(remaining + 1)
    if len(data) > remaining:
        raise DataError("OSV snapshot archive exceeds the uncompressed size limit")
    return data


def _read_osv_zip(body: bytes, max_uncompressed_bytes: int) -> list[dict[str, Any]]:
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            records = []
            remaining = max_uncompressed_bytes
            declared_total = 0
            for member in archive.infolist():
                if member.is_dir():
                    continue
                member_name = member.filename.replace("\\", "/")
                path = PurePosixPath(member_name)
                # PurePosixPath(".").parts is empty, so index the drive check safely.
                drive = path.parts[0] if path.parts else ""
                mode = member.external_attr >> 16
                if (
                    not member_name
                    or "\x00" in member_name
                    or member_name.startswith("/")
                    or path.is_absolute()
                    or ".." in path.parts
                    or ":" in drive
                    or stat.S_ISLNK(mode)
                ):
                    raise DataError(f"unsafe OSV ZIP member: {member.filename!r}")
                # The declared size is attacker-controlled, so it is only a cheap
                # pre-check; _read_member enforces the real budget afterwards.
                declared_total += max(0, member.file_size)
                if declared_total > max_uncompressed_bytes:
                    raise DataError("OSV snapshot archive exceeds the uncompressed size limit")
                raw = _read_member(archive, member, remaining)
                remaining -= len(raw)
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise DataError("OSV snapshot record must be a JSON object")
                records.append(value)
    except (
        OSError,
        KeyError,
        UnicodeError,
        ValueError,
        RecursionError,
        IndexError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        RuntimeError,
        EOFError,
        zlib.error,
    ) as exc:
        # Normalise every malformed-archive path to DataError: callers of this
        # tool get exactly one error type, and a remote snapshot must never be
        # able to surface zlib.error / ValueError / IndexError to the user.
        raise DataError(f"invalid OSV snapshot archive: {exc}") from exc
    if not records:
        raise DataError("OSV snapshot archive contains no records")
    return records


def _read_kev(body: bytes) -> dict[str, Any]:
    try:
        document = json.loads(body)
    except (UnicodeError, ValueError, RecursionError) as exc:
        # ValueError covers json.JSONDecodeError and the 3.11 int-str digit limit;
        # RecursionError is neither, and deep nesting is remote-reachable.
        raise DataError(f"invalid KEV snapshot JSON: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise DataError("KEV snapshot must contain a vulnerabilities array")
    count = document.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(
        document["vulnerabilities"]
    ):
        raise DataError("KEV count does not match vulnerabilities")
    for vulnerability in document["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            raise DataError("KEV vulnerability must be a JSON object")
        cve_id = vulnerability.get("cveID")
        if not isinstance(cve_id, str) or _CVE_ID_RE.fullmatch(cve_id.strip()) is None:
            raise DataError("KEV vulnerability has a malformed cveID")
        # Store the canonical form so the installed snapshot and the readers agree;
        # a raw "cve-2026-1234 " would otherwise fail the strict reader.
        vulnerability["cveID"] = cve_id.strip().upper()
    return document


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _write_json(path: Path, value: Any) -> bytes:
    body = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return body


def _is_stale(path: Path, cutoff: float, *, max_age_seconds: float) -> bool:
    """Decide whether a leftover artifact is abandoned rather than in flight.

    Both ends matter. A file newer than the cutoff may belong to a concurrent
    install, and must be spared. A file dated in the *future* cannot be
    in flight either: a crashed run on a host with a fast clock plants exactly
    that, and mtime alone would make it immortal.
    """
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return False
    if mtime < cutoff:
        return True
    return mtime > time.time() + max_age_seconds


def _sweep_stale_pointer_temporaries(cache: Path, *, max_age_seconds: float = 3600.0) -> None:
    """Best-effort removal of pointer temporaries orphaned by earlier failures.

    A pointer temp is only left behind when its own unlink failed. They are
    harmless (readers consult current.json and snapshots/ only), but without a
    sweep they accumulate one per failed install. Hygiene, not correctness.
    """
    cutoff = time.time() - max_age_seconds
    try:
        for stale in cache.glob(f".{CURRENT_POINTER}.*.tmp"):
            try:
                if _is_stale(stale, cutoff, max_age_seconds=max_age_seconds):
                    stale.unlink(missing_ok=True)
            except OSError:
                pass
    except OSError:
        pass


def _sweep_stale_staging_directories(
    snapshots_dir: Path, *, max_age_seconds: float = 3600.0
) -> None:
    """Best-effort removal of staging directories left by a crashed run.

    sync_snapshots removes its own staging on failure, so these only survive a
    hard crash (SIGKILL, power loss). Same rules as the pointer sweep: spare
    anything that could still be in flight, reclaim anything clearly abandoned.
    """
    cutoff = time.time() - max_age_seconds
    try:
        for stale in snapshots_dir.glob(".staging-*"):
            try:
                if _is_stale(stale, cutoff, max_age_seconds=max_age_seconds):
                    shutil.rmtree(stale, ignore_errors=True)
            except OSError:
                pass
    except OSError:
        pass


def sync_snapshots(
    cache_dir: str | Path,
    *,
    osv_url: str,
    kev_url: str,
    max_attempts: int = 3,
    max_download_bytes: int = 100 * 1024 * 1024,
    max_uncompressed_bytes: int = 1024 * 1024 * 1024,
) -> SyncResult:
    """Download, validate, stage, and atomically install both public snapshots."""
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise DataError("max_attempts must be an integer of at least 1")
    for name, value in (
        ("max_download_bytes", max_download_bytes),
        ("max_uncompressed_bytes", max_uncompressed_bytes),
    ):
        # bool is a subclass of int, so reject it explicitly. A limit at or
        # above sys.maxsize would later raise a raw OverflowError from the
        # C-level read(), so cap it here.
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > sys.maxsize - 1
        ):
            raise DataError(f"{name} must be a positive integer below {sys.maxsize}")
    for name, value in (("osv_url", osv_url), ("kev_url", kev_url)):
        # Validate before downloading: Request/urlopen would otherwise raise a
        # raw ValueError (or TypeError) for None, a non-str, or a bare path.
        if not isinstance(value, str) or not value.lower().startswith(("http://", "https://")):
            raise DataError(f"{name} must be an http(s) URL")

    osv_body, osv_etag, osv_modified = _download_with_retries(
        osv_url, max_download_bytes, max_attempts
    )
    kev_body, kev_etag, kev_modified = _download_with_retries(
        kev_url, max_download_bytes, max_attempts
    )
    osv_records = _read_osv_zip(osv_body, max_uncompressed_bytes)
    kev_document = _read_kev(kev_body)

    cache = _cache_path(cache_dir)
    snapshots_dir = cache / "snapshots"
    try:
        snapshots_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError) as exc:
        # A tampered or unusable cache layout is bad input, not a crash: the
        # mkdir sits outside the install try-block, so normalize it here.
        raise DataError(f"cache directory is unavailable: {exc}") from exc
    try:
        staging_dir = Path(tempfile.mkdtemp(prefix=".staging-", dir=snapshots_dir))
    except (OSError, ValueError) as exc:
        # Same hole as the mkdir above: a staging area we cannot create is an
        # unusable cache, not a crash.
        raise DataError(f"cannot create staging directory: {exc}") from exc
    snapshot_dir: Path | None = None
    pointer_replaced = False
    try:
        records_path = staging_dir / OSV_RECORDS_NAME
        records_path.parent.mkdir(parents=True, exist_ok=True)
        with records_path.open("wb") as stream:
            for record in osv_records:
                stream.write(
                    (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode(
                        "utf-8"
                    )
                )
        _write_json(staging_dir / KEV_NAME, kev_document)

        # Digests of the installed files, not only of the downloaded bodies:
        # readers must be able to detect on-disk tampering without network data.
        files = {
            name: {"sha256": _sha256((staging_dir / name).read_bytes()), "bytes": (staging_dir / name).stat().st_size}
            for name in (OSV_RECORDS_NAME, KEV_NAME)
        }

        fetched_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        manifest = {
            "format_version": 1,
            "tool_version": __version__,
            "fetched_at": fetched_at,
            "files": files,
            "sources": {
                "osv": {
                    "url": osv_url,
                    "sha256": _sha256(osv_body),
                    "record_count": len(osv_records),
                    "etag": osv_etag,
                    "last_modified": osv_modified,
                },
                "kev": {
                    "url": kev_url,
                    "sha256": _sha256(kev_body),
                    "record_count": len(kev_document["vulnerabilities"]),
                    "etag": kev_etag,
                    "last_modified": kev_modified,
                },
            },
        }
        manifest_path = staging_dir / MANIFEST_NAME
        manifest_bytes = _write_json(manifest_path, manifest)

        snapshot_name = f"snapshot-{uuid.uuid4().hex}"
        snapshot_dir = snapshots_dir / snapshot_name
        try:
            os.replace(staging_dir, snapshot_dir)
        except (OSError, ValueError) as exc:
            # Publishing the snapshot directory is the same commit step as the
            # pointer below, so it normalizes the same way.
            raise DataError(f"cannot install snapshot directory: {exc}") from exc
        manifest_path = snapshot_dir / MANIFEST_NAME

        pointer = {
            "snapshot": f"snapshots/{snapshot_name}",
            "manifest_sha256": _sha256(manifest_bytes),
        }
        pointer_path = cache / CURRENT_POINTER
        temporary_pointer = cache / f".{CURRENT_POINTER}.{uuid.uuid4().hex}.tmp"
        try:
            _write_json(temporary_pointer, pointer)
            os.replace(temporary_pointer, pointer_path)
            pointer_replaced = True
        except (OSError, ValueError) as exc:
            # A pointer slot occupied by something unwritable (a directory, a
            # read-only mount) is an unusable cache, not a crash. Raising here
            # still lets the outer handler drop the orphan and keep last-good.
            raise DataError(f"cannot install snapshot pointer: {exc}") from exc
        finally:
            # Cleanup must never become the escaping exception: it would mask
            # the real DataError raised above.
            try:
                temporary_pointer.unlink(missing_ok=True)
            except OSError:
                pass
        # Hygiene only, and deliberately outside the install try-block: the
        # pointer is already committed, so no sweep outcome may change the
        # result of a successful install.
        try:
            _sweep_stale_pointer_temporaries(cache)
            _sweep_stale_staging_directories(snapshots_dir)
        except Exception:
            pass
    except DataError:
        # Already normalized above; fall through to the shared cleanup below.
        if snapshot_dir is not None and not pointer_replaced:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
    except (OSError, ValueError) as exc:
        # Every other filesystem failure in the install path (a full disk, a
        # permission change mid-run) normalizes like its neighbours, so callers
        # only ever have to handle DataError.
        if snapshot_dir is not None and not pointer_replaced:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise DataError(f"cannot install snapshot: {exc}") from exc
    except Exception:
        if snapshot_dir is not None and not pointer_replaced:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
    # Built after the install try/except chain on purpose: by now the pointer
    # is committed, so a failure while resolving the result paths must not be
    # reported as a failed install (and must not roll anything back). Falling
    # back to the unresolved paths keeps the reported result honest.
    try:
        resolved_snapshot = snapshot_dir.resolve()
        resolved_manifest = manifest_path.resolve()
    except OSError:
        resolved_snapshot, resolved_manifest = snapshot_dir, manifest_path
    return SyncResult(snapshot_dir=resolved_snapshot, manifest_path=resolved_manifest)
