"""Validated local snapshot storage and readers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Iterator, Mapping

from .errors import DataError


CURRENT_POINTER = "current.json"
MANIFEST_NAME = "manifest.json"
OSV_RECORDS_NAME = "osv/records.jsonl"
KEV_NAME = "kev/kev.json"


def _cache_path(cache_dir: str | Path) -> Path:
    """Coerce a cache directory argument, normalizing a non-path value.

    Path() raises TypeError for None, an int, or bytes. Every public entrypoint
    funnels through here so that a bad argument is reported as DataError like
    every other malformed input.
    """
    try:
        return Path(cache_dir)
    except (TypeError, ValueError) as exc:
        raise DataError(f"cache directory path is invalid: {exc}") from exc


def _current_snapshot_dir(cache_dir: str | Path) -> Path:
    cache = _cache_path(cache_dir)
    try:
        cache_root = cache.resolve(strict=True)
    except OSError as exc:
        raise DataError(f"cache directory is unavailable: {exc}") from exc
    try:
        pointer = json.loads((cache / CURRENT_POINTER).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        # ValueError, not json.JSONDecodeError: Python 3.11 raises a plain
        # ValueError for an over-long int-str in the pointer, which is not a
        # JSONDecodeError subclass. RecursionError covers deep nesting.
        raise DataError(f"cannot read snapshot pointer: {exc}") from exc
    if not isinstance(pointer, dict):
        raise DataError("snapshot pointer must be a JSON object")
    relative = pointer.get("snapshot")
    if not isinstance(relative, str) or not relative:
        raise DataError("snapshot pointer is missing snapshot path")
    snapshot = cache / relative
    try:
        resolved = snapshot.resolve(strict=True)
    except (OSError, ValueError) as exc:
        # ValueError covers an embedded NUL byte in the pointer path.
        raise DataError(f"current snapshot is unavailable: {exc}") from exc
    # The pointer is trusted input: a "../" segment must not make readers serve
    # an arbitrary directory as if it were the installed snapshot.
    if resolved != cache_root and not resolved.is_relative_to(cache_root):
        raise DataError("snapshot pointer escapes the cache directory")
    return resolved


def _read_manifest_with_pointer(cache_dir: str | Path) -> dict[str, Any]:
    cache = _cache_path(cache_dir)
    pointer_path = cache / CURRENT_POINTER
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        # RecursionError: a deeply nested pointer is not a ValueError.
        raise DataError(f"cannot read snapshot pointer: {exc}") from exc
    manifest_path = _current_snapshot_dir(cache_dir) / MANIFEST_NAME
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise DataError(f"cannot read snapshot manifest: {exc}") from exc
    expected = _require_sha256_hex(
        pointer.get("manifest_sha256") if isinstance(pointer, dict) else None
    )
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
        raise DataError("snapshot manifest does not match the pointer digest")
    try:
        manifest = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError) as exc:
        # ValueError, not json.JSONDecodeError: the 3.11 int-str digit limit
        # raises a plain ValueError even for a digest-valid manifest.
        raise DataError(f"cannot read snapshot manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise DataError("snapshot manifest must be a JSON object")
    return manifest


def load_snapshot_manifest(cache_dir: str | Path) -> dict[str, Any]:
    return _read_manifest_with_pointer(cache_dir)


_CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


def _require_sha256_hex(digest: Any) -> str:
    """Reject anything that is not a lowercase sha256 hex string.

    hmac.compare_digest raises TypeError on non-ASCII input, which would break
    the module's DataError-only contract on hand-edited cache input.
    """
    if not isinstance(digest, str) or _SHA256_HEX_RE.fullmatch(digest) is None:
        raise DataError("snapshot digest is not a sha256 hex value")
    return digest


def _verified_snapshot(cache_dir: str | Path) -> tuple[Path, dict[str, Any]]:
    """Resolve the active snapshot and verify the manifest the pointer pins."""
    manifest = _read_manifest_with_pointer(cache_dir)
    return _current_snapshot_dir(cache_dir), manifest


def _verified_file(snapshot: Path, manifest: Mapping[str, Any], name: str) -> Path:
    """Return a snapshot file only if it still matches its manifest digest."""
    files = manifest.get("files")
    entry = files.get(name) if isinstance(files, dict) else None
    digest = _require_sha256_hex(entry.get("sha256") if isinstance(entry, dict) else None)
    path = snapshot / name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DataError(f"cannot read snapshot file: {exc}") from exc
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise DataError(f"snapshot file does not match its manifest digest: {name}")
    return path


def iter_osv_records(cache_dir: str | Path) -> Iterator[dict[str, Any]]:
    snapshot, manifest = _verified_snapshot(cache_dir)
    records_path = _verified_file(snapshot, manifest, OSV_RECORDS_NAME)
    try:
        with records_path.open(encoding="utf-8") as stream:
            for line in stream:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise DataError("OSV snapshot record must be a JSON object")
                yield value
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        # RecursionError: deep nesting in a cached record is not a ValueError.
        raise DataError(f"cannot read OSV snapshot: {exc}") from exc


def load_kev_ids(cache_dir: str | Path) -> tuple[str, ...]:
    snapshot, manifest = _verified_snapshot(cache_dir)
    kev_path = _verified_file(snapshot, manifest, KEV_NAME)
    try:
        document = json.loads(kev_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        # RecursionError: a deeply nested KEV document is not a ValueError.
        raise DataError(f"cannot read KEV snapshot: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise DataError("KEV snapshot must contain a vulnerabilities array")
    cve_ids: list[str] = []
    for record in document["vulnerabilities"]:
        if not isinstance(record, dict):
            raise DataError("KEV vulnerability must be a JSON object")
        cve_id = record.get("cveID")
        # Reject rather than drop: a silently skipped entry would understate the
        # catalog and make a later KEV join miss a real CVE.
        if not isinstance(cve_id, str) or _CVE_ID_RE.fullmatch(cve_id) is None:
            raise DataError("KEV vulnerability has a malformed cveID")
        cve_ids.append(cve_id)
    return tuple(cve_ids)
