"""Deterministic local analysis over a parsed SBOM and cached snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

from .errors import DataError
from .kev import match_kev
from .model import Component
from .osv import match_osv


# Only these statuses are reportable. "not_affected" is an evaluated negative and
# must not become a finding, while "review" and "withdrawn" stay visible.
_REPORTABLE_STATUSES = frozenset({"affected", "review", "withdrawn"})

_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
# Exactly the fields sync_snapshots guarantees in each manifest source entry.
# "bytes" is deliberately absent: the byte count lives in the separate "files"
# map keyed by installed path, not inside the source entry.
_PROVENANCE_FIELDS = ("url", "record_count", "sha256")


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DataError(f"provenance {label} must be a non-empty string")
    return value


def compute_analysis_fingerprint(
    *,
    sbom_sha256: str,
    sources: Mapping[str, Any],
    policy_version: str,
    rule_version: str,
) -> str:
    """Hash the normalized input, the snapshots and the policy/rule versions.

    This is the single value two runs must agree on. It is deliberately built
    from canonical JSON with sorted keys, so the caller's dict ordering cannot
    change the result.
    """
    if not isinstance(sbom_sha256, str) or not sbom_sha256:
        raise DataError("sbom_sha256 must be a non-empty string")
    if not isinstance(sources, Mapping):
        raise DataError("sources must be a mapping")
    policy = _require_str(policy_version, "policy_version")
    rules = _require_str(rule_version, "rule_version")
    payload = json.dumps(
        {
            "sbom_sha256": sbom_sha256,
            "sources": sources,
            "policy_version": policy,
            "rule_version": rules,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_sources(manifest: Mapping[str, Any], *, policy_version: str) -> dict[str, Any]:
    """Assemble the deterministic sources.json body from a snapshot manifest.

    Fetch timestamps are deliberately dropped: the snapshot identity that
    matters for reproducibility is the digest, and a wall-clock field would make
    two runs over the same snapshot differ.

    The manifest nests each dataset under "sources", which is the shape
    sync_snapshots actually writes.
    """
    if not isinstance(manifest, Mapping):
        raise DataError("snapshot manifest must be a mapping")
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, Mapping):
        raise DataError("snapshot manifest has no sources mapping")
    sources: dict[str, Any] = {"policy_version": _require_str(policy_version, "policy_version")}
    for dataset in ("osv", "kev"):
        entry = raw_sources.get(dataset)
        if not isinstance(entry, Mapping):
            raise DataError(f"snapshot manifest is missing a valid {dataset} entry")
        record: dict[str, Any] = {}
        for field in _PROVENANCE_FIELDS:
            if field not in entry:
                raise DataError(f"snapshot manifest {dataset} entry lacks {field}")
        url = _require_str(entry["url"], f"{dataset}.url")
        digest = entry["sha256"]
        if not isinstance(digest, str) or not _SHA256_HEX_RE.match(digest):
            raise DataError(f"snapshot manifest {dataset}.sha256 is not a sha256 digest")
        count = entry["record_count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise DataError(f"snapshot manifest {dataset}.record_count must be a non-negative int")
        record["url"] = url
        record["sha256"] = digest
        record["record_count"] = count
        sources[dataset] = record
    sources["versions"] = {
        dataset: {"sha256": sources[dataset]["sha256"]} for dataset in ("osv", "kev")
    }
    return sources


def canonical_components(components: Iterable[Component]) -> tuple[Component, ...]:
    """Return components in a total order that does not depend on input order."""
    return tuple(sorted(components, key=lambda component: component.coordinate))


def _kev_evidence(advisory: Mapping[str, Any], kev_cve_ids: tuple[str, ...]) -> dict[str, Any]:
    match = match_kev(dict(advisory), kev_cve_ids)
    return {
        "status": match.status,
        "reason": match.reason,
        "cve_id": match.cve_id,
    }


def findings_for_component(
    component: Component,
    advisories: Iterable[Mapping[str, Any]],
    *,
    kev_cve_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Return sorted, reportable findings for one component."""
    findings: list[dict[str, Any]] = []
    for advisory in advisories:
        result = match_osv(component, dict(advisory))
        if result.status not in _REPORTABLE_STATUSES:
            continue
        findings.append(
            {
                "component": component.coordinate,
                "ecosystem": component.ecosystem,
                "package": component.package_name,
                "version": component.version,
                "advisory_id": result.advisory_id,
                "status": result.status,
                "reason": result.reason,
                "kev": _kev_evidence(advisory, kev_cve_ids),
            }
        )
    findings.sort(key=lambda finding: (finding["component"], finding["advisory_id"]))
    return findings
