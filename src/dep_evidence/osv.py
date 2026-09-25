"""Deterministic matching of Maven components against OSV records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .model import Component
from .versioning import compare_versions


_OSV_TIMESTAMP_RE = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z"
)


@dataclass(frozen=True)
class OsvMatch:
    advisory_id: str
    status: str
    reason: str


def _evaluate_range(
    component_version: str,
    advisory_id: str,
    events: Any,
) -> OsvMatch | None:
    if not isinstance(events, list):
        return OsvMatch(advisory_id, "review", "malformed_range")

    terminators = {
        event_type
        for event in events
        for event_type in ("fixed", "last_affected")
        if isinstance(event, dict) and event_type in event
    }
    if len(terminators) > 1:
        return OsvMatch(advisory_id, "review", "mixed_terminator_events")

    introduced_seen = False
    introduced_boundary: str | None = None
    interval_open = False
    candidate_in_interval = False
    has_finite_limit = False
    candidate_before_limit = False
    limit_seen_since_introduced = False
    affected_match: OsvMatch | None = None
    for event in events:
        if not isinstance(event, dict):
            return OsvMatch(advisory_id, "review", "malformed_event")
        event_types = [
            name
            for name in ("introduced", "fixed", "last_affected", "limit")
            if name in event
        ]
        if len(event_types) != 1 or len(event) != 1:
            return OsvMatch(advisory_id, "review", "malformed_event")

        event_type = event_types[0]
        if event_type == "introduced":
            boundary = event["introduced"]
            if not isinstance(boundary, str):
                return OsvMatch(advisory_id, "review", "malformed_event")
            if interval_open and not limit_seen_since_introduced:
                return OsvMatch(advisory_id, "review", "ambiguous_event_ordering")
            comparison = None if boundary == "0" else compare_versions(component_version, boundary)
            if boundary != "0" and comparison is None:
                return OsvMatch(advisory_id, "review", "uncomparable_boundary")
            introduced_seen = True
            introduced_boundary = boundary
            interval_open = True
            candidate_in_interval = (
                candidate_in_interval or boundary == "0" or comparison >= 0
            )
            limit_seen_since_introduced = False
            continue

        if event_type == "limit":
            boundary = event["limit"]
            if not isinstance(boundary, str):
                return OsvMatch(advisory_id, "review", "malformed_event")
            if boundary == "*":
                continue
            if not introduced_seen:
                return OsvMatch(advisory_id, "review", "missing_introduced")
            if not interval_open:
                return OsvMatch(advisory_id, "review", "ambiguous_event_ordering")
            comparison = compare_versions(component_version, boundary)
            if comparison is None:
                return OsvMatch(advisory_id, "review", "uncomparable_boundary")
            if introduced_boundary is not None:
                boundary_order = compare_versions(introduced_boundary, boundary)
                if boundary_order is None or boundary_order >= 0:
                    return OsvMatch(advisory_id, "review", "ambiguous_event_ordering")
            has_finite_limit = True
            candidate_before_limit = candidate_before_limit or comparison < 0
            limit_seen_since_introduced = True
            continue
        if not introduced_seen:
            return OsvMatch(advisory_id, "review", "missing_introduced")
        if not interval_open:
            return OsvMatch(advisory_id, "review", "ambiguous_event_ordering")
        boundary = event[event_type]
        if not isinstance(boundary, str):
            return OsvMatch(advisory_id, "review", "malformed_event")
        comparison = compare_versions(component_version, boundary)
        if comparison is None:
            return OsvMatch(advisory_id, "review", "uncomparable_boundary")
        if introduced_boundary is not None:
            boundary_order = compare_versions(introduced_boundary, boundary)
            if boundary_order is None or boundary_order >= 0:
                return OsvMatch(advisory_id, "review", "ambiguous_event_ordering")
        if candidate_in_interval and (
            (event_type == "fixed" and comparison < 0)
            or (event_type == "last_affected" and comparison <= 0)
        ):
            affected_match = affected_match or OsvMatch(
                advisory_id,
                "affected",
                "range_last_affected" if event_type == "last_affected" else "range",
            )
        interval_open = False
        candidate_in_interval = False

    if not introduced_seen:
        return OsvMatch(advisory_id, "review", "missing_introduced")
    if has_finite_limit and not candidate_before_limit:
        return None
    if interval_open and candidate_in_interval:
        affected_match = affected_match or OsvMatch(advisory_id, "affected", "range")
    return affected_match


def match_osv(component: Component, advisory: dict[str, Any]) -> OsvMatch:
    """Return a deterministic result for a component and one OSV record."""
    if not isinstance(advisory, dict):
        return OsvMatch("", "review", "malformed_advisory")
    advisory_id = advisory.get("id")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        return OsvMatch("", "review", "malformed_advisory")
    advisory_id = advisory_id.strip()
    if "withdrawn" in advisory:
        withdrawn = advisory["withdrawn"]
        if not isinstance(withdrawn, str) or not _OSV_TIMESTAMP_RE.fullmatch(
            withdrawn.strip()
        ):
            return OsvMatch(advisory_id, "review", "malformed_advisory")
        try:
            datetime.fromisoformat(withdrawn.strip().replace("Z", "+00:00"))
        except ValueError:
            return OsvMatch(advisory_id, "review", "malformed_advisory")
        return OsvMatch(advisory_id, "withdrawn", "advisory_withdrawn")

    if "affected" not in advisory or not isinstance(advisory["affected"], list):
        return OsvMatch(advisory_id, "review", "malformed_affected")
    affected_records = advisory["affected"]
    if not affected_records:
        return OsvMatch(advisory_id, "review", "malformed_affected")

    matching_package_seen = False
    if compare_versions(component.version, component.version) is None:
        for affected in affected_records:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package")
            if not isinstance(package, dict):
                continue
            if package.get("ecosystem") == component.ecosystem and package.get("name") in {
                component.package_name,
                "*",
            }:
                matching_package_seen = True
                break
        if matching_package_seen:
            return OsvMatch(advisory_id, "review", "unparseable_component_version")

    review: OsvMatch | None = None
    affected_result: OsvMatch | None = None
    ecosystem_mismatch = False
    package_mismatch = False
    for affected in affected_records:
        if not isinstance(affected, dict):
            review = review or OsvMatch(advisory_id, "review", "malformed_affected")
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            review = review or OsvMatch(advisory_id, "review", "malformed_affected")
            continue
        if not isinstance(package.get("ecosystem"), str) or not isinstance(
            package.get("name"), str
        ):
            review = review or OsvMatch(advisory_id, "review", "malformed_affected")
            continue
        if package.get("ecosystem") != component.ecosystem:
            if package.get("name") in {component.package_name, "*"} and isinstance(
                package.get("ecosystem"), str
            ) and package["ecosystem"].startswith("Maven:"):
                review = review or OsvMatch(
                    advisory_id, "review", "unsupported_ecosystem_variant"
                )
            else:
                ecosystem_mismatch = True
            continue
        if package.get("name") not in {component.package_name, "*"}:
            package_mismatch = True
            continue

        if "versions" not in affected and "ranges" not in affected:
            review = review or OsvMatch(advisory_id, "review", "malformed_affected")
            continue

        versions = affected.get("versions", [])
        ranges = affected.get("ranges", [])
        if (
            "versions" not in affected and "ranges" not in affected
        ) or (
            isinstance(versions, list)
            and isinstance(ranges, list)
            and not versions
            and not ranges
        ):
            review = review or OsvMatch(advisory_id, "review", "malformed_affected")
            continue
        if "versions" in affected and not isinstance(versions, list):
            review = review or OsvMatch(
                advisory_id, "review", "malformed_exact_version"
            )
        elif versions:
            if any(not isinstance(version, str) for version in versions) or any(
                compare_versions(component.version, version) is None
                for version in versions
            ):
                review = review or OsvMatch(
                    advisory_id, "review", "malformed_exact_version"
                )
            elif component.version in versions or any(
                compare_versions(component.version, version) == 0 for version in versions
            ):
                reason = "wildcard_package" if package.get("name") == "*" else "exact_version"
                affected_result = affected_result or OsvMatch(
                    advisory_id, "affected", reason
                )
        if "ranges" in affected and not isinstance(ranges, list):
            review = review or OsvMatch(advisory_id, "review", "malformed_range")
            ranges = []
        for version_range in ranges:
            if not isinstance(version_range, dict):
                review = review or OsvMatch(advisory_id, "review", "malformed_range")
                continue
            if version_range.get("type") != "ECOSYSTEM":
                review = review or OsvMatch(advisory_id, "review", "unsupported_range_type")
                continue
            result = _evaluate_range(component.version, advisory_id, version_range.get("events", []))
            if result is not None:
                if result.status == "affected":
                    affected_result = affected_result or result
                    continue
                review = review or result
    if review is not None:
        return review
    if affected_result is not None:
        return affected_result
    if ecosystem_mismatch:
        return OsvMatch(advisory_id, "not_affected", "ecosystem_mismatch")
    if package_mismatch:
        return OsvMatch(advisory_id, "not_affected", "package_name_mismatch")
    return OsvMatch(advisory_id, "not_affected", "no_match")
