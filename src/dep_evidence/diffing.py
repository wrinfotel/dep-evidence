"""Deterministic local diff between two evidence bundles.

Pure and offline: it compares two already-produced bundles and never touches the
network or the cache. Every list it returns is sorted by its canonical key, so
two runs over the same inputs produce byte-identical output.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .errors import DataError

FINDING_KEYS = ("component", "advisory_id")
EXCEPTION_KEYS = ("component", "advisory_id")

_DIFF_FIELDS = (
    "components_added",
    "components_removed",
    "components_changed",
    "findings_new",
    "findings_resolved",
    "findings_changed",
    "exceptions_changed",
)


def _load(bundle: Any, label: str) -> tuple[list[dict], list[dict], list[dict]]:
    if not isinstance(bundle, Mapping):
        raise DataError(f"{label} bundle must be a mapping")
    evidence = bundle.get("evidence")
    if not isinstance(evidence, Mapping):
        raise DataError(f"{label} bundle has no evidence mapping")
    components = evidence.get("components")
    findings = evidence.get("findings")
    exceptions = bundle.get("exceptions", [])
    if not isinstance(components, list) or not isinstance(findings, list):
        raise DataError(f"{label} bundle evidence must hold lists")
    if not isinstance(exceptions, list):
        raise DataError(f"{label} bundle exceptions must be a list")
    for group, name in ((components, "components"), (findings, "findings"), (exceptions, "exceptions")):
        for item in group:
            if not isinstance(item, Mapping):
                raise DataError(f"{label} {name} entry must be a mapping")
    return list(components), list(findings), list(exceptions)


def _key_of(item: Mapping[str, Any], keys: Sequence[str], label: str) -> tuple:
    values = []
    for key in keys:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            raise DataError(f"{label} entry needs a non-empty {key}")
        values.append(value)
    return tuple(values)


def _index(items: list[dict], keys: Sequence[str], label: str) -> dict[tuple, dict]:
    return {_key_of(item, keys, label): item for item in items}


def diff_bundles(before: Any, after: Any) -> dict[str, list[dict]]:
    """Compare two bundles, returning a canonical, sorted diff."""
    old_components, old_findings, old_exceptions = _load(before, "before")
    new_components, new_findings, new_exceptions = _load(after, "after")

    old_by_coordinate = _index(old_components, ("coordinate",), "before components")
    new_by_coordinate = _index(new_components, ("coordinate",), "after components")
    old_by_finding = _index(old_findings, FINDING_KEYS, "before findings")
    new_by_finding = _index(new_findings, FINDING_KEYS, "after findings")
    old_by_exception = _index(old_exceptions, EXCEPTION_KEYS, "before exceptions")
    new_by_exception = _index(new_exceptions, EXCEPTION_KEYS, "after exceptions")

    added = [new_by_coordinate[k] for k in sorted(new_by_coordinate.keys() - old_by_coordinate.keys())]
    removed = [old_by_coordinate[k] for k in sorted(old_by_coordinate.keys() - new_by_coordinate.keys())]
    changed = []
    for coordinate in sorted(old_by_coordinate.keys() & new_by_coordinate.keys()):
        old_item, new_item = old_by_coordinate[coordinate], new_by_coordinate[coordinate]
        if old_item != new_item:
            changed.append({"coordinate": coordinate[0], "before": old_item, "after": new_item})

    findings_new = [new_by_finding[k] for k in sorted(new_by_finding.keys() - old_by_finding.keys())]
    findings_resolved = [old_by_finding[k] for k in sorted(old_by_finding.keys() - new_by_finding.keys())]
    findings_changed = []
    for key in sorted(old_by_finding.keys() & new_by_finding.keys()):
        old_item, new_item = old_by_finding[key], new_by_finding[key]
        if old_item != new_item:
            findings_changed.append(
                {"component": key[0], "advisory_id": key[1], "before": old_item, "after": new_item}
            )

    exceptions_changed = []
    for key in sorted(old_by_exception.keys() | new_by_exception.keys()):
        old_state = old_by_exception.get(key, {}).get("state")
        new_state = new_by_exception.get(key, {}).get("state")
        if old_state != new_state:
            exceptions_changed.append(
                {"component": key[0], "advisory_id": key[1], "from": old_state, "to": new_state}
            )

    return {
        "components_added": added,
        "components_removed": removed,
        "components_changed": changed,
        "findings_new": findings_new,
        "findings_resolved": findings_resolved,
        "findings_changed": findings_changed,
        "exceptions_changed": exceptions_changed,
    }


def summarize_diff(diff: Mapping[str, Sequence[Any]]) -> str:
    """Render a diff as one deterministic, human-readable line."""
    if not isinstance(diff, Mapping):
        raise DataError("diff must be a mapping")
    parts: list[str] = []
    labels = (
        ("components_added", "added"),
        ("components_removed", "removed"),
        ("components_changed", "changed"),
        ("findings_new", "new"),
        ("findings_resolved", "resolved"),
        ("findings_changed", "re-tested"),
        ("exceptions_changed", "exception changed"),
    )
    total = 0
    for field, label in labels:
        count = len(diff.get(field, ()))
        total += count
        if count:
            parts.append(f"{count} {label}")
    if not parts:
        return "no changes"
    return ", ".join(parts)


__all__ = ["diff_bundles", "summarize_diff", "_DIFF_FIELDS"]
