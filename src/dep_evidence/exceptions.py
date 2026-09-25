"""Versioned, expiring local exceptions that annotate dependency findings."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .errors import InputError


SUPPORTED_EXCEPTION_SCHEMA_VERSION = 1
_EXPIRES_ON_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_REQUIRED_TEXT_FIELDS = ("ecosystem", "package", "advisory_id", "reason")


def _normalize_identity(value: str) -> str:
    return value.strip()


@dataclass(frozen=True)
class ExceptionRule:
    ecosystem: str
    package: str
    advisory_id: str
    reason: str
    expires_on: date


@dataclass(frozen=True)
class ExceptionPolicy:
    schema_version: int
    rules: tuple[ExceptionRule, ...]


def _parse_exception(raw: Any, index: int) -> ExceptionRule:
    if not isinstance(raw, dict):
        raise InputError(f"exception at index {index} must be an object")
    values: dict[str, str] = {}
    for field in _REQUIRED_TEXT_FIELDS:
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise InputError(
                f"exception at index {index} requires non-empty '{field}'"
            )
        values[field] = value.strip()
    raw_expiry = raw.get("expires_on")
    if not isinstance(raw_expiry, str) or _EXPIRES_ON_RE.fullmatch(raw_expiry) is None:
        raise InputError(
            f"exception at index {index} requires expires_on as YYYY-MM-DD"
        )
    try:
        expires_on = date.fromisoformat(raw_expiry)
    except (TypeError, ValueError) as exc:
        raise InputError(
            f"exception at index {index} requires expires_on as YYYY-MM-DD"
        ) from exc
    return ExceptionRule(**values, expires_on=expires_on)


def load_exception_policy(path: str | Path) -> ExceptionPolicy:
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise InputError(f"cannot read exception policy '{source}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"exception policy must contain valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise InputError("exception policy root must be a JSON object")
    schema_version = document.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version != SUPPORTED_EXCEPTION_SCHEMA_VERSION
    ):
        raise InputError(
            f"exception policy schema_version must be {SUPPORTED_EXCEPTION_SCHEMA_VERSION}"
        )
    raw_exceptions = document.get("exceptions")
    if not isinstance(raw_exceptions, list):
        raise InputError("exception policy 'exceptions' must be an array")
    return ExceptionPolicy(
        schema_version=SUPPORTED_EXCEPTION_SCHEMA_VERSION,
        rules=tuple(
            _parse_exception(raw, index)
            for index, raw in enumerate(raw_exceptions)
        ),
    )


@dataclass(frozen=True)
class ExceptionDecision:
    ecosystem: str
    package: str
    advisory_id: str
    reason: str
    expires_on: date
    state: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "advisory_id": self.advisory_id,
            "reason": self.reason,
            "expires_on": self.expires_on.isoformat(),
            "state": self.state,
        }


def evaluate_exceptions(
    policy: ExceptionPolicy,
    *,
    ecosystem: str,
    package: str,
    advisory_id: str,
    as_of: date,
) -> list[ExceptionDecision]:
    """Return every rule decision, including expired and inapplicable rules."""
    normalized_ecosystem = _normalize_identity(ecosystem)
    normalized_package = _normalize_identity(package)
    normalized_advisory_id = _normalize_identity(advisory_id)
    decisions: list[ExceptionDecision] = []
    for rule in policy.rules:
        applicable = (
            _normalize_identity(rule.ecosystem) == normalized_ecosystem
            and _normalize_identity(rule.package) == normalized_package
            and _normalize_identity(rule.advisory_id) == normalized_advisory_id
        )
        if not applicable:
            state = "inapplicable"
        elif as_of > rule.expires_on:
            state = "expired"
        else:
            state = "active"
        decisions.append(
            ExceptionDecision(
                ecosystem=rule.ecosystem,
                package=rule.package,
                advisory_id=rule.advisory_id,
                reason=rule.reason,
                expires_on=rule.expires_on,
                state=state,
            )
        )
    return decisions


def annotate_finding(
    finding: dict[str, Any], decisions: list[ExceptionDecision]
) -> dict[str, Any]:
    """Copy a finding and attach visible exception decisions without erasing it."""
    annotated = deepcopy(finding)
    if "exceptions" not in annotated:
        prior: list[Any] = []
    else:
        existing = annotated["exceptions"]
        if isinstance(existing, list):
            prior = list(existing)
        else:
            # An explicit non-list value (including JSON ``null``) is producer
            # data, not an absence: keep it visible instead of silently
            # dropping it, because an exception must never hide prior evidence.
            prior = [existing]
    annotated["exceptions"] = [
        *prior,
        *(decision.as_dict() for decision in decisions),
    ]
    return annotated
