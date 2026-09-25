"""Exact alias joins between OSV advisories and the local CISA KEV set."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable


_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.IGNORECASE)

# Unicode skeletons for the ASCII letters of the ``CVE`` prefix. NFKC already
# folds fullwidth, mathematical and modifier compatibility forms, but it
# deliberately leaves cross-script homoglyphs (Cyrillic ``С``/``В``/``Е``, Greek
# ``Ε``) and Latin small capitals alone, so those must be folded explicitly
# before deciding whether a string claims to be a CVE identifier.
_CVE_PREFIX_SKELETON = str.maketrans(
    {
        # Cyrillic and Greek homoglyphs that NFKC intentionally leaves alone.
        "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
        "\u0412": "V",  # CYRILLIC CAPITAL LETTER VE
        "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
        "\u0395": "E",  # GREEK CAPITAL LETTER EPSILON
        # Latin small capitals, which are visually uppercase but not ASCII.
        "\u1d04": "C",  # LATIN LETTER SMALL CAPITAL C
        "\u1d20": "V",  # LATIN LETTER SMALL CAPITAL V
        "\u1d07": "E",  # LATIN LETTER SMALL CAPITAL E
    },
)


def _cve_prefix_skeleton(value: str) -> str:
    """Fold a candidate to a comparison form used only to detect CVE lookalikes."""
    folded = unicodedata.normalize("NFKC", value).strip().upper()
    return folded.translate(_CVE_PREFIX_SKELETON)


@dataclass(frozen=True)
class KevMatch:
    status: str
    reason: str
    cve_id: str | None = None


def _normalize_cve(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    if _CVE_RE.fullmatch(candidate) is None:
        return None
    return candidate


def _looks_like_cve(value: str) -> bool:
    """True when a string claims CVE shape after detection-only Unicode folding."""
    return _cve_prefix_skeleton(value).startswith("CVE-")


def match_kev(advisory: dict[str, Any], kev_cve_ids: Iterable[str]) -> KevMatch:
    """Match only exact normalized CVE identifiers from aliases or the OSV ID."""
    if not isinstance(advisory, dict):
        return KevMatch("review", "malformed_advisory")

    advisory_id = advisory.get("id")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        return KevMatch("review", "malformed_advisory")
    if _normalize_cve(advisory_id) is None and _looks_like_cve(advisory_id):
        return KevMatch("review", "malformed_advisory")

    raw_aliases = advisory.get("aliases", [])
    if raw_aliases is None:
        # The official OSV schema allows an explicit JSON null for aliases.
        raw_aliases = []
    if not isinstance(raw_aliases, list):
        return KevMatch("review", "malformed_aliases")
    try:
        # Materialize once: a hostile or single-pass container must not be
        # re-consumed by the join below.
        alias_values = list(raw_aliases)
    except Exception:
        return KevMatch("review", "malformed_aliases")
    for alias in alias_values:
        if not isinstance(alias, str) or not alias.strip():
            return KevMatch("review", "malformed_aliases")
        if _normalize_cve(alias) is None and _looks_like_cve(alias):
            return KevMatch("review", "malformed_aliases")

    if isinstance(kev_cve_ids, (str, bytes, bytearray)):
        return KevMatch("review", "malformed_kev_snapshot")
    try:
        raw_kev_ids = tuple(kev_cve_ids)
    except Exception:
        return KevMatch("review", "malformed_kev_snapshot")
    if not raw_kev_ids:
        return KevMatch("review", "malformed_kev_snapshot")

    known: set[str] = set()
    for cve_id in raw_kev_ids:
        normalized = _normalize_cve(cve_id)
        if normalized is None:
            return KevMatch("review", "malformed_kev_id")
        known.add(normalized)

    candidates = [advisory.get("id"), *alias_values]
    for raw_candidate in candidates:
        normalized = _normalize_cve(raw_candidate)
        if normalized in known and normalized is not None:
            return KevMatch("known_exploited", "exact_cve_alias", normalized)
    return KevMatch("not_known_exploited", "no_exact_cve_alias")
