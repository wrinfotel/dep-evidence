"""Deterministic report writers.

Every writer here must be a pure function of the evidence it is given. Runtime
metadata such as timestamps, hostnames or durations belong to run_manifest.json
and must never reach evidence.json, otherwise two runs over identical input
would not be byte-identical.
"""

from __future__ import annotations

import csv
import io
import json
from html import escape
from typing import Any, Iterable, Mapping


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def render_evidence_json(evidence: Mapping[str, Any]) -> bytes:
    """Render the deterministic analysis document."""
    return _canonical_json(evidence)


def render_sources_json(sources: Mapping[str, Any]) -> bytes:
    """Render local snapshot provenance, without volatile fetch timestamps."""
    return _canonical_json(sources)


def render_exceptions_json(decisions: Any) -> bytes:
    """Render normalized exception decisions."""
    return _canonical_json(decisions)


# A KEV match means "this CVE appears in the CISA KEV catalog", never "this
# component was exploited". The wording below must stay literal.
_KEV_CELLS = {
    "known_exploited": "CVE appears in the CISA KEV catalog: {cve}",
    "not_known_exploited": "CVE does not appear in the CISA KEV catalog",
    "review": "KEV join needs review ({reason})",
    "malformed_kev_snapshot": "KEV snapshot unavailable for this run",
}

_STATUS_LABELS = {
    "affected": "Affected",
    "review": "Needs review",
    "withdrawn": "Withdrawn advisory",
}


def _kev_cell(kev: Mapping[str, Any]) -> str:
    status = kev.get("status")
    template = _KEV_CELLS.get(status)
    if template is None:
        return "KEV join needs review (unknown_kev_status)"
    cve = kev.get("cve_id")
    return template.format(cve=escape(str(cve)), reason=escape(str(kev.get("reason"))))


_CSV_COLUMNS = (
    "ecosystem",
    "namespace",
    "name",
    "version",
    "coordinate",
    "purl",
    "bom_ref",
    "relationship",
    "licenses",
    "license_state",
)

# Spreadsheet software evaluates a cell whose first character is one of these.
# SBOM text is untrusted input, so a leading apostrophe neutralizes it while
# keeping the original value visible to whoever opens the file.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


def _license_cells(licenses: Iterable[Any]) -> tuple[str, str]:
    """Return (licenses, license_state); missing data is explicit, never blank."""
    names: list[str] = []
    for entry in licenses or ():
        if isinstance(entry, Mapping):
            name = entry.get("name") or entry.get("id")
            source = entry.get("source")
            if name and source:
                names.append(f"{name} ({source})")
            elif name:
                names.append(str(name))
        elif entry is not None:
            names.append(str(entry))
    if not names:
        # Design: missing or conflicting license data is `unknown`.
        return "", "unknown"
    return "; ".join(names), "known"


def render_components_csv(components: Iterable[Any]) -> bytes:
    """Render the canonical component inventory as deterministic CSV."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for component in components:
        licenses, license_state = _license_cells(getattr(component, "licenses", ()))
        writer.writerow(
            [
                _csv_cell(getattr(component, column, None))
                for column in _CSV_COLUMNS[:8]
            ]
            + [_csv_cell(licenses), license_state]
        )
    return buffer.getvalue().encode("utf-8")


def render_report_html(evidence: Mapping[str, Any], findings: Iterable[Mapping[str, Any]]) -> bytes:
    """Render a self-contained HTML report with no remote assets."""
    summary = evidence.get("summary") if isinstance(evidence.get("summary"), dict) else {}
    rows: list[str] = []
    for finding in findings:
        status = str(finding.get("status"))
        kev = finding.get("kev") if isinstance(finding.get("kev"), dict) else {}
        rows.append(
            "      <tr>"
            f"<td>{escape(str(finding.get('component')))}</td>"
            f"<td>{escape(str(finding.get('advisory_id')))}</td>"
            f"<td>{escape(_STATUS_LABELS.get(status, status))}</td>"
            f"<td>{escape(str(finding.get('reason')))}</td>"
            f"<td>{_kev_cell(kev)}</td>"
            "</tr>"
        )
    body = "\n".join(rows) if rows else "      <tr><td colspan=\"5\">No findings</td></tr>"
    summary_cells = "\n".join(
        f"      <li>{escape(str(key))}: {escape(str(value))}</li>"
        for key, value in sorted(summary.items())
    )
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Dependency evidence</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; }}
th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
</style>
</head>
<body>
<h1>Dependency evidence</h1>
<p>Analysis fingerprint: {escape(str(evidence.get("analysis_fingerprint")))}</p>
<h2>Summary</h2>
<ul>
{summary_cells}
</ul>
<h2>Findings</h2>
<table>
  <thead>
    <tr><th>Component</th><th>Advisory</th><th>Status</th><th>Reason</th><th>KEV</th></tr>
  </thead>
  <tbody>
{body}
  </tbody>
</table>
<p>A KEV match records that a CVE is listed in the CISA KEV catalog. It is not evidence
that this component was exploited.</p>
</body>
</html>
"""
    return document.encode("utf-8")
