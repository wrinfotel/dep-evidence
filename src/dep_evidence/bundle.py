"""Evidence bundle writer.

The bundle splits into two halves on purpose:

* deterministic artifacts (``evidence.json``, ``report.html``,
  ``components.csv``, ``exceptions.json``, ``sources.json``) that are a pure
  function of the input, the local snapshot and the policy version, so two
  runs over identical input are byte-identical;
* ``run_manifest.json``, which is the only place runtime metadata may live.

Anything volatile that leaks into the deterministic half breaks the
reproducibility claim, so keep it here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .errors import DataError
from .reporting import (
    render_components_csv,
    render_evidence_json,
    render_exceptions_json,
    render_report_html,
    render_sources_json,
)

BUNDLE_FILES = (
    "evidence.json",
    "report.html",
    "components.csv",
    "exceptions.json",
    "sources.json",
    "run_manifest.json",
)


def _write_bytes(path: Path, payload: bytes) -> None:
    try:
        with open(path, "wb") as stream:
            stream.write(payload)
    except OSError as exc:
        raise DataError(f"cannot write bundle file {path.name}: {exc}") from exc


def write_bundle(
    out_dir: Any,
    *,
    evidence: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    components: Iterable[Any],
    sources: Mapping[str, Any],
    exceptions: Any,
    run_metadata: Mapping[str, Any],
) -> list[Path]:
    """Write the full evidence bundle and return the written paths."""
    target = Path(out_dir)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError) as exc:
        raise DataError(f"cannot create output directory: {exc}") from exc

    artifacts: list[tuple[str, bytes]] = [
        ("evidence.json", render_evidence_json(evidence)),
        ("report.html", render_report_html(evidence, findings)),
        ("components.csv", render_components_csv(components)),
        ("exceptions.json", render_exceptions_json(exceptions)),
        ("sources.json", render_sources_json(sources)),
        # Runtime metadata lives only here, by design.
        ("run_manifest.json", render_sources_json(run_metadata)),
    ]

    written: list[Path] = []
    for name, payload in artifacts:
        path = target / name
        _write_bytes(path, payload)
        written.append(path)
    return written
