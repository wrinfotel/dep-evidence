"""Command line interface for the local dependency-evidence tool.

Design rules that the tests pin down:

* `analyze` and `diff` are strictly offline. Only `sync` touches the network,
  and it is a separate subcommand so the offline path cannot regress silently.
* No stack traces ever reach the user. Domain errors become one clear line on
  stderr with a non-zero exit code; an unexpected exception is reported by type
  only, because a traceback on stderr is not a user interface.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from . import __version__
from .analysis import (
    build_sources,
    canonical_components,
    compute_analysis_fingerprint,
    findings_for_component,
)
from .bundle import write_bundle
from .datasets import iter_osv_records, load_kev_ids, load_snapshot_manifest
from .diffing import diff_bundles, summarize_diff
from .errors import DataError
from .exceptions import load_exception_policy
from .reporting import render_evidence_json
from .sbom import parse_sbom
from .sync import sync_snapshots

POLICY_VERSION = "1"
RULE_VERSION = "1"

EXIT_OK = 0
EXIT_ERROR = 1


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return EXIT_ERROR


def _read_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DataError(f"cannot read {label} '{path}': {exc}") from exc
    except UnicodeError as exc:
        raise DataError(f"cannot decode {label} '{path}': {exc}") from exc
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise DataError(f"{label} '{path}' is not valid JSON: {exc}") from exc


def _load_bundle_evidence(directory: Path, label: str) -> dict[str, Any]:
    document = _read_json(directory / "evidence.json", f"{label} evidence.json")
    if not isinstance(document, dict):
        raise DataError(f"{label} evidence.json must contain a JSON object")
    return {"evidence": document, "exceptions": _load_bundle_exceptions(directory, label)}


def _load_bundle_exceptions(directory: Path, label: str) -> list[Any]:
    path = directory / "exceptions.json"
    if not path.exists():
        return []
    document = _read_json(path, f"{label} exceptions.json")
    if isinstance(document, list):
        return document
    if isinstance(document, dict) and isinstance(document.get("exceptions"), list):
        return document["exceptions"]
    raise DataError(f"{label} exceptions.json must hold a list")


def _sha256_file(path: Path) -> str:
    import hashlib

    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise DataError(f"cannot read '{path}': {exc}") from exc


def command_sync(args: argparse.Namespace) -> int:
    result = sync_snapshots(
        args.cache,
        osv_url=args.osv_url,
        kev_url=args.kev_url,
        max_attempts=args.max_attempts,
        max_download_bytes=args.max_download_bytes,
        max_uncompressed_bytes=args.max_uncompressed_bytes,
    )
    print(f"installed {result.snapshot_dir}")
    return EXIT_OK


def command_analyze(args: argparse.Namespace) -> int:
    sbom = parse_sbom(args.sbom)
    manifest = load_snapshot_manifest(args.cache)
    kev_cve_ids = load_kev_ids(args.cache)
    records = tuple(iter_osv_records(args.cache))

    components = canonical_components(sbom.components)
    by_package: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        for affected in record.get("affected", []):
            package = affected.get("package") or {}
            key = (
                str(package.get("ecosystem", "")).lower(),
                str(package.get("name", "")),
            )
            by_package.setdefault(key, []).append(record)

    policy = load_exception_policy(args.exceptions) if args.exceptions else None
    findings: list[dict[str, Any]] = []
    for component in components:
        key = (component.ecosystem.lower(), component.package_name)
        findings.extend(
            findings_for_component(component, by_package.get(key, ()), kev_cve_ids=kev_cve_ids)
        )
    findings.sort(key=lambda finding: (finding["component"], finding["advisory_id"]))

    if policy is not None:
        applied = _apply_exceptions(findings, policy)
    else:
        applied = list(findings)

    sources = build_sources(manifest, policy_version=POLICY_VERSION)
    fingerprint = compute_analysis_fingerprint(
        sbom_sha256=_sha256_file(Path(args.sbom)),
        sources=sources,
        policy_version=POLICY_VERSION,
        rule_version=RULE_VERSION,
    )
    evidence = {
        "schema_version": 1,
        "fingerprint": fingerprint,
        "sources": sources,
        "components": [
            {
                "coordinate": component.coordinate,
                "ecosystem": component.ecosystem,
                "name": component.package_name,
                "version": component.version,
            }
            for component in components
        ],
        "summary": {
            "components": len(components),
            "findings": len(applied),
        },
        "findings": applied,
    }
    written = write_bundle(
        args.out,
        evidence=evidence,
        findings=applied,
        components=list(components),
        sources=sources,
        exceptions=[],
        run_metadata={
            "tool_version": __version__,
            "policy_version": POLICY_VERSION,
            "rule_version": RULE_VERSION,
            "fingerprint": fingerprint,
            "exit_status": EXIT_OK,
        },
    )
    print(f"wrote {len(written)} files to {Path(args.out)}")
    return EXIT_OK


def _apply_exceptions(findings: Sequence[dict[str, Any]], policy: Any) -> list[dict[str, Any]]:
    """Drop findings covered by a non-expired exception rule."""
    today = _today()
    suppressed: set[tuple[str, str]] = set()
    for rule in policy.rules:
        if rule.expires_on < today:
            continue
        suppressed.add((f"{rule.ecosystem}:{rule.package}", rule.advisory_id))
    kept = []
    for finding in findings:
        key = (f"{finding['ecosystem']}:{finding['package']}", finding["advisory_id"])
        if key in suppressed:
            continue
        kept.append(finding)
    return kept


def _today():
    from datetime import date

    return date.today()


def command_diff(args: argparse.Namespace) -> int:
    before = _load_bundle_evidence(Path(args.before), "before")
    after = _load_bundle_evidence(Path(args.after), "after")
    diff = diff_bundles(before, after)
    if args.json:
        print(render_evidence_json(diff).decode("utf-8"))
    else:
        print(summarize_diff(diff))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-evidence",
        description="Local, offline dependency-evidence bundles from CycloneDX SBOMs.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync = subparsers.add_parser("sync", help="download and install public dataset snapshots")
    sync.add_argument("--cache", required=True, help="cache directory")
    sync.add_argument("--osv-url", required=True, help="OSV zip URL")
    sync.add_argument("--kev-url", required=True, help="KEV json URL")
    sync.add_argument("--max-attempts", type=int, default=3)
    sync.add_argument("--max-download-bytes", type=int, default=100 * 1024 * 1024)
    sync.add_argument("--max-uncompressed-bytes", type=int, default=1024 * 1024 * 1024)
    sync.set_defaults(handler=command_sync)

    analyze = subparsers.add_parser("analyze", help="build an evidence bundle (offline)")
    analyze.add_argument("--sbom", required=True, help="CycloneDX JSON SBOM")
    analyze.add_argument("--cache", required=True, help="cache directory from `sync`")
    analyze.add_argument("--out", required=True, help="bundle output directory")
    analyze.add_argument("--exceptions", help="optional exception policy JSON")
    analyze.set_defaults(handler=command_analyze)

    diff = subparsers.add_parser("diff", help="compare two evidence bundles (offline)")
    diff.add_argument("--before", required=True)
    diff.add_argument("--after", required=True)
    diff.add_argument("--json", action="store_true", help="emit the canonical diff JSON")
    diff.set_defaults(handler=command_diff)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except DataError as exc:
        return _fail(_with_hint(str(exc), args))
    except (ValueError, KeyError) as exc:
        # Domain errors are user-facing: one line, no traceback.
        return _fail(str(exc))
    except KeyboardInterrupt:
        return _fail("interrupted")
    except Exception as exc:  # noqa: BLE001 - a traceback is not a UI
        return _fail(f"unexpected {type(exc).__name__}: {exc}")


def _with_hint(message: str, args: argparse.Namespace) -> str:
    """Add the next actionable step, so the user is not left guessing."""
    if getattr(args, "command", None) == "analyze" and "current.json" in message:
        return f"{message} (run `dep-evidence sync` first to build the cache)"
    return message


if __name__ == "__main__":
    raise SystemExit(main())
