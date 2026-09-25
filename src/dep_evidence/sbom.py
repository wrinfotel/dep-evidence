"""Bounded CycloneDX JSON input adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .errors import InputError
from .model import Component, Sbom

SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_COMPONENTS = 2_000


def _parse_maven_purl(value: str) -> tuple[str, str, str, dict[str, str]] | None:
    if not value.startswith("pkg:maven/"):
        return None
    try:
        remainder = value.removeprefix("pkg:maven/")
        base, _, query = remainder.partition("?")
        path, separator, raw_version = base.rpartition("@")
        if not path or not separator or not raw_version:
            return None
        namespace_encoded, separator, name_encoded = path.rpartition("/")
        if not separator or not name_encoded:
            return None
        qualifiers = {}
        for item in query.split("&"):
            if not item or "=" not in item:
                continue
            key, raw = item.split("=", 1)
            qualifiers[unquote(key)] = unquote(raw)
        return (
            unquote(namespace_encoded),
            unquote(name_encoded),
            unquote(raw_version),
            qualifiers,
        )
    except (TypeError, ValueError):
        return None


def _license_records(raw_component: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    records = []
    for item in raw_component.get("licenses", []):
        if isinstance(item, dict) and isinstance(item.get("license"), dict):
            license_record = dict(item["license"])
            license_record.setdefault("expression", item.get("expression"))
            records.append(license_record)
        elif isinstance(item, dict) and item.get("expression"):
            records.append({"expression": item["expression"]})
    return tuple(records)


def _load_document(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot read SBOM '{path}': {exc}") from exc
    if size > MAX_INPUT_BYTES:
        raise InputError("SBOM exceeds the 50 MiB input limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise InputError(f"cannot read SBOM '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"SBOM must contain valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise InputError("SBOM root must be a JSON object")
    return document


def parse_sbom(path: str | Path) -> Sbom:
    source = Path(path)
    document = _load_document(source)
    if document.get("bomFormat") != "CycloneDX":
        raise InputError("bomFormat must be CycloneDX")
    spec_version = document.get("specVersion")
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise InputError("specVersion must be one of 1.4, 1.5, 1.6, or 1.7")
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise InputError("components must be an array")
    if len(raw_components) > MAX_COMPONENTS:
        raise InputError("SBOM exceeds the 2000 component limit")

    metadata_component = document.get("metadata", {}).get("component", {})
    root_ref = metadata_component.get("bom-ref") if isinstance(metadata_component, dict) else None
    direct_refs: set[str] = set()
    has_root_graph = bool(root_ref)
    dependencies = document.get("dependencies", [])
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if not isinstance(dependency, dict) or dependency.get("ref") != root_ref:
                continue
            has_root_graph = True
            depends_on = dependency.get("dependsOn", [])
            if isinstance(depends_on, list):
                direct_refs.update(ref for ref in depends_on if isinstance(ref, str))

    components: list[Component] = []
    for index, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            raise InputError(f"component at index {index} must be an object")
        purl = raw.get("purl") if isinstance(raw.get("purl"), str) else None
        purl_parts = _parse_maven_purl(purl) if purl else None
        if purl_parts:
            namespace, name, version, qualifiers = purl_parts
        else:
            namespace = str(raw.get("group", "") or "")
            name = str(raw.get("name", "") or "").strip()
            version = str(raw.get("version", "") or "").strip()
            qualifiers = {}
        if not name or not version:
            raise InputError(
                f"component at index {index} must have a name, version, and valid Maven purl"
            )
        bom_ref = raw.get("bom-ref") if isinstance(raw.get("bom-ref"), str) else None
        if bom_ref in direct_refs:
            relationship = "direct"
        elif has_root_graph:
            relationship = "transitive"
        else:
            relationship = "unknown"
        components.append(
            Component(
                ecosystem="Maven",
                namespace=namespace,
                name=name,
                version=version,
                purl=purl,
                bom_ref=bom_ref,
                relationship=relationship,
                licenses=_license_records(raw),
                purl_qualifiers=qualifiers,
            )
        )

    try:
        bom_version = int(document.get("version", 1))
    except (TypeError, ValueError) as exc:
        raise InputError("SBOM version must be an integer") from exc
    return Sbom(
        path=source,
        format=document["bomFormat"],
        spec_version=spec_version,
        bom_version=bom_version,
        root_ref=root_ref,
        components=tuple(components),
    )
