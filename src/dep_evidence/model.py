"""Stable domain objects shared by adapters and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Component:
    ecosystem: str
    namespace: str
    name: str
    version: str
    purl: str | None = None
    bom_ref: str | None = None
    relationship: str = "unknown"
    licenses: tuple[dict[str, Any], ...] = ()
    purl_qualifiers: dict[str, str] = field(default_factory=dict)

    @property
    def package_name(self) -> str:
        if self.namespace:
            return f"{self.namespace}:{self.name}"
        return self.name

    @property
    def coordinate(self) -> str:
        return f"{self.ecosystem}:{self.package_name}@{self.version}"


@dataclass(frozen=True)
class Sbom:
    path: Path
    format: str
    spec_version: str
    bom_version: int
    root_ref: str | None
    components: tuple[Component, ...]
