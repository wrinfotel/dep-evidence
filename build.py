"""Minimal PEP 517 build backend.

The project is pure standard library, so there is nothing to compile. This
backend exists only so `pip install .` and `uv pip install .` work, which in
turn is what makes the console entry point available.

It produces a wheel containing the `dep_evidence` package and nothing else: no
compiled artifacts, no dependency metadata (there are no runtime dependencies),
and no VCS metadata.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DISTRIBUTION = "dep-evidence"
# Wheel file names must use the escaped form: a hyphen in the distribution name
# is a field separator, so "dep-evidence" has to become "dep_evidence" there.
ESCAPED_NAME = DISTRIBUTION.replace("-", "_")
VERSION = "0.1.0"
PACKAGE_ROOT = os.path.join(HERE, "src")
TAG = "py3-none-any"


def _package_files() -> list[tuple[str, str]]:
    """Return (absolute_path, archive_path) for every shipped source file."""
    collected: list[tuple[str, str]] = []
    package_dir = os.path.join(PACKAGE_ROOT, "dep_evidence")
    for dirpath, dirnames, filenames in os.walk(package_dir):
        # Never ship caches or editor droppings.
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for filename in sorted(filenames):
            if filename.endswith((".pyc", ".pyo")):
                continue
            absolute = os.path.join(dirpath, filename)
            collected.append((absolute, os.path.relpath(absolute, PACKAGE_ROOT)))
    return collected


def _metadata() -> str:
    readme = os.path.join(HERE, "README.md")
    description = ""
    if os.path.exists(readme):
        with open(readme, encoding="utf-8") as handle:
            description = handle.read()
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {DISTRIBUTION}",
        f"Version: {VERSION}",
        "Summary: Local, reproducible dependency-evidence bundles from CycloneDX SBOMs.",
        "License-Expression: Apache-2.0",
        "Requires-Python: >=3.11",
        "Classifier: Programming Language :: Python :: 3.11",
        "Classifier: Environment :: Console",
        "Classifier: License :: OSI Approved :: Apache Software License",
    ]
    if description:
        lines.append("Description-Content-Type: text/markdown")
    body = "\n".join(lines) + "\n"
    if description:
        body += "\n" + description
    return body


def _entry_points() -> bytes:
    """The console script, as declared in pyproject.toml's [project.scripts].

    Without this file pip installs the package but never creates the
    `dep-evidence` command, which is the whole point of shipping it.
    """
    return b"[console_scripts]\ndep-evidence = dep_evidence.cli:main\n"


def _wheel_metadata() -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: dep_evidence.build\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def _dist_info_name() -> str:
    return f"{ESCAPED_NAME}-{VERSION}.dist-info"


def _write_dist_info(archive: zipfile.ZipFile, *, records: list[tuple[str, str, int]]) -> None:
    dist_info = _dist_info_name()
    metadata = _metadata().encode("utf-8")
    wheel = _wheel_metadata().encode("utf-8")
    entries = [
        (f"{dist_info}/METADATA", metadata),
        (f"{dist_info}/WHEEL", wheel),
        (f"{dist_info}/entry_points.txt", _entry_points()),
        (f"{dist_info}/top_level.txt", b"dep_evidence\n"),
    ]
    # RECORD lists every file with its hash and size, as the spec requires.
    record_rows = io.StringIO()
    writer = csv.writer(record_rows, lineterminator="\n")
    for name, payload in entries:
        writer.writerow([name, "sha256=" + _digest(payload), len(payload)])
        records.append((name, "sha256=" + _digest(payload), len(payload)))
    for absolute, archive_path in _package_files():
        with open(absolute, "rb") as handle:
            payload = handle.read()
        writer.writerow([archive_path, "sha256=" + _digest(payload), len(payload)])
        records.append((archive_path, "sha256=" + _digest(payload), len(payload)))
    record_name = f"{dist_info}/RECORD"
    writer.writerow([record_name, "", ""])
    entries.append((record_name, record_rows.getvalue().encode("utf-8")))
    for name, payload in entries:
        archive.writestr(name, payload)


def _digest(payload: bytes) -> str:
    raw = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return raw.decode("ascii")


def _build(wheel_directory: str) -> str:
    os.makedirs(wheel_directory, exist_ok=True)
    filename = f"{ESCAPED_NAME}-{VERSION}-{TAG}.whl"
    target = os.path.join(wheel_directory, filename)
    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for absolute, archive_path in _package_files():
            archive.write(absolute, archive_path)
        _write_dist_info(archive, records=records)
    return filename


# --- PEP 517 hooks -------------------------------------------------------


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return _build(wheel_directory)


def build_sdist(sdist_directory, config_settings=None):
    import tarfile

    os.makedirs(sdist_directory, exist_ok=True)
    base = f"{ESCAPED_NAME}-{VERSION}"
    filename = f"{base}.tar.gz"
    target = os.path.join(sdist_directory, filename)
    with tarfile.open(target, "w:gz") as archive:
        for relative in ("README.md", "LICENSE", "pyproject.toml", "build.py"):
            absolute = os.path.join(HERE, relative)
            if os.path.exists(absolute):
                archive.add(absolute, arcname=f"{base}/{relative}")
        for absolute, archive_path in _package_files():
            archive.add(absolute, arcname=f"{base}/src/{archive_path}")
        for dirpath, dirnames, filenames in os.walk(os.path.join(HERE, "tests")):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in sorted(filenames):
                if name.endswith(".py"):
                    full = os.path.join(dirpath, name)
                    rel = os.path.relpath(full, HERE)
                    archive.add(full, arcname=f"{base}/{rel}")
    return filename
