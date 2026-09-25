"""Typed application errors with stable CLI exit codes."""


class DepEvidenceError(Exception):
    """Base class for expected user-facing failures."""

    exit_code = 2


class InputError(DepEvidenceError):
    """The SBOM, snapshot, or configuration is invalid."""


class DataError(DepEvidenceError):
    """A required public-data snapshot is unavailable or invalid."""


class OutputError(DepEvidenceError):
    """The evidence bundle could not be written."""

    exit_code = 3
