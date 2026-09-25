# DepEvidence v0.1 Implementation Plan

> **For implementer:** Use TDD throughout. Write a failing test, run it, implement the minimum, then run the full suite.

**Goal:** Build and verify a stdlib-only Python 3.11 CLI that produces reproducible local dependency-evidence bundles from CycloneDX JSON.

**Architecture:** Pure-Python domain modules behind an argparse CLI. `sync` owns network I/O; `analyze` is strictly local. OSV and KEV adapters normalize public records into a versioned local cache; report and diff writers consume deterministic domain objects.

**Tech stack:** Python 3.11 standard library, `unittest`, `http.server` integration tests; no runtime dependencies.

---

## Task 1: Project skeleton and SBOM parser

**Files:**
- Create: `pyproject.toml`, `src/dep_evidence/__init__.py`, `src/dep_evidence/model.py`
- Test: `tests/test_sbom.py`, `tests/fixtures/valid-sbom.json`

1. Write failing tests for Maven purl parsing, direct dependency extraction, unsupported schema and 2,001-component limit.
2. Run `python3 -m unittest tests.test_sbom -v`; verify failures are caused by missing implementation.
3. Add the package metadata and minimal model/parser code.
4. Re-run the targeted test; expect all tests to pass.

## Task 2: Conservative OSV matching

**Files:**
- Create: `src/dep_evidence/versioning.py`, `src/dep_evidence/osv.py`
- Test: `tests/test_versioning.py`, `tests/test_osv.py`

1. Write failing tests for exact versions, introduced/fixed events, `last_affected`, withdrawn records, qualifiers and ambiguous ordering.
2. Run the targeted tests and confirm RED.
3. Implement deterministic normalization and conservative comparison; uncertain comparisons return `review`, never `match`.
4. Run targeted and full tests; expect GREEN.

## Task 3: KEV and exception policy

**Files:**
- Create: `src/dep_evidence/kev.py`, `src/dep_evidence/exceptions.py`
- Test: `tests/test_kev.py`, `tests/test_exceptions.py`

1. Write failing tests for exact alias joins, no fuzzy CVE joining, and active/expired/inapplicable exception states.
2. Verify RED.
3. Implement minimal KEV normalization and exception validation; exceptions annotate rather than delete findings.
4. Run targeted and full suites; expect GREEN.

## Task 4: Snapshot cache and explicit sync

**Files:**
- Create: `src/dep_evidence/datasets.py`, `src/dep_evidence/sync.py`
- Test: `tests/test_sync.py`

1. Write a local HTTP-server integration test for downloading OSV zip/KEV JSON, validation, SHA-256 manifest, retries, and preserving the last good snapshot.
2. Verify RED.
3. Implement size/time bounds, `Retry-After`/backoff, safe ZIP paths, schema checks, temp files and atomic replacement.
4. Run targeted/full tests; expect GREEN.

## Task 5: Deterministic evidence, HTML and CSV

**Files:**
- Create: `src/dep_evidence/analysis.py`, `src/dep_evidence/reporting.py`, `src/dep_evidence/bundle.py`
- Test: `tests/test_reporting.py`, `tests/test_analysis.py`

1. Write failing tests for stable ordering, byte-identical evidence, HTML escaping, safe KEV wording, explicit unknowns and complete bundle contents.
2. Verify RED.
3. Implement the minimal deterministic report writers. Runtime metadata must not enter evidence.
4. Run targeted/full tests; expect GREEN.

## Task 6: Local diff

**Files:**
- Create: `src/dep_evidence/diffing.py`
- Test: `tests/test_diffing.py`

1. Write failing tests for added/removed components, new/resolved findings and exception-state changes.
2. Verify RED.
3. Implement stable canonical diffs and summaries.
4. Run targeted/full tests; expect GREEN.

## Task 7: CLI and strict offline path

**Files:**
- Create: `src/dep_evidence/__main__.py`, `src/dep_evidence/cli.py`
- Test: `tests/test_cli.py`

1. Write failing subprocess tests for `sync`, `analyze`, `diff`, required data, malformed input, exit codes, bundle completeness and no network access during analysis.
2. Verify RED.
3. Implement argparse commands and human-readable errors without stack traces.
4. Run targeted/full tests; expect GREEN.

## Task 8: End-to-end verification and docs

**Files:**
- Create: `README.md`, `LICENSE`, `.gitignore`, `examples/`
- Test: `tests/test_e2e.py`

1. Add synthetic, locally authored sample SBOM/KEV/OSV fixtures and a public-data sync smoke test.
2. Run the full suite twice:
   - `python3 -m unittest discover -s tests -v`
   - repeat and compare deterministic evidence hashes excluding runtime metadata.
3. Run the CLI end-to-end into a temporary directory, inspect every bundle file, validate JSON/CSV/HTML and prove analyze makes no network call.
4. Run `python3 -m compileall -q src tests`.
5. Document installation-free usage, source terms, limits, non-goals and pilot boundaries.
6. Review `git diff --check` and repository status; remove temporary artifacts.

## Final acceptance criteria

- No pip or third-party runtime dependency.
- Analyze works with no network and fails clearly on missing snapshots.
- Same input/snapshots/rules produce identical `evidence.json` bytes and fingerprint.
- All exceptions, unknowns and KEV wording remain explicit.
- Sync failure cannot destroy the last valid cache.
- All automated tests and compile checks pass with real output recorded.
- No server is deployed and no pricing is published.
