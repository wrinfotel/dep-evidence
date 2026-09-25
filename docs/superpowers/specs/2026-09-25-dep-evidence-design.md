# DepEvidence v0.1 — design

**Status:** approved 2026-09-25  
**Working name:** DepEvidence (replaceable before public launch)

## Goal

Build a free, local CLI that turns a CycloneDX JSON SBOM for Java/Maven components into a reproducible evidence bundle: deterministic vulnerability findings, KEV alias matches, explicit unknowns, versioned exceptions, source provenance and a later run diff.

## Users and positioning

- Primary launch audience: Java OSS maintainers without a dedicated AppSec engineer.
- Monetization test: small Java/Spring companies and digital agencies serving enterprise customers.
- Positioning: local, reproducible dependency evidence — not an SCA scanner, legal compliance product, hosted service, or a replacement for CycloneDX/OSV-Scanner/Dependency-Track.
- No source code is uploaded. Analysis is offline after an explicit public-data sync.

## v0.1 commands

```text
dep-evidence sync [--cache DIR] [--osv-url URL] [--kev-url URL]
dep-evidence analyze BOM --cache DIR --out DIR [--exceptions FILE] [--previous FILE]
dep-evidence diff OLD_EVIDENCE NEW_EVIDENCE [--out FILE]
```

`analyze` never accesses the network. It fails clearly when a required local snapshot is missing instead of silently issuing online requests or reporting zero findings.

## Input

CycloneDX JSON, spec versions 1.4–1.7, maximum 50 MiB and 2,000 components. Maven components are recognized by `pkg:maven/...` purl or an explicit Maven group/name/version. The root component and dependency graph are used where available to label direct/transitive relationships. Ambiguous or missing graph data remains `unknown`.

## Data snapshots

`sync` explicitly downloads only public sources:

- OSV Maven records from the official per-ecosystem dump;
- CISA KEV JSON.

Downloads are bounded, validated and atomically installed. A manifest records URL, fetch time, HTTP validators, SHA-256, record count and tool version. Failed updates preserve the last valid snapshot. Provenance and redistribution of snapshot data are not claimed beyond the relevant upstream terms; bundled sample data must use locally authored synthetic records.

## Matching

- Component identity: ecosystem + normalized package name + version, using Maven `group:artifact`; purl is preserved.
- Version matching supports exact affected versions and OSV ecosystem introduced/fixed/last_affected events. A conservative tokenizer implements common numeric/qualifier Maven ordering. A comparison that cannot be made confidently becomes `review`, never a clean result.
- KEV is joined only through exact normalized OSV aliases/CVE IDs. A match means “this CVE appears in KEV”, not “this Maven component was exploited”.
- CycloneDX license fields are preserved with their source. Missing/conflicting license data is `unknown`; no legal policy or verdict is generated.

## Exceptions

A versioned local JSON file contains exceptions keyed by ecosystem, package and advisory ID. Every exception requires a reason and expiry date. Active exceptions annotate but never erase the underlying match. Expired and inapplicable exceptions remain visible with explicit state.

## Evidence bundle

- `evidence.json`: deterministic analysis, source/policy versions and analysis fingerprint;
- `report.html`: self-contained human report with no remote assets;
- `components.csv`: canonical component inventory;
- `exceptions.json`: normalized exception decisions;
- `sources.json`: immutable local snapshot provenance;
- `run_manifest.json`: runtime/tool/input metadata, intentionally separate from deterministic evidence;
- `diff.json`: optional comparison with a previous local evidence file.

The deterministic fingerprint hashes normalized input, snapshot manifests and policy/rule version. Runtime timestamps do not change `evidence.json`.

## Failure and safety behavior

- Exit 0: complete analysis and bundle written.
- Exit 2: invalid input/config/data snapshot; never masquerade as zero findings.
- Exit 3: output/write failure.
- Sync network failures: bounded retry/backoff; failed update does not replace the last valid cache.
- Input sizes/counts are bounded. HTML escapes all input. Secrets are never read or emitted.
- No telemetry, accounts, hosted storage, background scheduler, CI integration, automatic dependency updates, private registry support or continuous compliance.

## Tests

Use stdlib `unittest` and `unittest.mock`, plus a local `http.server` integration test:

1. CycloneDX parsing, component limits, direct/transitive/unknown graph states;
2. exact and ranged OSV matching, withdrawn records, fixed versions, aliases;
3. conservative version comparison and explicit review state;
4. KEV alias join and safe wording;
5. active/expired/inapplicable exceptions that never erase findings;
6. deterministic output and analysis fingerprint;
7. atomic sync, validation failure and last-good preservation;
8. CLI end-to-end, `--offline` no-egress behavior, bundle completeness and diff;
9. malformed JSON, unsupported schema, oversized input and HTML escaping.

## Validation with users

Before monetization claims: 8–10 OSS contacts plus 8–10 Java/Spring/agency contacts, at least 5 substantive conversations, and at least 2 real completed pilots. OSS success is repeat use/public cases/referrals; commercial success is actual customer workflow use and willingness to continue. Go only if three organizations confirm the same pain, two pilots produce usable artifacts, one user repeats the workflow, and support is about 2–4 hours per pilot.
