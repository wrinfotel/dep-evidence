# dep-evidence

Build a **reproducible evidence bundle** for your open-source dependencies from a
CycloneDX SBOM you already have.

Not another vulnerability scanner. The point is different: produce an artifact
you can hand to an enterprise customer or an auditor, and that **does not
change** between runs unless the input data changed.

Three properties drive the design:

1. **Offline by default.** The network is used exactly once, to fetch a snapshot
   of public data. After that, `analyze` and `diff` work purely from the local
   cache.
2. **Determinism.** The same SBOM plus the same snapshot produce **byte-for-byte
   identical** files. No run timestamp, hostname, or other runtime markers leak
   into the output.
3. **Provenance.** Every snapshot is authenticated by SHA-256, and `sources.json`
   records which URL and which digests the evidence was built from.

## Requirements

- Python 3.11+
- No dependencies. Standard library only.
- Java, Maven, and network access are **not** required for `analyze` or `diff`.

## Quick start

```bash
git clone https://github.com/wrinfotel/dep-evidence.git
cd dep-evidence
pip install .
```

The `dep-evidence` command is available after install:

```bash
dep-evidence --help
```

Running from source works too — add `src` to `PYTHONPATH` and use
`python3 -m dep_evidence`.

### 1. Sync public data (the only networked command)

```bash
dep-evidence sync --cache ./cache \
    --osv-url  https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip \
    --kev-url  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

```text
installed ./cache/snapshots/snapshot-4f1fdf88b24c46cbb41ab1059f845083
```

Downloads are bounded: there is a cap on the downloaded size and on the
uncompressed ZIP size (zip-bomb protection), a retry limit, and `Retry-After`
handling. Installation is atomic — if anything fails, the previous working
snapshot remains the only active one.

### 2. Build a bundle (offline)

```bash
dep-evidence analyze \
    --sbom sbom.json \
    --cache ./cache \
    --exceptions exceptions.json \
    --out ./bundle
```

```text
wrote 6 files to ./bundle
```

You need an SBOM up front — this tool **does not generate** one. The output of
`cyclonedx-maven-plugin` works:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

### 3. Diff two runs (offline)

```bash
dep-evidence diff --before ./bundle-previous --after ./bundle
```

```text
1 added, 1 removed, 2 new, 1 resolved
```

Use `--json` to emit the canonical diff JSON.

## What is in the bundle

| File | Contents |
|---|---|
| `evidence.json` | Main document: components, findings, summary, fingerprint, provenance |
| `report.html` | Self-contained report for humans, fully escaped |
| `components.csv` | **Component inventory**, not a findings report |
| `exceptions.json` | Applied and known exceptions |
| `sources.json` | Provenance: URL, SHA-256, record counts, policy/rule versions |
| `run_manifest.json` | Run metadata (tool version, policy, fingerprint) |

### About `components.csv`

This is the list of what was found in the SBOM, meant to be attached to a report
as an appendix. Findings live in `evidence.json` and `report.html`.

When a license is not declared, `license_state` is `unknown` — that is more
honest than guessing, and the license list is still recorded.

Cells starting with `=`, `+`, `-`, or `@` are neutralized with a leading
apostrophe, so Excel does not evaluate their contents as a formula.

## Exceptions

The exception policy is plain JSON. It suppresses a finding but **never removes
it from provenance**: the reason and the expiry are always in the bundle.

```json
{
  "schema_version": 1,
  "exceptions": [
    {
      "ecosystem": "Maven",
      "package": "com.acme:legacy",
      "advisory_id": "GHSA-bbbb-2222",
      "reason": "end-of-life, tracked in JIRA-1234",
      "expires_on": "2027-01-01"
    }
  ]
}
```

A rule stays in force until `expires_on` passes. Expired rules are ignored
silently — the finding surfaces again on its own.

## What a KEV match actually means

This matters and is commonly misunderstood.

`kev.status: known_exploited` means exactly one thing: **this CVE appears in the
CISA KEV catalog**. It does *not* assert that this specific Maven artifact was
exploited, or exploited in your application.

Matching is by exact CVE alias (`reason: exact_cve_alias`), with no heuristics
and no guessing. When there is no exact match, the result is
`not_known_exploited` — not "looks similar".

Similarly, `affected` in OSV means the version falls inside the vulnerability
range according to OSV data. It is not a claim of exploitation and not a verdict.

## Determinism: how to verify it

`evidence.json`, `report.html`, `components.csv`, `sources.json`, and
`run_manifest.json` are **byte-for-byte identical** across repeated runs on the
same input. Runtime metadata is kept separate and does not affect these five
files.

The `fingerprint` in `evidence.json` is a SHA-256 over a normalized
representation (SBOM digest plus provenance plus policy/rule versions). Same
input gives the same fingerprint; different input gives a different one. It
works as a comparison key in CI:

```bash
dep-evidence analyze --sbom sbom.json --cache ./cache --out ./bundle
grep -o '"fingerprint": "[0-9a-f]*"' bundle/evidence.json
```

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests
```

```text
Ran 196 tests in 28s
OK
```

The `-B` flag and `PYTHONDONTWRITEBYTECODE=1` keep `__pycache__` out of the
working tree.

## Structure

```text
build.py          minimal PEP 517 backend so that `pip install .` works
pyproject.toml    package metadata and the `dep-evidence` entry point
src/dep_evidence/
  cli.py          the three commands, error handling without traceback
  sync.py         download, validation, atomic snapshot install
  datasets.py     snapshot reads via the pointer, SHA-256 verification
  sbom.py         CycloneDX JSON parser
  analysis.py     component canonicalization, provenance, fingerprint
  osv.py          version matching against OSV ranges
  kev.py          CVE alias matching against CISA KEV
  versioning.py   version comparison
  exceptions.py   exception policy
  reporting.py    JSON/HTML/CSV renderers
  bundle.py       bundle writing
  diffing.py      bundle comparison
  errors.py       DataError / InputError
```

## Limitations

Be clear-eyed about what this tool **does not** do:

- **Does not generate an SBOM.** Bring your own from `cyclonedx-maven-plugin`.
- **Does not update dependencies.** It only assembles evidence.
- **Does not provide compliance or legal assurance.** It is not a certificate.
- **Is not continuous monitoring.** Data does not refresh on its own.
- **Does not check licenses against a policy** — it only records what the SBOM
  declares.
- **Does not guess CVE prefixes.** Exact match, or an honest `review`.

Before any public use or redistribution of the snapshots, check the terms of
OSV, CISA KEV, and the other sources separately.

## Status

MVP: covered by 196 tests and an end-to-end run against real HTTP. Published as
is, with no API stability guarantees.
