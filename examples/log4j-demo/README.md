# Example: log4j-core 2.14.1 + Guava 32.1.2-jre

A two-component CycloneDX 1.4 SBOM you can run the full workflow on without
generating an SBOM of your own:

- `org.apache.logging.log4j:log4j-core@2.14.1` — the Log4Shell version
- `com.google.guava:guava@32.1.2-jre` — a clean, current dependency

## What to expect

1. `sync` downloads the OSV (Maven) and CISA KEV snapshots — the only
   networked step.
2. `analyze` produces a bundle where:
   - **CVE-2021-44228** and **CVE-2021-45046** show up with
     `kev.status: known_exploited`, matched by exact CVE alias — this is the
     Log4Shell headline an auditor would look for.
   - Several 2025–2026 advisories also cover 2.14.1, because OSV ranges for
     log4j-core were extended over time (fix in the 2.25.x line).
   - **Guava** lands in `review` with the reason
     `unparseable_component_version`: the conservative version parser does not
     rank the `-jre` suffix and refuses to guess. That is by design — an
     honest "review" instead of a silent wrong verdict.
3. Run `analyze` twice into two different directories and `cmp` the files:
   they are byte-for-byte identical.

## Run it

```bash
dep-evidence sync --cache ./cache \
    --osv-url  https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip \
    --kev-url  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

dep-evidence analyze --cache ./cache \
    --sbom examples/log4j-demo/sbom.json --out ./bundle

# determinism check
dep-evidence analyze --cache ./cache \
    --sbom examples/log4j-demo/sbom.json --out ./bundle-again
cmp bundle/evidence.json bundle-again/evidence.json && echo "identical"
```

The bundle `report.html` is self-contained — open it in a browser.
