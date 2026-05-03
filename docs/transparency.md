# Transparency

This document describes exactly what data this tool transmits, how it produces its own SBOM, and how CI integrates the tooling.

---

## 1. What Data Leaves This Machine

### External endpoints contacted

| Endpoint | Purpose | Data transmitted |
|---|---|---|
| `https://api.osv.dev/v1/querybatch` | Vulnerability lookup | Package URLs (PURLs) only |

### What IS transmitted
- **PURLs** (Package URLs) — e.g. `pkg:npm/lodash@4.17.21` — sent to OSV.dev in batched POST requests (≤1000 PURLs/request, 30s timeout)
- No authentication token required; no user account needed

### What IS NOT transmitted
- Source code or file contents
- Repository URLs or names
- Environment variables or secrets
- Build logs or commit history
- Any personal or machine-identifying information

### Network failure handling
If OSV.dev is unreachable, the tool logs a warning (`⚠ Vulnerability scan skipped — offline or unreachable`) and exits with code 2. The SBOM and report are still written. No partial or cached data is transmitted.

---

## 2. Self-SBOM Generation

### Command
```bash
audit-ready audit-self
```

### What it does

1. **Locates project files** — resolves `package-lock.json` and `package.json` relative to the CLI binary location (`bin/audit-ready.js`), so the command works correctly regardless of the current working directory.

2. **Pipeline execution** — runs the production pipeline against itself:
   ```
   parse(lockfile) → applyTriage(nodes, DEFAULT_RULES) → buildBomDocument(nodes, metadata)
   ```
   No new logic is introduced. All functions are from `src/core/` and `src/adapters/`.

3. **AJV schema validation** — validates the generated BOM against `cyclonedx-1.5.schema.json` using `ajv` (included as a project dependency). On failure, prints the full error list and exits with code 1.

4. **Output files** — written to the current working directory:
   - `audit-ready-sbom.json` — valid CycloneDX 1.5 SBOM
   - `audit-ready-report.md` — human-readable triage summary

### Output includes
- All runtime and development dependencies from `package-lock.json`
- `arTriage` fields on each component (risk tier, rationale, reachability weight)
- `properties` array with `ar:reasonCode` per component
- VEX entries for components with vulnerabilities or explicit not-affected status

---

## 3. Provenance in CI

The `scripts/generate-provenance.ts` script is designed for CI use. It captures build-time metadata and embeds it into the SBOM so each artifact can be linked back to the exact commit and runtime that produced it.

### Run as a build step

Add a `generate-provenance` script to `package.json`:
```json
{
  "scripts": {
    "generate-provenance": "npx ts-node scripts/generate-provenance.ts"
  }
}
```

### GitHub Actions workflow snippet

```yaml
name: Build and Generate SBOM

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Generate provenance SBOM
        run: npm run generate-provenance

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-commit-${{ github.sha }}
          path: sbom.json
          retention-days: 90
```

### Linking artifact to commit

Each `sbom.json` contains a `properties` array at document root level with three fields:

```json
"properties": [
  { "name": "ar:commit", "value": "a1b2c3d4e5f6..." },
  { "name": "ar:nodeVersion", "value": "v20.19.0" },
  { "name": "ar:toolVersion", "value": "0.0.1" }
]
```

To retrieve the commit that generated a given `sbom.json`:
```bash
jq '.properties[] | select(.name == "ar:commit") | .value' sbom.json
```

The artifact name includes the commit SHA (`sbom-commit-<sha>`), providing a second link between artifact and source commit.

---

## 4. Audit Trail Chain

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Developer pushes commit  a1b2c3d  to GitHub                                 │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  GitHub Actions: on push, run npm run generate-provenance                    │
│  → scripts/generate-provenance.ts executes                                  │
│  → Reads: package-lock.json, package.json                                    │
│  → Captures: git commit, node version, tool version                         │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  sbom.json written to repository root                                        │
│  Contains:                                                                    │
│    metadata.component     = audit-ready@0.0.1                                │
│    properties[ar:commit]  = a1b2c3d                                          │
│    properties[ar:nodeVersion] = v20.19.0                                     │
│    properties[ar:toolVersion] = 0.0.1                                        │
│    components[]           = all 146 packages                                  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  GitHub Actions: actions/upload-artifact@v4                                 │
│  Artifact name: sbom-commit-a1b2c3d  (commit SHA embedded in name)           │
│  Artifact path: sbom.json                                                    │
│  Retention: 90 days                                                           │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  Audit evidence at any future point:                                         │
│                                                                                │
│  1. Download artifact sbom-commit-a1b2c3d                                   │
│  2. Read properties[ar:commit] → a1b2c3d → git show a1b2c3d                 │
│  3. Verify components match the lockfile at that commit                       │
│  4. Verify node version matches runner specification                          │
│                                                                                │
│  Evidence of build integrity: no tampering possible without changing commit  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Verification queries

```bash
# Extract the commit linked to a given sbom.json
jq '.properties[] | select(.name=="ar:commit") | .value' sbom.json

# Verify sbom matches this commit's lockfile
git checkout <commit> -- package-lock.json
# Run: audit-ready audit-self and diff the resulting components[]
```

---

## Summary

- **OSV.dev** (`https://api.osv.dev/v1/querybatch`) is the only external endpoint contacted.
- Only PURLs are transmitted — no code, secrets, or identifying information.
- `audit-ready audit-self` produces a valid CycloneDX 1.5 SBOM of the tool itself, AJV-validated before writing.
- `scripts/generate-provenance.ts` captures git commit, Node version, and tool version at build time and embeds them in `sbom.json` properties.
- Each CI artifact is linked to its source commit through both the artifact name and the `ar:commit` property inside the SBOM.