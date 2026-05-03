audit-ready

[![npm version](https://img.shields.io/npm/v/audit-ready.svg)](https://www.npmjs.com/package/audit-ready)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/audit-ready.svg)](https://nodejs.org)

> Generate a CycloneDX SBOM and auditable risk triage report from your package-lock.json.
> Every finding carries a machine-readable `reasonCode` — no black-box scores, no LLM inference.

**Status**: Beta release — Phase 2 complete, ready for testing. Phase 3 (caching + performance) in progress.

| | |
|---|---|
| License | MIT |
| Node | ≥ 18 |
| SBOM format | CycloneDX 1.5 |

---

## Installation

```bash
# Global install
npm install -g audit-ready@beta

# Or run directly without installation
npx audit-ready@beta scan --help
What it does
Parses your package-lock.json (v1 / v2 / v3) into normalized package nodes

Queries OSV for known vulnerabilities in your dependency tree

Triage every package with a deterministic reasonCode (rule-based, first-match-wins)

Enforces policy — exits non-zero when --fail-on codes appear

Generates sbom.json, audit-report.md, and optionally a SARIF 2.1.0 file

Suppresses violations via time-bounded exceptions in .audit-policy.json

Validates CycloneDX 1.5 compliance before every write

Quick start
bash
# 1. Dry-run — no network, no writes. See what the scan would flag.
npx audit-ready scan --dry-run

# 2. Create a .audit-policy.json template
npx audit-ready --init

# 3. Run with policy enforcement
npx audit-ready scan \
  --policy .audit-policy.json \
  --fail-on DIRECT_UNPATCHED

# 4. Validate your policy file separately
npx audit-ready validate-config
Core concepts
Concept	File
reasonCode triage system	docs/architecture.md
Time-bounded exceptions	docs/policy-schema.md
--fail-on policy enforcement	docs/architecture.md
SARIF output + GitHub Advanced Security	docs/sarif-integration.md
Network transparency (only PURLs sent to OSV)	docs/transparency.md
Command reference
Command / Flag	Description
audit-ready scan	Scan lockfile, generate SBOM + report
--policy <path>	Load exceptions from .audit-policy.json
--fail-on <codes>	Comma-separated reasonCodes that fail the build
--dry-run	Simulate scan — no network, no file writes
--output-sarif <path>	Write SARIF 2.1.0 report
audit-ready audit-self	Generate an SBOM of this tool itself
audit-ready audit-exceptions	Report and fail on expired exceptions
audit-ready validate-config	Validate .audit-policy.json schema and expiry dates
audit-ready --init	Write a .audit-policy.json template
--version / -V	Print version
reasonCode values
reasonCode	Description
DEV_DEPENDENCY_ONLY	dev dependency with a vuln (not in prod bundle)
OPTIONAL_DEPENDENCY	optional dependency — not installed by default
TRANSITIVE_NO_EXPLOIT	transitive dep with a vuln, no known exploit path
DIRECT_UNPATCHED	direct dependency with an unpatched vuln
NO_KNOWN_VULNERABILITY	vulnerability scan clean
EXEMPTED	suppressed by a valid, non-expired exception
Configuration
All tuning lives in .audit-policy.json. See docs/policy-schema.md for the full schema.

json
{
  "failOn": ["DIRECT_UNPATCHED"],
  "exceptions": [
    {
      "id": "exc-001",
      "purl": "pkg:npm/lodash@4.17.21",
      "reasonCode": "TRANSITIVE_NO_EXPLOIT",
      "reason": "Lodash is only in dev tooling (jest), not shipped to production bundle.",
      "expires_at": "2025-12-31T23:59:59.000Z",
      "approved_by": "security-team"
    }
  ]
}
Configuration precedence
Field	CLI + file both present
failOn	CLI flag overrides file value
exceptions	Merged — additive union, file exceptions are preserved
Output artifacts
File	Description
sbom.json	CycloneDX 1.5 BOM — schema-validated before write
audit-report.md	Human-readable triage summary with reasonCode rationale
results.sarif	Optional — SARIF 2.1.0 for GitHub Advanced Security
CI/CD examples
Pattern 1: Dry-run pre-commit gate
yaml
- name: Audit-ready scan
  run: npx audit-ready scan --dry-run --fail-on DIRECT_UNPATCHED
Exit 0 = no violations. Exit 1 = policy violated and build stops.

Pattern 2: SARIF upload to GitHub Advanced Security
yaml
- name: Run audit-ready
  run: npx audit-ready scan --output-sarif results.sarif --fail-on DIRECT_UNPATCHED --policy .audit-policy.json

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
Findings appear in the GitHub Security tab under Code scanning alerts, grouped by reasonCode.

Phase status
Phase	Status
Phase 1 — Foundation, triage, compliance	✅ Complete
Phase 2 — Exceptions, policy enforcement, externalized config	✅ Complete
Phase 3 — Caching + performance	🔜 Next
See docs/architecture.md for the full roadmap.

Docs
File	Audience
docs/architecture.md	Architects, CI/CD maintainers
docs/policy-schema.md	Security teams managing exceptions
docs/sarif-integration.md	DevOps integrating with GitHub Advanced Security
docs/transparency.md	Security/compliance reviewers
Contributors

neve7er 

Claude by Anthropic 
License
MIT © 2025 neve7er