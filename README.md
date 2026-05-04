# Audit-Ready SBOM Kit


[![npm version](https://img.shields.io/npm/v/audit-ready.svg)](https://www.npmjs.com/package/audit-ready)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/audit-ready.svg)](https://nodejs.org)

> Generate a CycloneDX SBOM and deterministic, audit-ready risk report from your package-lock.json.

No black-box scores. No LLM guesses.  
Every finding has a machine-readable `reasonCode` you can enforce in CI.

---

**Status**: Beta release — Phase 2 complete, ready for real-world testing.  
We are actively collecting feedback and bug reports before the production release (Phase 3+).

---

## 🚀 Why audit-ready?

Most vulnerability scanners tell you what is wrong.  
audit-ready tells you what to do — deterministically.

- 🔍 Rule-based triage (first-match-wins)
- 🧾 Every result has a `reasonCode` (explainable & enforceable)
- ⚖️ Policy-driven CI enforcement (`--fail-on`)
- 🧱 CycloneDX 1.5 SBOM (validated before write)
- 🔒 Transparent network usage (only PURLs sent to OSV)
- 🧯 Time-bounded exceptions (no permanent ignores)

---

## 📋 Requirements

### Runtime

| Requirement | Version | Notes |
|-------------|---------|-------|
| Node.js | ≥ 18.12.0 | LTS recommended |
| npm | ≥ 7.0.0 | v9+ recommended |
| OS | Windows 11 / macOS 14+ / Ubuntu 22.04+ | Verified |

### Input

- **Lockfile**: `package-lock.json` (v1 / v2 / v3)
- **package.json**: must exist in the same directory

### ⚠️ Beta Limitations

Current beta (Phase 2) has the following limitations:

- ❌ No caching yet (planned in Phase 3)
- ❌ Monorepo not supported (single lockfile per run)
- ❌ npm only (`yarn.lock` / `pnpm-lock.yaml` not supported)
- ❌ Private registries not fully tested

> 💡 **Tip**  
> If you use yarn or pnpm, you can generate a compatible lockfile without modifying `node_modules`:
>
> ```bash
> npm install --package-lock-only
> ```

---

## 📦 Installation

```bash
# Global
npm install -g audit-ready@beta

# Or run without install
npx audit-ready@beta scan --help
⚡ Quick Start (1 min)
# 1. Dry run (no network / no writes)
npx audit-ready scan --dry-run

# 2. Generate policy template
npx audit-ready --init

# 3. Run with enforcement
npx audit-ready scan \
  --policy .audit-policy.json \
  --fail-on DIRECT_UNPATCHED

## 4. Validate config
npx audit-ready validate-config
🧠 What it does
Parses package-lock.json (v1 / v2 / v3)
Queries OSV for vulnerabilities
Applies deterministic triage (reasonCode)
Enforces policy via exit codes
Generates:
sbom.json (CycloneDX 1.5)
audit-report.md
results.sarif (optional)
Supports time-bound exceptions via .audit-policy.json
🔒 Rules-Based Determinism

Same package-lock.json → identical output. Every time.

audit-ready uses a fully deterministic, rule-based triage engine.
There is no randomness, no hidden state, and no probabilistic scoring.

🧠 Core guarantees
🧩 Pure functions only (no Date, Math.random(), or env vars)
🔁 Same input = same output (reproducible across CI)
📜 Rule order defines outcome (no scoring, no ambiguity)
🧾 Every result has a reasonCode
⚙️ How triage works

Each dependency is evaluated against an ordered rule set:

1. NO_KNOWN_VULNERABILITY
2. DEV_DEPENDENCY_ONLY
3. OPTIONAL_DEPENDENCY
4. TRANSITIVE_NO_EXPLOIT
5. DIRECT_UNPATCHED

👉 First match wins — evaluation stops immediately.

There is:

no tie-breaking
no priority field
no dynamic sorting

The array order is the logic.

🧾 reasonCode as the source of truth

Every component receives exactly one reasonCode.

## 🧯 Exceptions (Phase 2)
applyTriage() → assigns base reasonCode  
applyExceptions() → may override to EXEMPTED

Still fully deterministic given the same inputs.

## 🧪 Determinism enforcement
Source is statically scanned for:
Date
Math.random()
process.env
Build fails if any are found
## 📊 Risk tier (separate from reasonCode)
Critical / NeedsReview / Acceptable
Does not affect reasonCode
Used only for reporting clarity
## 🧩 Core Concepts
Concept	Docs
reasonCode triage	docs/architecture.md
Policy & exceptions	docs/policy-schema.md
SARIF integration	docs/sarif-integration.md
Network transparency	docs/transparency.md
## 🛠️ Commands
Command	Description
audit-ready scan	Scan lockfile and generate reports
--policy <path>	Load .audit-policy.json
--fail-on <codes>	Fail build on reasonCodes
--dry-run	No network, no file writes
--output-sarif <path>	Write SARIF 2.1.0
audit-ready audit-self	Generate SBOM for this tool
audit-ready audit-exceptions	Fail on expired exceptions
audit-ready validate-config	Validate config schema
audit-ready --init	Create policy template
--version / -V	Show version
## 🏷️ reasonCode values
Code	Meaning
DEV_DEPENDENCY_ONLY	Not shipped to production
OPTIONAL_DEPENDENCY	Not installed by default
TRANSITIVE_NO_EXPLOIT	No known exploit path
DIRECT_UNPATCHED	Direct dependency, no patch
NO_KNOWN_VULNERABILITY	Clean
EXEMPTED	Suppressed via exception
## ⚙️ Configuration

All behavior is controlled via .audit-policy.json.

{
  "failOn": ["DIRECT_UNPATCHED"],
  "exceptions": [
    {
      "id": "exc-001",
      "purl": "pkg:npm/lodash@4.17.21",
      "reasonCode": "TRANSITIVE_NO_EXPLOIT",
      "reason": "Only used in dev tooling",
      "expires_at": "2025-12-31T23:59:59.000Z",
      "approved_by": "security-team"
    }
  ]
}
Precedence
Field	Behavior
failOn	CLI overrides file
exceptions	Merged (additive)
## 📤 Output
File	Description
sbom.json	CycloneDX 1.5
audit-report.md	Human-readable report
results.sarif	GitHub Security integration
## 🔄 CI/CD Examples
Pre-commit gate
- name: audit-ready scan
  run: npx audit-ready scan --dry-run --fail-on DIRECT_UNPATCHED

Exit 0 = no violations
Exit 1 = policy violated

GitHub Advanced Security (SARIF)
- name: Run audit-ready
  run: npx audit-ready scan \
    --output-sarif results.sarif \
    --fail-on DIRECT_UNPATCHED \
    --policy .audit-policy.json

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

Findings appear in Code scanning alerts, grouped by reasonCode.

## 🧪 Beta Feedback

audit-ready is currently in beta testing.

We are specifically looking for:

🐛 Bug reports (incorrect triage, crashes, edge cases)
📦 Real-world dependency trees
⚖️ Feedback on reasonCode
🧩 Missing CI / policy use cases

👉 https://github.com/neve7er/audit-ready/issues

## 🧭 Roadmap
Phase	Status
Phase 1 — Core triage & SBOM	✅
Phase 2 — Policy & exceptions	✅
Phase 3 — Caching & performance	🚧
🎯 Production Release

Planned after Phase 3:

Caching support
Performance improvements
Stabilized rule system
# 📚 Docs
File	Audience
docs/architecture.md	Architects
docs/policy-schema.md	Security teams
docs/sarif-integration.md	DevOps
docs/transparency.md	Compliance
# 👥 Contributors
neve7er
Claude (Anthropic)
# 📄 License

MIT © 2025 neve7er