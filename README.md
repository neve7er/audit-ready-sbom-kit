Audit-Ready


[![npm version](https://img.shields.io/npm/v/audit-ready.svg)](https://www.npmjs.com/package/audit-ready)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/audit-ready.svg)](https://nodejs.org)




> Generate a CycloneDX SBOM and deterministic, audit-ready risk report from your `package-lock.json`.

**No black-box scores. No LLM guesses.**  
Every finding has a machine-readable `reasonCode` you can enforce in CI.

**Status**: Beta release — Phase 2 complete, ready for real-world testing.  
We are actively collecting feedback and bug reports before the production release (Phase 3+).

---

## 🚀 Why audit-ready?

Most vulnerability scanners tell you **what is wrong**.  
`audit-ready` tells you **what to do** — deterministically.

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

| Limitation | Status |
|------------|--------|
| Caching | ❌ Not yet (planned in Phase 3) |
| Monorepo | ❌ Single lockfile per run |
| Package managers | ❌ npm only (yarn/pnpm not supported) |
| Private registries | ❌ Not fully tested |

> 💡 **Tip**: If you use yarn or pnpm, generate a compatible lockfile without modifying `node_modules`:
> ```bash
> npm install --package-lock-only
> ```

---

## 📦 Installation

```bash
# Global install
npm install -g audit-ready@beta

# Or run without installation
npx audit-ready@beta scan --help
⚡ Quick Start (1 min)
bash
# 1. Dry run (no network / no writes)
npx audit-ready scan --dry-run

# 2. Generate policy template
npx audit-ready --init

# 3. Run with enforcement
npx audit-ready scan \
  --policy .audit-policy.json \
  --fail-on DIRECT_UNPATCHED

# 4. Validate config
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
Guarantee	Description
🧩 Pure functions only	No Date, no Math.random(), no environment variables
🔁 Same input = same output	Reproducible across machines and CI
📜 Rule order defines outcome	No scoring, no ambiguity
🧾 Every result has a reasonCode	Machine-readable justification
How triage works
Each dependency is evaluated against an ordered rule set:

NO_KNOWN_VULNERABILITY

DEV_DEPENDENCY_ONLY

OPTIONAL_DEPENDENCY

TRANSITIVE_NO_EXPLOIT

DIRECT_UNPATCHED

👉 First match wins — evaluation stops immediately.

No tie-breaking

No priority field

No dynamic sorting

The array order is the logic.

🧾 reasonCode as the source of truth
Every component receives exactly one reasonCode:

Code	Meaning
DEV_DEPENDENCY_ONLY	Not shipped to production
OPTIONAL_DEPENDENCY	Not installed by default
TRANSITIVE_NO_EXPLOIT	No known exploit path
DIRECT_UNPATCHED	Direct dependency, no patch
NO_KNOWN_VULNERABILITY	Clean
EXEMPTED	Suppressed via exception
🧯 Exceptions (Phase 2)
text
applyTriage()     → assigns base reasonCode
applyExceptions() → may override to EXEMPTED
Still fully deterministic given the same inputs.

🔍 Why this matters
CI decisions are predictable

Results are diffable

Audits are reproducible

No black-box behavior

🛠️ Commands
Command / Flag	Description
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
⚙️ Configuration
All behavior is controlled via .audit-policy.json.

json
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
📤 Output
File	Description
sbom.json	CycloneDX 1.5
audit-report.md	Human-readable report
results.sarif	GitHub Security integration
🔄 CI/CD Examples
Pre-commit gate
yaml
- name: audit-ready scan
  run: npx audit-ready scan --dry-run --fail-on DIRECT_UNPATCHED
Exit 0 = no violations

Exit 1 = policy violated

GitHub Advanced Security (SARIF)
yaml
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

🧪 Beta Feedback
audit-ready is currently in beta testing.

We are specifically looking for:

🐛 Bug reports (incorrect triage, crashes, edge cases)

📦 Real-world dependency trees

⚖️ Feedback on reasonCode values

🧩 Missing CI / policy use cases

👉 Open an issue on GitHub

🧭 Roadmap
Phase	Status
Phase 1 — Core triage & SBOM	✅ Complete
Phase 2 — Policy & exceptions	✅ Complete
Phase 3 — Caching & performance	🚧 In progress
🎯 Production Release
Planned after Phase 3:

Caching support

Performance improvements

Stabilized rule system

📚 Documentation
File	Audience
docs/architecture.md	Architects, CI/CD maintainers
docs/policy-schema.md	Security teams
docs/sarif-integration.md	DevOps
docs/transparency.md	Compliance
👥 Contributors
neve7er - Creator & Maintainer

Claude by Anthropic - Code review, architecture design, debugging assistance, documentation

📄 License
MIT © 2025 neve7er