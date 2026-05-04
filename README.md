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