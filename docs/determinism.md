# Rules-Based Determinism

> Same `package-lock.json` input → identical `audit-report.md` output, every time.
> The system contains zero `Math.random()`, no `Date.now()` calls, no environment dependencies in core logic.

## What determinism means here

Audit-ready produces auditable decisions. An auditable decision must be reproducible — it must be provable that the same input always produces the same output, with no hidden state or non-deterministic branching.

This is verified mechanically: a test in `test/unit/policy.test.ts` (lines 97–113) statically scans the source of every core function for banned tokens (`Date`, `Date.now()`, `Math.random()`, `process.env`). If any are found, the test fails and the build stops.

---

## The pure function contract (`src/core/`)

All classification logic lives in `src/core/`. That directory is the **invariant layer**:

- **No I/O** — no `fs`, no `fetch`, no environment reads
- **No mutation** — all parameters are `readonly`, all outputs are `Object.freeze()`d
- **No global state** — every function is self-contained and context-free

The `matchesFailPolicy` JSDoc in `src/core/triage/engine.ts` (lines 51–54) states the contract explicitly:

```typescript
/**
 * Determinism contract: this function contains zero references to Date,
 * Date.now(), Math.random(), or any environment variable. Same input
 * always produces identical output.
 */
```

`DEFAULT_RULES` in `src/core/triage/rules/default-rules.ts` (line 31) is itself `Object.freeze()`d — it can never be extended at runtime.

Every interface in `src/core/sbom/cyclonedx/model.ts` uses `readonly` on all fields — the type system enforces immutability at compile time.

---

## The `ReasonCode` enum

Defined in `src/core/sbom/cyclonedx/model.ts` (lines 21–34):

```typescript
export enum ReasonCode {
  /** Dev dependency only — not deployed to production */
  DEV_DEPENDENCY_ONLY = 'DEV_DEPENDENCY_ONLY',
  /** Optional dependency — not installed by default */
  OPTIONAL_DEPENDENCY = 'OPTIONAL_DEPENDENCY',
  /** Transitive dependency with no known exploit */
  TRANSITIVE_NO_EXPLOIT = 'TRANSITIVE_NO_EXPLOIT',
  /** Direct dependency with unpatched vulnerability */
  DIRECT_UNPATCHED = 'DIRECT_UNPATCHED',
  /** No known vulnerabilities in current OSV data */
  NO_KNOWN_VULNERABILITY = 'NO_KNOWN_VULNERABILITY',
  /** Suppressed by a valid, non-expired security exception */
  EXEMPTED = 'EXEMPTED'
}
```

Every `Component` in the output SBOM carries exactly one `reasonCode` as its **primary auditable justification**.

---

## The first-match-wins engine

The triage engine in `src/core/triage/engine.ts` (lines 29–41) is deliberately simple:

```typescript
export function applyTriage(
  nodes: readonly Component[],
  rules: readonly Rule[]
): readonly Component[] {
  return nodes.map((node) => {
    for (const rule of rules) {
      if (rule.match(node)) {
        return Object.freeze({ ...node, reasonCode: rule.reasonCode });
      }
    }
    throw new UnmatchedTriageRuleError(node.purl);
  });
}
```

Key properties:
- `for-of` iterates rules in **exact array order** — no sorting, no shuffling, no randomness
- `DEFAULT_RULES` order **is** the priority — there is no separate priority field
- First matching rule wins; the loop stops immediately
- The rules array is injected as a parameter — the engine has zero knowledge of which rules exist

---

## The rule priority table

The five rules in `DEFAULT_RULES` (`src/core/triage/rules/default-rules.ts`, lines 31–65) — evaluated in order:

| Priority | id | reasonCode | Match condition |
|---|---|---|---|
| 1 | `no-vuln-data` | `NO_KNOWN_VULNERABILITY` | `node.vulnerabilities.length === 0` |
| 2 | `dev-dep` | `DEV_DEPENDENCY_ONLY` | `node.scope === 'excluded'` |
| 3 | `optional-dep` | `OPTIONAL_DEPENDENCY` | `node.scope === 'optional'` |
| 4 | `transitive-no-exploit` | `TRANSITIVE_NO_EXPLOIT` | `vulns > 0` AND `scope === 'required'` AND `!isDirect` |
| 5 | `direct-unpatched` | `DIRECT_UNPATCHED` | `vulns > 0` AND `scope === 'required'` AND `isDirect` |

### Why `scope === 'required'` is the critical guard

Rules 4 and 5 both check `scope === 'required'`. This is intentional — it means dev and optional packages are **already handled** before those rules are evaluated.

Consequence: a dev dependency with a known exploit will always match rule 2 first (`DEV_DEPENDENCY_ONLY`). It will never reach rule 5 (`DIRECT_UNPATCHED`), regardless of whether it has a vulnerability. There is no ambiguity, no tie-breaking, no scoring — only order.

### Missing reasonCode note: `EXEMPTED`

`EXEMPTED` is not in `DEFAULT_RULES` — it cannot be assigned by the rule engine alone. It is applied by `applyExceptions` in `src/core/policy/exceptions.ts` (Phase 2) as a **second pass** after `applyTriage`. The rule engine first assigns one of the five base reasonCodes; then `applyExceptions` overlays exceptions based on PURL matching from `.audit-policy.json`.

This does not break determinism — `applyExceptions` is itself a pure function. Given the same component and the same `.audit-policy.json`, it always produces the same `EXEMPTED` result.

---

## The determinism test: static source scan

`test/unit/policy.test.ts` (lines 97–113) contains a test that treats the source code itself as data:

```typescript
it('contains no references to Date, Date.now(), Math.random(), process.env in source', async () => {
  const fs = await import('fs');
  const sourcePath = new URL('../../src/core/triage/engine.ts', import.meta.url);
  const source = fs.readFileSync(sourcePath, 'utf-8');

  const fnStart = source.indexOf('export function matchesFailPolicy');
  const fnEnd = source.indexOf('\n}\n\n// =', fnStart);
  const fnBody = source.slice(fnStart, fnEnd);

  const banned = ['Date', 'Date.now()', 'Math.random()', 'process.env'];
  const found = banned.filter((token) => fnBody.includes(token));

  expect(found).toHaveLength(0);
});
```

This runs on every `npm test`. It is not a heuristic — it is a proof that the function body contains no non-deterministic references. If a future PR adds `new Date()` or `Math.random()`, this test fails before the code can be merged.

---

## Reachability scoring (separate from reasonCode)

Reachability scoring (`src/core/triage/reachability.ts`, lines 23–49) is **independent** from reasonCode assignment. It uses the `calculateReachability` pure function:

| Dependency type | scope value | reachability weight |
|---|---|---|
| dev | `'excluded'` | 0.2 |
| optional | `'optional'` | 0.1 |
| direct/production | `'required'` | 1.0 |
| unknown/transitive | (undefined) | 0.5 |

### Data flow

```
package-lock.json
       │
       ▼
  applyTriage()     assigns reasonCode (first-match-wins on rules 1-5)
       │
       ▼
calculateReachability()  assigns numeric weight (first-match-first on scope)
       │
       ▼
  triageComponent()  combines reasonCode + weight → arTriage.riskTier + arTriage.rationale
       │
       ▼
  Component { reasonCode, arTriage { riskTier, rationale, reachabilityWeight } }
```

**Important:** `reachability_weight` only affects the *human-readable rationale* and risk tier — it does not change the `reasonCode`. The two systems are decoupled.

---

## `triageComponent`: risk tier assignment (not reasonCode)

`src/core/triage/engine.ts` (lines 165–199) generates the supplemental `arTriage` field. This is separate from reasonCode — it adds a human-readable `riskTier` ('Critical' / 'NeedsReview' / 'Acceptable') and rationale:

```
1. isCritical && reachabilityWeight === 1.0  →  'Critical'
2. any vulnerability present                  →  'NeedsReview'
3. no vulnerabilities                          →  'Acceptable'
```

These tiers describe *severity context*, not classification. A dev dependency with a critical vuln gets `DEV_DEPENDENCY_ONLY` as its reasonCode (correct — it won't be in the prod bundle) but its `arTriage.riskTier` is 'NeedsReview' (correct — a vuln was still found).

---

## Why this is auditable

An auditor can independently verify every decision by:
1. Reading the source of `default-rules.ts` to confirm rule ordering
2. Running the same `package-lock.json` through `applyTriage()` to reproduce each `reasonCode`
3. Confirming through the static test that no non-deterministic functions were used
4. Tracing `triageComponent()` to verify the `arTriage.rationale` template matches the rule and score

There is no hidden logic, no opaque model, and no probabilistic output. The machine-readable `reasonCode` and the human-readable `arTriage.rationale` are both derived from the same deterministic function chain — neither can contradict the other.