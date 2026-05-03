# `.audit-policy.json` Specification

> Last updated: 2026-05-02

## Purpose

`.audit-policy.json` is the externalized policy file that drives the Policy Enforcement Layer. It is evaluated **after** `TriageResult[]` is produced and **before** CLI output is written. It maps `reasonCode` values to exception entries, each of which represents a deliberate, auditable waiver of the triage engine's default classification.

The policy file is optional — when absent, the tool runs normally with no waivers applied. When present, it must pass full JSON Schema validation before any scan proceeds.

## Evaluation Point in Pipeline

```
PackageNode[] → applyTriage() → TriageResult[] → applyPolicy(.audit-policy.json) → PolicyResult[] → exit code / report
                                          ↑
                              .audit-policy.json loaded and validated here
```

The policy layer is purely read-only. It never modifies `TriageResult` objects.

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/audit-policy.schema.json",
  "title": "Audit Policy",
  "description": "Externalized audit policy for the SBOM triage engine",
  "type": "object",
  "required": ["exceptions"],
  "additionalProperties": false,
  "properties": {
    "exceptions": {
      "type": "array",
      "description": "List of exception entries — each maps a reasonCode to a justified waiver",
      "items": {
        "type": "object",
        "required": ["reasonCode", "reason", "expires_at", "approved_by"],
        "additionalProperties": false,
        "properties": {
          "reasonCode": {
            "type": "string",
            "description": "The triage reasonCode this exception applies to (e.g. DEV_DEPENDENCY, TRANSITIVE_CRITICAL)",
            "pattern": "^[A-Z_]+$"
          },
          "reason": {
            "type": "string",
            "minLength": 20,
            "description": "Human-readable technical justification for the exception. Minimum 20 characters. Must be a specific justification, not a placeholder."
          },
          "expires_at": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 date-time at which this exception expires. Expired entries are silently ignored (treated as absent)."
          },
          "approved_by": {
            "type": "string",
            "minLength": 1,
            "description": "Name, identifier, or ticket reference of the party who approved this exception"
          }
        }
      }
    }
  }
}
```

## Required Fields Per Exception Entry

| Field | Type | Constraint |
|-------|------|------------|
| `reasonCode` | `string` | Uppercase with underscores (`[A-Z_]+`). Must match a known `reasonCode` from the triage engine |
| `reason` | `string` | **Minimum 20 characters.** Must be a specific technical justification. Placeholders such as `"ok"`, `"ignored"`, `"see ticket"`, or strings under 20 chars are rejected — the tool exits without scanning |
| `expires_at` | `string` (ISO 8601) | Hard expiry timestamp. Expired entries are **silently ignored** — the policy is not applied for that entry, no warning emitted |
| `approved_by` | `string` | Non-empty. Name, team identifier, or ticket reference |

## Example: Valid File

```json
{
  "exceptions": [
    {
      "reasonCode": "DEV_DEPENDENCY",
      "reason": "Lodash is only used in test files and is never bundled into the production runtime artifact",
      "expires_at": "2027-01-01T00:00:00Z",
      "approved_by": "security-team@jane.doe"
    },
    {
      "reasonCode": "TRANSITIVE_CRITICAL",
      "reason": "The vulnerable path is unreachable through our custom bundler config which excludes the transitive module",
      "expires_at": "2026-06-15T00:00:00Z",
      "approved_by": "CVE-2025-12345"
    }
  ]
}
```

## Example: Invalid Files

### Missing `approved_by`

```json
{
  "exceptions": [
    {
      "reasonCode": "DEV_DEPENDENCY",
      "reason": "Only used in tests",
      "expires_at": "2027-01-01T00:00:00Z"
    }
  ]
}
```

**Failure reason:** Schema validation fails. `approved_by` is required. Tool exits with code `1` before scanning.

---

### `reason` shorter than 20 characters

```json
{
  "exceptions": [
    {
      "reasonCode": "DEV_DEPENDENCY",
      "reason": "only in test",
      "expires_at": "2027-01-01T00:00:00Z",
      "approved_by": "jane"
    }
  ]
}
```

**Failure reason:** `"only in test"` is 13 characters — below the 20-character minimum. The tool exits without scanning and prompts for a specific technical justification.

---

### `reasonCode` format violation

```json
{
  "exceptions": [
    {
      "reasonCode": "dev-dependency",
      "reason": "Only referenced in test scripts and never shipped to production",
      "expires_at": "2027-01-01T00:00:00Z",
      "approved_by": "jane"
    }
  ]
}
```

**Failure reason:** `"dev-dependency"` does not match `^[A-Z_]+$`. Tool exits with code `1` before scanning.

---

### Expired entry (silently ignored — not an error)

```json
{
  "exceptions": [
    {
      "reasonCode": "DEV_DEPENDENCY",
      "reason": "Temporarily suppressed while waiting for upstream patch",
      "expires_at": "2025-01-01T00:00:00Z",
      "approved_by": "jane"
    }
  ]
}
```

**Behavior:** Entry is silently ignored. No warning is emitted. `applyPolicy()` behaves as if the entry is absent. The triage result is not waived.