/**
 * SARIF 2.1.0 output adapter.
 * Pure function: builds a SARIF 2.1.0 document from triaged components.
 * Zero I/O, zero external calls, zero non-deterministic inputs.
 *
 * Source of truth for reasonCode → SARIF level + message.text mapping.
 * Rationale text is aligned with builder.ts RATIONALE_MAP by convention.
 */

import type { Component, ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { ReasonCode as R } from '../../core/sbom/cyclonedx/model.js';

// =========================================================================
// Internal SARIF type hierarchy (subset of 2.1.0 spec)
// =========================================================================

interface SarifArtifactLocation {
  readonly uri: string;
  readonly uriBaseId?: string;
}

interface SarifPhysicalLocation {
  readonly artifactLocation: SarifArtifactLocation;
}

interface SarifLocation {
  readonly physicalLocation: SarifPhysicalLocation;
}

interface SarifMessage {
  readonly text: string;
}

interface SarifResult {
  readonly ruleId: string;
  readonly level: string;
  readonly message: SarifMessage;
  readonly locations: readonly SarifLocation[];
}

interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
}

interface SarifToolDriver {
  readonly name: string;
  readonly version: string;
  readonly informationUri: string;
  readonly rules: readonly SarifRule[];
}

interface SarifTool {
  readonly driver: SarifToolDriver;
}

interface SarifRun {
  readonly tool: SarifTool;
  readonly results: readonly SarifResult[];
  readonly columnKind: 'utf16CodeUnits';
}

interface SarifDocument {
  readonly version: '2.1.0';
  readonly runs: readonly SarifRun[];
}

// =========================================================================
// Lookup tables
// =========================================================================

const SARIF_LEVEL: Record<ReasonCode, string | null> = {
  [R.DEV_DEPENDENCY_ONLY]: 'note',
  [R.OPTIONAL_DEPENDENCY]: 'note',
  [R.TRANSITIVE_NO_EXPLOIT]: 'warning',
  [R.DIRECT_UNPATCHED]: 'error',
  [R.EXEMPTED]: 'note',
  [R.NO_KNOWN_VULNERABILITY]: null,
};

const JUSTIFICATION_TEXT: Record<ReasonCode, string> = {
  [R.DEV_DEPENDENCY_ONLY]: 'Development-only dependency — not deployed to production',
  [R.OPTIONAL_DEPENDENCY]: 'Optional dependency — not installed by default',
  [R.TRANSITIVE_NO_EXPLOIT]: 'Transitive dependency with limited exploitability in current context',
  [R.DIRECT_UNPATCHED]: 'Direct dependency with active vulnerability requiring remediation',
  [R.EXEMPTED]: 'Vulnerability suppressed by a valid, non-expired security exception',
  [R.NO_KNOWN_VULNERABILITY]: 'No known vulnerabilities in current OSV data'
};

const TOOL_DRIVER_NAME = 'audit-ready-sbom-kit';
const TOOL_DRIVER_VERSION = '0.1.0-beta.2';
export { TOOL_DRIVER_NAME, TOOL_DRIVER_VERSION };
const TOOL_INFORMATION_URI = 'https://github.com/example/audit-ready-sbom-kit';

// =========================================================================
// Pure builder
// =========================================================================

/**
 * Build a SARIF 2.1.0 document from triaged components.
 *
 * Rules:
 * - Nodes with `reasonCode === NO_KNOWN_VULNERABILITY` are omitted from results
 * - `level` is derived from the reasonCode → SARIF level table
 * - `message.text` uses the justification text table
 * - `locations[0].physicalLocation.artifactLocation.uri` = node.purl
 * - Tool rules array is deduplicated by reasonCode
 *
 * @param components - Triaged PackageNode[] (each has a resolved reasonCode)
 * @returns Frozen SarifDocument — deterministic, byte-identical for same input
 */
export function buildSarif(components: readonly Component[]): SarifDocument {
  // Collect unique reasonCodes present in input (excluding NO_KNOWN_VULNERABILITY)
  const seenCodes = new Set<ReasonCode>();
  const results: SarifResult[] = [];

  for (const node of components) {
    if (node.reasonCode === R.NO_KNOWN_VULNERABILITY) continue;

    seenCodes.add(node.reasonCode);

    const level = SARIF_LEVEL[node.reasonCode];
    if (!level) continue;

    results.push(Object.freeze({
      ruleId: node.reasonCode,
      level,
      message: Object.freeze({ text: JUSTIFICATION_TEXT[node.reasonCode] }),
      locations: Object.freeze([Object.freeze({
        physicalLocation: Object.freeze({
          artifactLocation: Object.freeze({
            uri: node.purl,
            uriBaseId: 'ROOT'
          })
        })
      })] as const)
    }));
  }

  // Build rules array from unique codes
  const rules: SarifRule[] = Array.from(seenCodes).map((code) =>
    Object.freeze({
      id: code,
      name: code,
      shortDescription: Object.freeze({ text: JUSTIFICATION_TEXT[code] })
    })
  );

  const run: SarifRun = Object.freeze({
    tool: Object.freeze({
      driver: Object.freeze({
        name: TOOL_DRIVER_NAME,
        version: TOOL_DRIVER_VERSION,
        informationUri: TOOL_INFORMATION_URI,
        rules: Object.freeze(rules)
      })
    }),
    results: Object.freeze(results),
    columnKind: 'utf16CodeUnits' as const
  });

  return Object.freeze({
    version: '2.1.0' as const,
    runs: Object.freeze([run])
  });
}