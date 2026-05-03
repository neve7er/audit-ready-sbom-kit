/**
 * CycloneDX SBOM Builder.
 * Pure function: builds a BomDocument from parsed components and project metadata.
 * Zero side effects. All I/O is caller's responsibility.
 */

import type {
  BomDocument,
  Component,
  Metadata,
  ProjectComponent,
  Tool,
  ReasonCode,
  TriageResult,
  RiskTier,
  Rating,
  Affects,
} from './model.js';
import { ReasonCode as R } from './model.js';

// Import from Node's crypto module — no external dependency
import { randomUUID } from 'crypto';

/** Tool metadata for the SBOM */
const TOOL: Tool = {
  name: 'audit-ready',
  version: '0.1.0-beta.2'
};

/** Input: Project metadata for the root component */
interface ProjectMetadata {
  name: string;
  version: string;
  description?: string;
  author?: string;
}

// =========================================================================
// VEX and justification lookup tables
// =========================================================================

/** Map reasonCode to VEX analysis.state per CycloneDX spec */
const VEX_STATE_MAP: Record<ReasonCode, string> = {
  [R.DEV_DEPENDENCY_ONLY]: 'not_affected',
  [R.OPTIONAL_DEPENDENCY]: 'not_affected',
  [R.TRANSITIVE_NO_EXPLOIT]: 'in_triage',
  [R.DIRECT_UNPATCHED]: 'affected',
  [R.EXEMPTED]: 'not_affected',
  [R.NO_KNOWN_VULNERABILITY]: '' // Omit from VEX
};

/** Map reasonCode to human-readable justification text */
const JUSTIFICATION_TEXT: Record<ReasonCode, string> = {
  [R.DEV_DEPENDENCY_ONLY]: 'Dependency is a development-only dependency and not deployed to production',
  [R.OPTIONAL_DEPENDENCY]: 'Dependency is optional and not installed by default',
  [R.TRANSITIVE_NO_EXPLOIT]: 'Transitive dependency with no known exploit in current context',
  [R.DIRECT_UNPATCHED]: 'Direct dependency with known unpatched vulnerability',
  [R.EXEMPTED]: 'Vulnerability suppressed by a valid, non-expired security exception. See exception reason in SBOM metadata.',
  [R.NO_KNOWN_VULNERABILITY]: 'No known vulnerabilities in current OSV data'
};

/** Map reasonCode to risk tier */
const RISK_TIER_MAP: Record<ReasonCode, RiskTier> = {
  [R.DEV_DEPENDENCY_ONLY]: 'Acceptable',
  [R.OPTIONAL_DEPENDENCY]: 'Acceptable',
  [R.TRANSITIVE_NO_EXPLOIT]: 'NeedsReview',
  [R.DIRECT_UNPATCHED]: 'Critical',
  [R.EXEMPTED]: 'Acceptable',
  [R.NO_KNOWN_VULNERABILITY]: 'Acceptable'
};

/** Map reasonCode to rationale text */
const RATIONALE_MAP: Record<ReasonCode, string> = {
  [R.DEV_DEPENDENCY_ONLY]: 'Development dependency — not deployed to production',
  [R.OPTIONAL_DEPENDENCY]: 'Optional dependency — not installed by default',
  [R.TRANSITIVE_NO_EXPLOIT]: 'Transitive dependency with vulnerability but limited exploitability',
  [R.DIRECT_UNPATCHED]: 'Direct dependency with active vulnerability requiring remediation',
  [R.EXEMPTED]: 'Under security exception — see SBOM for exception details', // Runtime value replaced in buildVexEntries
  [R.NO_KNOWN_VULNERABILITY]: 'No known vulnerabilities in current OSV data'
};

// =========================================================================
// Component transformation
// =========================================================================

/**
 * Build a Component with reasonCode embedded in properties.
 */
function buildComponent(node: Component): Component {
  // Build properties array with reasonCode
  const properties = [
    { name: 'ar:reasonCode', value: node.reasonCode }
  ];

  // Build arTriage based on reasonCode
  const arTriage: TriageResult = {
    riskTier: RISK_TIER_MAP[node.reasonCode],
    rationale: node.reasonCode === R.EXEMPTED && node.arExemptReason
      ? node.arExemptReason
      : RATIONALE_MAP[node.reasonCode],
    reachabilityWeight: node.arTriage?.reachabilityWeight ?? (node.scope === 'optional' ? 0.1 : node.scope === 'excluded' ? 0.2 : 1.0)
  };

  return Object.freeze({
    ...node,
    properties: Object.freeze(properties),
    arTriage: Object.freeze(arTriage)
  });
}

// =========================================================================
// VEX document construction
// =========================================================================

/**
 * VEX vulnerability entry per CycloneDX spec.
 */
interface VexVulnerability {
  readonly id: string;
  readonly ratings: readonly Rating[];
  readonly affects: readonly Affects[];
  readonly analysis: {
    state: string;
    justification?: string;
  };
}

/**
 * Build VEX entries for components with vulnerabilities.
 * Mapping: reasonCode → analysis.state per spec.
 */
function buildVexEntries(components: readonly Component[]): readonly VexVulnerability[] {
  const vexEntries: VexVulnerability[] = [];

  for (const comp of components) {
    // Skip components without vulnerabilities
    if (comp.vulnerabilities.length === 0) continue;

    // Skip NO_KNOWN_VULNERABILITY — no VEX entry needed
    if (comp.reasonCode === R.NO_KNOWN_VULNERABILITY) continue;

    const state = VEX_STATE_MAP[comp.reasonCode];
    if (!state) continue; // Skip if no mapping

    for (const vuln of comp.vulnerabilities) {
      // For EXEMPTED, use the embedded exception reason when available
      const justification = comp.reasonCode === R.EXEMPTED && comp.arExemptReason
        ? comp.arExemptReason
        : JUSTIFICATION_TEXT[comp.reasonCode];
      vexEntries.push(Object.freeze({
        id: vuln.id,
        ratings: vuln.ratings,
        affects: vuln.affects,
        analysis: Object.freeze({
          state,
          justification,
          // Note: arExemptApprovedBy is visible on the Component record itself
        })
      }));
    }
  }

  return Object.freeze(vexEntries);
}

// =========================================================================
// Metadata and main builder
// =========================================================================

/**
 * Build metadata section for the BOM.
 */
function buildMetadata(pkgMeta: ProjectMetadata, timestamp: string): Metadata {
  const projectComponent: ProjectComponent = {
    type: 'application',
    name: pkgMeta.name,
    version: pkgMeta.version,
    description: pkgMeta.description,
    author: pkgMeta.author,
    'bom-ref': `pkg:npm/${pkgMeta.name}@${pkgMeta.version}`
  };

  return Object.freeze({
    timestamp,
    tools: Object.freeze([Object.freeze({ ...TOOL })]),
    component: Object.freeze(projectComponent)
  });
}

/**
 * Build a complete CycloneDX BOM document.
 * Pure function — no side effects, no I/O.
 *
 * @param nodes - Array of PackageNode from normalization + triage
 * @param pkgMeta - Project metadata (name, version, description, author)
 * @returns Complete BomDocument conforming to CycloneDX 1.5 spec
 */
export function buildBomDocument(
  nodes: readonly Component[],
  pkgMeta: ProjectMetadata
): BomDocument {
  const timestamp = new Date().toISOString();

  // Transform nodes to components with properties
  const components = nodes.map(buildComponent);

  // Build VEX entries
  const vexEntries = buildVexEntries(components);

  return Object.freeze({
    bomFormat: 'CycloneDX' as const,
    specVersion: '1.5' as const,
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: buildMetadata(pkgMeta, timestamp),
    components: Object.freeze(components),
    // Embed VEX as external references (CycloneDX pattern)
    ...(vexEntries.length > 0 && {
      vulnerabilities: Object.freeze(
        vexEntries.map((v) => Object.freeze({
          id: v.id,
          ratings: v.ratings,
          affects: v.affects,
          analysis: v.analysis
        }))
      )
    })
  });
}