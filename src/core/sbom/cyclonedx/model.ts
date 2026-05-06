/**
 * CycloneDX 1.5-inspired data model for Audit-Ready SBOM Kit
 * This is the canonical data contract for the entire pipeline.
 *
 * Constraints:
 * - All arrays are readonly
 * - All objects are immutable (no mutating methods)
 * - Custom fields use 'ar' (audit-ready) prefix
 * - No external dependencies
 * - TypeScript strict mode compatible
 */

/** FilePath: A string representing a file path */
export type FilePath = string;

/**
 * ReasonCode: Machine-readable audit justification for triage decisions.
 * Every Component MUST carry a reasonCode as the primary auditable justification.
 * Deterministic, rule-based classification — no probabilistic scoring.
 */
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
  EXEMPTED = 'EXEMPTED',
  /** Package is deprecated — npm registry has marked it obsolete */
  DEPRECATED_PACKAGE = 'DEPRECATED_PACKAGE',
}

/** -
 * Evidence of component usage.
 * Per spec: contains only occurrences, no snippets or callstacks.
 */
export interface Evidence {
  readonly occurrences: readonly FilePath[];
}

/** -
 * Severity levels for vulnerabilities.
 * Matches CycloneDX 1.5 severity enumeration.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

/**
 * Risk tier for triage results.
 * Custom audit-ready enumeration.
 */
export type RiskTier = 'Critical' | 'NeedsReview' | 'Acceptable';

/**
 * Triage result for a component vulnerability.
 * Custom audit-ready type with 'ar' prefix fields.
 */
export interface TriageResult {
  /** Risk tier classification */
  readonly riskTier: RiskTier;
  /** Human-readable rationale for the triage decision (required) */
  readonly rationale: string;
  /** Reachability weight score (direct=1.0, transitive=0.5, dev=0.2, optional=0.1) */
  readonly reachabilityWeight: number;
}

/**-
 * Rating: CVSS or other scoring method for a vulnerability.
 * Per CycloneDX 1.5 spec.
 */
export interface Rating {
  /** Severity level */
  readonly severity: Severity;
  /** Scoring method (e.g., 'CVSSv3', 'CVSSv2', 'OWASP') */
  readonly method?: string;
  /** Numeric score (0-10 for CVSS) */
  readonly score?: number;
  /** Vector string (e.g., CVSS vector) */
  readonly vector?: string;
}

/**
 * Affected version range for a vulnerability.
 * Per CycloneDX 1.5 spec.
 */
export interface Affects {
  /** Reference to the affected component (bom-ref) */
  readonly ref: string;
  /** Version range or specific versions affected */
  readonly versions?: readonly string[];
}

/**
 * External reference for additional information.
 * Per CycloneDX 1.5 spec.
 */
export interface ExternalReference {
  /** URL to external resource */
  readonly url: string;
  /** Type of reference (e.g., 'website', 'vcs', 'documentation') */
  readonly type: string;
  /** Optional comment describing the reference */
  readonly comment?: string;
}

/**
 * Vulnerability entry.
 * Maps OSV data to CycloneDX 1.5 structure.
 */
export interface Vulnerability {
  /** Vulnerability ID (e.g., 'CVE-2023-1234', 'GHSA-xxxx') */
  readonly id: string;
  /** Description of the vulnerability */
  readonly description?: string;
  /** Risk ratings (CVSS scores) */
  readonly ratings: readonly Rating[];
  /** Components affected by this vulnerability */
  readonly affects: readonly Affects[];
  /** Recommended fix version or action */
  readonly recommendation?: string;
  /** Source of the vulnerability data */
  readonly source?: {
    readonly name: string;
    readonly url: string;
  };
  /** External references (advisories, patches) */
  readonly externalReferences?: readonly ExternalReference[];
}

/**
 * Component scope (dependency type).
 * Per CycloneDX 1.5 spec.
 */
export type ComponentScope = 'required' | 'optional' | 'excluded';

/**
 * Component type.
 * Per CycloneDX 1.5 spec.
 */
export type ComponentType = 'application' | 'framework' | 'library' | 'container' | 'operating-system' | 'device' | 'firmware' | 'file';

/**
 * License information for a component.
 * Per CycloneDX 1.5 spec.
 */
export interface License {
  /** SPDX license ID */
  readonly id?: string;
  /** License name if not SPDX */
  readonly name?: string;
  /** License text URL */
  readonly url?: string;
}

/**
 * Component: A dependency in the SBOM.
 * Per CycloneDX 1.5 spec with audit-ready extensions.
 */
export interface Component {
  /** Component type */
  readonly type: ComponentType;
  /** Component name */
  readonly name: string;
  /** Component version */
  readonly version: string;
  /** Package URL (PURL) - RFC-compliant */
  readonly purl: string;
  /** Unique reference for this component within the BOM */
  readonly 'bom-ref': string;
  /** Machine-readable audit justification (primary output) */
  readonly reasonCode: ReasonCode;
  /** Scope of the component (required, optional, excluded) */
  readonly scope?: ComponentScope;
  /** Licenses for this component */
  readonly licenses?: readonly License[];
  /** Evidence of component usage */
  readonly evidence?: Evidence;
  /** -
   * Vulnerabilities affecting this component.
   * Inline per design decision - not a separate table.
   */
  readonly vulnerabilities: readonly Vulnerability[];
  /**
   * Audit-ready triage result for this component.
   * Custom field with 'ar' prefix.
   */
  readonly arTriage?: TriageResult;
  /**
   * Exception metadata — populated when reasonCode is EXEMPTED.
   * Carries the exception reason and approver from .audit-policy.json
   * so that the SBOM is self-contained and auditable without the policy file.
   */
  readonly arExemptReason?: string;
  readonly arExemptApprovedBy?: string;
  /** Author or publisher of the component */
  readonly author?: string;
  /** Component description */
  readonly description?: string;
  /**
   * Whether this package is a direct (first-party) dependency of the root project.
   * Set by the normalizer during lockfile parsing.
   * Used by triage rules to distinguish direct from transitive vulnerabilities.
   */
  readonly isDirect?: boolean;
  /**
   * Deprecation message from the package registry, if the package has been
   * officially deprecated and the lockfile contains this field (npm v2+).
   * Undefined when the package is live or the field is absent from the lockfile.
   */
  readonly deprecated?: string;
}

/**
 * Tool: Information about the tool that generated the SBOM.
 * Per CycloneDX 1.5 spec.
 */
export interface Tool {
  /** Tool name */
  readonly name: string;
  /** Tool version */
  readonly version: string;
  /** External references for the tool */
  readonly externalReferences?: readonly ExternalReference[];
}

/**
 * Project component: metadata about the project being audited.
 * Per CycloneDX 1.5 spec.
 */
export interface ProjectComponent {
  /** Project type (always 'application') */
  readonly type: 'application';
  /** Project name from package.json */
  readonly name: string;
  /** Project version from package.json */
  readonly version: string;
  /** Project description from package.json */
  readonly description?: string;
  /** Project author from package.json */
  readonly author?: string;
  /** Unique reference for the project */
  readonly 'bom-ref': string;
}

/**
 * Metadata: Information about the BOM itself.
 * Per CycloneDX 1.5 spec.
 */
export interface Metadata {
  /** Timestamp of SBOM generation (ISO-8601) */
  readonly timestamp: string;
  /** Tools used to generate the SBOM */
  readonly tools: readonly Tool[];
  /** The component being described (the project) */
  readonly component?: ProjectComponent;
}

/**
 * BomDocument: The root CycloneDX 1.5 SBOM document.
 * Per CycloneDX 1.5 spec with audit-ready extensions.
 */
export interface BomDocument {
  /** BOM format identifier */
  readonly bomFormat: 'CycloneDX';
  /** CycloneDX specification version */
  readonly specVersion: '1.5';
  /** Unique serial number for this BOM (UUID) */
  readonly serialNumber: string;
  /** BOM version number (starts at 1) */
  readonly version: number;
  /** BOM metadata */
  readonly metadata: Metadata;
  /** Components in the BOM */
  readonly components: readonly Component[];
  /** VEX vulnerability entries for the BOM */
  readonly vulnerabilities?: readonly Vulnerability[];
  /**
   * External references at BOM level.
   * Per CycloneDX 1.5 spec.
   */
  readonly externalReferences?: readonly ExternalReference[];
}

/**
 * SeverityWeight: Weight for severity-based risk calculation.
 * Helper type for triage calculations.
 */
export type SeverityWeight = 0 | 0.1 | 0.2 | 0.5 | 1.0;

/**
 * ReachabilityScore: Score based on dependency reachability.
 * - direct = 1.0
 * - transitive = 0.5
 * - dev = 0.2
 * - optional = 0.1
 */
export type ReachabilityScore = 0.1 | 0.2 | 0.5 | 1.0;

/**
 * Ecosystem: Supported package ecosystems.
 */
export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'golang' | 'cargo' | 'nuget' | 'gem';

/**
 * DependencyKind: Classification of dependency relationship.
 */
export type DependencyKind = 'direct' | 'transitive' | 'dev' | 'optional';