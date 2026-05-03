/**
 * Triage engine — rule-based reasonCode assignment.
 *
 * applyTriage: applies an ordered rule set to every PackageNode.
 * Rules are injected as a parameter — the engine has zero knowledge
 * of which specific rules exist.
 *
 * Backward compat: triageComponent (riskTier-based) is preserved.
 */

import type { Component, Vulnerability, TriageResult, Severity, RiskTier } from '../sbom/cyclonedx/model.js';
import { ReasonCode } from '../sbom/cyclonedx/model.js';
import { UnmatchedTriageRuleError } from '../../utils/errors.js';
import type { Rule } from './rules/default-rules.js';

// =========================================================================
// New rule-based API
// =========================================================================

/**
 * Apply triage rules to every node in the array.
 * Returns a new readonly array — input is never mutated.
 *
 * @param nodes - Normalized PackageNode[] (input unchanged)
 * @param rules - Ordered rule set (first-match-wins)
 * @returns New array with reasonCode set per the first matching rule
 * @throws UnmatchedTriageRuleError if no rule matches a node
 */
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

// =========================================================================
// matchesFailPolicy
// =========================================================================

/**
 * Check whether a PackageNode matches the `--fail-on` policy.
 * Returns true if the node's reasonCode is in the failOnCodes set.
 *
 * Determinism contract: this function contains zero references to Date,
 * Date.now(), Math.random(), or any environment variable. Same input
 * always produces identical output.
 *
 * @param node       - The package node to test
 * @param failOnCodes - The validated ReasonCode[] from --fail-on
 */
export function matchesFailPolicy(
  node: Component,
  failOnCodes: readonly ReasonCode[]
): boolean {
  return (failOnCodes as readonly string[]).includes(node.reasonCode as string);
}

// =========================================================================
// Legacy triageComponent (riskTier-based) — kept for backward compat
// =========================================================================

/**
 * Get the highest severity from a list of vulnerabilities.
 */
function getHighestSeverity(vulns: readonly Vulnerability[]): Severity {
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown', 'none'];
  let highestIndex = -1;

  for (const vuln of vulns) {
    for (const rating of vuln.ratings) {
      const idx = severityOrder.indexOf(rating.severity);
      if (idx > highestIndex) {
        highestIndex = idx;
      }
    }
  }

  return highestIndex >= 0 ? severityOrder[highestIndex] : 'unknown';
}

/**
 * Check if any vulnerability is critical severity.
 */
function hasCriticalVulnerability(vulns: readonly Vulnerability[]): boolean {
  return vulns.some((vuln) =>
    vuln.ratings.some((r) => r.severity === 'critical')
  );
}

/**
 * Get all vulnerability IDs for a component.
 */
function getVulnerabilityIds(vulns: readonly Vulnerability[]): string[] {
  return vulns.map((v) => v.id);
}

/**
 * Generate rationale string based on classification.
 */
function generateRationale(
  riskTier: RiskTier,
  reachabilityWeight: number,
  highestSeverity: Severity,
  vulnIds: string[]
): string {
  const reachabilityLabel = getReachabilityLabel(reachabilityWeight);

  switch (riskTier) {
    case 'Critical':
      return `This package is a direct production dependency with a critical severity vulnerability (${vulnIds.join(', ')}). ` +
        `Immediate remediation required. Risk tier: Critical.`;

    case 'NeedsReview':
      return `Vulnerability present (${highestSeverity} severity: ${vulnIds.join(', ')}). ` +
        `Impact is limited due to ${reachabilityLabel} (reachability weight: ${reachabilityWeight}). ` +
        `Risk tier: Needs Review — evaluate exploitability in your context.`;

    case 'Acceptable':
      return `No known vulnerabilities detected in current OSV data. ` +
        `Dependency type: ${reachabilityLabel} (reachability weight: ${reachabilityWeight}). ` +
        `Risk tier: Acceptable.`;

    default:
      return `Unknown risk classification.`;
  }
}

/**
 * Get human-readable label for reachability weight.
 */
function getReachabilityLabel(weight: number): string {
  switch (weight) {
    case 1.0:
      return 'direct production dependency';
    case 0.5:
      return 'transitive dependency';
    case 0.2:
      return 'dev-only dependency';
    case 0.1:
      return 'optional dependency';
    default:
      return 'unknown dependency type';
  }
}

/**
 * Triage a component based on its vulnerabilities and reachability.
 *
 * Rules (evaluated in order):
 * 1. Any vuln with severity === 'critical' AND reachabilityWeight === 1.0 → 'Critical'
 * 2. Any vuln present → 'NeedsReview'
 * 3. No vulns → 'Acceptable'
 *
 * @param component - The component to triage
 * @param reachabilityWeight - Calculated reachability weight (0.1-1.0)
 * @returns TriageResult with risk tier and rationale
 */
export function triageComponent(
  component: Component,
  reachabilityWeight: number
): TriageResult {
  const vulns = component.vulnerabilities;
  const hasVulns = vulns.length > 0;
  const isCritical = hasCriticalVulnerability(vulns);
  const highestSeverity = getHighestSeverity(vulns);
  const vulnIds = getVulnerabilityIds(vulns);

  // Rule 1: Critical vuln + direct dependency (reachability 1.0)
  if (isCritical && reachabilityWeight === 1.0) {
    return {
      riskTier: 'Critical',
      rationale: generateRationale('Critical', reachabilityWeight, highestSeverity, vulnIds),
      reachabilityWeight
    };
  }

  // Rule 2: Any vuln present
  if (hasVulns) {
    return {
      riskTier: 'NeedsReview',
      rationale: generateRationale('NeedsReview', reachabilityWeight, highestSeverity, vulnIds),
      reachabilityWeight
    };
  }

  // Rule 3: No vulns
  return {
    riskTier: 'Acceptable',
    rationale: generateRationale('Acceptable', reachabilityWeight, 'none', []),
    reachabilityWeight
  };
}