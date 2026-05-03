/**
 * Findings and Accepted Risks sections for the Markdown report.
 * Pure function: accepts BomDocument, returns Markdown section strings.
 */

import type { BomDocument, Component } from '../../../../core/sbom/cyclonedx/model.js';

/**
 * Filter components by risk tier.
 */
function filterByRiskTier(
  components: readonly Component[],
  tiers: readonly ('Critical' | 'NeedsReview' | 'Acceptable')[]
): Component[] {
  return components.filter((c) => c.arTriage && tiers.includes(c.arTriage.riskTier));
}

/**
 * Get severity for a component (highest from vulnerabilities).
 */
function getHighestSeverity(component: Component): string {
  if (component.vulnerabilities.length === 0) {
    return 'none';
  }

  const order = ['critical', 'high', 'medium', 'low', 'unknown'];
  let highest = -1;

  for (const vuln of component.vulnerabilities) {
    for (const rating of vuln.ratings) {
      const idx = order.indexOf(rating.severity);
      if (idx > highest) {
        highest = idx;
      }
    }
  }

  return highest >= 0 ? order[highest] : 'unknown';
}

/**
 * Get vulnerability IDs for a component.
 */
function getVulnIds(component: Component): string {
  if (component.vulnerabilities.length === 0) {
    return '-';
  }
  return component.vulnerabilities.map((v) => v.id).join(', ');
}

/**
 * Generate the ## Findings section.
 * Includes Critical and NeedsReview components.
 */
function generateFindingsSection(components: Component[]): string {
  const lines: string[] = [];

  lines.push('## Findings');
  lines.push('');
  lines.push('Components with identified vulnerabilities requiring attention.');
  lines.push('');

  if (components.length === 0) {
    lines.push('*No findings identified.*');
    lines.push('');
    return lines.join('\n');
  }

  lines.push('| Package | Version | Severity | Vulnerability ID | Reachability |');
  lines.push('|---------|---------|----------|------------------|--------------|');

  for (const component of components) {
    const severity = getHighestSeverity(component);
    const vulnIds = getVulnIds(component);
    const reachability = component.arTriage?.reachabilityWeight ?? 'N/A';

    lines.push(
      `| ${component.name} | ${component.version} | ${severity} | ${vulnIds} | ${reachability} |`
    );
  }

  lines.push('');

  return lines.join('\n');
}

/**
 * Generate the ## Accepted Risks section.
 * Includes Acceptable components with their rationale.
 */
function generateAcceptedRisksSection(components: Component[]): string {
  const lines: string[] = [];

  lines.push('## Accepted Risks');
  lines.push('');
  lines.push('Components with no known vulnerabilities or minimal risk profile.');
  lines.push('');

  if (components.length === 0) {
    lines.push('*No accepted risks — all components identified as findings.*');
    lines.push('');
    return lines.join('\n');
  }

  for (const component of components) {
    const triage = component.arTriage!;
    lines.push(`### ${component.name}@${component.version}`);
    lines.push('');
    lines.push(`**Reachability Weight:** ${triage.reachabilityWeight}`);
    lines.push('');
    lines.push(`**Rationale:** ${triage.rationale}`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Generate both Findings and Accepted Risks sections for the Markdown report.
 *
 * @param bom - The CycloneDX BOM document
 * @returns Markdown string containing both sections
 */
export function generateFindingsSections(bom: BomDocument): string {
  const componentsWithTriage = bom.components.filter((c) => c.arTriage !== undefined);

  const criticalAndNeedsReview = filterByRiskTier(componentsWithTriage, ['Critical', 'NeedsReview']);
  const acceptable = filterByRiskTier(componentsWithTriage, ['Acceptable']);

  const findingsSection = generateFindingsSection(criticalAndNeedsReview);
  const acceptedRisksSection = generateAcceptedRisksSection(acceptable);

  return findingsSection + '\n' + acceptedRisksSection;
}