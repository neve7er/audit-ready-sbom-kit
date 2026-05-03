/**
 * Markdown report renderer.
 * Pure function: accepts BomDocument, returns Markdown string.
 * Zero side effects. No I/O.
 */

import type { BomDocument } from '../../../core/sbom/cyclonedx/model.js';
import { generateFindingsSections } from './sections/findings.js';

/**
 * Render a Markdown report from a CycloneDX BOM.
 *
 * MVP includes three sections:
 * 1. Scan timestamp
 * 2. Total package count
 * 3. Component table (name + version)
 *
 * @param bom - The CycloneDX BOM document
 * @returns Markdown string for writing to disk
 */
export function renderMarkdown(bom: BomDocument): string {
  const lines: string[] = [];

  // Header
  lines.push('# Audit Report');
  lines.push('');

  // Section 1: Scan timestamp
  lines.push(`**Scan Timestamp:** ${bom.metadata.timestamp}`);
  lines.push('');

  // Section 2: Total package count
  lines.push(`**Total Packages:** ${bom.components.length}`);
  lines.push('');

  // Section 3: Component table
  lines.push('## Dependencies');
  lines.push('');
  lines.push('| Package | Version |');
  lines.push('|---------|---------|');

  for (const component of bom.components) {
    lines.push(`| ${component.name} | ${component.version} |`);
  }

  lines.push('');

  // Phase 2: Add Findings and Accepted Risks sections
  const findingsSections = generateFindingsSections(bom);
  lines.push(findingsSections);

  return lines.join('\n');
}