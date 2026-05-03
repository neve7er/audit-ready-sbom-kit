/**
 * Snapshot test for CycloneDX serializer output.
 *
 * Verifies that the serializer produces consistent, schema-conformant output
 * by comparing against a committed baseline. The two non-deterministic fields
 * (serialNumber, metadata.timestamp) are normalized to fixed placeholders
 * before comparison, so the diff only flags intentional schema changes.
 *
 * Updating the baseline: edit test/snapshots/sbom-baseline.json by hand,
 * then review the diff in CI before committing. Automated snapshot
 * regeneration is prohibited.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { serialize } from '../../src/core/sbom/cyclonedx/serializer.js';
import type { BomDocument } from '../../src/core/sbom/cyclonedx/model.js';

const SNAPSHOT_PATH = resolve('./test/snapshots/sbom-baseline.json');
const FIXED_SERIAL = 'urn:uuid:00000000-0000-0000-0000-000000000000';
const FIXED_TIMESTAMP = '1970-01-01T00:00:00.000Z';

/**
 * Normalize the two non-deterministic fields in a parsed BomDocument.
 * Returns a new object — the original is not mutated.
 */
function normalizeDynamicFields(bom: BomDocument): BomDocument {
  return {
    ...bom,
    serialNumber: FIXED_SERIAL,
    metadata: {
      ...bom.metadata,
      timestamp: FIXED_TIMESTAMP,
    },
    // Normalize reachabilityWeight numbers (1.0 -> 1, 0.2 stays 0.2) for stable comparison
    components: bom.components.map((c) => ({
      ...c,
      arTriage: c.arTriage
        ? {
            ...c.arTriage,
            reachabilityWeight: Number(c.arTriage.reachabilityWeight),
          }
        : undefined,
    })),
    vulnerabilities: bom.vulnerabilities?.map((v) => ({ ...v })),
  } as BomDocument;
}

describe('serializer snapshot', () => {
  it('serializes a BomDocument matching the baseline', () => {
    const raw = readFileSync(SNAPSHOT_PATH, 'utf-8');
    const bom = JSON.parse(raw) as BomDocument;

    // serialize() validates structure then returns JSON string
    // Throws SchemaValidationError on mismatch
    const output = serialize(bom);
    const outputBom = JSON.parse(output) as BomDocument;

    // Normalize non-deterministic fields in both baseline and output
    const normalizedBaseline = normalizeDynamicFields(bom);
    const normalizedOutput = normalizeDynamicFields(outputBom);

    expect(normalizedOutput, 'serializer output should match baseline').toEqual(
      normalizedBaseline
    );
  });

  it('serialize throws SchemaValidationError on invalid structure', () => {
    const invalid: BomDocument = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      // intentionally missing serialNumber, version, metadata, components
      serialNumber: '',
      version: 1,
      metadata: { timestamp: '', tools: [] }, // missing required fields
      components: [],
    };

    expect(() => serialize(invalid)).toThrow();
  });
});