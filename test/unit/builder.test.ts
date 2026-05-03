/**
 * Unit tests for the CycloneDX builder and serializer.
 * All fixtures constructed inline — no file I/O, no OSV calls.
 */

import { describe, it, expect } from 'vitest';
import { ReasonCode as R, type Component, type ComponentType, type ComponentScope } from '../../src/core/sbom/cyclonedx/model.js';
import { buildBomDocument } from '../../src/core/sbom/cyclonedx/builder.js';
import { serialize } from '../../src/core/sbom/cyclonedx/serializer.js';

/**
 * Build a minimal PackageNode fixture for testing.
 */
function makeNode(overrides: Partial<Component> & { name: string; version: string }): Component {
  const purl = `pkg:npm/${overrides.name}@${overrides.version}`;
  return {
    type: 'library' as ComponentType,
    name: overrides.name,
    version: overrides.version,
    purl,
    'bom-ref': purl,
    reasonCode: overrides.reasonCode ?? R.NO_KNOWN_VULNERABILITY,
    scope: overrides.scope ?? ('required' as ComponentScope),
    vulnerabilities: overrides.vulnerabilities ?? [],
    isDirect: overrides.isDirect ?? false,
    ...overrides,
  };
}

describe('buildBomDocument', () => {
  const metadata = { name: 'test-project', version: '1.0.0', description: 'A test project' };

  it('every component has properties containing ar:reasonCode', () => {
    const nodes = [
      makeNode({ name: 'lodash', version: '4.17.21', reasonCode: R.NO_KNOWN_VULNERABILITY }),
      makeNode({ name: 'vitest', version: '1.0.0', reasonCode: R.DEV_DEPENDENCY_ONLY }),
      makeNode({ name: 'fsevents', version: '2.3.0', reasonCode: R.OPTIONAL_DEPENDENCY }),
    ];

    const bom = buildBomDocument(nodes, metadata);

    for (const comp of bom.components) {
      expect(comp.properties).toBeDefined();
      const reasonProp = comp.properties?.find((p) => p.name === 'ar:reasonCode');
      expect(reasonProp).toBeDefined();
      expect(reasonProp?.value).toBe(comp.reasonCode);
    }
  });

  it('VEX entries exist for nodes with vulnerabilities', () => {
    const nodes = [
      makeNode({
        name: 'vuln-pkg',
        version: '1.0.0',
        reasonCode: R.DIRECT_UNPATCHED,
        vulnerabilities: [{ id: 'CVE-2023-1234', ratings: [], affects: [] }],
      }),
      makeNode({
        name: 'safe-pkg',
        version: '2.0.0',
        reasonCode: R.NO_KNOWN_VULNERABILITY,
        vulnerabilities: [],
      }),
    ];

    const bom = buildBomDocument(nodes, metadata);

    // Should have VEX entry for vuln-pkg
    expect(bom.vulnerabilities).toBeDefined();
    expect(bom.vulnerabilities?.length).toBe(1);
    expect(bom.vulnerabilities?.[0].id).toBe('CVE-2023-1234');

    // Should NOT have VEX entry for safe-pkg (NO_KNOWN_VULNERABILITY)
    const vexIds = bom.vulnerabilities?.map((v) => v.id) ?? [];
    expect(vexIds).not.toContain('safe-pkg');
  });

  it('analysis.state matches reasonCode mapping', () => {
    const testCases = [
      { reasonCode: R.DEV_DEPENDENCY_ONLY, expectedState: 'not_affected' },
      { reasonCode: R.OPTIONAL_DEPENDENCY, expectedState: 'not_affected' },
      { reasonCode: R.TRANSITIVE_NO_EXPLOIT, expectedState: 'in_triage' },
      { reasonCode: R.DIRECT_UNPATCHED, expectedState: 'affected' },
    ];

    for (const tc of testCases) {
      const nodes = [
        makeNode({
          name: `test-${tc.reasonCode}`,
          version: '1.0.0',
          reasonCode: tc.reasonCode,
          vulnerabilities: [{ id: 'TEST-1', ratings: [], affects: [] }],
        }),
      ];

      const bom = buildBomDocument(nodes, metadata);
      const vex = bom.vulnerabilities?.[0];

      expect(vex).toBeDefined();
      expect(vex?.analysis.state).toBe(tc.expectedState);
    }
  });

  it('serialNumber is a valid UUID v4 format', () => {
    const nodes = [makeNode({ name: 'pkg', version: '1.0.0' })];
    const bom = buildBomDocument(nodes, metadata);

    const uuidRegex = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(bom.serialNumber).toMatch(uuidRegex);
  });

  it('output passes ajv schema validation', () => {
    const nodes = [
      makeNode({ name: 'lodash', version: '4.17.21', reasonCode: R.NO_KNOWN_VULNERABILITY }),
      makeNode({
        name: 'vitest',
        version: '1.0.0',
        reasonCode: R.DEV_DEPENDENCY_ONLY,
        scope: 'excluded' as ComponentScope,
      }),
      makeNode({
        name: 'vuln-pkg',
        version: '1.0.0',
        reasonCode: R.DIRECT_UNPATCHED,
        vulnerabilities: [{ id: 'CVE-2023-1234', ratings: [], affects: [] }],
      }),
    ];

    const bom = buildBomDocument(nodes, metadata);

    // This will throw if validation fails
    const json = serialize(bom);

    // Verify it's valid JSON
    expect(() => JSON.parse(json)).not.toThrow();

    // Verify we got output
    expect(json.length).toBeGreaterThan(0);
  });

  it('NO_KNOWN_VULNERABILITY does NOT produce VEX entry', () => {
    const nodes = [
      makeNode({
        name: 'safe-pkg',
        version: '1.0.0',
        reasonCode: R.NO_KNOWN_VULNERABILITY,
        vulnerabilities: [], // Empty vulnerabilities
      }),
    ];

    const bom = buildBomDocument(nodes, metadata);

    // Should NOT have vulnerabilities array at all
    expect(bom.vulnerabilities).toBeUndefined();
  });

  it('DEV_DEPENDENCY_ONLY has not_affected with justification', () => {
    const nodes = [
      makeNode({
        name: 'dev-pkg',
        version: '1.0.0',
        reasonCode: R.DEV_DEPENDENCY_ONLY,
        vulnerabilities: [{ id: 'CVE-999', ratings: [], affects: [] }],
      }),
    ];

    const bom = buildBomDocument(nodes, metadata);
    const vex = bom.vulnerabilities?.[0];

    expect(vex).toBeDefined();
    expect(vex?.analysis.state).toBe('not_affected');
    expect(vex?.analysis.justification).toBeDefined();
    expect(vex?.analysis.justification).toContain('development');
  });
});