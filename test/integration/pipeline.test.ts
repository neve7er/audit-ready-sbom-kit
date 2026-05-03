/**
 * Integration test: lockfile normalization pipeline.
 * Verifies that v1/v2/v3 lockfiles representing the same dependency set
 * produce identical PackageNode shapes.
 */
import { describe, it, expect } from 'vitest';
import { normalizeV1 } from '../../src/adapters/npm/normalizer.js';
import { normalizeV2 } from '../../src/adapters/npm/normalizer.js';
import { normalizeV3 } from '../../src/adapters/npm/normalizer.js';
import { parse } from '../../src/adapters/npm/parser.js';

import v1Fixture from '../fixtures/lockfiles/npm-v1/package-lock.json';
import v2Fixture from '../fixtures/lockfiles/npm-v2/package-lock.json';
import v3Fixture from '../fixtures/lockfiles/npm-v3/package-lock.json';

describe('lockfile normalization pipeline', () => {
  const v1 = normalizeV1(v1Fixture as Parameters<typeof normalizeV1>[0]);
  const v2 = normalizeV2(v2Fixture as Parameters<typeof normalizeV2>[0]);
  const v3 = normalizeV3(v3Fixture as Parameters<typeof normalizeV3>[0]);

  function getPackageNames(nodes: ReturnType<typeof normalizeV1>): Set<string> {
    return new Set(nodes.map((n) => n.name));
  }

  it('produces the same set of package names across all versions', () => {
    expect(getPackageNames(v1)).toEqual(getPackageNames(v2));
    expect(getPackageNames(v2)).toEqual(getPackageNames(v3));
  });

  it('produces the same PURL for each package across v1, v2, and v3', () => {
    const names = getPackageNames(v1);
    for (const name of names) {
      const p1 = v1.find((n) => n.name === name)!;
      const p2 = v2.find((n) => n.name === name)!;
      const p3 = v3.find((n) => n.name === name)!;
      expect(p2.purl).toBe(p1.purl);
      expect(p3.purl).toBe(p1.purl);
    }
  });

  it('all PackageNode objects are frozen', () => {
    for (const nodes of [v1, v2, v3]) {
      for (const node of nodes) {
        expect(Object.isFrozen(node), `${node.name} should be frozen`).toBe(true);
      }
    }
  });

  it('no PackageNode has an undefined or empty reasonCode', () => {
    for (const nodes of [v1, v2, v3]) {
      for (const node of nodes) {
        expect(
          node.reasonCode != null && node.reasonCode.length > 0,
          `${node.name} should have a valid reasonCode`
        ).toBe(true);
      }
    }
  });

  it('parse() dispatches correctly and returns equivalent results', () => {
    const parsedV1 = parse(v1Fixture);
    const parsedV2 = parse(v2Fixture);
    const parsedV3 = parse(v3Fixture);

    expect(parsedV1.length).toBe(parsedV2.length);
    expect(parsedV2.length).toBe(parsedV3.length);

    const p1Names = parsedV1.map((n) => n.name).sort();
    const p2Names = parsedV2.map((n) => n.name).sort();
    const p3Names = parsedV3.map((n) => n.name).sort();
    expect(p1Names).toEqual(p2Names);
    expect(p2Names).toEqual(p3Names);
  });
});