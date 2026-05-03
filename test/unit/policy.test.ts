/**
 * Unit tests for matchesFailPolicy.
 *
 * Determinism contract: this test suite asserts that matchesFailPolicy
 * contains zero references to Date, Date.now(), Math.random(), or env vars.
 */

import { describe, it, expect } from 'vitest';
import { ReasonCode as R } from '../../src/core/sbom/cyclonedx/model.js';
import { matchesFailPolicy } from '../../src/core/triage/engine.js';

/**
 * Build a minimal Component fixture with an explicit reasonCode.
 * reasonCode is set directly to skip the applyTriage step.
 */
function makeComponent(
  name: string,
  version: string,
  reasonCode: R
): import('../../src/core/sbom/cyclonedx/model.js').Component {
  const purl = `pkg:npm/${name}@${version}`;
  return {
    type: 'library',
    name,
    version,
    purl,
    'bom-ref': purl,
    reasonCode,
    vulnerabilities: [],
  };
}

describe('matchesFailPolicy', () => {
  describe('node matches fail code', () => {
    it('returns true when node.reasonCode equals the single fail code', () => {
      const node = makeComponent('lodash', '4.17.21', R.DIRECT_UNPATCHED);
      expect(matchesFailPolicy(node, [R.DIRECT_UNPATCHED])).toBe(true);
    });
  });

  describe('node does not match', () => {
    it('returns false when reasonCode not in fail codes', () => {
      const node = makeComponent('vitest', '1.0.0', R.DEV_DEPENDENCY_ONLY);
      expect(matchesFailPolicy(node, [R.DIRECT_UNPATCHED])).toBe(false);
    });
  });

  describe('empty fail codes', () => {
    it('returns false for any node when failOnCodes is empty', () => {
      const nodes = [
        makeComponent('lodash', '4.17.21', R.DIRECT_UNPATCHED),
        makeComponent('vitest', '1.0.0', R.DEV_DEPENDENCY_ONLY),
        makeComponent('fsevents', '2.3.0', R.OPTIONAL_DEPENDENCY),
        makeComponent('x', '1.0.0', R.NO_KNOWN_VULNERABILITY),
      ];
      for (const node of nodes) {
        expect(matchesFailPolicy(node, [])).toBe(false);
      }
    });
  });

  describe('multiple codes, one matches', () => {
    it('returns true when reasonCode matches any code in the array', () => {
      const node = makeComponent('transitive-pkg', '1.0.0', R.TRANSITIVE_NO_EXPLOIT);
      expect(
        matchesFailPolicy(node, [R.DIRECT_UNPATCHED, R.TRANSITIVE_NO_EXPLOIT])
      ).toBe(true);
    });

    it('returns false when reasonCode matches neither code', () => {
      const node = makeComponent('optional-pkg', '2.0.0', R.OPTIONAL_DEPENDENCY);
      expect(
        matchesFailPolicy(node, [R.DIRECT_UNPATCHED, R.TRANSITIVE_NO_EXPLOIT])
      ).toBe(false);
    });
  });

  describe('determinism check', () => {
    it('returns identical result for identical inputs across multiple calls', () => {
      const node = makeComponent('pkg', '1.0.0', R.DIRECT_UNPATCHED);
      const failOnCodes: readonly R[] = [R.DIRECT_UNPATCHED, R.TRANSITIVE_NO_EXPLOIT];

      const results = Array.from({ length: 100 }, () =>
        matchesFailPolicy(node, failOnCodes)
      );

      expect(results.every((r) => r === true)).toBe(true);
    });

    it('never returns true when failOnCodes is empty — verified 50 times', () => {
      const node = makeComponent('any', '1.0.0', R.NO_KNOWN_VULNERABILITY);
      for (let i = 0; i < 50; i++) {
        expect(matchesFailPolicy(node, [])).toBe(false);
      }
    });

    it('contains no references to Date, Date.now(), Math.random(), process.env in source', async () => {
      // This is a static-source check: import the source and scan for banned tokens.
      // This does not run the function — it reads the source text.
      const fs = await import('fs');
      const sourcePath = new URL('../../src/core/triage/engine.ts', import.meta.url);
      const source = fs.readFileSync(sourcePath, 'utf-8');

      // Extract just the matchesFailPolicy function body
      const fnStart = source.indexOf('export function matchesFailPolicy');
      const fnEnd = source.indexOf('\n}\n\n// =', fnStart);
      const fnBody = source.slice(fnStart, fnEnd);

      const banned = ['Date', 'Date.now()', 'Math.random()', 'process.env'];
      const found = banned.filter((token) => fnBody.includes(token));

      expect(found, `matchesFailPolicy contains banned non-deterministic references: ${found.join(', ')}`).toHaveLength(0);
    });
  });
});