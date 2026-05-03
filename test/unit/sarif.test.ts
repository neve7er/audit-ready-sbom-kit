/**
 * Unit tests for the SARIF 2.1.0 output adapter.
 *
 * Verifies buildSarif() output:
 * - reasonCode → SARIF level mapping
 * - NO_KNOWN_VULNERABILITY omission from results
 * - Tool driver metadata
 * - Determinism (byte-identical output for same input)
 * - ajv schema validation against schemas/sarif-schema-2.1.0.json
 */

import { describe, it, expect } from 'vitest';
import { createRequire } from 'module';
import { ReasonCode as R, type Component } from '../../src/core/sbom/cyclonedx/model.js';
import { buildSarif, TOOL_DRIVER_VERSION } from '../../src/adapters/output/sarif.js';

const require = createRequire(import.meta.url);

// =========================================================================
// Fixture helper
// =========================================================================

function makeNode(
  name: string,
  version: string,
  reasonCode: R,
  properties?: Partial<Component>
): Component {
  const purl = `pkg:npm/${name}@${version}`;
  return {
    type: 'library',
    name,
    version,
    purl,
    'bom-ref': purl,
    reasonCode,
    vulnerabilities: [],
    ...properties,
  } as Component;
}

/** Shortcut for doc.runs[0].results — the only.results location in SarifDocument */
function results(doc: ReturnType<typeof buildSarif>) {
  return doc.runs[0].results;
}

// =========================================================================
// Test suites
// =========================================================================

describe('buildSarif', () => {
  it('DIRECT_UNPATCHED node produces result entry with level: "error"', () => {
    const node = makeNode('lodash', '4.17.21', R.DIRECT_UNPATCHED);
    const doc = buildSarif([node]);

    expect(results(doc)).toHaveLength(1);
    expect(results(doc)[0].ruleId).toBe(R.DIRECT_UNPATCHED);
    expect(results(doc)[0].level).toBe('error');
    expect(results(doc)[0].message.text).toBeTruthy();
    expect(results(doc)[0].locations).toHaveLength(1);
    expect(results(doc)[0].locations[0].physicalLocation.artifactLocation.uri).toBe(node.purl);
  });

  it('NO_KNOWN_VULNERABILITY node produces zero result entries', () => {
    const node = makeNode('safe-lib', '1.0.0', R.NO_KNOWN_VULNERABILITY);
    const doc = buildSarif([node]);

    expect(results(doc)).toHaveLength(0);
  });

  it('OPTIONAL_DEPENDENCY node produces level: "note"', () => {
    const node = makeNode('fsevents', '2.3.0', R.OPTIONAL_DEPENDENCY);
    const doc = buildSarif([node]);

    expect(results(doc)).toHaveLength(1);
    expect(results(doc)[0].level).toBe('note');
    expect(results(doc)[0].ruleId).toBe(R.OPTIONAL_DEPENDENCY);
  });

  it('DEV_DEPENDENCY_ONLY node produces level: "note"', () => {
    const node = makeNode('vitest', '1.0.0', R.DEV_DEPENDENCY_ONLY);
    const doc = buildSarif([node]);

    expect(results(doc)).toHaveLength(1);
    expect(results(doc)[0].level).toBe('note');
  });

  it('TRANSITIVE_NO_EXPLOIT node produces level: "warning"', () => {
    const node = makeNode('transitive-pkg', '1.0.0', R.TRANSITIVE_NO_EXPLOIT);
    const doc = buildSarif([node]);

    expect(results(doc)).toHaveLength(1);
    expect(results(doc)[0].level).toBe('warning');
  });

  it('mixed nodes — one per ReasonCode — correct level per mapping table', () => {
    const nodes = [
      makeNode('direct', '1.0.0', R.DIRECT_UNPATCHED),
      makeNode('transitive', '1.0.0', R.TRANSITIVE_NO_EXPLOIT),
      makeNode('dev', '1.0.0', R.DEV_DEPENDENCY_ONLY),
      makeNode('optional', '1.0.0', R.OPTIONAL_DEPENDENCY),
      makeNode('safe', '1.0.0', R.NO_KNOWN_VULNERABILITY),
    ];
    const doc = buildSarif(nodes);

    // 4 results (NO_KNOWN_VULNERABILITY is omitted)
    expect(results(doc)).toHaveLength(4);
    const r = results(doc);
    const byCode = Object.fromEntries(r.map((result) => [result.ruleId, result.level]));
    expect(byCode[R.DIRECT_UNPATCHED]).toBe('error');
    expect(byCode[R.TRANSITIVE_NO_EXPLOIT]).toBe('warning');
    expect(byCode[R.DEV_DEPENDENCY_ONLY]).toBe('note');
    expect(byCode[R.OPTIONAL_DEPENDENCY]).toBe('note');
  });

  it('tool driver has correct metadata', () => {
    const node = makeNode('x', '1.0.0', R.DIRECT_UNPATCHED);
    const doc = buildSarif([node]);

    expect(doc.runs[0].tool.driver.name).toBe('audit-ready-sbom-kit');
    expect(doc.runs[0].tool.driver.version).toBe(TOOL_DRIVER_VERSION);
    expect(doc.runs[0].tool.driver.informationUri).toBeTruthy();
  });

  it('tool rules array contains one entry per unique reasonCode', () => {
    const nodes = [
      makeNode('a', '1.0.0', R.DIRECT_UNPATCHED),
      makeNode('b', '1.0.0', R.DIRECT_UNPATCHED), // duplicate code
      makeNode('c', '1.0.0', R.TRANSITIVE_NO_EXPLOIT),
    ];
    const doc = buildSarif(nodes);

    const ruleIds = doc.runs[0].tool.driver.rules.map((r) => r.id).sort();
    expect(ruleIds).toEqual([R.DIRECT_UNPATCHED, R.TRANSITIVE_NO_EXPLOIT].sort());
  });

  it('empty components array produces empty results', () => {
    const doc = buildSarif([]);
    expect(results(doc)).toHaveLength(0);
    expect(doc.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('result locations use purl as artifactLocation.uri with ROOT baseId', () => {
    const node = makeNode('my-package', '2.0.0', R.TRANSITIVE_NO_EXPLOIT);
    const doc = buildSarif([node]);
    const r = results(doc);
    const loc = r[0].locations[0].physicalLocation.artifactLocation;

    expect(loc.uri).toBe('pkg:npm/my-package@2.0.0');
    expect(loc.uriBaseId).toBe('ROOT');
  });

  it('determinism — calling buildSarif five times with identical input produces byte-identical output', () => {
    const nodes = [
      makeNode('pkg-a', '1.0.0', R.DIRECT_UNPATCHED),
      makeNode('pkg-b', '2.0.0', R.TRANSITIVE_NO_EXPLOIT),
    ];

    const doc1 = buildSarif(nodes);
    const json1 = JSON.stringify(doc1);

    for (let i = 0; i < 4; i++) {
      expect(JSON.stringify(buildSarif(nodes))).toBe(json1);
    }
  });

  it('single-node output passes ajv schema validation', async () => {
    const Ajv = require('ajv');
    const node = makeNode('test-lib', '3.1.4', R.DIRECT_UNPATCHED);
    const doc = buildSarif([node]);
    // @ts-ignore
    const AjvClass: new (o: object) => object = Ajv;
    // @ts-ignore
    const ajv = new AjvClass({ strict: false });
    const schema = require('../../schemas/sarif-schema-2.1.0.json');
    const validate = ajv.compile(schema);
    expect(validate(doc), JSON.stringify(validate.errors ?? null)).toBe(true);
  });

  it('full mixed-output passes ajv schema validation', async () => {
    const Ajv = require('ajv');
    const nodes = [
      makeNode('a', '1.0.0', R.DIRECT_UNPATCHED),
      makeNode('b', '2.0.0', R.TRANSITIVE_NO_EXPLOIT),
      makeNode('c', '3.0.0', R.DEV_DEPENDENCY_ONLY),
      makeNode('d', '4.0.0', R.OPTIONAL_DEPENDENCY),
      makeNode('e', '5.0.0', R.NO_KNOWN_VULNERABILITY),
    ];
    const doc = buildSarif(nodes);
    // @ts-ignore
    const AjvClass: new (o: object) => object = Ajv;
    // @ts-ignore
    const ajv = new AjvClass({ strict: false });
    const schema = require('../../schemas/sarif-schema-2.1.0.json');
    const validate = ajv.compile(schema);
    expect(validate(doc), JSON.stringify(validate.errors ?? null)).toBe(true);
  });
});