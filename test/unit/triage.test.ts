/**
 * Unit tests for the triage engine and default rules.
 *
 * All fixtures are constructed inline — no file I/O, no OSV calls.
 */

import { describe, it, expect } from 'vitest';
import { ReasonCode as R, type Component, type ComponentType, type ComponentScope } from '../../src/core/sbom/cyclonedx/model.js';
import { applyTriage } from '../../src/core/triage/engine.js';
import { DEFAULT_RULES } from '../../src/core/triage/rules/default-rules.js';
import type { Rule } from '../../src/core/triage/rules/default-rules.js';
import { UnmatchedTriageRuleError } from '../../src/utils/errors.js';

/**
 * Build a minimal PackageNode fixture for testing.
 * All unspecified fields get sensible defaults so tests focus on
 * the properties that determine the rule match.
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

describe('DEFAULT_RULES', () => {
  it('rule 1: no vuln data → NO_KNOWN_VULNERABILITY', () => {
    const node = makeNode({ name: 'lodash', version: '4.17.21', vulnerabilities: [] });
    const result = applyTriage([node], DEFAULT_RULES);
    expect(result[0].reasonCode).toBe(R.NO_KNOWN_VULNERABILITY);
  });

  it('rule 2: dev dependency (scope excluded) with vulns → DEV_DEPENDENCY_ONLY', () => {
    const node = makeNode({
      name: 'vitest',
      version: '1.0.0',
      scope: 'excluded' as ComponentScope,
      vulnerabilities: [{ id: 'CVE-123', ratings: [], affects: [] }],
    });
    const result = applyTriage([node], DEFAULT_RULES);
    expect(result[0].reasonCode).toBe(R.DEV_DEPENDENCY_ONLY);
  });

  it('rule 3: optional dependency with vulns → OPTIONAL_DEPENDENCY', () => {
    const node = makeNode({
      name: 'fsevents',
      version: '2.3.0',
      scope: 'optional' as ComponentScope,
      vulnerabilities: [{ id: 'CVE-456', ratings: [], affects: [] }],
    });
    const result = applyTriage([node], DEFAULT_RULES);
    expect(result[0].reasonCode).toBe(R.OPTIONAL_DEPENDENCY);
  });

  it('rule 4: transitive (isDirect false) with vulns → TRANSITIVE_NO_EXPLOIT', () => {
    const node = makeNode({
      name: 'transitive-pkg',
      version: '1.0.0',
      scope: 'required' as ComponentScope,
      isDirect: false,
      vulnerabilities: [{ id: 'CVE-789', ratings: [], affects: [] }],
    });
    const result = applyTriage([node], DEFAULT_RULES);
    expect(result[0].reasonCode).toBe(R.TRANSITIVE_NO_EXPLOIT);
  });

  it('rule 5: direct (isDirect true) with vulns → DIRECT_UNPATCHED', () => {
    const node = makeNode({
      name: 'direct-pkg',
      version: '2.0.0',
      scope: 'required' as ComponentScope,
      isDirect: true,
      vulnerabilities: [{ id: 'CVE-101', ratings: [], affects: [] }],
    });
    const result = applyTriage([node], DEFAULT_RULES);
    expect(result[0].reasonCode).toBe(R.DIRECT_UNPATCHED);
  });

  it('no matching rule throws UnmatchedTriageRuleError', () => {
    const node = makeNode({ name: 'lonely', version: '1.0.0' });
    expect(() => applyTriage([node], [])).toThrow(UnmatchedTriageRuleError);
  });

  it('error message includes the unmatched package PURL', () => {
    const node = makeNode({ name: 'lonely', version: '1.0.0' });
    expect(() => applyTriage([node], [])).toThrow('pkg:npm/lonely@1.0.0');
  });

  it('input nodes are never mutated', () => {
    const node = makeNode({ name: 'frozen', version: '1.0.0', reasonCode: R.NO_KNOWN_VULNERABILITY });
    const originalReasonCode = node.reasonCode;
    const result = applyTriage([node], DEFAULT_RULES);
    expect(node).not.toBe(result[0]); // different object reference
    expect(node.reasonCode).toBe(originalReasonCode); // input unchanged
  });

  it('DEFAULT_RULES array is frozen', () => {
    expect(Object.isFrozen(DEFAULT_RULES)).toBe(true);
  });
});