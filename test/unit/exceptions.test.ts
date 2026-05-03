/**
 * Unit tests for the exception management module.
 *
 * All fixtures are constructed inline — no file I/O, no OSV calls.
 * Determinism contract: no test calls Date.now() or new Date().
 * All time-dependent behaviour is driven by injected `now: Date`.
 */

import { describe, it, expect } from 'vitest';
import { ReasonCode as R, type Component, type ComponentType, type ComponentScope } from '../../src/core/sbom/cyclonedx/model.js';
import { isExceptionExpired, isExceptionValid, applyExceptions } from '../../src/core/policy/exceptions.js';
import type { Exception } from '../../src/core/policy/exceptions.js';

function makeNode(
  overrides: Partial<Component> & { name: string; version: string }
): Component {
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
    ...overrides,
  };
}

function makeException(overrides: Partial<Exception> & {
  id: string;
  purl: string;
  reasonCode: R;
}): Exception {
  return {
    id: overrides.id,
    purl: overrides.purl,
    reasonCode: overrides.reasonCode,
    reason: overrides.reason ?? 'This is a valid exception reason string.',
    expires_at: overrides.expires_at ?? '2099-12-31T23:59:59.000Z',
    approved_by: overrides.approved_by ?? 'security-team',
  };
}

describe('isExceptionExpired', () => {
  it('returns true when expires_at is in the past (pre-set epoch)', () => {
    const exc = makeException({
      id: 'exc-1',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: '2020-01-01T00:00:00.000Z',
    });
    const now = new Date('2024-06-15T12:00:00.000Z');
    expect(isExceptionExpired(exc, now)).toBe(true);
  });

  it('returns false when expires_at is in the future', () => {
    const exc = makeException({
      id: 'exc-2',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: '2099-12-31T23:59:59.000Z',
    });
    const now = new Date('2024-06-15T12:00:00.000Z');
    expect(isExceptionExpired(exc, now)).toBe(false);
  });

  it('returns true when expires_at equals now (boundary: at expiry)', () => {
    const fixed = '2024-06-15T12:00:00.000Z';
    const exc = makeException({
      id: 'exc-3',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: fixed,
    });
    const now = new Date(fixed);
    expect(isExceptionExpired(exc, now)).toBe(true);
  });

  it('returns true when expires_at has invalid ISO string', () => {
    const exc = makeException({
      id: 'exc-4',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: 'not-a-date',
    });
    const now = new Date('2024-06-15T12:00:00.000Z');
    expect(isExceptionExpired(exc, now)).toBe(true);
  });
});

describe('isExceptionValid', () => {
  it('returns true for a fully valid exception', () => {
    const exc = makeException({
      id: 'exc-5',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
      reason: 'This is a fully valid reason for exception acceptance.',
      expires_at: '2025-12-31T23:59:59.000Z',
      approved_by: 'security-team',
    });
    expect(isExceptionValid(exc)).toBe(true);
  });

  it('returns false when reason is less than 20 characters', () => {
    const exc = makeException({
      id: 'exc-6',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
      reason: 'Too short',
      expires_at: '2025-12-31T23:59:59.000Z',
      approved_by: 'security-team',
    });
    expect(isExceptionValid(exc)).toBe(false);
  });

  it('returns false when approved_by is empty', () => {
    const exc = makeException({
      id: 'exc-7',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
      reason: 'Valid reason for the exception to be applied.',
      expires_at: '2025-12-31T23:59:59.000Z',
      approved_by: '',
    });
    expect(isExceptionValid(exc)).toBe(false);
  });

  it('returns false when approved_by is whitespace-only', () => {
    const exc = makeException({
      id: 'exc-8',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
      reason: 'Another valid reason for the exception to apply.',
      expires_at: '2025-12-31T23:59:59.000Z',
      approved_by: '   ',
    });
    expect(isExceptionValid(exc)).toBe(false);
  });

  it('returns false when expires_at is not valid ISO 8601', () => {
    const exc = makeException({
      id: 'exc-9',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
      reason: 'One more valid reason for this exception.',
      expires_at: 'yyyy-mm-dd',
      approved_by: 'security-team',
    });
    expect(isExceptionValid(exc)).toBe(false);
  });
});

describe('applyExceptions', () => {
  const NOW = new Date('2024-06-15T12:00:00.000Z');
  const TOMORROW = '2024-06-16T12:00:00.000Z';
  const YESTERDAY = '2024-06-14T12:00:00.000Z';

  it('active exception: matching purl + reasonCode → node gets EXEMPTED', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    const exc = makeException({
      id: 'exc-active',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const result = applyExceptions([node], [exc], NOW);

    expect(result[0].reasonCode).toBe(R.EXEMPTED);
    expect(result[0].purl).toBe(node.purl);
  });

  it('expired exception: expires_at = yesterday → node keeps original reasonCode', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    const exc = makeException({
      id: 'exc-expired',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: YESTERDAY,
    });

    const result = applyExceptions([node], [exc], NOW);

    expect(result[0].reasonCode).toBe(R.TRANSITIVE_NO_EXPLOIT);
    expect(result[0].reasonCode).not.toBe(R.EXEMPTED);
  });

  it('mismatched purl: exception purl ≠ node purl → node unchanged', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    const exc = makeException({
      id: 'exc-wrong-purl',
      purl: 'pkg:npm/express@4.18.2',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const result = applyExceptions([node], [exc], NOW);

    expect(result[0].reasonCode).toBe(R.TRANSITIVE_NO_EXPLOIT);
    expect(result[0].reasonCode).not.toBe(R.EXEMPTED);
  });

  it('mismatched reasonCode: exception reasonCode ≠ node reasonCode → node unchanged', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
    });
    const exc = makeException({
      id: 'exc-wrong-code',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const result = applyExceptions([node], [exc], NOW);

    expect(result[0].reasonCode).toBe(R.DIRECT_UNPATCHED);
    expect(result[0].reasonCode).not.toBe(R.EXEMPTED);
  });

  it('no exceptions → node unchanged', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.DIRECT_UNPATCHED,
    });

    const result = applyExceptions([node], [], NOW);

    expect(result[0].reasonCode).toBe(R.DIRECT_UNPATCHED);
  });

  it('multiple nodes: only matching one is exempted', () => {
    const [nodeLodash, nodeExpress] = [
      makeNode({ name: 'lodash', version: '4.17.21', reasonCode: R.TRANSITIVE_NO_EXPLOIT }),
      makeNode({ name: 'express', version: '4.18.2', reasonCode: R.TRANSITIVE_NO_EXPLOIT }),
    ];
    const exc = makeException({
      id: 'exc-lodash-only',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const result = applyExceptions([nodeLodash, nodeExpress], [exc], NOW);

    expect(result[0].reasonCode).toBe(R.EXEMPTED);
    expect(result[1].reasonCode).toBe(R.TRANSITIVE_NO_EXPLOIT);
  });

  it('determinism: same inputs called twice → identical output', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    const exc = makeException({
      id: 'exc-deterministic',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const first = applyExceptions([node], [exc], NOW);
    const second = applyExceptions([node], [exc], NOW);

    expect(first[0].reasonCode).toBe(second[0].reasonCode);
    expect(first[0].purl).toBe(second[0].purl);
    expect(first[0]).toStrictEqual(second[0]);
  });

  it('input nodes are never mutated', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    const exc = makeException({
      id: 'exc-no-mutate',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const originalReasonCode = node.reasonCode;
    const result = applyExceptions([node], [exc], NOW);

    expect(node.reasonCode).toBe(originalReasonCode);
    expect(node).not.toBe(result[0]);
  });

  it('first matching exception wins (only exception per node)', () => {
    const node = makeNode({
      name: 'lodash',
      version: '4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
    });
    // Two exceptions — both would match, but first should win
    const exc1 = makeException({
      id: 'exc-first',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });
    const exc2 = makeException({
      id: 'exc-second',
      purl: 'pkg:npm/lodash@4.17.21',
      reasonCode: R.TRANSITIVE_NO_EXPLOIT,
      expires_at: TOMORROW,
    });

    const result = applyExceptions([node], [exc1, exc2], NOW);

    // Exactly one exception is applied (first match), result is deterministic
    expect(result[0].reasonCode).toBe(R.EXEMPTED);
  });
});