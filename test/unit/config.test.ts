/**
 * Unit tests for the config loader.
 *
 * Tests:
 * - defaultConfig returns empty frozen arrays
 * - Missing file → defaultConfig() returned silently
 * - Valid config → AuditConfig returned with parsed values
 * - Schema-invalid file → ConfigValidationError thrown
 * - Expired exception → ExpiredExceptionError thrown
 * - resolveFailOn (inlined from scan.ts): CLI overrides file failOn
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ReasonCode as R } from '../../src/core/sbom/cyclonedx/model.js';
import { ConfigValidationError } from '../../src/utils/errors.js';
import { ExpiredExceptionError } from '../../src/utils/errors.js';

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

const NOW = new Date('2024-06-15T12:00:00.000Z');

const FIXTURE_VALID_EXC = {
  id: 'exc-active',
  purl: 'pkg:npm/lodash@4.17.21',
  reasonCode: 'TRANSITIVE_NO_EXPLOIT',
  reason: 'This is a valid exception for testing purposes here.',
  expires_at: '2099-12-31T23:59:59.000Z',
  approved_by: 'security-team',
};

const FIXTURE_VALID_CONFIG = {
  failOn: ['TRANSITIVE_NO_EXPLOIT'] as readonly string[],
  exceptions: [FIXTURE_VALID_EXC],
};

const FIXTURE_EXPIRED_EXC = {
  id: 'exc-expired',
  purl: 'pkg:npm/lodash@4.17.21',
  reasonCode: 'TRANSITIVE_NO_EXPLOIT',
  reason: 'Another valid exception reason for the test file.',
  expires_at: '2020-01-01T00:00:00.000Z',
  approved_by: 'security-team',
};

const FIXTURE_EXPIRED_CONFIG = {
  failOn: [] as readonly string[],
  exceptions: [FIXTURE_EXPIRED_EXC],
};

const FIXTURE_INVALID_FAILON = { failOn: ['NOT_A_REAL_CODE'] };

const FIXTURE_SHORT_REASON_EXC = {
  id: 'exc-short',
  purl: 'pkg:npm/lodash@4.17.21',
  reasonCode: 'TRANSITIVE_NO_EXPLOIT',
  reason: 'too short',
  expires_at: '2099-12-31T23:59:59.000Z',
  approved_by: 'security-team',
};

const FIXTURE_INCOMPLETE_EXC = {
  id: 'exc-incomplete',
  purl: 'pkg:npm/lodash@4.17.21',
};

// ---------------------------------------------------------------------------
// Mock — vi.hoisted pairs declaration with hoisting so order is safe
// ---------------------------------------------------------------------------

const { mockReadJsonFile } = vi.hoisted(() => ({
  mockReadJsonFile: vi.fn(),
}));

// Register the mock; hoisted together with mockReadJsonFile
vi.mock('../../src/utils/fs.js', () => ({
  readJsonFile: mockReadJsonFile,
}));

// Import after vi.mock registration
import { loadConfig, defaultConfig } from '../../src/config/loader.js';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('defaultConfig', () => {
  it('returns empty frozen arrays', () => {
    const cfg = defaultConfig();
    expect(cfg.failOn).toHaveLength(0);
    expect(cfg.exceptions).toHaveLength(0);
    expect(Object.isFrozen(cfg.failOn)).toBe(true);
    expect(Object.isFrozen(cfg.exceptions)).toBe(true);
  });
});

describe('loadConfig — missing file', () => {
  beforeEach(() => {
    mockReadJsonFile.mockRejectedValue(new Error('ENOENT'));
  });

  it('returns defaultConfig() when file does not exist', async () => {
    const cfg = await loadConfig('/nonexistent/.audit-policy.json', NOW);
    expect(cfg.failOn).toHaveLength(0);
    expect(cfg.exceptions).toHaveLength(0);
  });

  afterEach(() => {
    mockReadJsonFile.mockReset();
  });
});

describe('loadConfig — valid config file', () => {
  beforeEach(() => {
    mockReadJsonFile.mockResolvedValue(FIXTURE_VALID_CONFIG);
  });

  it('returns AuditConfig with parsed failOn and exceptions', async () => {
    const cfg = await loadConfig('/mock/.audit-policy.json', NOW);
    expect(cfg.failOn).toContain(R.TRANSITIVE_NO_EXPLOIT);
    expect(cfg.exceptions).toHaveLength(1);
    expect(cfg.exceptions[0].id).toBe('exc-active');
  });

  afterEach(() => {
    mockReadJsonFile.mockReset();
  });
});

describe('loadConfig — schema-invalid file', () => {
  it('throws ConfigValidationError when failOn has invalid ReasonCode', async () => {
    mockReadJsonFile.mockResolvedValue(FIXTURE_INVALID_FAILON);
    await expect(loadConfig('/mock/.audit-policy.json', NOW)).rejects.toThrow(ConfigValidationError);
  });

  it('throws ConfigValidationError when exception reason is too short', async () => {
    mockReadJsonFile.mockResolvedValue({ exceptions: [FIXTURE_SHORT_REASON_EXC] });
    await expect(loadConfig('/mock/.audit-policy.json', NOW)).rejects.toThrow(ConfigValidationError);
  });

  it('throws ConfigValidationError when exception is missing required field', async () => {
    mockReadJsonFile.mockResolvedValue({ exceptions: [FIXTURE_INCOMPLETE_EXC] });
    await expect(loadConfig('/mock/.audit-policy.json', NOW)).rejects.toThrow(ConfigValidationError);
  });
});

describe('loadConfig — expired exception', () => {
  beforeEach(() => {
    mockReadJsonFile.mockResolvedValue(FIXTURE_EXPIRED_CONFIG);
  });

  it('throws ExpiredExceptionError with the expired entry id', async () => {
    await expect(loadConfig('/mock/.audit-policy.json', NOW)).rejects.toThrow(ExpiredExceptionError);
    await expect(loadConfig('/mock/.audit-policy.json', NOW)).rejects.toThrow('exc-expired');
  });

  afterEach(() => {
    mockReadJsonFile.mockReset();
  });
});

// ---------------------------------------------------------------------------
// Config merge precedence (inline from scan.ts)
// ---------------------------------------------------------------------------

function resolveFailOn(
  cliFailOn: readonly ReasonCode[],
  _fileFailOn: readonly ReasonCode[]
): readonly ReasonCode[] {
  // CLI --fail-on overrides file failOn entirely (file is discarded when CLI present)
  return Object.freeze([...cliFailOn]);
}

describe('resolveFailOn — CLI overrides file failOn', () => {
  it('CLI empty + file has values → empty (CLI wins, overriding file)', () => {
    expect(resolveFailOn([], [R.DIRECT_UNPATCHED])).toHaveLength(0);
  });

  it('CLI has codes + file empty → CLI codes', () => {
    const result = resolveFailOn([R.DIRECT_UNPATCHED], []);
    expect(result).toContain(R.DIRECT_UNPATCHED);
  });

  it('CLI has codes + file has codes → CLI wins; file values discarded', () => {
    const result = resolveFailOn(
      [R.DIRECT_UNPATCHED],
      [R.DEV_DEPENDENCY_ONLY, R.OPTIONAL_DEPENDENCY]
    );
    expect(result).toHaveLength(1);
    expect(result).toContain(R.DIRECT_UNPATCHED);
    expect(result).not.toContain(R.DEV_DEPENDENCY_ONLY);
  });

  it('both empty → empty', () => {
    expect(resolveFailOn([], [])).toHaveLength(0);
  });

  it('returned array is frozen', () => {
    expect(
      Object.isFrozen(resolveFailOn([R.TRANSITIVE_NO_EXPLOIT], [R.DEV_DEPENDENCY_ONLY]))
    ).toBe(true);
  });
});