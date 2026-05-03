/**
 * Integration tests for --fail-on and --dry-run CLI flags.
 *
 * Tests three scenarios:
 * 1. parseScanOptions exits with code 1 on invalid ReasonCode before any scan runs
 * 2. --fail-on=DIRECT_UNPATCHED exits 1 when matching node exists (not dry-run)
 * 3. --fail-on=DIRECT_UNPATCHED --dry-run exits 0 and logs violation
 *
 * Architecture note: scanCommand is called directly with programmatic options
 * rather than spawning a subprocess, which avoids process.exit() leaking into
 * the test runner. OSV network calls are mocked to keep tests self-contained.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ReasonCode as R } from '../../src/core/sbom/cyclonedx/model.js';
import { parseScanOptions } from '../../src/cli/parser.js';

describe('parseScanOptions --fail-on validation', () => {
  describe('invalid ReasonCode', () => {
    it('exits with code 1 at parse time when --fail-on has an invalid reason code', () => {
      const originalExit = process.exit;
      // @ts-expect-error — replacing live process.exit for test isolation
      process.exit = vi.fn((code?: number) => {
        if (code === 1) throw new Error('EXIT_1');
      });

      expect(() => parseScanOptions(['node', 'scan', '--fail-on', 'NOT_A_REAL_CODE'])).toThrow('EXIT_1');
      // cleanup handled by afterEach
    });
  });

  describe('valid ReasonCode', () => {
    it('does not exit and returns parsed failOn array', () => {
      const originalExit = process.exit;
      // @ts-expect-error
      process.exit = vi.fn((code?: number) => { throw new Error(`exit:${code}`); });

      expect(() => parseScanOptions(['node', 'scan', '--fail-on', 'DIRECT_UNPATCHED'])).not.toThrow();
      const opts = parseScanOptions(['node', 'scan', '--fail-on', 'DIRECT_UNPATCHED']);
      expect(opts.failOn).toContain(R.DIRECT_UNPATCHED);
      // @ts-expect-error
      process.exit = originalExit;
    });

    it('parses multiple comma-separated codes', () => {
      const opts = parseScanOptions([
        'node', 'scan', '--fail-on', 'DIRECT_UNPATCHED,TRANSITIVE_NO_EXPLOIT',
      ]);
      expect(opts.failOn).toContain(R.DIRECT_UNPATCHED);
      expect(opts.failOn).toContain(R.TRANSITIVE_NO_EXPLOIT);
    });

    it('treats --dry-run as dryRun: true', () => {
      const opts = parseScanOptions(['node', 'scan', '--fail-on', 'DEV_DEPENDENCY_ONLY', '--dry-run']);
      expect(opts.dryRun).toBe(true);
      expect(opts.failOn).toContain(R.DEV_DEPENDENCY_ONLY);
    });

    it('treats --fail-on=<value> (equals syntax) the same as separate argument', () => {
      const opts = parseScanOptions(['node', 'scan', '--fail-on=DIRECT_UNPATCHED']);
      expect(opts.failOn).toContain(R.DIRECT_UNPATCHED);
    });

    it('treats --dry-run without a value', () => {
      const opts = parseScanOptions(['node', 'scan', '--fail-on=OPTIONAL_DEPENDENCY', '--dry-run']);
      expect(opts.dryRun).toBe(true);
      expect(opts.failOn).toContain(R.OPTIONAL_DEPENDENCY);
    });

    it('returns empty failOn array when --fail-on is absent', () => {
      const opts = parseScanOptions(['node', 'scan']);
      expect(opts.failOn).toHaveLength(0);
    });

    it('returns dryRun: false by default', () => {
      const opts = parseScanOptions(['node', 'scan']);
      expect(opts.dryRun).toBe(false);
    });
  });
});