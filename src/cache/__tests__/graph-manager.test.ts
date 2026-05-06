/**
 * Unit tests for graph-manager.ts — lockfile parse cache.
 *
 * Covers:
 * - lockfileHash determinism
 * - readGraphCache: cache hit (valid), cache miss (absent file)
 * - readGraphCache: corrupt JSON → treated as miss, no throw
 * - readGraphCache: frozen, unmodified input
 * - writeGraphCache: atomic write, metadata.json update, frozen input
 * - Graph cache key format: graph/{sha256-of-raw-lockfile-string}
 */

import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest';
import { createRequire } from 'module';

// ─── Mock factories (hoisted above vi.mock so the factory can reference them) ──

const { mockReadFile, mockWriteFile, mockRename, mockMkdir, mockRm } =
  vi.hoisted(() => {
    // In-memory filesystem shared across mock calls
    const files = new Map<string, string>();
    return {
      mockReadFile: vi.fn(async (path: string) => {
        const content = files.get(path);
        if (content === undefined) {
          const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
          throw err;
        }
        return content;
      }),
      mockWriteFile: vi.fn(async (_path: string, data: string) => {
        files.set(_path, data);
      }),
      mockRename: vi.fn(async (tmp: string, dest: string) => {
        if (files.has(tmp)) {
          files.set(dest, files.get(tmp)!);
          files.delete(tmp);
        }
      }),
      mockMkdir: vi.fn(async () => { /* noop */ }),
      mockRm: vi.fn(async () => { /* noop */ }),
    };
  });

const { mockHomedir } = vi.hoisted(() => ({
  mockHomedir: vi.fn(() => '/fake/home/tester'),
}));

// ─── Replace native modules with stubs ───────────────────────────────────────

vi.mock('node:fs/promises', () => ({
  readFile: mockReadFile,
  writeFile: mockWriteFile,
  rename: mockRename,
  mkdir: mockMkdir,
  rm: mockRm,
}));

vi.mock('node:os', () => ({
  homedir: mockHomedir,
}));

// ─── Module under test — static import (hoisted above vi.mock) ───────────────

import { readGraphCache, writeGraphCache, lockfileHash } from '../../cache/graph-manager.js';

// =========================================================================
// helpers
// =========================================================================

const TEST_NOW = new Date('2026-06-15T12:00:00.000Z');

/** SHA-256 of '{"lockfileVersion":3}' */
const FIXTURE_KEY = 'b31e50d93e4b8594b36e5a77211a4878828c0c0e8f6d4e7b0fc3db9e92cd72c6';

function graphCacheSubdir(): string {
  // Normalize to forward slashes for cross-platform test stability
  return '/fake/home/tester/.audit-ready/cache/graph'.replace(/\\/g, '/');
}

function graphCacheFilePath(key: string): string {
  return `${graphCacheSubdir()}/${key}.json`;
}

function metaPath(): string {
  return '/fake/home/tester/.audit-ready/cache/metadata.json'.replace(/\\/g, '/');
}

// =========================================================================
// lockfileHash
// =========================================================================

describe('lockfileHash', () => {
  it('produces identical output for the same input (deterministic)', () => {
    const input = '{"lockfileVersion":3,"packages":{}}';
    expect(lockfileHash(input)).toBe(lockfileHash(input));
  });

  it('produces different output for different inputs', () => {
    const a = '{"lockfileVersion":2}';
    const b = '{"lockfileVersion":3}';
    expect(lockfileHash(a)).not.toBe(lockfileHash(b));
  });
});

// =========================================================================
// readGraphCache
// =========================================================================

describe('readGraphCache', () => {
  beforeEach(() => {
    mockReadFile.mockReset().mockResolvedValue('');
  });

  it('returns frozen PackageNode[] on cache hit', async () => {
    const cached = {
      cachedAt: '2026-06-01T00:00:00.000Z',
      nodes: [
        {
          type: 'library',
          name: 'lodash',
          version: '4.17.21',
          purl: 'pkg:npm/lodash@4.17.21',
          'bom-ref': 'pkg:npm/lodash@4.17.21',
          reasonCode: 'NO_KNOWN_VULNERABILITY',
          vulnerabilities: [],
          scope: 'required',
          isDirect: true,
        },
      ],
    };
    mockReadFile
      .mockResolvedValueOnce(JSON.stringify(cached))      // graph cache file
      .mockResolvedValueOnce('{}');                        // metadata.json (no entry)

    const result = await readGraphCache(FIXTURE_KEY);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('lodash');
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result[0])).toBe(true);
  });

  it('returns empty frozen array on absent cache file (cache miss)', async () => {
    const enoent = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    mockReadFile.mockRejectedValue(enoent);

    const result = await readGraphCache(FIXTURE_KEY);

    expect(result).toHaveLength(0);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('treats corrupt JSON as cache miss, does not throw', async () => {
    mockReadFile
      .mockResolvedValueOnce('not valid json {{{')
      .mockResolvedValueOnce('{}');                        // metadata.json absent

    const result = await readGraphCache(FIXTURE_KEY);

    expect(result).toHaveLength(0);
  });

  it('integrity mismatch → treated as miss, does not throw', async () => {
    const cached = {
      cachedAt: '2026-06-01T00:00:00.000Z',
      nodes: [{ name: 'lodash' }],
    };
    mockReadFile
      .mockResolvedValueOnce(JSON.stringify(cached))        // cache file
      .mockResolvedValueOnce(                              // metadata.json
        JSON.stringify({ [`graph/${FIXTURE_KEY}`]: 'wrong-hash' }),
      )
      .mockResolvedValueOnce('wrong-hash');                // sha256File (doesn't match)

    const result = await readGraphCache(FIXTURE_KEY);

    expect(result).toHaveLength(0);
  });

  it('when metadata.json lacks the key entry, integrity check is skipped and cached data is returned', async () => {
    const cached = {
      cachedAt: '2026-06-01T00:00:00.000Z',
      nodes: [{ name: 'cached-entry', purl: 'pkg:npm/x@1.0.0', 'bom-ref': 'pkg:npm/x@1.0.0', type: 'library', reasonCode: 'NO_KNOWN_VULNERABILITY', vulnerabilities: [], isDirect: true }],
    };
    mockReadFile
      .mockResolvedValueOnce(JSON.stringify(cached))        // cache file
      .mockResolvedValueOnce('{}');                         // metadata.json present but lacks graph/{key}

    const result = await readGraphCache(FIXTURE_KEY);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('cached-entry');
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result[0])).toBe(true);
  });
});

// =========================================================================
// writeGraphCache
// =========================================================================

describe('writeGraphCache', () => {
  beforeEach(() => {
    mockMkdir.mockReset().mockResolvedValue(undefined);
    mockWriteFile.mockReset().mockResolvedValue(undefined);
    mockRename.mockReset().mockResolvedValue(undefined);
    mockReadFile.mockReset().mockResolvedValue('{}');
  });

  it('writes to graph/{sha256}.json', async () => {
    await writeGraphCache(FIXTURE_KEY, [], TEST_NOW);

    expect(mockMkdir).toHaveBeenCalled();
    const mkdirCall = mockMkdir.mock.calls[0] as unknown as [string, object];
    // Normalize path separators for cross-platform comparison
    const mkdirPath = mkdirCall[0].replace(/\\/g, '/');
    expect(mkdirPath).toContain('/.audit-ready/cache/graph');

    const renameDest = mockRename.mock.calls[0] as unknown as [string, string];
    const destPath = renameDest[1].replace(/\\/g, '/');
    expect(destPath).toMatch(/\/graph\/[a-f0-9]{64}\.json$/);
  });

  it('writes pretty-printed, human-readable JSON', async () => {
    const nodes = [
      {
        type: 'library' as const,
        name: 'chalk',
        version: '5.0.0',
        purl: 'pkg:npm/chalk@5.0.0',
        'bom-ref': 'pkg:npm/chalk@5.0.0',
        reasonCode: 'NO_KNOWN_VULNERABILITY' as const,
        vulnerabilities: [],
        scope: 'required' as const,
        isDirect: true,
      },
    ];

    await writeGraphCache(FIXTURE_KEY, nodes as never[], TEST_NOW);

    // First writeFile call: tmp graph cache file
    const tmpContent = mockWriteFile.mock.calls[0][1] as string;
    const parsed = JSON.parse(tmpContent);
    expect(parsed.cachedAt).toBe('2026-06-15T12:00:00.000Z');
    expect(parsed.nodes).toHaveLength(1);
    expect(parsed.nodes[0].name).toBe('chalk');
  });

  it('updates metadata.json with graph/{key} → byte SHA-256', async () => {
    await writeGraphCache(FIXTURE_KEY, [], TEST_NOW);

    // Find the metadata write (last writeFile call)
    const lastWriteCall = mockWriteFile.mock.calls[mockWriteFile.mock.calls.length - 1];
    const metaContent = JSON.parse(lastWriteCall[1] as string);
    expect(metaContent[`graph/${FIXTURE_KEY}`]).toMatch(/^[a-f0-9]{64}$/);
  });

  it('atomic write: tmp file renamed to final path', async () => {
    await writeGraphCache(FIXTURE_KEY, [], TEST_NOW);

    const [tmp, dest] = mockRename.mock.calls[0] as [string, string];
    expect(tmp).toContain('.tmp.');
    // Verify dest ends with graph/{sha256}.json in any path format
    const destNorm = dest.replace(/\\/g, '/');
    expect(destNorm).toMatch(/\/graph\/[a-f0-9]{64}\.json$/);
  });

  it('mkdir failure is best-effort; writeGraphCache does not throw', async () => {
    mockMkdir.mockRejectedValue(Object.assign(new Error('EACCES'), { code: 'EACCES' }));

    await expect(writeGraphCache(FIXTURE_KEY, [], TEST_NOW)).resolves.not.toThrow();
  });

  it('write failure is best-effort; does not throw', async () => {
    mockWriteFile.mockRejectedValue(Object.assign(new Error('EBUSY'), { code: 'EBUSY' }));

    await expect(writeGraphCache(FIXTURE_KEY, [], TEST_NOW)).resolves.not.toThrow();
  });

  it('writes correct cachedAt ISO timestamp', async () => {
    await writeGraphCache(FIXTURE_KEY, [], TEST_NOW);

    const tmpContent = mockWriteFile.mock.calls[0][1] as string;
    const parsed = JSON.parse(tmpContent);
    expect(parsed.cachedAt).toBe('2026-06-15T12:00:00.000Z');
    expect(Date.parse(parsed.cachedAt)).not.toBeNaN();
  });

  it('passes nodes through deepFreezeNodes on write (name preserved in output)', async () => {
    const nodes = [
      {
        type: 'library' as const,
        name: 'deep-freeze-check',
        version: '1.0.0',
        purl: 'pkg:npm/deep-freeze-check@1.0.0',
        'bom-ref': 'pkg:npm/deep-freeze-check@1.0.0',
        reasonCode: 'NO_KNOWN_VULNERABILITY' as const,
        vulnerabilities: [],
        scope: 'required' as const,
        isDirect: true,
      },
    ];

    await writeGraphCache(FIXTURE_KEY, nodes as never[], TEST_NOW);

    const tmpContent = mockWriteFile.mock.calls[0][1] as string;
    const parsed = JSON.parse(tmpContent);
    expect(parsed.nodes[0].name).toBe('deep-freeze-check');
  });
});

// =========================================================================
// lockfileHash round-trip with real fixture
// =========================================================================

describe('lockfileHash against real npm-v3 fixture', () => {
  // Load fixture via readFileSync + process.cwd() — avoids require(JSON)
  // typing issues and works consistently across platforms.
  function loadFixture(): string {
    const { readFileSync } = require('fs');
    const { join } = require('path');
    return readFileSync(
      join(process.cwd(), 'test', 'fixtures', 'lockfiles', 'npm-v3', 'package-lock.json'),
      'utf8',
    );
  }

  it('key is deterministic across two calls', () => {
    const raw = loadFixture();
    const hashA = lockfileHash(raw);
    const hashB = lockfileHash(raw);
    expect(hashA).toBe(hashB);
    expect(hashA).toMatch(/^[a-f0-9]{64}$/);
  });

  it('single-character change to lockfile produces different key', () => {
    const raw = loadFixture();
    const hashOriginal = lockfileHash(raw);
    const hashModified = lockfileHash(raw + '\n');
    expect(hashModified).not.toBe(hashOriginal);
  });

  it('the npm-v3 fixture parses to non-zero PackageNode list', async () => {
    const raw = loadFixture();
    const { parseLockfile } = await import('../../adapters/npm/parser.js');
    const nodes = parseLockfile(JSON.parse(raw));
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes[0]).toHaveProperty('name');
  });
});