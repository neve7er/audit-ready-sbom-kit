/**
 * Graph cache — frozen snapshot of parsed PackageNode[] indexed by lockfile SHA-256.
 *
 * Design contract:
 * - Invalidation is by lockfile SHA-256 change ONLY. No TTL. No manual flag.
 * - Cache files are human-readable JSON — an auditor can `cat` any entry and
 *   verify "this lockfile parsed to these nodes" independently.
 * - All returned values are deeply frozen via Object.freeze().
 * - Every write is atomic (temp file + rename).
 * - Best-effort: any read failure → treat as cache miss and fall through.
 *   No error is thrown; the scan always continues.
 * - `metadata.json` is the integrity ledger: `graph/{sha256}` → SHA-256(file bytes).
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import type { PackageNode } from '../adapters/npm/normalizer.js';
import { lockfileHash } from './keys.js';

/**
 * On-disk format of a graph cache entry.
 * `nodes` is the frozen PackageNode array. `cachedAt` is the wall-clock write time.
 */
interface GraphCacheEntry {
  readonly cachedAt: string;
  readonly nodes: readonly PackageNode[];
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Attempt a graph cache read for `lockfileKey` (SHA-256 of the raw lockfile string).
 *
 * Cache hit → deeply frozen PackageNode[] returned.
 * Cache miss (absent, corrupt, integrity failure) → empty array returned.
 *
 * No TTL — only lockfile SHA-256 change invalidates the entry.
 */
export async function readGraphCache(
  lockfileKey: string,
): Promise<readonly PackageNode[]> {
  const filePath = join(graphDir_(), `${lockfileKey}.json`);

  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch {
    return EMPTY;
  }

  let entry: GraphCacheEntry;
  try {
    entry = JSON.parse(raw) as GraphCacheEntry;
  } catch {
    return EMPTY;
  }

  // ── Integrity guard: verify on-disk bytes against metadata.json ledger ────
  const meta = await readMetadata_();
  if (meta !== null) {
    const expected = meta[`graph/${lockfileKey}`];
    if (expected !== undefined) {
      try {
        const actual = await sha256File_(filePath);
        if (actual !== expected) {
          console.warn(
            `[audit-ready graph-cache] integrity mismatch for "${lockfileKey}" — ` +
            `treating as cache miss.`,
          );
          return EMPTY;
        }
      } catch {
        return EMPTY;
      }
    }
  }

  return deepFreezeNodes(entry.nodes);
}

/**
 * Write a frozen PackageNode[] snapshot to the graph cache under `lockfileKey`.
 *
 * The write is atomic (temp file + rename). After successful persistence the
 * `metadata.json` ledger is updated with the SHA-256 of the bytes on disk.
 *
 * Best-effort: failures are logged and silently swallowed — the scan continues.
 */
export async function writeGraphCache(
  lockfileKey: string,
  nodes: readonly PackageNode[],
  now: Date,
): Promise<void> {
  const graphDir = graphDir_();
  // Best-effort directory creation — if mkdir fails, writeFile will catch
  // the error downstream, so the caller always sees the scan continue.
  try {
    await mkdir(graphDir, { recursive: true });
  } catch { /* best-effort */ }

  const filePath = join(graphDir, `${lockfileKey}.json`);
  const tmpPath = join(graphDir, `${lockfileKey}.tmp.${process.pid}`);

  const entry: GraphCacheEntry = {
    cachedAt: now.toISOString(),
    nodes: deepFreezeNodes(nodes),
  };

  let fileBytes: string;
  try {
    fileBytes = JSON.stringify(entry, null, 2);
    await writeFile(tmpPath, fileBytes, 'utf8');
    await rename(tmpPath, filePath);
  } catch (err) {
    try { await rm(tmpPath, { force: true }); } catch { /* noop */ }
    console.warn(`[audit-ready graph-cache] write failed for "${lockfileKey}": ${err}`);
    return;
  }

  // ── Record file bytes SHA-256 in metadata.json ─────────────────────────────
  let fileDigest: string;
  try {
    fileDigest = createHash('sha256').update(fileBytes, 'utf8').digest('hex');
  } catch {
    return; // best-effort
  }

  const meta = (await readMetadata_()) ?? {};
  meta[`graph/${lockfileKey}`] = fileDigest;
  try {
    await writeMetadata_(meta);
  } catch {
    console.warn(
      `[audit-ready graph-cache] metadata update failed for "${lockfileKey}"`,
    );
  }
}

/**
 * Compute the graph-cache key from raw lockfile content.
 * Alias for `lockfileHash` from keys.ts — exposed here so callers do not
 * need to import from two places.
 */
export { lockfileHash };

// ─── Private helpers ─────────────────────────────────────────────────────────

function cacheDir_(): string {
  return resolve(homedir(), '.audit-ready', 'cache');
}

function graphDir_(): string {
  return join(cacheDir_(), 'graph');
}

function metaPath_(): string {
  return join(cacheDir_(), 'metadata.json');
}

type MetadataJson = Record<string, string>; // basename → sha256 hex

async function sha256File_(filePath: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(filePath))
    .digest('hex');
}

async function readMetadata_(): Promise<MetadataJson | null> {
  try {
    const raw = await readFile(metaPath_(), 'utf8');
    return JSON.parse(raw) as MetadataJson;
  } catch {
    return null;
  }
}

async function writeMetadata_(meta: MetadataJson): Promise<void> {
  const tmp = join(cacheDir_(), `metadata.tmp.${process.pid}`);
  try {
    await writeFile(tmp, JSON.stringify(meta, null, 2), 'utf8');
    await rename(tmp, metaPath_());
  } catch (err) {
    try { await rm(tmp, { force: true }); } catch { /* noop */ }
    throw err;
  }
}

/**
 * Apply Object.freeze() recursively through a PackageNode[] so the returned
 * array and every nested object/array is provably immutable.
 *
 * Note: The spread `{ ...n }` is required — without it Object.freeze() would
 * mark the original object as frozen, corrupting the caller's state if the same
 * object is frozen twice on different code paths (e.g. write then read).
 * The spread creates a fresh plain object to freeze, leaving the original untouched.
 */
function deepFreezeNodes(nodes: readonly unknown[]): readonly PackageNode[] {
  return Object.freeze(
    nodes.map((n) => {
      const entry = n as Record<string, unknown>;
      // Shallow copy + freeze each own property; recursive values (arrays/objects)
      // are also frozen in case future fields add nested structure.
      const frozen: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(entry)) {
        frozen[k] = (v !== null && typeof v === 'object') ? Object.freeze(v) : v;
      }
      return Object.freeze(frozen) as unknown as PackageNode;
    }),
  );
}

const EMPTY = Object.freeze([]) as readonly PackageNode[];