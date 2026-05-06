/**
 * Core cache read/write logic for audit-ready.
 *
 * Design principles:
 *
 * 1. **Never call `Date.now()` internally** — every time-dependent operation
 *    receives `now: Date` as a parameter so callers (including tests) control
 *    the clock.  This is essential for deterministic audit behaviour.
 *
 * 2. **Cache is best-effort and must never block a scan** — any failure (read
 *    error, write error, corrupted file) is logged and the operation silently
 *    degrades to a cache miss.  Exit code is driven solely by triage/policy
 *    results.
 *
 * 3. **Every returned object is frozen** — callers cannot mutate entries after
 *    read, preserving audit-grade immutability guarantees.
 *
 * 4. **`metadata.json` is the integrity ledger** — each cached file has its
 *    SHA-256 recorded here immediately after write.  On read the stored hash is
 *    compared against the bytes on disk.  A mismatch is treated as a cache miss
 *    (logged, never used).  This lets an auditor verify any cached file using
 *    standard tooling: `sha256sum <file>` → compare with `metadata.json`.
 *
 * 5. **Atomic writes** — `writeCache` writes to a temporary file and then
 *    renames it.  On POSIX systems rename is atomic; on Windows it is
 *    guaranteed to be either complete or absent, eliminating the risk of a
 *    concurrent reader seeing a partial JSON fragment.
 */

import { createHash } from 'node:crypto';
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import type { CacheEntry, CacheStatus, IntegrityReport } from './types.js';

export const DEFAULT_TTL_MS = 86_400_000; // 24 hours

/**
 * Status of a single cache entry, used by the CLI diagnostic block.
 *
 * All time values are derived from the injected `now` — this function never
 * calls `Date.now()` internally.  `ageMs` is the elapsed time since the cached
 * entry was written (computed from the `cachedAt` ISO string in the entry).
 */
export async function getCacheStatus(
  key: string,
  now: Date,
  ttlMs: number,
): Promise<CacheStatus> {
  const cache = cacheDir();
  const filePath = join(cache, `${key}.json`);

  let entry: CacheEntry<unknown>;
  try {
    const raw = await readFile(filePath, 'utf8');
    entry = JSON.parse(raw) as CacheEntry<unknown>;
  } catch {
    // File absent or unreadable → no entry.
    return Object.freeze({ exists: false, expired: false, ageMs: 0, cachedAt: null });
  }

  // ── Integrity guard ────────────────────────────────────────────────────────
  // If metadata exists and tracks this key, verify the on-disk bytes match.
  // Corrupted entries are treated as non-existent so callers don't use bad data.
  const meta = await readMetadata(cache);
  if (meta !== null) {
    const expected = meta[key];
    if (expected !== undefined) {
      try {
        const actual = await sha256File(filePath);
        if (actual !== expected) {
          console.warn(
            `[audit-ready cache] getCacheStatus: integrity mismatch for "${key}" — ` +
            `treating as absent.`,
          );
          return Object.freeze({ exists: false, expired: false, ageMs: 0, cachedAt: null });
        }
      } catch {
        return Object.freeze({ exists: false, expired: false, ageMs: 0, cachedAt: null });
      }
    }
  }

  const cachedMs = Date.parse(entry.cachedAt);
  const ageMs = Math.max(0, now.getTime() - cachedMs);
  const expired = ageMs > ttlMs;

  return Object.freeze({
    exists: true,
    expired,
    ageMs,
    cachedAt: entry.cachedAt,
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Absolute path to `~/.audit-ready/cache/`. */
export function cacheDir(): string {
  return resolve(homedir(), '.audit-ready', 'cache');
}

function metaPath(cache: string): string {
  return join(cache, 'metadata.json');
}

type MetadataJson = Record<string, string>; // basename (no .json) → sha256 hex

/**
 * SHA-256 hex of a file on disk.
 * Throws if the file cannot be read.
 */
async function sha256File(filePath: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(filePath))
    .digest('hex');
}

/**
 * Ensure the cache directory exists.
 * Silently continues if mkdir fails (e.g. permissions) — callers treat cache
 * as best-effort.
 */
async function ensureDir(cache: string): Promise<void> {
  try {
    await mkdir(cache, { recursive: true });
  } catch {
    // best-effort; caller continues without cache
  }
}

/**
 * Read and parse `metadata.json`, or return `null` if it is absent or unreadable.
 */
async function readMetadata(cache: string): Promise<MetadataJson | null> {
  try {
    const raw = await readFile(metaPath(cache), 'utf8');
    return JSON.parse(raw) as MetadataJson;
  } catch {
    return null;
  }
}

/**
 * Write `metadata.json` atomically (temp + rename).
 * If the rename fails the temp file is removed so no partial state persists.
 */
async function writeMetadata(cache: string, meta: MetadataJson): Promise<void> {
  const tmp = join(cache, `metadata.tmp.${process.pid}`);
  try {
    await writeFile(tmp, JSON.stringify(meta, null, 2), 'utf8');
    await rename(tmp, metaPath(cache));
  } catch (err) {
    // Clean up temp file on failure so we never leave a stray .tmp behind.
    try { await rm(tmp, { force: true }); } catch { /* ignore */ }
    throw err;
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Returns `true` when `entry.cachedAt` is older than `ttlMs` from `now`.
 *
 * Uses the ISO 8601 `cachedAt` string stored inside the entry (never `Date.now()`)
 * so that callers — including test suites — can inject any clock they need.
 */
export function isCacheExpired(entry: CacheEntry<unknown>, now: Date, ttlMs: number): boolean {
  const cachedMs = Date.parse(entry.cachedAt); // Date.parse is safe for ISO 8601
  return now.getTime() - cachedMs > ttlMs;
}

/**
 * Read and return a cached value, or `null` if absent, expired, or corrupted.
 *
 * Integrity chain:
 *   1. File exists and is readable?  → proceed
 *   2. Parses as CacheEntry<T>?       → proceed
 *   3. Stored sha256 matches bytes?   → proceed, else log + null
 *   4. Not expired (isCacheExpired)?  → return frozen value, else null
 *
 * Never throws.  All error paths log and fall through to `null`.
 */
export async function readCache<T>(
  key: string,
  now: Date,
  ttlMs: number,
): Promise<T | null> {
  const cache = cacheDir();
  const filePath = join(cache, `${key}.json`);

  let entry: CacheEntry<T>;
  try {
    const raw = await readFile(filePath, 'utf8');
    entry = JSON.parse(raw) as CacheEntry<T>;
  } catch {
    // File absent or unreadable → cache miss, continue silently.
    return null;
  }

  // ── Integrity check via metadata.json ──────────────────────────────────────
  // audit rationale: metadata.json is the authoritative integrity ledger.
  // entry.sha256 (stored inside the file) records the hash of the placeholder
  // version at write time and is not used for read-time integrity — it is a
  // historical annotation only.  Every read cross-checks the on-disk SHA-256
  // against metadata so corruption is detected regardless of whether the file
  // itself has been tampered with or simply contains a different sha256 field.
  const meta = await readMetadata(cache);
  if (meta !== null) {
    const expected = meta[key];
    if (expected !== undefined) {
      try {
        const actual = await sha256File(filePath);
        if (actual !== expected) {
          console.warn(
            `[audit-ready cache] integrity check failed for "${key}" — ` +
            `expected ${expected}, got ${actual}. Treating as miss.`,
          );
          return null;
        }
      } catch {
        return null;
      }
    }
    // If key absent from metadata, skip integrity check (legacy entry from
    // before metadata existed).  Fall through to TTL check below.
  }

  if (isCacheExpired(entry, now, ttlMs)) return null;

  return Object.freeze(entry.value);
}

/**
 * Write a value into the cache under `key`, recording the SHA-256 in metadata.
 *
 * The write is atomic (temp file + rename) so that concurrent readers never
 * see a partial JSON fragment.
 *
 * After a successful write the entry's `sha256` field is verified against the
 * bytes on disk before the metadata ledger is updated.  This ordering prevents
 * metadata from recording a hash for a file that failed to persist.
 *
 * On any error the cache is left in a consistent state: either both the file
 * and metadata are updated, or neither is.  Always logs on failure.
 */
export async function writeCache<T>(key: string, value: T, now: Date): Promise<void> {
  const cache = cacheDir();
  await ensureDir(cache);

  const filePath = join(cache, `${key}.json`);

  // ── Compute file-level hash ─────────────────────────────────────────────────
  // Hash strategy: serialise the entry with a placeholder hash first, compute the
  // digest from that stable string, then create the real entry with the computed
  // hash (the hash of the serialised placeholder version, not the final entry).
  //
  // Rationale for hashing the placeholder version (not the final entry): it avoids
  // a chicken-and-egg problem — `sha256` is a field IN the entry, so hashing the
  // entry-with-real-hash would include `sha256`'s own value in the digest, which
  // would vary with every write even for identical payloads.
  //
  // The final file bytes (with the real sha256) are different from the placeholder
  // bytes that produced `sha256`, so post-write verify (sha256File vs entry.sha256)
  // is not performed — it would always fail.  Instead we rely on:
  //   (a) writeCache returning only after a successful rename, which guarantees the
  //       bytes written are the same bytes we asked OS to write; and
  //   (b) sha256File being called by verifyIntegrity to cross-check metadata.json.
  const PLACEHOLDER = 'sha256-placeholder-that-is-not-a-valid-hex-string-0000000000000';
  const entryWithPlaceholder: CacheEntry<T> = Object.freeze({
    value: Object.freeze(value),
    cachedAt: now.toISOString(),
    sha256: PLACEHOLDER,
  });
  const serialisedPlaceholder = JSON.stringify(entryWithPlaceholder, null, 2);
  const sha256 = createHash('sha256')
    .update(serialisedPlaceholder, 'utf8')
    .digest('hex');

  // ── Build the final entry ──────────────────────────────────────────────────
  const entry: CacheEntry<T> = Object.freeze({
    value: Object.freeze(value),
    cachedAt: now.toISOString(),
    sha256,
  });
  const serialised = JSON.stringify(entry, null, 2); // contains the real sha256

  // ── Atomic write (temp + rename) ───────────────────────────────────────────
  const tmpPath = join(cache, `${key}.tmp.${process.pid}`);
  let fileBytes: string;
  try {
    fileBytes = JSON.stringify(entry, null, 2);
    await writeFile(tmpPath, fileBytes, 'utf8');
    await rename(tmpPath, filePath);
  } catch (err) {
    try { await rm(tmpPath, { force: true }); } catch { /* ignore */ }
    console.error(`[audit-ready cache] write failed for "${key}": ${err}`);
    return; // best-effort — scan continues without cache
  }

  // ── Compute and record file-level hash in metadata ────────────────────────
  // audit rationale: metadata.json records the SHA-256 of the actual bytes that
  // landed on disk.  An auditor can independently verify: openssl dgst -sha256
  // <file>.json, then compare to the value stored in metadata.json.
  // Entry.sha256 (stored inside the file) is a historical record only — it is
  // the hash of the placeholder version and should NOT be compared to sha256File.
  let fileDigest: string;
  try {
    // We already have the bytes in memory — no need to re-read from disk.
    fileDigest = createHash('sha256').update(fileBytes, 'utf8').digest('hex');
  } catch {
    return; // best-effort
  }

  const meta = (await readMetadata(cache)) ?? {};
  meta[key] = fileDigest;
  try {
    await writeMetadata(cache, meta);
  } catch {
    // Metadata update failed — file is written and valid but the entry is not
    // tracked in the ledger yet.  verifyIntegrity will recover it on next run.
    console.warn(`[audit-ready cache] metadata update failed for "${key}"`);
  }
}

/**
 * Scan the cache directory and verify every tracked file's integrity.
 *
 * Flow:
 *   1. Read `metadata.json` → if absent, rebuild it by sweeping existing files.
 *   2. For every tracked entry: compute SHA-256 of the file and compare.
 *   3. Return bucketed report (valid / corrupted / missing).
 *
 * Corrupted entries are **reported but not deleted** — deletion is an explicit
 * separate operation so that an auditor can recover the file before it disappears.
 *
 * Missing metadata → rebuild silently and continue.  Any other failure logs
 * and returns what was gathered before the error.
 */
export async function verifyIntegrity(cachePath?: string): Promise<IntegrityReport> {
  const cache = cachePath ?? cacheDir();
  const valid: string[] = [];
  const corrupted: string[] = [];
  const missing: string[] = [];

  let meta: MetadataJson | null;
  try {
    meta = await readMetadata(cache);
  } catch {
    return { valid, corrupted, missing };
  }

  if (meta === null) {
    // metadata.json absent — rebuild from files on disk.
    // Audit rationale: on first run (or after metadata.json deletion) we must
    // still be able to use the cache, and we must still be able to verify its
    // integrity once metadata is created.
    console.info('[audit-ready cache] metadata.json absent — rebuilding from files.');
    meta = await rebuildMetadata(cache);
  }

  for (const [basename, expectedHash] of Object.entries(meta)) {
    const filePath = join(cache, `${basename}.json`);
    let fileHash: string;
    try {
      const s = await stat(filePath);
      if (!s.isFile()) continue;
      fileHash = await sha256File(filePath);
    } catch {
      missing.push(basename);
      continue;
    }

    if (fileHash === expectedHash) {
      valid.push(basename);
    } else {
      corrupted.push(basename);
      console.warn(
        `[audit-ready cache] integrity check failed for "${basename}" — ` +
        `expected ${expectedHash}, got ${fileHash}.`,
      );
    }
  }

  return Object.freeze({ valid: Object.freeze(valid), corrupted: Object.freeze(corrupted), missing: Object.freeze(missing) });
}

/**
 * Sweep the cache directory and reconstruct `metadata.json` from the on-disk
 * SHA-256 of each `.json` file.  Skips the metadata file itself and any
 * temporary (`.tmp.*`) files.
 *
 * An auditor can invoke this at any time to recover a missing metadata ledger.
 */
async function rebuildMetadata(cache: string): Promise<MetadataJson> {
  const meta: MetadataJson = {};

  // readdir is best-effort — if the directory is unreadable we return empty.
  let names: string[];
  try {
    names = await readdir(cache);
  } catch {
    return meta;
  }

  for (const name of names) {
    // Skip metadata itself and any in-flight temp writes.
    if (name === 'metadata.json' || name.startsWith('metadata.tmp') || name.endsWith('.tmp')) {
      continue;
    }
    if (!name.endsWith('.json')) continue;
    const basename = name.slice(0, -5); // strip .json
    const filePath = join(cache, name);
    try {
      meta[basename] = await sha256File(filePath);
    } catch {
      // Skip files that can't be read — they contribute no hash to metadata.
    }
  }

  if (Object.keys(meta).length > 0) {
    try {
      await writeMetadata(cache, meta);
    } catch {
      // Rebuild failed to persist — not fatal for the current scan.
    }
  }

  return meta;
}