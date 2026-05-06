/**
 * Cache-local types for the audit-ready cache layer.
 *
 * Design contract:
 * - CacheEntry<T> stores the serialized value plus metadata sufficient to
 *   independently verify integrity without re-deserializing.  This lets an auditor
 *   run `sha256sum` against the on-disk JSON file and compare it to `entry.sha256`.
 * - All properties are `readonly`; the surrounding code wraps returned objects in
 *   Object.freeze() to eliminate accidental mutation after read.
 * - `cachedAt` is stored as an ISO 8601 string (not a numeric timestamp) so that it
 *   is human-readable when inspecting the cache file directly.
 */

export interface CacheEntry<T> {
  /** The cached payload — frozen at read time. */
  readonly value: T;
  /** Wall-clock time when the entry was written, ISO 8601. */
  readonly cachedAt: string;
  /**
   * SHA-256 hex digest of the JSON-serialised value.
   * Auditor can verify: openssl dgst -sha256 <file>, compares with this field.
   */
  readonly sha256: string;
}

/**
 * Result of a full integrity scan of the cache directory.
 * Files are bucketed by outcome; none are deleted automatically — deletion is an
 * explicit separate operation so that an auditor can recover a corrupted entry
 * before it disappears.
 */
export interface IntegrityReport {
  /** Files whose stored hash matches the bytes on disk. */
  readonly valid: readonly string[];
  /** Files whose hash on disk differs from the stored hash — treat as miss. */
  readonly corrupted: readonly string[];
  /** Files listed in metadata.json with no corresponding file on disk. */
  readonly missing: readonly string[];
}

/**
 * Snapshot of a single cache entry's health, used by the CLI diagnostic block.
 *
 * `ageMs` is computed from the injected `now` against the `cachedAt` stored in
 * the entry so tests can control the clock.  `expired` is derived — not stored.
 */
export interface CacheStatus {
  /** Whether a file exists for this key in the cache directory. */
  readonly exists: boolean;
  /** Whether `ageMs` exceeds the TTL. Always false when `exists` is false. */
  readonly expired: boolean;
  /** Elapsed milliseconds since write, or 0 if `exists` is false. */
  readonly ageMs: number;
  /** Stored write timestamp, or null if the entry does not exist. */
  readonly cachedAt: string | null;
}