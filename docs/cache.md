# Cache Design

> Where data lives, how it is keyed, and how the system detects that it has been tampered with or has gone stale.

## Architecture overview

The cache system consists of two independent stores, each with a different invalidation model:

| Store | Location | Key | Invalidation | TTL |
|---|---|---|---|---|
| OSV cache | `~/.audit-ready/cache/` | PURL filename (`pkg_npm_lodash_4.17.21.json`) | TTL only | 24 h (configurable via `--cache-ttl`) |
| Graph cache | `~/.audit-ready/cache/graph/` | Lockfile SHA-256 | Lockfile SHA-256 change only | None |

These two stores are independent. The OSV cache caches *vulnerability responses from OSV*; the graph cache caches the *parsed lockfile dependency tree*. A lockfile change busts the graph cache; it has no effect on OSV entries.

---

## Directory layout

```
~/.audit-ready/
└── cache/
    ├── metadata.json          ← integrity ledger (SHA-256 of every cached file)
    ├── pkg_npm_lodash_4.17.21.json   ← OSV entry (keyed by purlToFilename)
    ├── pkg_npm_debug_4.3.1.json
    ├── …
    └── graph/
        ├── d33c9bfeec7914f…          ← graph entry (keyed by lockfile SHA-256)
        └── 125c6a22b06a0…            ← one entry per distinct lockfile
```

`metadata.json` lives in `cache/` alongside OSV entries. Graph entries are inside the `graph/` subdirectory. Neither subdirectory holds a copy of `metadata.json`.

---

## OSV cache (`cache-manager.ts`)

### Cache entry format

```json
{
  "value": { /* OSV API response body */ },
  "cachedAt": "2026-05-06T01:00:00.000Z",
  "sha256": "a3f1e9d2…"
}
```

- `value` is the frozen OSV response (or `null` if OSV returned no vulnerabilities).
- `cachedAt` is the wall-clock write time written by the caller — never computed internally. This allows tests to control the clock.
- `sha256` is the hash of the *placeholder serialisation* (see [Hashing strategy](#hashing-strategy) below).

### Key derivation (`keys.ts: purlToFilename`)

```typescript
export function purlToFilename(purl: string): string {
  const encoded = purl.replace(/[\/:@]/g, '_');
  return `${encoded}.json`;
}
```

Delimiters (`/`, `:`, `@`) are replaced with `_`. URL-encoded sequences (e.g. `%40` for `@`) are preserved because `%` is not a delimiter.

### TTL policy

Each OSV entry has a per-key TTL. The default is **24 hours** (86 400 000 ms).

TTL enforcement uses the `cachedAt` ISO string stored *inside* the entry — not `Date.now()` at the cache layer:

```typescript
export function isCacheExpired(entry: CacheEntry<unknown>, now: Date, ttlMs: number): boolean {
  const cachedMs = Date.parse(entry.cachedAt);
  return now.getTime() - cachedMs > ttlMs;
}
```

Before returning a cached entry, `readCache` in `cache-manager.ts` (line 238) checks expiration:

```typescript
if (isCacheExpired(entry, now, ttlMs)) return null;
```

Override TTL with `--cache-ttl <hours>` on the scan command. A cache entry older than the current TTL is treated identically to a missing entry — the scan fetches from OSV and re-caches.

> **Rationale for TTL on OSV data:** OSV vulnerability data changes over time. A package that had no reported vulnerabilities today may have a disclosure next week. The TTL ensures scans performed more than 24 h after the last OSV fetch see fresh data.

### Lockfile SHA-256 is not used for OSV invalidation

The OSV cache is keyed by PURL, not by lockfile hash. The same package at the same version always maps to the same OSV cache file, regardless of which project consumed it. This means the OSV cache is shared across all projects on the same machine.

---

## Graph cache (`graph-manager.ts`)

### Cache entry format

```json
{
  "cachedAt": "2026-05-06T01:00:00.000Z",
  "nodes": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "reasonCode": "NO_KNOWN_VULNERABILITY",
      "scope": "required",
      "vulnerabilities": [],
      "isDirect": true
    }
  ]
}
```

`nodes` is a frozen array of `PackageNode` objects — the same shape that the normalizer returns. An auditor can `cat` this file and read every package's name, version, PURL, scope, and base `reasonCode` without any tool.

### Key derivation (`keys.ts: lockfileHash`)

```typescript
export function lockfileHash(lockfileContent: string): string {
  return createHash('sha256')
    .update(lockfileContent, 'utf8')
    .digest('hex');
}
```

The input is the *raw file string*, not a re-serialised object. This means:

- Whitespace differences introduced by text editors do not change the hash.
- An auditor can independently compute the key from the original lockfile.

### Invalidation model: lockfile SHA-256 only

There is **no TTL** on the graph cache. An entry persists until the lockfile on disk changes. This is intentional — the parsed dependency tree is a pure function of the lockfile bytes. When the lockfile bytes change, the graph cache for the previous hash is simply not found, and the normalizer re-runs.

This is verified by the integrity test:

```
audit-ready scan        → graph cache: d33c9bfe… ("lodash@1.0.1")
# edit package-lock.json: lodash → lodash-hacked
audit-ready scan        → graph cache: 125c6a22… ("lodash-hacked@1.0.1")
# old entry d33c9bfe… is left on disk but never used again
```

---

## Integrity verification (`metadata.json`)

### Role of the ledger

`metadata.json` is the single source of truth for cache integrity. Every time a file is written, its SHA-256 is recorded here *after* the write completes. Every read cross-checks the on-disk bytes against the recorded hash.

```json
{
  "pkg_npm_lodash_4.17.21": "a3f1e9d2c4b1…",
  "graph/d33c9bfeec7914f1486001eb4f625f2c7b438fd014e937999c1c6b9094241730": "e7f8…"
}
```

### On read

`readGraphCache` in `graph-manager.ts` (lines 61–79) checks the ledger before returning:

```typescript
const actual = await sha256File_(filePath);
if (actual !== expected) {
  console.warn(`[audit-ready graph-cache] integrity mismatch — treating as cache miss.`);
  return EMPTY;
}
```

Same pattern in `readCache` in `cache-manager.ts` (lines 217–233). A mismatch is treated as a **cache miss** — the scan fetches from the network and re-caches, never using suspect data.

### On write

1. Write the entry to a temp file (`<basename>.tmp.<pid>`).
2. `rename()` the temp file to its final path (atomic on both POSIX and Windows).
3. **After** the rename succeeds, update `metadata.json` with the SHA-256 of the bytes that are now on disk.

### Rebuild on absent metadata

If `metadata.json` is absent (first run, or deleted by the user), `rebuildMetadata` in `cache-manager.ts` (lines 404–438) sweeps the cache directory, hashes every `.json` file, and writes a fresh ledger. This means the system is self-recovering — an auditor can invoke `audit-ready scan --offline` at any time and the metadata is reconstructed from the files.

### `verifyIntegrity` command

`verifyIntegrity` in `cache-manager.ts` (lines 349–395) performs a full sweep:

```typescript
for (const [basename, expectedHash] of Object.entries(meta)) {
  if (fileHash === expectedHash) valid.push(basename);
  else corrupted.push(basename);
}
```

Returns an `IntegrityReport` bucketed into `valid`, `corrupted`, and `missing`. Corrupted files are **not deleted** — deletion is an explicit separate step so that an auditor can inspect a corrupted entry before it disappears.

---

## Hashing strategy

### OSV cache: sha256-of-placeholder

`writeCache` serialises the entry with a `PLACEHOLDER` hash, computes the SHA-256 of that fixed string, then uses that hash as `entry.sha256`. The file on disk contains the real hash. This avoids the chicken-and-egg problem of hashing an object that contains its own hash value.

The *on-disk file* is hashed separately by `sha256File()` and stored in `metadata.json`. `entry.sha256` inside the file is a historical annotation only — it is the hash of the placeholder serialisation while `metadata.json` holds the hash of the actual bytes.

### Graph cache: lockfile-derived

The graph cache key *is* the SHA-256 of the lockfile. Its on-disk SHA-256 is recorded in `metadata.json` under the `graph/<hash>` key.

---

## Atomic writes

All file writes use the temp-file-then-rename pattern:

```typescript
// OSV cache
await writeFile(tmpPath, fileBytes, 'utf8');
await rename(tmpPath, filePath);

// Graph cache — same pattern
await writeFile(tmpPath, fileBytes, 'utf8');
await rename(tmpPath, filePath);

// metadata.json
await writeFile(tmp, JSON.stringify(meta, null, 2), 'utf8');
await rename(tmp, metaPath());
```

`rename` is atomic on both POSIX and Windows. On Windows, the directory entry either appears with its final name or does not exist — there is no intermediate state visible to a concurrent reader.

Temp files are cleaned up on error:

```typescript
} catch (err) {
  try { await rm(tmpPath, { force: true }); } catch { /* noop */ }
  console.warn(`[audit-ready cache] write failed`);
}
```

---

## Best-effort contract

Every cache operation is best-effort. Failures are logged and the scan continues without the cache entry — the exit code reflects triage and policy results only.

```typescript
// readGraphCache — best-effort
} catch {
  return EMPTY;
}

// writeCache — best-effort
} catch (err) {
  try { await rm(tmpPath, { force: true }); } catch { /* ignore */ }
  console.error(`[audit-ready cache] write failed for "${key}": ${err}`);
  return;
}
```

This means the cache can be completely absent or corrupt and `audit-ready scan` continues with a fresh network fetch and a fresh parse. The cache never blocks the scan.

---

## Offline mode

`--offline` blocks all network calls. The scan serves every result from the OSV cache. If any PURL is not present in the cache, the scan exits with code **2** (distinguishable from a policy violation exit code **1**):

```typescript
const cached = await readCache(key, now, ttlMs);
if (cached === null) {
  console.error(`[cache] ${key} not in cache — offline mode requires full cache`);
  process.exit(2);
}
```

This makes `--offline` a deterministic CI mode: same lockfile + warm cache = same output, every time, no network.

---

## Immutability guarantees

Returned values are frozen at read time:

```typescript
// cache-manager.ts
return Object.freeze(entry.value);
```

```typescript
// graph-manager.ts — deep freeze
function deepFreezeNodes(nodes: readonly unknown[]): readonly PackageNode[] {
  return Object.freeze(
    nodes.map((n) => Object.freeze({ ...n as object })),
  );
}
```

No caller can mutate a cache entry after it is read. This preserves the immutability guarantees of the core classification layer all the way to the output.

---

## Summary of guarantees

| Property | Mechanism |
|---|---|
| OSV entries expire | TTL on each entry via `cachedAt` |
| Stale lockfile busted | Graph cache key changes (lockfile SHA-256) |
| Tamper detection | `metadata.json` SHA-256 ledger, cross-checked on every read |
| Atomic writes | Temp file + rename |
| Human-readable graph cache | Frozen `PackageNode[]` JSON in `graph/<sha256>.json` |
| No partial entries | Metadata updated *after* successful rename |
| Self-recovering ledger | `rebuildMetadata` sweeps files on absent metadata |
| Audit reproducibility | `--offline` mode skips network, serves from deterministically-keyed cache |