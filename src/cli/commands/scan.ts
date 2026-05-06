/**
 * Scan command implementation.
 * Orchestrates the full pipeline: parse → build → output.
 * All side effects (file I/O) live here.
 *
 * Cache notes:
 * - `now: Date` is injected at the CLI layer and threaded through all cache calls.
 * - Offline mode (--offline): if readCache returns null, exit code 2.
 * - Force-refresh (--force-refresh): readCache is skipped; cache is written after fetch.
 * - ttlOverrideMs overrides DEFAULT_TTL_MS when passed via --cache-ttl.
 */

import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Component } from '../../core/sbom/cyclonedx/model.js';
import { ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { buildBomDocument } from '../../core/sbom/cyclonedx/builder.js';
import { renderMarkdown } from '../../adapters/output/markdown/renderer.js';
import { parseLockfile } from '../../adapters/npm/parser.js';
import type { PackageNode } from '../../adapters/npm/normalizer.js';
import { readJsonFile } from '../../utils/fs.js';
import {
  UnsupportedLockfileVersionError,
  ConfigValidationError,
  ExpiredExceptionError,
  ConflictingFlagsError,
} from '../../utils/errors.js';
import { validateBom, formatValidationErrors } from '../../core/sbom/cyclonedx/validator.js';
import { fetchVulnerabilities } from '../../adapters/vuln-db/osv-client.js';
import { calculateReachability } from '../../core/triage/reachability.js';
import { applyTriage } from '../../core/triage/engine.js';
import { applyExceptions, type Exception } from '../../core/policy/exceptions.js';
import { matchesFailPolicy } from '../../core/triage/engine.js';
import { DEFAULT_RULES } from '../../core/triage/rules/default-rules.js';
import { buildSarif } from '../../adapters/output/sarif.js';
import { loadConfig } from '../../config/loader.js';
import { purlToFilename } from '../../cache/keys.js';
import {
  getCacheStatus,
  readCache,
  writeCache,
  DEFAULT_TTL_MS,
  cacheDir,
} from '../../cache/cache-manager.js';
import { readGraphCache, writeGraphCache, lockfileHash } from '../../cache/graph-manager.js';
import { readFile, parseJson } from '../../utils/fs.js';
import { readdir } from 'node:fs/promises';

/** Output file paths */
const OUTPUT_SBOM = './sbom.json';
const OUTPUT_REPORT = './audit-report.md';

/** Package.json metadata for the root component */
interface PackageJson {
  name?: string;
  version?: string;
  description?: string;
  author?: string;
}

/** Scan command options including cache and policy flags */
interface ScanCommandOptions {
  readonly lockfile?: string;
  readonly pkgJson?: string;
  readonly failOn?: readonly ReasonCode[];
  readonly dryRun?: boolean;
  /** Optional path to write a SARIF 2.1.0 report. */
  readonly outputSarif?: string;
  /** Optional path to .audit-policy.json containing exceptions. */
  readonly policyPath?: string;
  /** Block all network calls; exit 2 if a required cache entry is absent. */
  readonly offline?: boolean;
  /** Skip cache reads; fetch fresh data and overwrite cache. */
  readonly forceRefresh?: boolean;
  /** Override DEFAULT_TTL_MS in milliseconds (0 = use DEFAULT_TTL_MS). */
  readonly ttlOverrideMs?: number;
  /** Injected clock set once at the CLI entry. */
  readonly now?: Date;
}

/** ─────────────────────────────────────────────────────────────────────────────
 * Policy helper
 * ───────────────────────────────────────────────────────────────────────────── */

/** Check for policy violations against the --fail-on set */
function checkPolicyViolations(
  components: readonly Component[],
  failOn: readonly ReasonCode[],
  dryRun: boolean
): void {
  const violations = components.filter((c) => matchesFailPolicy(c, failOn));
  if (violations.length === 0) return;
  for (const v of violations) {
    const prefix = dryRun ? '⚠ Policy Violation (DRY-RUN)' : '✖ Policy Violation';
    console.log(`${prefix}: ${v.purl} would have failed the build [${v.reasonCode}]`);
  }
  if (!dryRun) process.exit(1);
}

/** Write SARIF report, validate, and log result. Failure logs a warning and continues. */
async function writeSarifReport(
  components: readonly Component[],
  outputPath: string
): Promise<void> {
  try {
    const sarifDoc = buildSarif(components);
    if (
      sarifDoc.version !== '2.1.0' ||
      !Array.isArray(sarifDoc.runs) ||
      sarifDoc.runs.length === 0
    ) {
      console.warn(`⚠ SARIF validation failed: invalid document structure`);
      return;
    }
    await writeFile(outputPath, JSON.stringify(sarifDoc, null, 2), 'utf-8');
    console.log(`✅ SARIF report written to ${outputPath}`);
  } catch {
    console.warn(`⚠ SARIF report could not be written to ${outputPath}`);
  }
}

/** ─────────────────────────────────────────────────────────────────────────────
 * CLI output — deprecated packages
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * Print console warnings for every component assigned DEPRECATED_PACKAGE.
 * Called after triage, before the policy-violation check so deprecation signals
 * are not missed if the build fails on an earlier violation.
 *
 * Spec output format:
 *   ⚠ DEPRECATED: {purl}
 *   Message: {deprecated message}
 *   Reason: DEPRECATED_PACKAGE
 *
 * @param components - Post-triage component list.
 */
function reportDeprecatedPackages(components: readonly Component[]): void {
  const deprecated = components.filter(
    (c) => c.reasonCode === ReasonCode.DEPRECATED_PACKAGE && c.deprecated !== undefined,
  );
  for (const pkg of deprecated) {
    console.log(`⚠ DEPRECATED: ${pkg.purl}`);
    console.log(`  Message: ${pkg.deprecated}`);
    console.log(`  Reason: ${ReasonCode.DEPRECATED_PACKAGE}`);
  }
}

/** ─────────────────────────────────────────────────────────────────────────────
 * CLI output — cache diagnostic block
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * Return the display name for the current cache mode.
 * "force-refresh" implies online (fresh fetch wins over any stale cache).
 */
function cacheModeLabel(offline: boolean, forceRefresh: boolean): string {
  if (forceRefresh) return 'force-refresh';
  if (offline) return 'offline';
  return 'online';
}

/**
 * Count OSV cache entry files in the cache root.
 * OSV entries are written directly to `cacheDir()` (not a subdirectory).
 * Returns the count of `pkg_*.json` files, excluding metadata.json and .tmp.
 * Returns 0 if the cache root is absent or unreadable (best-effort).
 */
async function countOvfEntries(): Promise<number> {
  const dir = cacheDir();
  try {
    const names = await readdir(dir);
    return names.filter(
      (n) => n.startsWith('pkg_') && n.endsWith('.json') && !n.includes('.tmp'),
    ).length;
  } catch {
    return 0;
  }
}

/**
 * Format milliseconds as a short human string (e.g. "12h", "3d", "45m").
 */
function formatAge(ms: number): string {
  if (ms < 60 * 1_000) return `${Math.round(ms / 1_000)}s`;
  if (ms < 3_600 * 1_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400 * 1_000) return `${Math.round(ms / 3_600_000)}h`;
  return `${Math.round(ms / 86_400_000)}d`;
}

/**
 * Print the cache diagnostic block after the lockfile has been parsed.
 *
 * The block runs before any network call so it reflects the starting state.
 *
 * Display:
 *   ── Cache Status ────────────────────────────────────
 *   OSV cache:    {N} entries, oldest {X}h ago
 *   Graph cache:  {hit|miss} for current lockfile
 *   Mode:         {online|offline|force-refresh}
 *   ─────────────────────────────────────────────────────
 *
 * @param now      - Injected clock.
 * @param ttlMs    - Effective TTL in ms (DEFAULT_TTL_MS or --cache-ttl override).
 * @param purls    - Parsed PURLs from the lockfile.
 * @param graphHit - True when readGraphCache returned a non-empty cache hit.
 */
async function cacheDiagnostic(
  now: Date,
  ttlMs: number,
  purls: readonly string[],
  graphHit: boolean,
  offline: boolean,
  forceRefresh: boolean,
): Promise<void> {
  const count = await countOvfEntries();

  // Find the oldest OSV entry by checking the first few (we just need an estimate).
  let oldestAgeStr = '—';
  if (count > 0) {
    // Check the first PURL to get an age estimate for the block label.
    // This is a best-effort diagnostic — not an exhaustive scan.
    const sample = purls[0];
    if (sample) {
      const key = purlToFilename(sample).replace(/\.json$/, '');
      const status = await getCacheStatus(key, now, ttlMs);
      if (status.exists) {
        oldestAgeStr = formatAge(status.ageMs) + ' ago';
      }
    }
  }

  const graphStatus = graphHit ? 'hit' : 'miss';
  const modeLabel = forceRefresh ? 'force-refresh' : offline ? 'offline' : 'online';

  const bar = '──'.repeat(25);
  console.log(`── Cache Status ${bar.slice(0, 50)}`);
  console.log(`  OSV cache:    ${count} entries${count > 0 ? `, oldest ${oldestAgeStr}` : ''}`);
  console.log(`  Graph cache:  ${graphStatus} for current lockfile`);
  console.log(`  Mode:         ${modeLabel}`);
  console.log(`${'──'.repeat(27)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Config merge helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Merge failOn codes: CLI wins over file.
 * When --fail-on is passed via CLI, it overrides the file's failOn entirely.
 */
function resolveFailOn(
  cliFailOn: readonly ReasonCode[],
  fileFailOn: readonly ReasonCode[]
): readonly ReasonCode[] {
  return Object.freeze([...cliFailOn]);
}

/**
 * Load and merge config from policy file, applying CLI precedence rules.
 * @param now - Injected clock (set once at the CLI layer entry).
 */
async function loadAndMergeConfig(
  policyPath: string | undefined,
  now: Date,
): Promise<{ failOn: readonly ReasonCode[]; exceptions: readonly Exception[] }> {
  if (!policyPath) {
    return { failOn: Object.freeze([]), exceptions: Object.freeze([]) };
  }
  const config = await loadConfig(policyPath, now);
  return { failOn: config.failOn, exceptions: config.exceptions };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scan command
// ─────────────────────────────────────────────────────────────────────────────

export async function scanCommand(
  options: ScanCommandOptions = {},
): Promise<void> {
  const startTime = performance.now();
  const dryRun = options.dryRun ?? false;
  const offline = options.offline ?? false;
  const forceRefresh = options.forceRefresh ?? false;

  // `now` is injected so tests can control the clock.  If not injected we
  // create it here (one time only) to satisfy the constraint of never calling
  // `new Date()` inside cache functions.
  const now = options.now ?? new Date();
  const ttlMs = options.ttlOverrideMs ?? DEFAULT_TTL_MS;

  const lockfilePath = options.lockfile ?? './package-lock.json';
  const pkgJsonPath = options.pkgJson ?? './package.json';

  if (offline) {
    console.log('[offline mode — cache reads only, no network calls]');
  }
  if (forceRefresh) {
    console.log('[force-refresh — skipping cache reads, overwriting after fetch]');
  }

  if (dryRun) {
    console.log('[dry-run] Simulating audit-ready scan (no network, no file writes)');
  } else {
    console.log('Starting audit-ready scan...');
  }

  // ── Load config from .audit-policy.json ──────────────────────────────────
  const { exceptions: fileExceptions, failOn: fileFailOn } = await loadAndMergeConfig(
    options.policyPath,
    now,
  );
  const resolvedFailOn = resolveFailOn(options.failOn ?? [], fileFailOn);

  try {
    // Declared here so both branches can assign to it; used after the branch block.
    let triagedComponents: readonly Component[];

    // ── Step 1: Read project metadata ───────────────────────────────────────
    if (!dryRun) console.log(`Reading ${pkgJsonPath}...`);
    const pkgJson = await readJsonFile<PackageJson>(pkgJsonPath);
    if (!pkgJson.name || !pkgJson.version) {
      throw new Error('package.json must have name and version fields');
    }

    // ── Step 2: Read and parse lockfile ─────────────────────────────────────
    if (!dryRun) console.log(`Reading ${lockfilePath}...`);

    // Read the raw lockfile as a string so we can compute a deterministic
    // SHA-256 key from the exact bytes on disk (before JSON.parse).  An auditor
    // can independently reproduce the key from the original file.
    const rawLockfileStr = await readFile(lockfilePath);
    const rawLockfile = parseJson<unknown>(rawLockfileStr);

    // Graph cache key: SHA-256 of the raw file bytes.
    const lockfileKey = lockfileHash(rawLockfileStr);

    // ── Graph cache: check before parsing ──────────────────────────────────
    // Cache hit → skip parse entirely.  Cache miss or corrupt → parse + cache.
    let components: readonly Component[];
    let graphHit = false;
    const purls: string[] = [];
    if (!dryRun) {
      const cached = await readGraphCache(lockfileKey);
      if (cached.length > 0) {
        components = cached;
        graphHit = true;
        console.log(`Graph cache hit — parsed ${components.length} packages from cache`);
      } else {
        console.log('Parsing dependencies...');
        components = parseLockfile(rawLockfile);
        // Components already have the PackageNode shape (from normalizer);
        // the double-cast via unknown is safe because the runtime values
        // already carry all fields that PackageNode requires.
        await writeGraphCache(lockfileKey, components as unknown as readonly PackageNode[], now);
      }
    } else {
      // Dry-run: parse normally, no cache write.
      console.log('Parsing dependencies...');
      components = parseLockfile(rawLockfile);
    }
    // Build purls after components is assigned in either branch.
    purls.length = 0;
    purls.push(...components.map((c) => c.purl));
    console.log(`Found ${components.length} packages`);

    // ── Cache diagnostic block — before any network call ─────────────────
    await cacheDiagnostic(now, ttlMs, purls, graphHit, offline, forceRefresh);

    // ── Step 3: Fetch vulnerabilities from OSV ─────────────────────────────
    let networkError = false;
    if (!dryRun) {
      console.log('Fetching vulnerabilities from OSV...');

      // ── OSV cache integration ──────────────────────────────────────────────
      // online mode:  try cache → if miss, fetch → write cache
      // offline mode: try cache → if miss, exit 2
      // force-refresh: skip cache read, fetch → write cache
      const vulnMap = new Map<string, Component['vulnerabilities']>();
      let fetchCount = 0;
      let cacheHitCount = 0;
      let offlineMissing = false;

      for (const purl of purls) {
        const key = purlToFilename(purl).replace(/\.json$/, '');

        if (!forceRefresh) {
          // ── Attempt cache read ────────────────────────────────────────────
          const cached = await readCache<Component['vulnerabilities']>(key, now, ttlMs);
          if (cached !== null) {
            vulnMap.set(purl, cached);
            cacheHitCount++;
            continue;
          }
          // Cache miss — if offline, this is a fatal error.
          if (offline) {
            console.warn(
              `[offline] Cache miss for "${purl}" — ` +
              `no network allowed and this entry is not cached.`,
            );
            offlineMissing = true;
          }
        }

        // Fetch from network (unless we already determined a fatal offline miss)
        if (!offlineMissing) {
          // fetchVulnerabilities returns { vulnerabilities: Map, networkError: boolean }
          const { vulnerabilities: vulnsMap, networkError: fetchNetErr } =
            await fetchVulnerabilities([purl]);
          if (fetchNetErr) networkError = true;
          fetchCount++;
          const val = vulnsMap.get(purl) ?? [];
          vulnMap.set(purl, val);

          // Write to cache for future use (force-refresh always overwrites)
          await writeCache(key, val, now);
        }
      }

      if (offlineMissing) {
        process.exit(2);
      }

      if (networkError) {
        console.warn('⚠ Vulnerability scan skipped — offline or unreachable');
      } else if (fetchCount > 0) {
        console.log(`Fetched: ${fetchCount} fresh, ${cacheHitCount} from cache`);
      } else {
        console.log(`All ${purls.length} packages served from cache`);
      }

      // ── Enrich components ─────────────────────────────────────────────────
      const enrichedComponents: Component[] = components.map((component) => {
        const vulns = vulnMap.get(component.purl) ?? [];
        const reachabilityWeight = calculateReachability(component);
        return Object.freeze<Component>({
          ...component,
          vulnerabilities: vulns,
          arTriage: { riskTier: 'NeedsReview', rationale: '', reachabilityWeight },
        });
      });

      // ── Apply rule-based triage (sets reasonCode) ─────────────────────────
      triagedComponents = applyTriage(enrichedComponents, DEFAULT_RULES);

      // ── Apply exceptions (loaded at top of function) ──────────────────────
      if (fileExceptions.length > 0) {
        triagedComponents = applyExceptions(triagedComponents, fileExceptions, now);
        console.log(
          `Applied ${fileExceptions.length} exception(s) from ` +
          `${options.policyPath ?? '.audit-policy.json'}`,
        );
      }

      // ── Report deprecated packages ─────────────────────────────────────────
      reportDeprecatedPackages(triagedComponents);

      // ── Check policy violations ────────────────────────────────────────────
      checkPolicyViolations(triagedComponents, resolvedFailOn, dryRun);

      // SARIF output if requested
      if (options.outputSarif) {
        await writeSarifReport(triagedComponents, options.outputSarif);
      }

      // ── Build BOM document ─────────────────────────────────────────────────
      const bom = buildBomDocument(triagedComponents, {
        name: pkgJson.name,
        version: pkgJson.version,
        description: pkgJson.description,
        author: pkgJson.author,
      });

      // ── Validate BOM ──────────────────────────────────────────────────────
      console.log('Validating BOM against CycloneDX 1.5 schema...');
      const validation = validateBom(bom);
      if (!validation.valid) {
        console.error('Validation FAILED:');
        console.error(formatValidationErrors(validation.errors));
        throw new Error('BOM validation failed');
      }
      console.log('Validation PASSED');

      // ── Write outputs ─────────────────────────────────────────────────────
      const bomJson = JSON.stringify(bom, null, 2);
      const reportMd = renderMarkdown(bom);
      const sbomPath = join(process.cwd(), OUTPUT_SBOM);
      const reportPath = join(process.cwd(), OUTPUT_REPORT);

      await writeFile(sbomPath, bomJson, 'utf-8');
      console.log(`Written: ${sbomPath}`);
      await writeFile(reportPath, reportMd, 'utf-8');
      console.log(`Written: ${reportPath}`);
    } else {
      // ── dry-run branch ─────────────────────────────────────────────────────
      const enrichedComponents: Component[] = components.map((component) =>
        Object.freeze<Component>({
          ...component,
          vulnerabilities: [],
          arTriage: { riskTier: 'Acceptable', rationale: '', reachabilityWeight: 1.0 },
        }),
      );

      triagedComponents = applyTriage(enrichedComponents, DEFAULT_RULES);

      if (fileExceptions.length > 0) {
        triagedComponents = applyExceptions(triagedComponents, fileExceptions, now);
        console.log(
          `[dry-run] Applied ${fileExceptions.length} exception(s) from ` +
          `${options.policyPath ?? '.audit-policy.json'}`,
        );
      }

      reportDeprecatedPackages(triagedComponents);
      checkPolicyViolations(triagedComponents, resolvedFailOn, dryRun);

      if (options.outputSarif) {
        await writeSarifReport(triagedComponents, options.outputSarif);
      }
    }

    const duration = Math.round(performance.now() - startTime);
    if (!dryRun) {
      console.log(`Scan completed in ${duration}ms`);
    }
    process.exit(networkError ? 2 : 0);

  } catch (error) {
    if (error instanceof ConflictingFlagsError) {
      // ConflictingFlagsError is thrown by parseScanOptions before scanCommand;
      // this catch is a guard in case it propagates here from a nested call.
      console.error(`Error: ${error.message}`);
      process.exit(1);
    } else if (error instanceof UnsupportedLockfileVersionError) {
      console.error(`Error: ${error.message}`);
    } else if (error instanceof ConfigValidationError) {
      console.error(error.message);
    } else if (error instanceof ExpiredExceptionError) {
      console.error(`Error: ${error.message}`);
    } else if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
    } else {
      console.error('Error: Unknown error occurred');
    }
    process.exit(1);
  }
}

// If this file is run directly (e.g., via ts-node in dev), execute scanCommand
if (import.meta.url === `file://${process.argv[1]}`) {
  scanCommand().catch(() => process.exit(1));
}