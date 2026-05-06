/**
 * CLI argument parser and scan options interface.
 * All CLI validation happens here — the scan never starts with invalid input.
 *
 * Exit codes:
 *   0  — success (including --cache-clear)
 *   1  — policy / validation errors
 *   2  — offline + cache miss, or network error during scan
 */

import { readFile } from 'node:fs/promises';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

import { ReasonCode } from '../core/sbom/cyclonedx/model.js';
import { ConflictingFlagsError } from '../utils/errors.js';

/** ────────────────────────────────────────────────────────────────────────────
 * Shared cache operations used by the CLI top-level
 * ──────────────────────────────────────────────────────────────────────────── */

/** Absolute path to the cache directory */
export function cacheDir(): string {
  return join(homedir(), '.audit-ready', 'cache');
}

/**
 * --cache-clear: wipe ~/.audit-ready/cache/ and exit 0.
 * No scan runs.
 */
export async function cacheClear(): Promise<never> {
  const dir = cacheDir();
  try {
    await rm(dir, { recursive: true, force: true });
  } catch {
    // best-effort — the directory may never have existed
  }
  console.log('Cache cleared.');
  process.exit(0);
}

/** ────────────────────────────────────────────────────────────────────────────
 * ScanOptions interface
 * ──────────────────────────────────────────────────────────────────────────── */

/** Scan command options produced by the CLI parser */
export interface ScanOptions {
  readonly lockfile: string;
  readonly pkgJson: string;
  readonly failOn: readonly ReasonCode[];
  readonly dryRun: boolean;
  readonly outputSarif?: string;
  /** Path to .audit-policy.json containing exceptions and triage rules */
  readonly policyPath?: string;
  /** Block all network calls; require a valid cache entry or exit 2 */
  readonly offline: boolean;
  /** Skip cache reads; fetch fresh data and overwrite cache */
  readonly forceRefresh: boolean;
  /** Override TTL in milliseconds for this invocation */
  readonly ttlOverrideMs: number;
  readonly now: Date;
}

/** ────────────────────────────────────────────────────────────────────────────
 * Valid ReasonCode values
 * ──────────────────────────────────────────────────────────────────────────── */

const VALID_REASON_CODES: readonly string[] = Object.freeze([
  ReasonCode.DEV_DEPENDENCY_ONLY,
  ReasonCode.OPTIONAL_DEPENDENCY,
  ReasonCode.TRANSITIVE_NO_EXPLOIT,
  ReasonCode.DIRECT_UNPATCHED,
  ReasonCode.NO_KNOWN_VULNERABILITY,
  ReasonCode.EXEMPTED,
  ReasonCode.DEPRECATED_PACKAGE,
]);

/**
 * Parse the --fail-on argument.
 * Validates each code against ReasonCode and exits with code 1 before any
 * scan runs if an invalid code is encountered.
 */
function parseFailOnCodes(raw: string | undefined): readonly ReasonCode[] {
  if (raw === undefined) return [];
  const codes = raw.split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  const invalid = codes.filter((c) => !(VALID_REASON_CODES as readonly string[]).includes(c));
  if (invalid.length > 0) {
    console.error(
      `Invalid --fail-on code: "${invalid[0]}". Valid codes: ${VALID_REASON_CODES.join(', ')}`
    );
    process.exit(1);
  }
  return codes as readonly ReasonCode[];
}

/** ────────────────────────────────────────────────────────────────────────────
 * parseScanOptions
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Parse raw CLI argv and return a validated ScanOptions object.
 *
 * Validation order:
 *   1. Conflicting flags (--offline + --force-refresh) → ConflictingFlagsError
 *   2. --fail-on invalid ReasonCode → exit 1 (caught by calling layer)
 *   3. --cache-ttl <= 0             → exit 1
 *
 * `now` is created once here and passed to all time-dependent logic.
 */
export function parseScanOptions(argv: readonly string[]): ScanOptions {
  let lockfile = './package-lock.json';
  let pkgJson = './package.json';
  let failOnRaw: string | undefined;
  let dryRun = false;
  let outputSarif: string | undefined;
  let policyPath: string | undefined;
  let offline = false;
  let forceRefresh = false;
  let cacheTtlRaw: string | undefined;

  const args = [...argv];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--lockfile' || arg === '-l') {
      lockfile = args[++i] ?? lockfile;
    } else if (arg === '--pkg' || arg === '-p') {
      pkgJson = args[++i] ?? pkgJson;
    } else if (arg === '--fail-on') {
      failOnRaw = args[++i];
    } else if (arg === '--dry-run' || arg === '--dryrun') {
      dryRun = true;
    } else if (arg.startsWith('--fail-on=')) {
      failOnRaw = arg.slice('--fail-on='.length);
    } else if (arg === '--dry-run=true' || arg === '--dryrun=true') {
      dryRun = true;
    } else if (arg === '--output-sarif') {
      outputSarif = args[++i];
    } else if (arg.startsWith('--output-sarif=')) {
      outputSarif = arg.slice('--output-sarif='.length);
    } else if (arg === '--policy') {
      policyPath = args[++i];
    } else if (arg.startsWith('--policy=')) {
      policyPath = arg.slice('--policy='.length);
    } else if (arg === '--offline') {
      offline = true;
    } else if (arg === '--force-refresh') {
      forceRefresh = true;
    } else if (arg === '--cache-ttl') {
      cacheTtlRaw = args[++i];
    } else if (arg.startsWith('--cache-ttl=')) {
      cacheTtlRaw = arg.slice('--cache-ttl='.length);
    }
  }

  // ── Conflict guard: --offline + --force-refresh cannot coexist ───────────
  if (offline && forceRefresh) {
    throw new ConflictingFlagsError('--offline and --force-refresh');
  }

  // ── Validate --fail-on codes ───────────────────────────────────────────────
  const failOn = parseFailOnCodes(failOnRaw);

  // ── Validate --cache-ttl ───────────────────────────────────────────────────
  const ttlOverrideMs: number = (() => {
    if (cacheTtlRaw === undefined) return 0;
    const hours = Number(cacheTtlRaw);
    if (!Number.isFinite(hours) || hours <= 0) {
      console.error(`--cache-ttl must be a positive number of hours, got: "${cacheTtlRaw}"`);
      process.exit(1);
    }
    // Convert hours → milliseconds, rounding to avoid floating-point noise
    return Math.round(hours * 3_600_000);
  })();

  return Object.freeze({
    lockfile,
    pkgJson,
    failOn,
    dryRun,
    outputSarif,
    policyPath,
    offline,
    forceRefresh,
    ttlOverrideMs,
    now: new Date(),
  });
}