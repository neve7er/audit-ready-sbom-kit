/**
 * CLI argument parser and scan options interface.
 * All CLI validation happens here — the scan never starts with invalid input.
 */

import { ReasonCode } from '../core/sbom/cyclonedx/model.js';

/** Scan command options produced by the CLI parser */
export interface ScanOptions {
  readonly lockfile: string;
  readonly pkgJson: string;
  readonly failOn: readonly ReasonCode[];
  readonly dryRun: boolean;
  readonly outputSarif?: string;
  /** Path to .audit-policy.json containing exceptions and triage rules */
  readonly policyPath?: string;
}

/** Valid ReasonCode values as a string array */
const VALID_REASON_CODES: readonly string[] = Object.freeze([
  ReasonCode.DEV_DEPENDENCY_ONLY,
  ReasonCode.OPTIONAL_DEPENDENCY,
  ReasonCode.TRANSITIVE_NO_EXPLOIT,
  ReasonCode.DIRECT_UNPATCHED,
  ReasonCode.NO_KNOWN_VULNERABILITY,
  ReasonCode.EXEMPTED,
]);

/**
 * Parse the --fail-on argument.
 * Validates each code against the ReasonCode enum and exits with code 1
 * before any scan runs if an invalid code is encountered.
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

/**
 * Parse raw CLI argv and return a validated ScanOptions object.
 * Exits immediately with code 1 for any invalid --fail-on value.
 */
export function parseScanOptions(argv: readonly string[]): ScanOptions {
  let lockfile = './package-lock.json';
  let pkgJson = './package.json';
  let failOnRaw: string | undefined;
  let dryRun = false;
  let outputSarif: string | undefined;
  let policyPath: string | undefined;

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
    }
  }

  const failOn = parseFailOnCodes(failOnRaw);

  return Object.freeze({ lockfile, pkgJson, failOn, dryRun, outputSarif, policyPath });
}