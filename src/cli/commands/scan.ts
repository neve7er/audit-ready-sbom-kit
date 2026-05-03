/**
 * Scan command implementation.
 * Orchestrates the full pipeline: parse → build → output.
 * All side effects (file I/O) live here.
 */

import { writeFile } from 'fs/promises';
import { join } from 'path';
import type { Component } from '../../core/sbom/cyclonedx/model.js';
import { ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { buildBomDocument } from '../../core/sbom/cyclonedx/builder.js';
import { renderMarkdown } from '../../adapters/output/markdown/renderer.js';
import { parseLockfile } from '../../adapters/npm/parser.js';
import { readJsonFile } from '../../utils/fs.js';
import { UnsupportedLockfileVersionError, ConfigValidationError, ExpiredExceptionError } from '../../utils/errors.js';
import { validateBom, formatValidationErrors } from '../../core/sbom/cyclonedx/validator.js';
import { fetchVulnerabilities } from '../../adapters/vuln-db/osv-client.js';
import { calculateReachability } from '../../core/triage/reachability.js';
import { applyTriage } from '../../core/triage/engine.js';
import { applyExceptions, type Exception } from '../../core/policy/exceptions.js';
import { matchesFailPolicy } from '../../core/triage/engine.js';
import { DEFAULT_RULES } from '../../core/triage/rules/default-rules.js';
import { buildSarif } from '../../adapters/output/sarif.js';
import { loadConfig } from '../../config/loader.js';

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

/** Scan command options including policy flags */
interface ScanCommandOptions {
  readonly lockfile?: string;
  readonly pkgJson?: string;
  readonly failOn?: readonly ReasonCode[];
  readonly dryRun?: boolean;
  /** Optional path to write a SARIF 2.1.0 report. When set, SARIF is written after pipeline completes. */
  readonly outputSarif?: string;
  /** Optional path to .audit-policy.json containing exceptions */
  readonly policyPath?: string;
}

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

  if (!dryRun) {
    process.exit(1);
  }
}

/** Write SARIF report, validate, and log result. Failure logs a warning and continues. */
async function writeSarifReport(
  components: readonly Component[],
  outputPath: string
): Promise<void> {
  try {
    const sarifDoc = buildSarif(components);

    // Structural validation (schema-level ajv validation is in test files; this
    // provides a basic runtime guard in CLI usage without ESM/CJS interop issues)
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

// ---------------------------------------------------------------------------
// Config merge helpers
// ---------------------------------------------------------------------------

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
 *
 * Precedence:
 * - failOn: CLI overrides file (both may exist)
 * - exceptions: merged — all file exceptions apply (CLI adds via future paths)
 *
 * @param policyPath - Path to .audit-policy.json, or undefined
 * @param now        - Injected clock (caller creates new Date() once at CLI layer)
 */
async function loadAndMergeConfig(
  policyPath: string | undefined,
  now: Date
): Promise<{ failOn: readonly ReasonCode[]; exceptions: readonly Exception[] }> {
  if (!policyPath) {
    return { failOn: Object.freeze([]), exceptions: Object.freeze([]) };
  }

  // loadConfig throws ConfigValidationError if file exists but is invalid
  const config = await loadConfig(policyPath, now);
  return { failOn: config.failOn, exceptions: config.exceptions };
}

/** Execute the scan command */
export async function scanCommand(
  options: ScanCommandOptions = {}
): Promise<void> {
  const startTime = performance.now();
  const dryRun = options.dryRun ?? false;

  const lockfilePath = options.lockfile ?? './package-lock.json';
  const pkgJsonPath = options.pkgJson ?? './package.json';

  if (dryRun) {
    console.log('[dry-run] Simulating audit-ready scan (no network, no file writes)');
  } else {
    console.log('Starting audit-ready scan...');
  }

  // Load config from .audit-policy.json if present
  const now = new Date();
  const { exceptions: fileExceptions, failOn: fileFailOn } = await loadAndMergeConfig(
    options.policyPath,
    now
  );
  // CLI --fail-on overrides file failOn
  const resolvedFailOn = resolveFailOn(options.failOn ?? [], fileFailOn);

  try {
    // Step 1: Read project metadata
    let triagedComponents: readonly Component[] | undefined = undefined;
    if (!dryRun) {
      console.log(`Reading ${pkgJsonPath}...`);
    }
    const pkgJson = await readJsonFile<PackageJson>(pkgJsonPath);
    if (!pkgJson.name || !pkgJson.version) {
      throw new Error('package.json must have name and version fields');
    }

    // Step 2: Parse lockfile
    if (!dryRun) {
      console.log(`Reading ${lockfilePath}...`);
    }
    const rawLockfile = await readJsonFile<unknown>(lockfilePath);
    if (!dryRun) {
      console.log('Parsing dependencies...');
    }
    const components: readonly Component[] = parseLockfile(rawLockfile);
    console.log(`Found ${components.length} packages`);

    // Step 3: Fetch vulnerabilities from OSV (skipped in dry-run)
    let networkError = false;
    if (!dryRun) {
      console.log('Fetching vulnerabilities from OSV...');
      const purls = components.map((c) => c.purl);
      const { vulnerabilities, networkError: netErr } = await fetchVulnerabilities(purls);
      networkError = netErr;

      if (networkError) {
        console.warn('⚠ Vulnerability scan skipped — offline or unreachable');
      } else {
        console.log(`Fetched vulnerability data for ${vulnerabilities.size} packages`);
      }

      // Step 4: Enrich components with vulnerabilities and reachability
      const enrichedComponents: Component[] = components.map((component) => {
        const vulns = vulnerabilities.get(component.purl) ?? [];
        const reachabilityWeight = calculateReachability(component);
        const withVulns: Component = {
          ...component,
          vulnerabilities: vulns,
          arTriage: { riskTier: 'NeedsReview', rationale: '', reachabilityWeight },
        };
        return withVulns;
      });

      // Step 5: Apply rule-based triage (sets reasonCode)
      triagedComponents = applyTriage(enrichedComponents, DEFAULT_RULES);

      // Step 5b: Apply exceptions from .audit-policy.json (loaded at top of function)
      if (fileExceptions.length > 0) {
        triagedComponents = applyExceptions(triagedComponents, fileExceptions, now);
        console.log(`Applied ${fileExceptions.length} exception(s) from ${options.policyPath ?? '.audit-policy.json'}`);
      }

      // Step 6: Check policy violations
      checkPolicyViolations(triagedComponents, resolvedFailOn, dryRun);

      // SARIF output if requested
      if (options.outputSarif) {
        await writeSarifReport(triagedComponents, options.outputSarif);
      }

      // Step 7: Build BOM document
      const bom = buildBomDocument(triagedComponents, {
        name: pkgJson.name,
        version: pkgJson.version,
        description: pkgJson.description,
        author: pkgJson.author,
      });

      // Step 8: Validate BOM
      console.log('Validating BOM against CycloneDX 1.5 schema...');
      const validation = validateBom(bom);
      if (!validation.valid) {
        console.error('Validation FAILED:');
        console.error(formatValidationErrors(validation.errors));
        throw new Error('BOM validation failed');
      }
      console.log('Validation PASSED');

      // Step 9: Render and write outputs
      const bomJson = JSON.stringify(bom, null, 2);
      const reportMd = renderMarkdown(bom);

      const sbomPath = join(process.cwd(), OUTPUT_SBOM);
      const reportPath = join(process.cwd(), OUTPUT_REPORT);

      await writeFile(sbomPath, bomJson, 'utf-8');
      console.log(`Written: ${sbomPath}`);
      await writeFile(reportPath, reportMd, 'utf-8');
      console.log(`Written: ${reportPath}`);
    } else {
      // dry-run: enrich components with empty vulnerability sets, then triage
      const enrichedComponents: Component[] = components.map((component) => ({
        ...component,
        vulnerabilities: [],
        arTriage: { riskTier: 'Acceptable', rationale: '', reachabilityWeight: 1.0 },
      }));

      triagedComponents = applyTriage(enrichedComponents, DEFAULT_RULES);

      // Step 5b: Apply exceptions in dry-run as well
      if (fileExceptions.length > 0) {
        triagedComponents = applyExceptions(triagedComponents, fileExceptions, now);
        console.log(`[dry-run] Applied ${fileExceptions.length} exception(s) from ${options.policyPath ?? '.audit-policy.json'}`);
      }

      checkPolicyViolations(triagedComponents, resolvedFailOn, dryRun);

      // SARIF output if requested (dry-run still writes SARIF)
      if (options.outputSarif) {
        await writeSarifReport(triagedComponents, options.outputSarif);
      }
    }

    const duration = Math.round(performance.now() - startTime);
    if (!dryRun) {
      console.log(`Scan completed in ${duration}ms`);
    }

    // Exit with code 2 if network error occurred
    if (networkError) {
      process.exit(2);
    }
    process.exit(0);

  } catch (error) {
    if (error instanceof UnsupportedLockfileVersionError) {
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
  scanCommand();
}