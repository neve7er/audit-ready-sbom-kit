/**
 * Audit-Ready SBOM Kit CLI entry point.
 * Uses Commander for argument parsing and command routing.
 */

import { fileURLToPath } from 'url';
import { resolve } from 'path';
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { auditSelfCommand } from './commands/audit-self.js';
import { auditExceptionsCommand } from './commands/audit-exceptions.js';
import { initCommand } from './commands/init.js';
import { validateConfigCommand } from './commands/validate-config.js';
import { parseScanOptions, cacheClear } from './parser.js';
import { ConflictingFlagsError } from '../utils/errors.js';

const program = new Command('audit-ready');

program
  .description('Generate CycloneDX SBOM and audit-ready risk triage reports')
  .version('0.1.0-beta.3');

// Standalone flags handled before any subcommand
// --cache-clear: wipe cache and exit 0 immediately, no scan
const cacheArgs = process.argv.filter(
  (a) => a === '--cache-clear' || a === 'cache-clear',
);
if (cacheArgs.includes('--cache-clear') || cacheArgs.includes('cache-clear')) {
  await cacheClear();
}

program
  .command('scan')
  .description('Scan lockfile and generate SBOM + report')
  .option('-l, --lockfile <path>', 'Path to package-lock.json', './package-lock.json')
  .option('-p, --pkg <path>', 'Path to package.json', './package.json')
  .option('--policy <path>', 'Path to .audit-policy.json (loads exceptions)', '.audit-policy.json')
  .option('--fail-on <codes>', 'Comma-separated ReasonCode values that should fail the build')
  .option('--dry-run', 'Simulate scan without writing output files or making network calls', false)
  .option('--output-sarif <path>', 'Write SARIF 2.1.0 report to the specified path')
  .option('--offline', 'Block all network calls — exit 2 if a required cache entry is missing')
  .option('--force-refresh', 'Skip cache reads; fetch fresh data and overwrite cache with results')
  .option('--cache-ttl <hours>', 'Override the 24h cache TTL for this invocation (must be > 0)')
  .action(async (cmd) => {
    try {
      // parseScanOptions handles validation (including ConflictingFlagsError).
      // `now` is created once at this top-level call and threaded through all
      // time-dependent logic so tests can inject an arbitrary clock.
      const parsed = parseScanOptions(process.argv);
      await scanCommand({
        // Subset of ScanOptions — scan.ts only reads what it needs
        lockfile: parsed.lockfile,
        pkgJson: parsed.pkgJson,
        failOn: parsed.failOn,
        dryRun: parsed.dryRun,
        outputSarif: parsed.outputSarif,
        policyPath: parsed.policyPath,
        // New cache-oriented options
        offline: parsed.offline,
        forceRefresh: parsed.forceRefresh,
        ttlOverrideMs: parsed.ttlOverrideMs,
        now: parsed.now,
      });
    } catch (err) {
      if (err instanceof ConflictingFlagsError) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      }
      // Re-throw for the scan command's own error handling
      throw err;
    }
  });

program
  .command('audit-self')
  .description('Scan this project and produce a valid CycloneDX SBOM of itself')
  .action(async () => {
    await auditSelfCommand();
  });

program
  .command('audit-exceptions')
  .description('Audit exception records in .audit-policy.json — report and fail on expired entries')
  .option('--policy <path>', 'Path to .audit-policy.json', '.audit-policy.json')
  .action(async (cmd) => {
    await auditExceptionsCommand({ policyPath: cmd.opts().policy });
  });

program
  .command('validate-config')
  .description('Validate .audit-policy.json — checks schema and expiry dates')
  .option('--policy <path>', 'Path to .audit-policy.json', '.audit-policy.json')
  .action(async (cmd) => {
    await validateConfigCommand({ policyPath: cmd.opts().policy });
  });

// Global --init flag (runs before subcommand parse)
let initFlag = false;
const savedArgv = [...process.argv];
for (const arg of savedArgv) {
  if (arg === '--init') { initFlag = true; break; }
}

if (initFlag) {
  await initCommand();
  process.exit(0);
}

// Only parse when this module is the main entry point
const isMain = fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  program.parse();
}

export { program };