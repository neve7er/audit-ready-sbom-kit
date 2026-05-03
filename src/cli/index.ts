/**
 * Audit-Ready SBOM Kit CLI entry point.
 * Uses Commander for argument parsing and command routing.
 *
 * This module can be required from the bin wrapper (bin/audit-ready.js) without
 * triggering argument parsing at require-time — program.parse() only runs when
 * this is the main entry point (detected via import.meta.url).
 */

import { fileURLToPath } from 'url';
import { resolve } from 'path';
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { auditSelfCommand } from './commands/audit-self.js';
import { auditExceptionsCommand } from './commands/audit-exceptions.js';
import { initCommand } from './commands/init.js';
import { validateConfigCommand } from './commands/validate-config.js';
import { parseScanOptions } from './parser.js';

const program = new Command('audit-ready');

program
  .description('Generate CycloneDX SBOM and audit-ready risk triage reports')
  .version('0.1.0-beta.2');

program
  .command('scan')
  .description('Scan lockfile and generate SBOM + report')
  .option('-l, --lockfile <path>', 'Path to package-lock.json', './package-lock.json')
  .option('-p, --pkg <path>', 'Path to package.json', './package.json')
  .option('--policy <path>', 'Path to .audit-policy.json (loads exceptions)', '.audit-policy.json')
  .option('--fail-on <codes>', 'Comma-separated ReasonCode values that should fail the build')
  .option('--dry-run', 'Simulate scan without writing output files or making network calls', false)
  .option('--output-sarif <path>', 'Write SARIF 2.1.0 report to the specified path')
  .action(async () => {
    const parsed = parseScanOptions(process.argv);
    await scanCommand({
      lockfile: parsed.lockfile,
      pkgJson: parsed.pkgJson,
      failOn: parsed.failOn,
      dryRun: parsed.dryRun,
      outputSarif: parsed.outputSarif,
      policyPath: parsed.policyPath,
    });
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

// Only parse when this module is the main entry point — not when required by bin/audit-ready.js
// fileURLToPath normalizes file:///C:/... → C:\... on Windows so it compares reliably against
// resolve(process.argv[1]) which already returns OS-native path format.
const isMain = fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  program.parse();
}

export { program };