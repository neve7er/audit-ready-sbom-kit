/**
 * validate-config command.
 * Loads .audit-policy.json, reports schema errors and expired exception IDs,
 * exits 1 on either condition.
 */

import { readJsonFile } from '../../utils/fs.js';
import { loadConfig } from '../../config/loader.js';
import { isExceptionExpired, isExceptionValid } from '../../core/policy/exceptions.js';
import type { Exception } from '../../core/policy/exceptions.js';
import { ConfigValidationError } from '../../utils/errors.js';

interface ValidateConfigOptions {
  readonly policyPath: string;
}

export async function validateConfigCommand(
  options: ValidateConfigOptions
): Promise<void> {
  let raw: unknown;
  try {
    raw = await readJsonFile<unknown>(options.policyPath);
  } catch {
    console.log(`File not found: ${options.policyPath}`);
    // Not an error — missing file means defaultConfig (exit 0)
    process.exit(0);
    return;
  }

  const now = new Date();

  // Schema check (AJV via loadConfig)
  try {
    await loadConfig(options.policyPath, now);
  } catch (err) {
    if (err instanceof ConfigValidationError) {
      console.error('Schema validation failed:');
      for (const e of err.message.split('\n').slice(1)) {
        console.error(`  ${e.trim()}`);
      }
      process.exit(1);
      return;
    }
    // ExpiredExceptionError — handle below
    if (err instanceof Error && err.name === 'ExpiredExceptionError') {
      // fall through to expired handling
    } else {
      throw err;
    }
  }

  // If we get here: schema valid. Now check expired exceptions in detail.
  const config = raw as { exceptions?: readonly Exception[]; failOn?: readonly string[] };
  const exceptions = config.exceptions ?? [];

  const expired = exceptions.filter(
    (exc: Exception) => isExceptionValid(exc) && isExceptionExpired(exc, now)
  );

  if (expired.length > 0) {
    console.log(`Expired exception(s) in ${options.policyPath}:`);
    for (const exc of expired) {
      console.log(`  [${exc.id}] expires at ${exc.expires_at}`);
    }
    process.exit(1);
    return;
  }

  const validExc = exceptions.filter((exc: Exception) => isExceptionValid(exc));
  const failOnCount = (config.failOn ?? []).length;

  console.log(
    `✅ Config valid — ${validExc.length} active exception(s), ${failOnCount} fail-on code(s)`
  );
  process.exit(0);
}