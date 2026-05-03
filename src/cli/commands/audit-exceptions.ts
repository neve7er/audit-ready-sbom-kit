/**
 * audit-exceptions command.
 * Validates exception records in .audit-policy.json and reports expiry status.
 * Groups outputs into: Active | Expiring Soon (≤30 days) | Expired.
 * Exits with code 1 if any expired exception exists.
 */

import { readJsonFile } from '../../utils/fs.js';
import { isExceptionValid, isExceptionExpired, type Exception } from '../../core/policy/exceptions.js';

interface AuditExceptionsOptions {
  readonly policyPath: string;
}

interface GroupedExceptions {
  valid: readonly Exception[];
  expiringSoon: readonly Exception[];
  expired: readonly Exception[];
  invalid: readonly InvalidException[];
}

interface InvalidException {
  readonly exception: Exception;
  readonly reason: string;
}

const EXPIRY_WARN_DAYS = 30;

function groupExceptions(
  exceptions: readonly Exception[],
  now: Date
): GroupedExceptions {
  const valid: Exception[] = [];
  const expiringSoon: Exception[] = [];
  const expired: Exception[] = [];
  const invalid: InvalidException[] = [];

  for (const exc of exceptions) {
    if (!isExceptionValid(exc)) {
      invalid.push({ exception: exc, reason: buildInvalidReason(exc) });
      continue;
    }

    if (isExceptionExpired(exc, now)) {
      expired.push(exc);
    } else {
      const msUntilExpiry = Date.parse(exc.expires_at) - now.getTime();
      const daysUntilExpiry = msUntilExpiry / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry <= EXPIRY_WARN_DAYS) {
        expiringSoon.push(exc);
      } else {
        valid.push(exc);
      }
    }
  }

  return {
    valid: Object.freeze(valid),
    expiringSoon: Object.freeze(expiringSoon),
    expired: Object.freeze(expired),
    invalid: Object.freeze(invalid),
  };
}

function buildInvalidReason(exc: Exception): string {
  const reasons: string[] = [];
  if (exc.reason.length < 20) reasons.push('reason < 20 characters');
  if (exc.approved_by.trim().length === 0) reasons.push('approved_by is empty');
  const parsed = Date.parse(exc.expires_at);
  if (isNaN(parsed)) reasons.push('expires_at is not valid ISO 8601');
  else if (exc.reason.length >= 20 && exc.approved_by.trim().length > 0) reasons.push('unknown validation error');
  return reasons.join('; ') || 'unknown';
}

function printGroups(groups: GroupedExceptions): void {
  if (groups.valid.length > 0) {
    console.log(`\n✅ Active (${groups.valid.length})`);
    for (const exc of groups.valid) {
      console.log(`  [${exc.id}] ${exc.purl} → ${exc.reasonCode} (expires ${exc.expires_at})`);
    }
  }

  if (groups.expiringSoon.length > 0) {
    console.log(`\n⚠ Expiring soon (${groups.expiringSoon.length}) — within ${EXPIRY_WARN_DAYS} days`);
    for (const exc of groups.expiringSoon) {
      console.log(`  [${exc.id}] ${exc.purl} → ${exc.reasonCode} (expires ${exc.expires_at})`);
    }
  }

  if (groups.expired.length > 0) {
    console.log(`\n✖ Expired (${groups.expired.length}) — must be removed or renewed`);
    for (const exc of groups.expired) {
      console.log(`  [${exc.id}] ${exc.purl} → ${exc.reasonCode} (expired ${exc.expires_at})`);
    }
  }

  if (groups.invalid.length > 0) {
    console.log(`\n⚠ Invalid (${groups.invalid.length}) — structural validation failed`);
    for (const { exception: exc, reason } of groups.invalid) {
      console.log(`  [${exc.id}] ${exc.purl} — ${reason}`);
    }
  }
}

export async function auditExceptionsCommand(
  options: AuditExceptionsOptions
): Promise<void> {
  const policy = await readJsonFile<{ exceptions?: readonly Exception[] }>(options.policyPath);
  const exceptions = policy.exceptions ?? [];

  if (exceptions.length === 0) {
    console.log(`No exceptions found in ${options.policyPath}`);
    return;
  }

  const now = new Date();
  const groups = groupExceptions(exceptions, now);

  console.log(`Audit policy: ${options.policyPath}`);
  console.log(`Total exceptions: ${exceptions.length}`);
  printGroups(groups);

  if (groups.expired.length > 0) {
    console.log(
      `\n✖ ${groups.expired.length} expired exception(s) must be removed or renewed.`
    );
    process.exit(1);
  }
}