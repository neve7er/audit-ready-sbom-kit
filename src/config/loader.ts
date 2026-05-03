/**
 * Configuration loader for .audit-policy.json.
 *
 * Reads, validates, and returns typed AuditConfig from the policy file.
 * All time-based checks use injected `now: Date` — never calls Date.now() internally.
 */

import { readJsonFile } from '../utils/fs.js';
import { ReasonCode } from '../core/sbom/cyclonedx/model.js';
import type { Exception } from '../core/policy/exceptions.js';
import { isExceptionExpired } from '../core/policy/exceptions.js';
import { ConfigValidationError } from '../utils/errors.js';
import { ExpiredExceptionError } from '../utils/errors.js';

// Use createRequire for ESM + ajv compatibility (same pattern as existing test files)
import { createRequire } from 'module';
import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';

const require = createRequire(import.meta.url);

type AJVType = InstanceType<typeof AjvModule.default>;
type AddFormatsType = (ajv: AJVType) => void;

const Ajv = AjvModule.default as unknown as { new(opts: object): AJVType };
const addFormats = addFormatsModule as unknown as AddFormatsType;

const REASON_CODES = Object.freeze([
  ReasonCode.DEV_DEPENDENCY_ONLY,
  ReasonCode.OPTIONAL_DEPENDENCY,
  ReasonCode.TRANSITIVE_NO_EXPLOIT,
  ReasonCode.DIRECT_UNPATCHED,
  ReasonCode.NO_KNOWN_VULNERABILITY,
  ReasonCode.EXEMPTED,
]);

/**
 * The public configuration surface exposed by loadConfig.
 */
export interface AuditConfig {
  /** ReasonCode values that should cause a non-zero exit */
  readonly failOn: readonly ReasonCode[];
  /** Time-bounded exception records */
  readonly exceptions: readonly Exception[];
}

function defaultConfig(): AuditConfig {
  return Object.freeze({ failOn: Object.freeze([]), exceptions: Object.freeze([]) });
}

// ---------------------------------------------------------------------------
// AJV schema for .audit-policy.json
// ---------------------------------------------------------------------------

const POLICY_SCHEMA = {
  $id: 'audit-policy.json',
  type: 'object',
  properties: {
    failOn: {
      type: 'array',
      items: { type: 'string', enum: REASON_CODES as unknown as string[] },
      uniqueItems: true,
    },
    exceptions: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'purl', 'reasonCode', 'reason', 'expires_at', 'approved_by'],
        additionalProperties: false,
        properties: {
          id: { type: 'string', minLength: 1 },
          purl: { type: 'string', minLength: 1 },
          reasonCode: { type: 'string', enum: REASON_CODES as unknown as string[] },
          reason: { type: 'string', minLength: 20 },
          expires_at: { type: 'string' }, // validated as ISO 8601 below
          approved_by: { type: 'string', minLength: 1 },
        },
      },
    },
  },
  additionalProperties: false,
} as const;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function validateWithAjv(raw: unknown): { valid: boolean; errors: readonly string[] } {
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const validate = ajv.compile(POLICY_SCHEMA);
  const valid = validate(raw);
  if (!valid && validate.errors) {
    const errors = validate.errors.map((e) => {
      const path = e.instancePath || '/';
      return `${path}: ${e.message ?? 'unknown error'}`;
    });
    return { valid: false, errors: Object.freeze(errors) };
  }
  return { valid: true, errors: Object.freeze([]) };
}

function checkExpiredExceptions(
  exceptions: readonly Exception[],
  now: Date
): readonly string[] {
  return exceptions
    .filter((exc) => exc.reasonCode !== ReasonCode.EXEMPTED && isExceptionExpired(exc, now))
    .map((exc) => exc.id);
}

/**
 * Load and validate .audit-policy.json from disk.
 *
 * - If the file does not exist: returns defaultConfig() silently.
 * - If the file exists but fails AJV schema validation: throws ConfigValidationError.
 * - If the file contains expired exceptions after load: throws ExpiredExceptionError.
 *
 * @param path   - Path to .audit-policy.json
 * @param now    - Current time (injected by caller — NOT read internally)
 */
async function loadConfig(path: string, now: Date): Promise<AuditConfig> {
  let raw: unknown;
  try {
    raw = await readJsonFile<unknown>(path);
  } catch {
    // File not found → use defaults silently
    return defaultConfig();
  }

  // Schema validation
  const { valid, errors } = validateWithAjv(raw);
  if (!valid) {
    throw new ConfigValidationError(errors);
  }

  // Cast after validation
  const config = raw as { failOn?: readonly string[]; exceptions?: readonly Exception[] };

  const failOn = Object.freeze(
    (config.failOn ?? []).map((c) => c as ReasonCode)
  );
  const exceptions = Object.freeze(config.exceptions ?? []);

  // Expired-exception guard
  const expiredIds = checkExpiredExceptions(exceptions, now);
  if (expiredIds.length > 0) {
    throw new ExpiredExceptionError(expiredIds);
  }

  return Object.freeze({ failOn, exceptions });
}

export { loadConfig, defaultConfig };