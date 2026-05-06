/**
 * Error taxonomy for structured error handling.
 * All errors extend native Error for compatibility.
 */

/** Base error class for all audit-ready errors */
export class AuditReadyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** Error thrown when parsing lockfile fails */
export class ParseError extends AuditReadyError {}

/** Error thrown for unsupported lockfile versions */
export class UnsupportedLockfileVersionError extends ParseError {
  constructor(version: number, supportedVersions: readonly number[]) {
    super(
      `Unsupported lockfile version: ${version}. ` +
      `Supported versions: ${supportedVersions.join(', ')}.`
    );
  }
}

/** Error thrown when file operations fail */
export class FileSystemError extends AuditReadyError {}

/** Error thrown for network-related failures */
export class NetworkError extends AuditReadyError {}

/** Error thrown for validation failures */
export class ValidationError extends AuditReadyError {}

/** Error thrown for cache-related errors */
export class CacheError extends AuditReadyError {}

/** Error thrown when no triage rule matches a PackageNode */
export class UnmatchedTriageRuleError extends AuditReadyError {
  constructor(purl: string) {
    super(`No triage rule matched package: ${purl}`);
  }
}

/** Error thrown when CycloneDX schema validation fails */
export class SchemaValidationError extends AuditReadyError {
  constructor(errors: readonly string[]) {
    super(`Schema validation failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
}

/** Error thrown when .audit-policy.json fails schema validation */
export class ConfigValidationError extends AuditReadyError {
  constructor(errors: readonly string[]) {
    super(`Config validation failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
}

/** Error thrown when .audit-policy.json contains expired exceptions */
export class ExpiredExceptionError extends AuditReadyError {
  constructor(expiredIds: readonly string[]) {
    super(
      `Expired exception(s): ${expiredIds.join(', ')}. ` +
      `Remove or renew these entries before running a scan.`
    );
  }
}

/** Error thrown when mutually exclusive CLI flags are used together */
export class ConflictingFlagsError extends AuditReadyError {
  constructor(flags: string) {
    super(`Conflicting flags: ${flags}`);
  }
}