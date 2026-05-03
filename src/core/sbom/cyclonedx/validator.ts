/**
 * CycloneDX 1.5 BOM Validator.
 * Validates BomDocument against required CycloneDX 1.5 structure.
 *
 * Note: Full schema validation with AJV is deferred due to external
 * reference resolution complexity. This validator checks essential
 * structural requirements ensuring downstream tools can consume the BOM.
 */

import type { BomDocument, Component } from './model.js';

interface ValidationError {
  readonly path: string;
  readonly message: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: readonly ValidationError[];
}

/**
 * Validate a string is non-empty.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Validate a Component has all required fields.
 */
function validateComponent(component: Component, index: number): ValidationError[] {
  const errors: ValidationError[] = [];
  const prefix = `components[${index}]`;

  if (!component.type) {
    errors.push({ path: `${prefix}.type`, message: 'Component type is required' });
  }

  if (!isNonEmptyString(component.name)) {
    errors.push({ path: `${prefix}.name`, message: 'Component name is required' });
  }

  if (!isNonEmptyString(component.version)) {
    errors.push({ path: `${prefix}.version`, message: 'Component version is required' });
  }

  if (!isNonEmptyString(component.purl)) {
    errors.push({ path: `${prefix}.purl`, message: 'PURL is required' });
  } else if (!component.purl.startsWith('pkg:')) {
    errors.push({ path: `${prefix}.purl`, message: 'PURL must start with "pkg:"' });
  }

  if (!isNonEmptyString(component['bom-ref'])) {
    errors.push({ path: `${prefix}.bom-ref`, message: 'bom-ref is required' });
  }

  return errors;
}

/**
 * Validate a BomDocument has required CycloneDX 1.5 structure.
 *
 * This validates essential requirements without full schema validation:
 * - bomFormat === "CycloneDX"
 * - specVersion === "1.5"
 * - serialNumber is present and is a valid UUID format
 * - metadata.timestamp is present
 * - metadata.tools exists and is array
 * - components exist and have required fields
 */
function validateStructure(bom: BomDocument): ValidationError[] {
  const errors: ValidationError[] = [];

  // Check bomFormat
  if (bom.bomFormat !== 'CycloneDX') {
    errors.push({
      path: '/bomFormat',
      message: `bomFormat must be "CycloneDX", got "${String(bom.bomFormat)}"`
    });
  }

  // Check specVersion
  if (bom.specVersion !== '1.5') {
    errors.push({
      path: '/specVersion',
      message: `specVersion must be "1.5", got "${String(bom.specVersion)}"`
    });
  }

  // Check serialNumber
  if (!isNonEmptyString(bom.serialNumber)) {
    errors.push({ path: '/serialNumber', message: 'serialNumber is required' });
  } else if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(bom.serialNumber)) {
    errors.push({
      path: '/serialNumber',
      message: 'serialNumber must be a valid RFC-4122 UUID with "urn:uuid:" prefix'
    });
  }

  // Check metadata
  if (!bom.metadata) {
    errors.push({ path: '/metadata', message: 'metadata is required' });
    return errors; // Can't check further without metadata
  }

  // Check timestamp
  if (!isNonEmptyString(bom.metadata.timestamp)) {
    errors.push({ path: '/metadata/timestamp', message: 'metadata.timestamp is required' });
  } else {
    // ISO 8601 regex validation
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
    if (!iso8601Regex.test(bom.metadata.timestamp)) {
      errors.push({
        path: '/metadata/timestamp',
        message: 'metadata.timestamp must be ISO 8601 format'
      });
    }
  }

  // Check tools
  if (!Array.isArray(bom.metadata.tools)) {
    errors.push({ path: '/metadata/tools', message: 'metadata.tools must be an array' });
  }

  // Check components
  if (!Array.isArray(bom.components)) {
    errors.push({ path: '/components', message: 'components must be an array' });
    return errors;
  }

  // Validate each component
  for (let i = 0; i < bom.components.length; i++) {
    const componentErrors = validateComponent(bom.components[i], i);
    errors.push(...componentErrors);
  }

  return errors;
}

/**
 * Validate a BomDocument against the CycloneDX 1.5 required structure.
 *
 * Performs structural validation without AJV schema resolution.
 * This ensures the BOM can be consumed by downstream tools.
 *
 * @param bom - The BOM document to validate
 * @returns Validation result with boolean and error details
 */
export function validateBom(bom: BomDocument): ValidationResult {
  const errors = validateStructure(bom);

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Format validation errors for human-readable display.
 */
export function formatValidationErrors(errors: readonly ValidationError[]): string {
  return errors.map((e) => `  - ${e.path}: ${e.message}`).join('\n');
}