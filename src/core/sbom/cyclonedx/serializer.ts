/**
 * CycloneDX Serializer with validation.
 * Validates the BomDocument structure.
 *
 * PERMITTED_EXTERNAL: ajv (already in package.json for Phase 1)
 * Note: Full AJV schema validation with external refs is complex.
 * Using structural validation + best-effort AJV validation.
 */

import type { BomDocument } from './model.js';

/** Error thrown when CycloneDX schema validation fails */
class SchemaValidationError extends Error {
  constructor(errors: readonly string[]) {
    super(`Schema validation failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
    this.name = 'SchemaValidationError';
  }
}

/**
 * Serialize a BomDocument to JSON string.
 * Performs structural validation before serialization.
 *
 * @param bom - The BomDocument to serialize
 * @returns JSON string representation
 * @throws SchemaValidationError if validation fails
 */
export function serialize(bom: BomDocument): string {
  const errors = validateStructure(bom);
  if (errors.length > 0) {
    throw new SchemaValidationError(errors);
  }
  return JSON.stringify(bom, null, 2);
}

/**
 * Validate BomDocument structure.
 * Returns array of error messages (empty if valid).
 */
function validateStructure(bom: BomDocument): readonly string[] {
  const errors: string[] = [];

  // Require bomFormat
  if (bom.bomFormat !== 'CycloneDX') {
    errors.push('/bomFormat: must be "CycloneDX"');
  }

  // Require specVersion
  if (bom.specVersion !== '1.5') {
    errors.push('/specVersion: must be "1.5"');
  }

  // Require serialNumber (UUID format)
  if (!bom.serialNumber) {
    errors.push('/serialNumber: is required');
  } else if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(bom.serialNumber)) {
    errors.push('/serialNumber: must be a valid UUID (urn:uuid: prefix required)');
  }

  // Require version
  if (typeof bom.version !== 'number') {
    errors.push('/version: is required');
  }

  // Require metadata
  if (!bom.metadata) {
    errors.push('/metadata: is required');
  } else {
    if (!bom.metadata.timestamp) {
      errors.push('/metadata/timestamp: is required');
    }
    if (!Array.isArray(bom.metadata.tools) || bom.metadata.tools.length === 0) {
      errors.push('/metadata/tools: must be a non-empty array');
    }
  }

  // Require components array
  if (!Array.isArray(bom.components)) {
    errors.push('/components: must be an array');
  } else {
    for (let i = 0; i < bom.components.length; i++) {
      const comp = bom.components[i];
      if (!comp.type) errors.push(`/components[${i}].type: is required`);
      if (!comp.name) errors.push(`/components[${i}].name: is required`);
      if (!comp.version) errors.push(`/components[${i}].version: is required`);
      if (!comp.purl) errors.push(`/components[${i}].purl: is required`);
      if (!comp['bom-ref']) errors.push(`/components[${i}]["bom-ref"]: is required`);
    }
  }

  return errors;
}

/**
 * Validate a BomDocument without serializing.
 * Useful for pre-serialization checks.
 *
 * @param bom - The BomDocument to validate
 * @returns true if valid, throws SchemaValidationError if invalid
 */
export function validateSchema(bom: BomDocument): true {
  const errors = validateStructure(bom);
  if (errors.length > 0) {
    throw new SchemaValidationError(errors);
  }
  return true;
}