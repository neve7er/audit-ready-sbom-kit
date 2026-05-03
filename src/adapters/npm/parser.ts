/**
 * NPM lockfile parser entry point.
 * Detects lockfile version and dispatches to the appropriate normalizer.
 */

import type { Component } from '../../core/sbom/cyclonedx/model.js';
import { UnsupportedLockfileVersionError } from '../../utils/errors.js';
import { normalizeV1, normalizeV2, normalizeV3 } from './normalizer.js';

/** Supported lockfile versions */
const SUPPORTED = [1, 2, 3] as const;

/**
 * Parse a raw lockfile JSON object into normalized Component[].
 *
 * @param rawLockfile - The parsed JSON content of package-lock.json
 * @throws UnsupportedLockfileVersionError if version is not supported
 */
export function parse(rawLockfile: unknown): readonly Component[] {
  if (!isLockfileObject(rawLockfile)) {
    throw new UnsupportedLockfileVersionError(0, SUPPORTED);
  }

  switch (rawLockfile.lockfileVersion) {
    case 1:
      return normalizeV1(rawLockfile as Parameters<typeof normalizeV1>[0]);
    case 2:
      return normalizeV2(rawLockfile as Parameters<typeof normalizeV2>[0]);
    case 3:
      return normalizeV3(rawLockfile as Parameters<typeof normalizeV3>[0]);
    default:
      throw new UnsupportedLockfileVersionError(rawLockfile.lockfileVersion, SUPPORTED);
  }
}

/** @deprecated Use parse() — kept for backward compatibility */
export const parseLockfile = parse;

function isLockfileObject(obj: unknown): obj is { lockfileVersion: number } {
  return typeof obj === 'object' && obj !== null && 'lockfileVersion' in obj
    && typeof (obj as Record<string, unknown>).lockfileVersion === 'number';
}