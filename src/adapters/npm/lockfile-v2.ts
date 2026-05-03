/**
 * NPM lockfileVersion 2 parser.
 * Maps the lockfile `packages` object to CycloneDX Components.
 *
 * The lockfile structure:
 * {
 *   "lockfileVersion": 2,
 *   "packages": {
 *     "": { root package },
 *     "node_modules/pkg-a": { name: "pkg-a", version: "1.0.0", dev: true },
 *     "node_modules/@scope/pkg-b": { name: "@scope/pkg-b", version: "2.0.0" }
 *   }
 * }
 *
 * We skip the root entry (key "") and map node_modules/* entries to Components.
 */

import type { Component, ComponentType, ComponentScope, ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { buildPurl } from '../../core/utils/purl.js';

/** Raw package entry from lockfileVersion 2 packages object */
interface LockfilePackageEntry {
  /** Package name (may differ from the path key) */
  name?: string;
  /** Package version */
  version?: string;
  /** Whether this is a dev dependency */
  dev?: boolean;
  /** Whether this is an optional dependency */
  optional?: boolean;
  /** Resolved URL (unused in MVP) */
  resolved?: string;
  /** Integrity hash (unused in MVP) */
  integrity?: string;
  /** License field (unused in MVP - will be populated in Phase 1) */
  license?: string;
}

/** The full package-lock.json structure for version 2 */
export interface LockfileV2 {
  readonly lockfileVersion: 2;
  readonly packages: {
    readonly [path: string]: LockfilePackageEntry | undefined;
  };
}

/** Extract package name from lockfile entry */
function extractName(path: string, entry: LockfilePackageEntry): string | undefined {
  // Use explicit name field if present, otherwise derive from path
  if (entry.name) {
    return entry.name;
  }
  // Derive from path: node_modules/@scope/pkg -> @scope/pkg
  // or node_modules/pkg -> pkg
  const match = path.match(/^node_modules\/(.+)$/);
  return match ? match[1] : undefined;
}

/** Map a lockfile package entry to a CycloneDX Component */
function mapEntryToComponent(
  path: string,
  entry: LockfilePackageEntry
): Component | undefined {
  const name = extractName(path, entry);
  const version = entry.version;

  // Skip entries without name or version
  if (!name || !version) {
    return undefined;
  }

  const purl = buildPurl(name, version);
  const isDev = entry.dev ?? false;
  const isOptional = entry.optional ?? false;

  // Determine scope: dev dependencies get special scope, optional is always optional
  const scope: ComponentScope = isOptional ? 'optional' : isDev ? 'excluded' : 'required';

  // Determine reasonCode based on dependency type
  const reasonCode: ReasonCode = isDev
    ? 'DEV_DEPENDENCY_ONLY' as ReasonCode
    : isOptional
    ? 'OPTIONAL_DEPENDENCY' as ReasonCode
    : 'NO_KNOWN_VULNERABILITY' as ReasonCode;

  return {
    type: 'library' as ComponentType,
    name,
    version,
    purl,
    'bom-ref': purl,
    reasonCode,
    scope,
    // vulnerabilities and arTriage are populated downstream
    vulnerabilities: [],
    arTriage: undefined
  };
}

/**
 * Parse lockfileVersion 2 packages object into Component[].
 * Skips the root entry (key "").
 * Returns flat list — tree reconstruction is out of scope.
 */
export function parseLockfileV2(lockfile: LockfileV2): readonly Component[] {
  const components: Component[] = [];

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    // Skip root entry
    if (path === '') {
      continue;
    }

    // Skip undefined entries
    if (!entry) {
      continue;
    }

    const component = mapEntryToComponent(path, entry);
    if (component) {
      components.push(component);
    }
  }

  return components;
}