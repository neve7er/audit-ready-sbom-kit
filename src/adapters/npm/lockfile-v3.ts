/**
 * NPM lockfileVersion 3 parser.
 * Maps the lockfile `packages` object to CycloneDX Components.
 *
 * lockfileVersion 3 structure (npm v9+):
 * {
 *   "lockfileVersion": 3,
 *   "packages": {
 *     "": { root package },
 *     "node_modules/pkg-a": { name: "pkg-a", version: "1.0.0", dev: true },
 *     "node_modules/@scope/pkg-b": { name: "@scope/pkg-b", version: "2.0.0" }
 *   }
 * }
 *
 * lockfileVersion 3 is very similar to version 2 — both use the `packages` key.
 * The main difference is v3 removed some backward-compatibility fields and
 * dependencies are always in packages.
 */

import type { Component, ComponentType, ComponentScope, ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { buildPurl } from '../../core/utils/purl.js';

/** Raw package entry from lockfileVersion 3 packages object */
interface LockfilePackageEntry {
  /** Package name (may differ from the path key) */
  name?: string;
  /** Package version */
  version?: string;
  /** Whether this is a dev dependency */
  dev?: boolean;
  /** Whether this is an optional dependency */
  optional?: boolean;
  /** Resolved URL */
  resolved?: string;
  /** Integrity hash */
  integrity?: string;
  /** License field */
  license?: string;
}

/** The full package-lock.json structure for version 3 */
export interface LockfileV3 {
  readonly lockfileVersion: 3;
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

  // Determine scope: dev dependencies get excluded, optional gets optional
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
    vulnerabilities: [],
    arTriage: undefined
  };
}

/**
 * Parse lockfileVersion 3 packages object into Component[].
 * Skips the root entry (key "").
 * Returns flat list.
 */
export function parseLockfileV3(lockfile: LockfileV3): readonly Component[] {
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