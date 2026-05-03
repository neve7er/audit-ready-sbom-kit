/**
 * NPM lockfileVersion 1 parser.
 * Maps the lockfile `dependencies` tree to CycloneDX Components.
 *
 * lockfileVersion 1 structure (npm v5/v6):
 * {
 *   "lockfileVersion": 1,
 *   "dependencies": {
 *     "lodash": {
 *       "version": "4.17.21",
 *       "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
 *       "integrity": "sha512-...",
 *       "dev": true,
 *       "optional": false,
 *       "requires": { "other-dep": "^1.0.0" },
 *       "dependencies": { "nested": { ... } }
 *     },
 *     "@scope/pkg": {
 *       "version": "2.0.0",
 *       "dev": false
 *     }
 *   }
 * }
 *
 * Note: lockfileVersion 1 has dependencies at the root level, NOT under packages.
 * We flatten the dependency tree — nested dependencies are treated as peers.
 */

import type { Component, ComponentType, ComponentScope, ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { buildPurl } from '../../core/utils/purl.js';

/** Raw dependency entry from lockfileVersion 1 */
interface LockfileV1Dependency {
  /** Package version */
  version: string;
  /** Resolved URL */
  resolved?: string;
  /** Integrity hash */
  integrity?: string;
  /** Whether this is a dev dependency */
  dev?: boolean;
  /** Whether this is an optional dependency */
  optional?: boolean;
  /** Whether this is bundled */
  bundled?: boolean;
  /** Required versions of other packages */
  requires?: { readonly [name: string]: string };
  /** Nested dependencies */
  dependencies?: { readonly [name: string]: LockfileV1Dependency };
}

/** The full package-lock.json structure for version 1 */
export interface LockfileV1 {
  readonly lockfileVersion: 1;
  readonly dependencies?: {
    readonly [name: string]: LockfileV1Dependency | undefined;
  };
}

/** Map a lockfile dependency entry to a CycloneDX Component */
function mapEntryToComponent(
  name: string,
  entry: LockfileV1Dependency
): Component | undefined {
  const version = entry.version;

  // Skip entries without version
  if (!version) {
    return undefined;
  }

  const purl = buildPurl(name, version);
  const isDev = entry.dev ?? false;
  const isOptional = entry.optional ?? false;
  const isBundled = entry.bundled ?? false;

  // Determine scope: optional > dev > bundled > required
  const scope: ComponentScope = isOptional
    ? 'optional'
    : isDev
      ? 'excluded'
      : isBundled
        ? 'optional'
        : 'required';

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

/** Collect all dependencies recursively from the tree */
function collectDependencies(
  dependencies: Readonly<Record<string, LockfileV1Dependency | undefined>>,
  seen: Set<string>
): Component[] {
  const components: Component[] = [];

  for (const [name, entry] of Object.entries(dependencies)) {
    if (!entry) {
      continue;
    }

    const purlKey = buildPurl(name, entry.version);

    // Skip duplicates
    if (seen.has(purlKey)) {
      continue;
    }
    seen.add(purlKey);

    const component = mapEntryToComponent(name, entry);
    if (component) {
      components.push(component);
    }

    // Recursively collect nested dependencies
    if (entry.dependencies) {
      const nested = collectDependencies(entry.dependencies, seen);
      components.push(...nested);
    }
  }

  return components;
}

/**
 * Parse lockfileVersion 1 dependencies into Component[].
 * Flattens the nested dependency tree into a flat list.
 * Deduplicates by PURL.
 */
export function parseLockfileV1(lockfile: LockfileV1): readonly Component[] {
  if (!lockfile.dependencies) {
    return [];
  }

  const seen = new Set<string>();
  return collectDependencies(lockfile.dependencies, seen);
}