/**
 * Lockfile normalizers — absorb v1/v2/v3 structural differences.
 * Each normalizer returns a flat, frozen PackageNode[].
 */

import type { Component, ComponentType, ComponentScope, ReasonCode } from '../../core/sbom/cyclonedx/model.js';
import { ReasonCode as R } from '../../core/sbom/cyclonedx/model.js';
import { buildPurl } from '../../core/utils/purl.js';

/** PackageNode is the normalized form — same shape across all lockfile versions */
export interface PackageNode extends Component {
  /** Direct dependency of the root project (true for top-level entries, false for transitive) */
  readonly isDirect: boolean;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function freeze<T>(obj: T): Readonly<T> {
  return Object.freeze(obj);
}

function makeNode(
  name: string,
  version: string,
  dev: boolean,
  optional: boolean,
  isDirect: boolean
): PackageNode {
  const purl = buildPurl(name, version);
  const scope: ComponentScope = optional
    ? 'optional'
    : dev
      ? 'excluded'
      : 'required';
  const reasonCode: ReasonCode = dev
    ? R.DEV_DEPENDENCY_ONLY
    : optional
      ? R.OPTIONAL_DEPENDENCY
      : R.NO_KNOWN_VULNERABILITY;

  return Object.freeze<PackageNode>({
    type: 'library' as ComponentType,
    name,
    version,
    purl,
    'bom-ref': purl,
    reasonCode,
    scope,
    vulnerabilities: Object.freeze([]),
    isDirect,
  });
}

// ---------------------------------------------------------------------------
// v1 — recursive `dependencies` tree
// ---------------------------------------------------------------------------

interface V1Dep {
  version: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, V1Dep>;
}

export function normalizeV1(lockfile: { lockfileVersion: 1; dependencies?: Record<string, V1Dep> }): readonly PackageNode[] {
  if (!lockfile.dependencies) return freeze([]);

  const seen = new Set<string>();
  const nodes: PackageNode[] = [];

  function walk(deps: Record<string, V1Dep>, direct: boolean): void {
    for (const [name, dep] of Object.entries(deps)) {
      if (!dep?.version) continue;
      if (seen.has(buildPurl(name, dep.version))) continue;
      seen.add(buildPurl(name, dep.version));
      nodes.push(makeNode(name, dep.version, dep.dev ?? false, dep.optional ?? false, direct));
      if (dep.dependencies) walk(dep.dependencies, false);
    }
  }

  walk(lockfile.dependencies, true);
  return freeze(nodes);
}

// ---------------------------------------------------------------------------
// v2 — flat `packages` with path keys
// ---------------------------------------------------------------------------

interface V2Entry {
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
}

export function normalizeV2(lockfile: { lockfileVersion: 2; packages: Record<string, V2Entry> }): readonly PackageNode[] {
  const nodes: PackageNode[] = [];

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === '') continue; // skip root
    if (!entry?.version) continue;

    const name = entry.name ?? deriveName(path);
    if (!name) continue;

    // Direct if exactly one path segment under node_modules/ (e.g. node_modules/lodash)
    // Transitive if nested deeper (e.g. node_modules/pkg/node_modules/nested)
    const isDirect = deriveIsDirect(path);

    nodes.push(makeNode(name, entry.version, entry.dev ?? false, entry.optional ?? false, isDirect));
  }

  return freeze(nodes);
}

// ---------------------------------------------------------------------------
// v3 — identical structure to v2
// ---------------------------------------------------------------------------

interface V3Entry {
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
}

export function normalizeV3(lockfile: { lockfileVersion: 3; packages: Record<string, V3Entry> }): readonly PackageNode[] {
  const nodes: PackageNode[] = [];

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === '') continue; // skip root
    if (!entry?.version) continue;

    const name = entry.name ?? deriveName(path);
    if (!name) continue;

    const isDirect = deriveIsDirect(path);

    nodes.push(makeNode(name, entry.version, entry.dev ?? false, entry.optional ?? false, isDirect));
  }

  return freeze(nodes);
}

// ---------------------------------------------------------------------------
// Shared path → name derivation
// ---------------------------------------------------------------------------

function deriveName(path: string): string | undefined {
  const m = path.match(/^node_modules\/(.+)$/);
  return m?.[1];
}

/**
 * Returns true if the package is direct (installed at the top level of node_modules),
 * false if it is a transitive dependency (nested under another package's node_modules).
 * e.g.  node_modules/lodash          → true  (1 segment after node_modules/)
 *       node_modules/pkg/node_modules/nested → false (nested path)
 */
function deriveIsDirect(path: string): boolean {
  const m = path.match(/^node_modules\/([^/]+)(\/.*)?$/);
  // If it doesn't match the pattern, treat as non-direct for safety
  return m?.[2] === undefined;
}