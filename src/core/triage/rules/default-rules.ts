/**
 * Default triage rules — first-match-wins array.
 * Evaluation order is the contract.
 *
 * Each rule inspects a PackageNode and assigns a reasonCode
 * based solely on the node's own properties. No external data.
 */

import type { Component, ComponentScope, ReasonCode } from '../../sbom/cyclonedx/model.js';
import { ReasonCode as R } from '../../sbom/cyclonedx/model.js';

/** A single triage rule */
export interface Rule {
  readonly id: string;
  readonly match: (node: Component) => boolean;
  readonly reasonCode: ReasonCode;
}

/**
 * Default triage rules in evaluation order.
 *
 * 1. Package is deprecated from the registry → DEPRECATED_PACKAGE
 *    (checked before NO_KNOWN_VULNERABILITY so deprecated packages without
 *    OSV data are still surfaced as a health signal)
 * 2. No vulnerability data → NO_KNOWN_VULNERABILITY
 * 3. Dev dependency (scope === 'excluded') → DEV_DEPENDENCY_ONLY
 * 4. Optional dependency (scope === 'optional') → OPTIONAL_DEPENDENCY
 * 5. Transitive (isDirect === false) + vulnerable + required → TRANSITIVE_NO_EXPLOIT
 * 6. Direct (isDirect === true) + vulnerable + required → DIRECT_UNPATCHED
 *
 * Note: rules 5 and 6 intentionally check `scope === 'required'` to exclude
 * dev and optional packages (already handled by rules 3 and 4 above them).
 */
export const DEFAULT_RULES: readonly Rule[] = Object.freeze([
  {
    id: 'deprecated-package',
    // Deprecated without known vulnerabilities: the deprecation itself is
    // the primary health signal.  Packages with both vulns AND deprecation
    // report their vulnerability reasonCode (handled by rules 5 and 6 below).
    match: (node) => !!(
      node.deprecated !== undefined &&
      node.vulnerabilities.length === 0
    ),
    reasonCode: R.DEPRECATED_PACKAGE,
  },
  {
    id: 'no-vuln-data',
    match: (node) => node.vulnerabilities.length === 0,
    reasonCode: R.NO_KNOWN_VULNERABILITY,
  },
  {
    id: 'dev-dep',
    match: (node) => !!(node.scope === ('excluded' as ComponentScope)),
    reasonCode: R.DEV_DEPENDENCY_ONLY,
  },
  {
    id: 'optional-dep',
    match: (node) => !!(node.scope === ('optional' as ComponentScope)),
    reasonCode: R.OPTIONAL_DEPENDENCY,
  },
  {
    id: 'transitive-no-exploit',
    match: (node) => !!(
      node.vulnerabilities.length > 0 &&
      node.scope === 'required' &&
      !node.isDirect
    ),
    reasonCode: R.TRANSITIVE_NO_EXPLOIT,
  },
  {
    id: 'direct-unpatched',
    match: (node) => !!(
      node.vulnerabilities.length > 0 &&
      node.scope === 'required' &&
      node.isDirect
    ),
    reasonCode: R.DIRECT_UNPATCHED,
  },
]);