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
 * 1. No vulnerability data → NO_KNOWN_VULNERABILITY
 * 2. Dev dependency (scope === 'excluded') → DEV_DEPENDENCY_ONLY
 * 3. Optional dependency (scope === 'optional') → OPTIONAL_DEPENDENCY
 * 4. Transitive (isDirect === false) + vulnerable + required → TRANSITIVE_NO_EXPLOIT
 * 5. Direct (isDirect === true) + vulnerable + required → DIRECT_UNPATCHED
 *
 * Note: rules 4 and 5 intentionally check `scope === 'required'` to exclude
 * dev and optional packages (already handled by rules 2 and 3 above them).
 */
export const DEFAULT_RULES: readonly Rule[] = Object.freeze([
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