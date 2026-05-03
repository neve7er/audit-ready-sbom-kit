/**
 * Reachability scoring engine.
 * Pure function: calculates reachability weight for a component.
 *
 * Rules (first match wins):
 * 1. dev === true → 0.2
 * 2. optional === true → 0.1
 * 3. direct dependency (depth 1) → 1.0
 * 4. otherwise (transitive) → 0.5
 *
 * TODO: Phase 3 - Integrate graph-depth detection from dependency-graph.ts
 * Currently uses scope flags as proxy for depth.
 */

import type { Component, ComponentScope } from '../sbom/cyclonedx/model.js';

/**
 * Calculate reachability weight for a component.
 *
 * @param component - The component to score
 * @returns Weight between 0.1 and 1.0
 */
export function calculateReachability(component: Component): number {
  const scope: ComponentScope | undefined = component.scope;

  // Rule 1: Dev dependencies are lower risk (0.2)
  // In CycloneDX, dev deps have scope 'excluded' per our mapping
  if (scope === 'excluded') {
    return 0.2;
  }

  // Rule 2: Optional dependencies are lowest risk (0.1)
  if (scope === 'optional') {
    return 0.1;
  }

  // TODO: Phase 3 - Add proper depth detection
  // For now, we use 'required' scope as proxy for direct deps (1.0)
  // and would need graph analysis for transitive detection (0.5)
  // Current heuristic: assume 'required' means direct

  // Rule 3: Direct/production dependencies (1.0)
  if (scope === 'required') {
    return 1.0;
  }

  // Rule 4: Unknown scope treated as transitive (0.5)
  return 0.5;
}

/**
 * Get human-readable label for reachability weight.
 */
export function getReachabilityLabel(weight: number): string {
  switch (weight) {
    case 1.0:
      return 'direct production dependency';
    case 0.5:
      return 'transitive dependency';
    case 0.2:
      return 'dev-only dependency';
    case 0.1:
      return 'optional dependency';
    default:
      return 'unknown dependency type';
  }
}