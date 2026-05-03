/**
 * Exception management — time-bounded suppression of triage violations.
 *
 * Determinism contract: none of these functions reads Date.now() or new Date().
 * All time-based logic requires an explicit `now: Date` parameter injected by the caller.
 *
 * Expired exceptions are invisible to the policy gate — they never suppress violations.
 */

import { ReasonCode } from '../sbom/cyclonedx/model.js';
import type { Component } from '../sbom/cyclonedx/model.js';

/**
 * A security exception — used to suppress a specific triage violation for a bounded period.
 * Exceptions are stored in `.audit-policy.json` alongside triage rules.
 */
export interface Exception {
  readonly id: string;
  readonly purl: string;
  readonly reasonCode: ReasonCode;
  /** Human-readable justification (minimum 20 characters — enforced at validation time) */
  readonly reason: string;
  /** ISO 8601 expiration timestamp, e.g. "2025-06-01T00:00:00.000Z" */
  readonly expires_at: string;
  /** Name or identifier of the approver */
  readonly approved_by: string;
}

/**
 * Check whether an exception has expired as of `now`.
 *
 * @param exception - The exception to test
 * @param now       - Current time (provided by caller — NOT read internally)
 */
export function isExceptionExpired(exception: Exception, now: Date): boolean {
  const expiry = Date.parse(exception.expires_at);
  // NaN means the string is not a valid ISO 8601 date — treat as expired (will also be caught by isExceptionValid)
  if (isNaN(expiry)) return true;
  return expiry <= now.getTime();
}

/**
 * Validate structural correctness of an exception.
 * Returns false if: reason < 20 chars, expires_at is not valid ISO 8601, approved_by is empty.
 *
 * Note: this does NOT check expiry — use isExceptionExpired for that.
 */
export function isExceptionValid(exception: Exception): boolean {
  if (exception.reason.length < 20) return false;
  if (exception.approved_by.trim().length === 0) return false;
  const parsed = Date.parse(exception.expires_at);
  return !isNaN(parsed);
}

/**
 * Apply active exceptions to the triage output.
 *
 * For each node: if a non-expired exception matches node.purl + node.reasonCode,
 * the node's reasonCode is set to EXEMPTED.
 *
 * Expired exceptions are ignored — they do not suppress violations.
 *
 * @param nodes      - Output from applyTriage (readonly)
 * @param exceptions - Exceptions loaded from .audit-policy.json (readonly)
 * @param now        - Current time (provided by caller — NOT read internally)
 */
export function applyExceptions(
  nodes: readonly Component[],
  exceptions: readonly Exception[],
  now: Date
): readonly Component[] {
  return nodes.map((node) => {
    const match = (exceptions as readonly Exception[]).find(
      (exc) =>
        exc.purl === node.purl &&
        exc.reasonCode === node.reasonCode &&
        !isExceptionExpired(exc, now)
    );
    if (match) {
      return Object.freeze({
        ...node,
        reasonCode: ReasonCode.EXEMPTED,
        arExemptReason: match.reason,
        arExemptApprovedBy: match.approved_by,
      });
    }
    return node;
  });
}