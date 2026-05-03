/**
 * OSV.dev API client for vulnerability lookups.
 * Batches requests and handles network failures gracefully.
 *
 * OSV API: https://api.osv.dev/v1/querybatch
 * Batch limit: 1000 queries per request
 */

import type { Vulnerability, Severity } from '../../core/sbom/cyclonedx/model.js';

const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;

/** OSV query structure */
interface OSVQuery {
  package: {
    purl: string;
  };
}

/** OSV batch request */
interface OSVBatchRequest {
  queries: OSVQuery[];
}

/** OSV severity entry */
interface OSVSeverity {
  type: string;
  score: string;
}

/** OSV vulnerability entry */
interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: OSVSeverity[];
  aliases?: string[];
}

/** OSV batch response */
interface OSVBatchResponse {
  results?: Array<{
    vulns?: OSVVulnerability[];
  }>;
}

/** Severity mapping from OSV to CycloneDX */
function mapSeverity(osvSeverity: string): Severity {
  const lower = osvSeverity.toLowerCase();
  switch (lower) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'unknown';
  }
}

/** Extract CVSS severity from OSV severity array */
function extractSeverity(severities?: OSVSeverity[]): Severity {
  if (!severities || severities.length === 0) {
    return 'unknown';
  }
  // Prefer CVSSv3, then CVSSv2, then first available
  const cvssV3 = severities.find((s) => s.type === 'CVSS_V3');
  const cvssV2 = severities.find((s) => s.type === 'CVSS_V2');
  const first = severities[0];
  return mapSeverity((cvssV3 ?? cvssV2 ?? first).score);
}

/** Map OSV vulnerability to CycloneDX Vulnerability */
function mapOSVVulnerability(osvVuln: OSVVulnerability): Vulnerability {
  const severity = extractSeverity(osvVuln.severity);

  return {
    id: osvVuln.id,
    description: osvVuln.summary || osvVuln.details || '',
    ratings: [
      {
        severity,
        method: severity !== 'unknown' ? 'CVSS' : undefined,
        score: undefined
      }
    ],
    affects: [], // Populated by caller
    recommendation: undefined,
    source: {
      name: 'OSV',
      url: `https://osv.dev/${osvVuln.id}`
    }
  };
}

/**
 * Fetch vulnerabilities for a single batch of PURLs.
 * Never throws — returns empty array on any error.
 */
async function fetchBatch(
  queries: OSVQuery[],
  signalNetworkError: () => void
): Promise<Map<string, Vulnerability[]>> {
  const result = new Map<string, Vulnerability[]>();

  if (queries.length === 0) {
    return result;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    const response = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ queries } as OSVBatchRequest),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`OSV API returned ${response.status}: ${response.statusText}`);
      signalNetworkError();
      return result;
    }

    const data = (await response.json()) as OSVBatchResponse;

    if (!data.results) {
      return result;
    }

    // Map results back to PURLs
    for (let i = 0; i < data.results.length; i++) {
      const purl = queries[i].package.purl;
      const vulns = data.results[i]?.vulns ?? [];
      result.set(purl, vulns.map(mapOSVVulnerability));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`OSV API request failed: ${message}`);
    signalNetworkError();
  }

  return result;
}

/**
 * Fetch vulnerabilities for all components.
 * Batches at 1000 PURLs per request, runs sequentially.
 *
 * @param purls - Array of PURL strings to query
 * @returns Map of PURL -> Vulnerability[], plus network error flag
 */
export async function fetchVulnerabilities(
  purls: readonly string[]
): Promise<{ vulnerabilities: Map<string, Vulnerability[]>; networkError: boolean }> {
  const result = new Map<string, Vulnerability[]>();
  let networkError = false;

  const signalError = () => {
    networkError = true;
  };

  // Build queries
  const queries: OSVQuery[] = purls.map((purl) => ({
    package: { purl }
  }));

  // Process in batches
  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    const batchResults = await fetchBatch(batch, signalError);

    // Merge into result
    for (const [purl, vulns] of batchResults.entries()) {
      result.set(purl, vulns);
    }
  }

  return { vulnerabilities: result, networkError };
}