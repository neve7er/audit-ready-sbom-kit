/**
 * Package URL (PURL) generation for npm packages.
 * RFC-compliant encoding per https://github.com/package-url/purl-spec
 *
 * CRITICAL: This is the canonical PURL source. All PURL generation MUST route through
 * buildPurl() in this file. Standard library encoders (encodeURIComponent, URL, etc.)
 * are FORBIDDEN for PURL generation.
 *
 * Encoding rules:
 * - @ → %40
 * - / → %2F
 * - Version string appended unencoded
 */

const PURL_TYPE = 'npm';

/**
 * %-encode @ and / for use in PURLs.
 * Manual implementation — no standard library encoders.
 */
function encodePurlChar(char: string): string {
  return `%${char.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`;
}

/**
 * Encode package name for PURL per spec §3.3.
 * - @ becomes %40
 * - / becomes %2F
 * - Everything else stays as-is
 */
function encodePackageName(name: string): string {
  let result = '';
  for (let i = 0; i < name.length; i++) {
    const char = name[i];
    if (char === '@' || char === '/') {
      result += encodePurlChar(char);
    } else {
      result += char;
    }
  }
  return result;
}

/**
 * Build a PURL from package name and version.
 * This is the ONLY permitted function for PURL generation in the codebase.
 *
 * @param name - Package name (e.g., "lodash" or "@types/node")
 * @param version - Package version (e.g., "4.17.21" or "1.2.3-beta.1")
 * @returns RFC-compliant PURL per spec §3.3
 */
export function buildPurl(name: string, version: string): string {
  const encodedName = encodePackageName(name);
  return `pkg:${PURL_TYPE}/${encodedName}@${version}`;
}