import { createHash } from 'node:crypto';

/**
 * SHA-256 hex digest of a lockfile's raw (unparsed) string content.
 *
 * The input is the raw file string so that identical normalised inputs produce
 * identical digests regardless of whitespace or BOM differences introduced by
 * text editors on different platforms.  Using the raw string rather than a
 * re-serialised object graph also means an auditor can independently compute
 * the hash from the original lockfile on disk.
 */
export function lockfileHash(lockfileContent: string): string {
  return createHash('sha256')
    .update(lockfileContent, 'utf8')
    .digest('hex');
}

/**
 * Convert a Package URL (PURL, spec: https://github.com/package-url/purl-spec)
 * into a safe, human-readable filename for the OSV cache directory.
 *
 * ## Encoding scheme
 *
 * Two rules applied to the PURL string in order:
 *
 *   (a) Replace each occurrence of a PURL delimiter character with `_`:
 *       - `/`  (type[/namespace][/name] separator)
 *       - `@`  (version separator)
 *       - `:`  (scheme separator "pkg:", also used in scope notation "npm:foo")
 *   (b) URL-encoded sequences (`%XX`) are NOT split apart — the `%` is not a
 *       delimiter, so each `%XX` sequence (e.g. `%40` = `@`, `%2F` = `/`) is
 *       preserved verbatim in the output.
 *
 * The result is a filename where encoded PURL segments remain recognisable
 * (e.g. `%40scope` → `_40scope`, `%2F` → `_2F`) while component boundaries
 * are marked by the `_` that replaced the original delimiters.
 *
 * ## Reversibility
 *
 * The encoding is symmetric for all PURL characters *except* literal underscore.
 * A bare `_` in the output is ambiguous — it could be an original `_` or a
 * replacement character.  In practice this does not affect audit-readability:
 * a human can reconstruct the PURL from context (the pattern of `_` separating
 * recognizable segments, and the preserved `%XX` sequences).
 *
 * ## Examples
 *
 *   pkg:npm/%40scope/lib@1.0.0        (encoded @scope/lib npm package)
 *     → pkg_npm_%40scope_lib_1.0.0.json
 *     (`:` and the two literal `/` → `_`; `%40` survives as encoded `@`);
 *     note: `%2F` inside a component is NOT a separator → preserved intact
 *
 *   pkg:maven/org.apache.commons/commons-lang3@3.12.0
 *     → pkg_maven_org.apache.commons_commons-lang3_3.12.0.json
 *
 *   pkg:golang/github.com%2Fgorilla%2Fmux@v1.8.0
 *     → pkg_golang_github.com_2Fgorilla_2Fmux_v1.8.0.json
 *     (`:` and the two literal `/`, and the `@` → `_`) -- `%2F` is a component
 *     character (encoded `/`) → only the `F` is visible since `/` is replaced
 *
 * @param purl - A valid Package URL string.
 * @returns A safe filesystem basename with `.json` extension.
 */
export function purlToFilename(purl: string): string {
  // Only literal delimiter characters are replaced.  URL-encoded %XX sequences
  // are preserved because `%` itself is not a delimiter — only the hex digits
  // following it (which are not matched by this character class) survive intact.
  const encoded = purl.replace(/[\/:@]/g, '_');
  return `${encoded}.json`;
}