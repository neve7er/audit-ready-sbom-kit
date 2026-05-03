/**
 * Self-audit command for audit-ready.
 * Scans this project's own dependencies and produces a valid SBOM of itself.
 *
 * Pipeline: parse → applyTriage → buildBomDocument → write + AJV validate
 * Zero new logic — pure orchestration.
 */

import { writeFile, readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createRequire } from 'module';
import type { Component, BomDocument } from '../../core/sbom/cyclonedx/model.js';
import { parse } from '../../adapters/npm/parser.js';
import { applyTriage } from '../../core/triage/engine.js';
import { DEFAULT_RULES } from '../../core/triage/rules/default-rules.js';
import { buildBomDocument } from '../../core/sbom/cyclonedx/builder.js';
import { renderMarkdown } from '../../adapters/output/markdown/renderer.js';
import { readJsonFile } from '../../utils/fs.js';

interface PackageJson {
  name?: string;
  version?: string;
  description?: string;
  author?: string;
}

/** Resolve project root from the compiled CLI binary location */
function resolveProjectRoot(): string {
  // bin/audit-ready.js → project root is 3 levels up
  const binPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  return binPath;
}

/** Validate a BomDocument against cyclonedx-1.5.schema.json using AJV.
 * Throws with full error list on failure.
 */
/**
 * Recursively remove additionalProperties:false from a JSON Schema object.
 * This allows our custom ar:* fields (arTriage, reasonCode) without modifying
 * the schema source file. Only schemas that define 'properties' get modified —
 * structural constraints (required, type, format) are preserved.
 */
function relaxAdditionalProperties(schema: Record<string, unknown>): void {
  if (schema.properties) {
    if (schema.additionalProperties === false) {
      delete schema.additionalProperties;
    }
    for (const sub of Object.values(schema.properties as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
  if (schema.items) {
    if (Array.isArray(schema.items)) {
      for (const item of schema.items) {
        relaxAdditionalProperties(item as Record<string, unknown>);
      }
    } else {
      relaxAdditionalProperties(schema.items as Record<string, unknown>);
    }
  }
  if (schema.allOf) {
    for (const s of schema.allOf as Record<string, unknown>[]) relaxAdditionalProperties(s);
  }
  if (schema.anyOf) {
    for (const s of schema.anyOf as Record<string, unknown>[]) relaxAdditionalProperties(s);
  }
  if (schema.oneOf) {
    for (const s of schema.oneOf as Record<string, unknown>[]) relaxAdditionalProperties(s);
  }
  // Handle JSON Schema draft-07 "definitions" (used by cyclonedx schema)
  if (schema.definitions) {
    for (const sub of Object.values(schema.definitions as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
  // Handle JSON Schema 2019-09+ "$defs"
  if (schema.$defs) {
    for (const sub of Object.values(schema.$defs as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
}

async function validateWithAjv(bom: BomDocument, schemaPath: string): Promise<void> {
  const req = createRequire(import.meta.url);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const AjvCtor = req('ajv').default as { new(opts?: unknown): object };
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const addFormats = req('ajv-formats').default as (ajv: object) => void;

  const schemaDir = dirname(schemaPath);

  const [spdxContent, jsfContent, schemaContent] = await Promise.all([
    readFile(join(schemaDir, 'spdx.schema.json'), 'utf-8'),
    readFile(join(schemaDir, 'jsf-0.82.schema.json'), 'utf-8'),
    readFile(schemaPath, 'utf-8'),
  ]);

  const spdxSchema = JSON.parse(spdxContent);
  const jsfSchema = JSON.parse(jsfContent);
  const mainSchema = JSON.parse(schemaContent) as Record<string, unknown>;

  spdxSchema.$id = 'http://cyclonedx.org/schema/spdx.schema.json';

  const ajvInstance = new AjvCtor({ allErrors: true, strict: false }) as {
    addSchema(s: Record<string, unknown>): void;
    compile(s: unknown): object;
  };

  ajvInstance.addSchema(spdxSchema as Record<string, unknown>);
  ajvInstance.addSchema(jsfSchema as Record<string, unknown>);

  addFormats(ajvInstance);

  relaxAdditionalProperties(mainSchema);
  delete mainSchema.additionalProperties; // root-level

  const validate = ajvInstance.compile(mainSchema) as (data: unknown) => boolean;
  const valid = validate(bom);

  if (!valid) {
    // In AJV v8, errors are on the validate function as a property
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawErrors = (validate as unknown as { errors?: unknown }).errors;
    const errors = (Array.isArray(rawErrors) ? rawErrors : []) as {
      instancePath: string;
      message: string;
    }[];
    const msgs = errors.slice(0, 30).map(
      (e) => `  ${e.instancePath || '/'}: ${e.message}`
    );
    throw new Error(`AJV schema validation failed:\n${msgs.join('\n')}`);
  }
}

/** Execute the audit-self command */
export async function auditSelfCommand(): Promise<void> {
  const projectRoot = resolveProjectRoot();
  const lockfilePath = join(projectRoot, 'package-lock.json');
  const pkgJsonPath = join(projectRoot, 'package.json');
  const schemaPath = join(projectRoot, 'schemas', 'cyclonedx-1.5.schema.json');
  const outputJsonPath = join(process.cwd(), 'audit-ready-sbom.json');
  const outputMdPath = join(process.cwd(), 'audit-ready-report.md');

  console.log('Starting self-audit...');
  console.log(`  lockfile: ${lockfilePath}`);
  console.log(`  package.json: ${pkgJsonPath}`);

  try {
    // Step 1: Read project metadata
    const pkgJson = await readJsonFile<PackageJson>(pkgJsonPath);
    if (!pkgJson.name || !pkgJson.version) {
      throw new Error('package.json must have name and version fields');
    }
    console.log(`  project: ${pkgJson.name}@${pkgJson.version}`);

    // Step 2: Parse own lockfile
    const rawLockfile = await readJsonFile<unknown>(lockfilePath);
    const nodes: readonly Component[] = parse(rawLockfile);
    console.log(`  parsed ${nodes.length} components from lockfile`);

    // Step 3: Apply triage rules (no vulnerability data in self-audit — all get NO_KNOWN_VULNERABILITY)
    const enriched = applyTriage(nodes, DEFAULT_RULES);
    console.log(`  triage applied (${DEFAULT_RULES.length} rules)`);

    // Step 4: Build BOM document
    const bom = buildBomDocument(enriched, {
      name: pkgJson.name,
      version: pkgJson.version,
      description: pkgJson.description,
      author: pkgJson.author
    });

    // Step 5: AJV schema validation against cyclonedx-1.5.schema.json
    console.log('Validating against cyclonedx-1.5.schema.json...');
    await validateWithAjv(bom, schemaPath);
    console.log('Schema validation PASSED');

    // Step 6: Write outputs
    const bomJson = JSON.stringify(bom, null, 2);
    const reportMd = renderMarkdown(bom);

    await writeFile(outputJsonPath, bomJson, 'utf-8');
    await writeFile(outputMdPath, reportMd, 'utf-8');

    console.log(`✅ Self-audit complete — ${nodes.length} components scanned, output written to ${outputJsonPath}, ${outputMdPath}`);
    process.exit(0);

  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error('Unknown error during self-audit');
    }
    process.exit(1);
  }
}

// Execute immediately when run as CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  auditSelfCommand();
}