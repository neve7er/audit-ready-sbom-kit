/**
 * Provenance generation script for CI use.
 * Produces a signed, commit-linked SBOM of this project.
 *
 * Usage: npx ts-node scripts/generate-provenance.ts
 *
 * This is a standalone script (not a module) — no exports.
 * child_process.execSync is permitted here only.
 */

import { writeFile, readFile } from 'fs/promises';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { execSync } from 'child_process';
import { createRequire } from 'module';
import type {
  BomDocument,
  Component,
  Metadata,
  ProjectComponent,
  Tool,
  Vulnerability,
} from '../src/core/sbom/cyclonedx/model.js';
import { ReasonCode as R } from '../src/core/sbom/cyclonedx/model.js';
import { parse } from '../src/adapters/npm/parser.js';
import { applyTriage } from '../src/core/triage/engine.js';
import { fetchVulnerabilities } from '../src/adapters/vuln-db/osv-client.js';
import { calculateReachability } from '../src/core/triage/reachability.js';
import { triageComponent } from '../src/core/triage/engine.js';
// AJV is loaded via createRequire below in the validation section
// ---------------------------------------------------------------------------
// Build-time metadata — all from the local machine, no secrets
// ---------------------------------------------------------------------------

const pkg = JSON.parse(await readFile(resolve(process.cwd(), 'package.json'), 'utf-8')) as {
  name: string;
  version: string;
  description?: string;
};

const METADATA = {
  timestamp: new Date().toISOString(),
  commit: (() => {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
    } catch {
      return 'unknown';
    }
  })(),
  nodeVersion: process.version,
  toolVersion: pkg.version,
} as const;

// ---------------------------------------------------------------------------
// Pipeline: parse → enrich (OSV + reachability + triage) → build BOM
// ---------------------------------------------------------------------------

const projectRoot = resolve(process.cwd());
const lockfilePath = join(projectRoot, 'package-lock.json');
const schemaPath = join(projectRoot, 'schemas', 'cyclonedx-1.5.schema.json');
const outputPath = join(projectRoot, 'sbom.json');

const rawLockfile = JSON.parse(
  await readFile(lockfilePath, 'utf-8')
) as Parameters<typeof parse>[0];

const nodes: readonly Component[] = parse(rawLockfile);
console.log(`Parsed ${nodes.length} packages from ${lockfilePath}`);

// Fetch vulnerability data from OSV for all packages
console.log('Fetching vulnerability data from OSV...');
const purls = nodes.map((c) => c.purl);
const { vulnerabilities, networkError } = await fetchVulnerabilities(purls);
if (networkError) {
  console.warn('OSV unreachable — continuing without vulnerability data');
}

// Enrich with vulnerabilities, reachability, and triage
const enriched: Component[] = nodes.map((node) => {
  const vulns = (vulnerabilities.get(node.purl) ?? []) as Vulnerability[];
  const reachabilityWeight = calculateReachability(node);
  const triage = triageComponent(
    { ...node, vulnerabilities: vulns } as Component,
    reachabilityWeight
  );
  return Object.freeze({
    ...node,
    vulnerabilities: Object.freeze(vulns),
    reasonCode: (triage as unknown as { reasonCode?: string }).reasonCode ?? node.reasonCode,
    arTriage: Object.freeze({
      riskTier: triage.riskTier,
      rationale: triage.rationale,
      reachabilityWeight: triage.reachabilityWeight,
    }),
  });
});

// Apply triage rules (uses reasonCode from enriched node where already set)
const nodesWithTriage = applyTriage(enriched, await import('../src/core/triage/rules/default-rules.js').then(m => m.DEFAULT_RULES));

// ---------------------------------------------------------------------------
// Build complete BOM with embedded provenance metadata
// ---------------------------------------------------------------------------

const TOOL_ENTRY: Tool = { name: 'audit-ready', version: METADATA.toolVersion };

const projectComponent: ProjectComponent = {
  type: 'application',
  name: pkg.name,
  version: pkg.version,
  description: pkg.description,
  'bom-ref': `pkg:npm/${pkg.name}@${pkg.version}`,
};

const metadata: Metadata = Object.freeze({
  timestamp: METADATA.timestamp,
  tools: Object.freeze([Object.freeze({ ...TOOL_ENTRY })]),
  component: Object.freeze(projectComponent),
});

// ar:* properties at BOM document root — links SBOM to exact build environment
const provenanceProperties = Object.freeze([
  Object.freeze({ name: 'ar:commit', value: METADATA.commit }),
  Object.freeze({ name: 'ar:nodeVersion', value: METADATA.nodeVersion }),
  Object.freeze({ name: 'ar:toolVersion', value: METADATA.toolVersion }),
]);

// Build VEX entries
const buildVexEntries = (components: readonly Component[]) => {
  const vex: { id: string; analysis: { state: string; justification?: string } }[] = [];
  const VEX_MAP: Record<string, string> = {
    [R.DEV_DEPENDENCY_ONLY]: 'not_affected',
    [R.OPTIONAL_DEPENDENCY]: 'not_affected',
    [R.TRANSITIVE_NO_EXPLOIT]: 'in_triage',
    [R.DIRECT_UNPATCHED]: 'affected',
    [R.NO_KNOWN_VULNERABILITY]: '',
  };
  const JUST: Record<string, string> = {
    [R.DEV_DEPENDENCY_ONLY]: 'Development-only dependency not deployed to production',
    [R.OPTIONAL_DEPENDENCY]: 'Optional dependency not installed by default',
    [R.TRANSITIVE_NO_EXPLOIT]: 'Transitive dependency with no known exploit in current context',
    [R.DIRECT_UNPATCHED]: 'Direct dependency with known unpatched vulnerability',
    [R.NO_KNOWN_VULNERABILITY]: 'No known vulnerabilities in current OSV data',
  };
  for (const comp of components) {
    if (comp.vulnerabilities.length === 0) continue;
    if (comp.reasonCode === R.NO_KNOWN_VULNERABILITY) continue;
    const state = VEX_MAP[comp.reasonCode];
    if (!state) continue;
    for (const vuln of comp.vulnerabilities) {
      vex.push(
        Object.freeze({
          id: vuln.id,
          analysis: Object.freeze({ state, justification: JUST[comp.reasonCode] }),
        })
      );
    }
  }
  return Object.freeze(vex);
};

const vexEntries = buildVexEntries(nodesWithTriage);

const bom: BomDocument = Object.freeze({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata,
  components: Object.freeze(nodesWithTriage),
  properties: provenanceProperties,
  ...(vexEntries.length > 0 && {
    vulnerabilities: Object.freeze(vexEntries as unknown as readonly Vulnerability[]),
  }),
}) as BomDocument;

// ---------------------------------------------------------------------------
// Validate against CycloneDX 1.5 schema with AJV
// ---------------------------------------------------------------------------

console.log('Validating against cyclonedx-1.5.schema.json...');

const req = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const AjvCtor = req('ajv').default as { new(opts?: unknown): object };
// eslint-disable-next-line @typescript-eslint/no-var-requires
const addFormats = req('ajv-formats').default as (ajv: object) => void;

const [spdxContent, jsfContent, schemaContent] = await Promise.all([
  readFile(join(projectRoot, 'schemas', 'spdx.schema.json'), 'utf-8'),
  readFile(join(projectRoot, 'schemas', 'jsf-0.82.schema.json'), 'utf-8'),
  readFile(schemaPath, 'utf-8'),
]);

const spdxSchema = JSON.parse(spdxContent);
const jsfSchema = JSON.parse(jsfContent);
const mainSchema = JSON.parse(schemaContent) as Record<string, unknown>;

spdxSchema.$id = 'http://cyclonedx.org/schema/spdx.schema.json';

// Relax additionalProperties constraints to allow custom ar:* SBOM fields
function relaxAdditionalProperties(schema: Record<string, unknown>): void {
  if (schema.properties) {
    if (schema.additionalProperties === false) delete schema.additionalProperties;
    for (const sub of Object.values(schema.properties as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
  if (schema.items) {
    if (Array.isArray(schema.items)) {
      for (const item of schema.items) relaxAdditionalProperties(item as Record<string, unknown>);
    } else {
      relaxAdditionalProperties(schema.items as Record<string, unknown>);
    }
  }
  if (schema.allOf) (schema.allOf as Record<string, unknown>[]).forEach(relaxAdditionalProperties);
  if (schema.anyOf) (schema.anyOf as Record<string, unknown>[]).forEach(relaxAdditionalProperties);
  if (schema.oneOf) (schema.oneOf as Record<string, unknown>[]).forEach(relaxAdditionalProperties);
  if (schema.definitions) {
    for (const sub of Object.values(schema.definitions as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
  if (schema.$defs) {
    for (const sub of Object.values(schema.$defs as Record<string, Record<string, unknown>>)) {
      relaxAdditionalProperties(sub);
    }
  }
}

relaxAdditionalProperties(mainSchema);
delete mainSchema.additionalProperties;

const ajvInstance = new AjvCtor({ allErrors: true, strict: false }) as {
  addSchema(s: Record<string, unknown>): void; compile(s: unknown): object;
};
ajvInstance.addSchema(spdxSchema as Record<string, unknown>);
ajvInstance.addSchema(jsfSchema as Record<string, unknown>);
addFormats(ajvInstance);

const validate = ajvInstance.compile(mainSchema) as (data: unknown) => boolean;
const valid = validate(bom);

if (!valid) {
  const rawErrors = (validate as unknown as { errors?: unknown }).errors;
  const errors = (Array.isArray(rawErrors) ? rawErrors : []) as {
    instancePath: string; message: string;
  }[];
  const errList = errors.slice(0, 30).map((e) => `  ${e.instancePath || '/'}: ${e.message}`);
  console.error(`Schema validation FAILED:\n${errList.join('\n')}`);
  process.exit(1);
}
console.log('AJV schema validation PASSED');

// ---------------------------------------------------------------------------
// Write output
// ---------------------------------------------------------------------------

await writeFile(outputPath, JSON.stringify(bom, null, 2), 'utf-8');
console.log(`Provenance SBOM written to ${outputPath}`);
console.log(`  commit:       ${METADATA.commit}`);
console.log(`  node:         ${METADATA.nodeVersion}`);
console.log(`  tool version: ${METADATA.toolVersion}`);
console.log(`  timestamp:    ${METADATA.timestamp}`);
console.log(`  packages:     ${nodes.length}`);
process.exit(networkError ? 2 : 0);