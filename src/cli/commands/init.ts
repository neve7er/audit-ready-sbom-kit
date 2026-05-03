/**
 * audit-ready --init command.
 * Writes a template .audit-policy.json to the current working directory.
 * Prompts before overwriting an existing file.
 */

import { writeFile, access } from 'fs/promises';
import { constants } from 'fs';
import { createInterface } from 'readline';

const POLICY_FILE = '.audit-policy.json';

const TEMPLATE = `{
  "failOn": [
    // ReasonCode values that should cause the scan to fail with exit code 1.
    // Valid values: DEV_DEPENDENCY_ONLY, OPTIONAL_DEPENDENCY,
    //               TRANSITIVE_NO_EXPLOIT, DIRECT_UNPATCHED,
    //               NO_KNOWN_VULNERABILITY, EXEMPTED
    "DIRECT_UNPATCHED"
  ],
  "exceptions": [
    {
      "id": "exc-001",
      // PURL this exception applies to — must match exactly
      "purl": "pkg:npm/lodash@4.17.21",
      // reasonCode to suppress — must match the node's current reasonCode after triage
      "reasonCode": "TRANSITIVE_NO_EXPLOIT",
      // Justification (minimum 20 characters). Be specific:
      // explain the technical context that justifies accepting this risk.
      "reason": "Lodash is only in dev tooling (jest config), not shipped to production bundle.",
      // ISO 8601 expiration. After this date, the exception is ignored and the
      // original reasonCode resumes triggering policy violations.
      "expires_at": "2025-12-31T23:59:59.000Z",
      // Who approved this exception (team name, individual, or ticket ID)
      "approved_by": "security-team"
    }
  ]
}
`;

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function promptOverwrite(): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<boolean>((resolve) => {
    rl.question(`${POLICY_FILE} already exists. Overwrite? [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

export async function initCommand(): Promise<void> {
  if (await fileExists(POLICY_FILE)) {
    const overwrite = await promptOverwrite();
    if (!overwrite) {
      console.log('Aborted.');
      return;
    }
  }

  await writeFile(POLICY_FILE, TEMPLATE, 'utf-8');
  console.log(`Created ${POLICY_FILE}`);
}