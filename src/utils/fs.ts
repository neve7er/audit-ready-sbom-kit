/**
 * Type-safe filesystem wrappers.
 * All file I/O is centralized here per architecture constraints.
 */

import { readFile as nodeReadFile } from 'fs/promises';
import { ParseError } from './errors.js';

/** Read a file as UTF-8 string */
export async function readFile(path: string): Promise<string> {
  return nodeReadFile(path, 'utf-8');
}

/** Parse JSON string with descriptive error */
export function parseJson<T = unknown>(content: string): T {
  try {
    return JSON.parse(content) as T;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new ParseError(`Invalid JSON: ${message}`);
  }
}

/** Read and parse JSON file */
export async function readJsonFile<T = unknown>(path: string): Promise<T> {
  const content = await readFile(path);
  return parseJson<T>(content);
}