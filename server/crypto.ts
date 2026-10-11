/**
 * @file server/crypto.ts
 * @description Server-side cryptographic engine using Node.js crypto module.
 * Provides canonical serialization (RFC 8785 principles) and SHA-256 hashing.
 */

import { createHash } from 'node:crypto';

/**
 * Deterministically canonicalizes any JavaScript value to a JSON string with sorted keys.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const canonicalElements = value.map((elem) => canonicalizeJson(elem));
    return `[${canonicalElements.join(',')}]`;
  }

  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs: string[] = [];

  for (const key of sortedKeys) {
    const val = obj[key];
    if (val !== undefined && typeof val !== 'function' && typeof val !== 'symbol') {
      pairs.push(`${JSON.stringify(key)}:${canonicalizeJson(val)}`);
    }
  }

  return `{${pairs.join(',')}}`;
}

/**
 * Computes SHA-256 digest in lowercase hexadecimal format.
 */
export function sha256(data: string | Buffer | Uint8Array): string {
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Computes the SHA-256 hash of a canonically serialized object.
 */
export function hashCanonicalObject(payload: unknown): string {
  const canonicalString = canonicalizeJson(payload);
  return sha256(Buffer.from(canonicalString, 'utf-8'));
}
