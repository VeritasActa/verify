/**
 * JCS canonicalization utilities.
 *
 * Implements RFC 8785 (JCS — JSON Canonicalization Scheme) with the
 * AIP-0001 extension requiring ASCII-only object keys. This restriction
 * sidesteps the Unicode normalization surface at the cost of rejecting
 * non-ASCII keys.
 *
 * This module is pure: no I/O, no network, no side effects.
 *
 * References:
 *   - RFC 8785 (JCS)
 *   - AIP-0001 §JCS Canonicalization
 *   - draft-farley-acta-signed-receipts-03 §Canonicalization
 *
 * @module verify-cli/src/util/canonical
 * @license Apache-2.0
 */

import { createHash } from 'node:crypto';

/**
 * Assert that every object key in the given value is ASCII-only.
 * Per AIP-0001, non-ASCII keys MUST be rejected at ingest.
 *
 * @param {unknown} obj
 * @throws {Error} with code 'non_ascii_key' if any key is non-ASCII
 */
export function assertAsciiKeys(obj) {
  if (obj === null || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const item of obj) assertAsciiKeys(item);
    return;
  }
  for (const key of Object.keys(obj)) {
    // ASCII range is 0x00-0x7F inclusive. We also reject control chars.
    for (let i = 0; i < key.length; i++) {
      const code = key.charCodeAt(i);
      if (code > 0x7F) {
        const err = new Error(`non-ASCII key rejected per AIP-0001: ${JSON.stringify(key)}`);
        err.code = 'non_ascii_key';
        throw err;
      }
    }
    assertAsciiKeys(obj[key]);
  }
}

/**
 * Deep-sort object keys lexicographically (recursively).
 * Arrays preserve order; objects are re-built with sorted keys.
 *
 * @param {unknown} obj
 * @returns {unknown}
 */
export function sortKeysDeep(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  const sorted = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortKeysDeep(obj[key]);
  }
  return sorted;
}

/**
 * Normalize numbers per ECMAScript JSON.stringify: whole-number floats
 * collapse to integers. Matches the Acta implementation convention.
 *
 * @param {unknown} obj
 * @returns {unknown}
 */
export function normalizeNumbers(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'boolean') return obj;
  if (typeof obj === 'number') {
    // Only normalize finite whole-number floats; leave integers alone.
    if (Number.isFinite(obj) && !Number.isInteger(obj) && Number.isInteger(obj)) {
      return obj | 0;
    }
    return obj;
  }
  if (Array.isArray(obj)) return obj.map(normalizeNumbers);
  if (typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) out[k] = normalizeNumbers(obj[k]);
    return out;
  }
  return obj;
}

/**
 * Produce the canonical JCS string for a given value, enforcing
 * AIP-0001 ASCII-only keys.
 *
 * @param {unknown} obj
 * @returns {string}
 */
export function canonicalize(obj) {
  assertAsciiKeys(obj);
  const normalized = normalizeNumbers(obj);
  return JSON.stringify(sortKeysDeep(normalized));
}

/**
 * SHA-256 of the canonical JCS encoding of the value.
 * Returns a hex string (lowercase, no prefix).
 *
 * @param {unknown} obj
 * @returns {string}
 */
export function canonicalHash(obj) {
  return createHash('sha256').update(canonicalize(obj), 'utf8').digest('hex');
}

/**
 * SHA-256 of a raw string. Convenience for non-JCS hashing paths.
 *
 * @param {string} s
 * @returns {string}
 */
export function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}
