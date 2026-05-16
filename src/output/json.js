/**
 * JSON output formatter.
 *
 * Machine-readable structured output for CI/CD pipelines and other
 * programmatic consumers. All fields are stable across patch versions.
 *
 * @module verify-cli/src/output/json
 * @license Apache-2.0
 */

import { deriveFilteredSigil } from '../engines/sigil.js';

/**
 * Format a verification result as structured JSON.
 *
 * @param {Object} result
 * @returns {string}
 */
export function formatAsJson(result) {
  const out = { ...result };
  if (result.valid && result.publicKey && result.publicKey.length === 64) {
    const { fingerprint } = deriveFilteredSigil(result.publicKey);
    out.sigil_fingerprint = fingerprint;
  }
  // Strip ANSI-specific fields and internal underscored fields
  for (const k of Object.keys(out)) {
    if (k.startsWith('_') && k !== '_partialReason') delete out[k];
  }
  return JSON.stringify(out, null, 2);
}
