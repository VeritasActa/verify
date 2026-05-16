/**
 * AIP-0002 selective-disclosure verification engine.
 *
 * Verifies receipts that carry a `_commitments` field: salted SHA-256
 * commitments over redacted fields. When the caller provides a
 * disclosure package (field + salt + value), this engine checks that
 * the commitment reconstructs to the claimed value.
 *
 * Commitment scheme (per AIP-0002 §Commitment Scheme):
 *   commitment = SHA-256(salt || canonical(value))
 *
 * where canonical(value) is JSON.stringify() of the value.
 *
 * References:
 *   - AIP-0002 §Selective Disclosure
 *   - draft-farley-acta-signed-receipts-03 §Selective Disclosure
 *
 * @module verify-cli/src/engines/selective-disclosure
 * @license Apache-2.0
 */

import { createHash } from 'node:crypto';

/**
 * @typedef {Object} DisclosurePackage
 * @property {string} field   dot-notation path (e.g., "payload.patient_id")
 * @property {string} salt    hex-encoded random salt
 * @property {unknown} value  the original (pre-redaction) value
 */

/**
 * @typedef {Object} SelectiveDisclosureResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {number} disclosuresVerified
 * @property {Array<{field: string, ok: boolean, reason?: string}>} checks
 */

/**
 * Verify a receipt with selective-disclosure commitments.
 *
 * @param {Object} receipt
 * @param {DisclosurePackage[]} disclosures
 * @returns {SelectiveDisclosureResult}
 */
export function verifySelectiveDisclosure(receipt, disclosures = []) {
  const commitments = receipt._commitments || {};
  const checks = [];
  let allValid = true;

  for (const d of disclosures) {
    const expected = commitments[d.field];
    if (!expected) {
      checks.push({ field: d.field, ok: false, reason: 'field not in _commitments' });
      allValid = false;
      continue;
    }

    // Strip "sha256:" prefix if present
    const expectedHex = expected.startsWith('sha256:') ? expected.slice(7) : expected;

    // Reconstruct: SHA-256(salt || canonical(value))
    const canonical = JSON.stringify(d.value);
    const reconstructed = createHash('sha256')
      .update(d.salt + canonical, 'utf8')
      .digest('hex');

    const ok = constantTimeStringEqual(expectedHex.toLowerCase(), reconstructed.toLowerCase());
    checks.push({ field: d.field, ok, reason: ok ? undefined : 'commitment does not match disclosed value' });
    if (!ok) allValid = false;
  }

  return {
    valid: allValid,
    error: allValid ? undefined : 'commitment_mismatch',
    disclosuresVerified: disclosures.length,
    checks,
  };
}

/**
 * Return the list of fields redacted in a selective-disclosure receipt.
 *
 * @param {Object} receipt
 * @returns {string[]}
 */
export function listRedactedFields(receipt) {
  return Object.keys(receipt._commitments || {});
}

/**
 * Constant-time string comparison (for hex digests).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function constantTimeStringEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
