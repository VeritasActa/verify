/**
 * FIPS mode enforcement.
 *
 * When --fips is set, the verifier accepts only algorithms that are
 * approved for FIPS 140-3 use. Ed25519 is NOT FIPS 140-3 approved as
 * of 2026; hybrid ed25519+ml-dsa-65 is conditionally approved once
 * NIST finalizes ML-DSA (FIPS 204).
 *
 * This v0.5.0 implementation marks Ed25519 as non-FIPS and returns a
 * clear error in FIPS mode. Full FIPS support waits for v0.6+ when
 * hybrid PQ verification lands.
 *
 * @module verify-cli/src/util/fips
 * @license Apache-2.0
 */

/**
 * FIPS-approved algorithm list (per FIPS 140-3 plus drafts).
 * Notes on status:
 *   - EdDSA / Ed25519: NOT FIPS 140-3 approved as of 2026-04.
 *   - ML-DSA-65 (FIPS 204): approved but not yet implemented in v0.5.0.
 *   - Hybrid classical+PQ: conditional, pending NIST guidance.
 */
const FIPS_APPROVED = new Set([
  'ml-dsa-65',
  'ml-dsa-87',
  // Hybrid modes are conditionally approved; the verifier accepts them in FIPS mode
  // but v0.5.0 cannot fully verify them (returns unsupported_algorithm).
  'ed25519+ml-dsa-65',
  'ed25519+ml-dsa-87',
]);

/**
 * Check whether an algorithm is acceptable in FIPS mode.
 *
 * @param {string} algorithm
 * @returns {boolean}
 */
export function fipsApproves(algorithm) {
  if (!algorithm) return false;
  return FIPS_APPROVED.has(algorithm.toLowerCase());
}

/**
 * Describe FIPS status of an algorithm.
 *
 * @param {string} algorithm
 * @returns {{approved: boolean, reason: string}}
 */
export function fipsStatus(algorithm) {
  const lower = (algorithm || '').toLowerCase();
  if (lower === 'ed25519' || lower === 'eddsa') {
    return {
      approved: false,
      reason: 'Ed25519 / EdDSA is not FIPS 140-3 approved as of 2026. For FIPS deployments use ed25519+ml-dsa-65 (requires v0.6+ for full verification).',
    };
  }
  if (FIPS_APPROVED.has(lower)) {
    return { approved: true, reason: 'Algorithm is FIPS-approved or conditionally approved (hybrid).' };
  }
  return { approved: false, reason: `Algorithm "${algorithm}" is not on the FIPS 140-3 approved list.` };
}
