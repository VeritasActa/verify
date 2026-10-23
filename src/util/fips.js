/**
 * FIPS mode enforcement.
 *
 * When --fips is set, a result is valid only when every signature
 * algorithm the verifier actually checked is approved for FIPS use. The
 * algorithm is the one the engine reports it verified, never a label in
 * the file being checked.
 *
 * Ed25519 is approved: FIPS 186-5 (2023) adds EdDSA over Ed25519 and Ed448
 * to the approved digital signature algorithms. Earlier releases of this
 * module refused it, and read the file's own unsigned `algorithm` member,
 * so an Ed25519 record labelled ml-dsa-65 passed. ML-DSA (FIPS 204) is
 * approved but not implemented here, so a record that declares it is
 * undecidable (unsupported_algorithm) whatever --fips says.
 *
 * @module verify-cli/src/util/fips
 * @license Apache-2.0
 */

/**
 * FIPS-approved algorithm list.
 * Notes on status:
 *   - EdDSA / Ed25519: approved, FIPS 186-5.
 *   - ML-DSA-65, ML-DSA-87 (FIPS 204): approved; not implemented in this verifier.
 *   - Hybrid classical+PQ: conditional, pending NIST guidance; not implemented.
 */
const FIPS_APPROVED = new Set([
  'ed25519',
  'eddsa',
  'ml-dsa-65',
  'ml-dsa-87',
  // Hybrid modes are conditionally approved; the verifier accepts them in FIPS mode
  // but cannot verify them (returns unsupported_algorithm).
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
    return { approved: true, reason: 'Ed25519 (EdDSA) is an approved signature algorithm under FIPS 186-5.' };
  }
  if (FIPS_APPROVED.has(lower)) {
    return { approved: true, reason: 'Algorithm is FIPS-approved or conditionally approved (hybrid).' };
  }
  return { approved: false, reason: `Algorithm "${algorithm}" is not on the FIPS approved list.` };
}

/**
 * The signature algorithms a result says its engine verified: each receipt's for an audit bundle, the result's own
 * otherwise. An empty list means the engine does not report one for this format.
 *
 * @param {Object} result
 * @returns {string[]}
 */
export function verifiedAlgorithms(result) {
  const named = (a) => typeof a === 'string' && a.length > 0;
  if (Array.isArray(result?.receipts) && result.total !== undefined) {
    const list = result.receipts.map((r) => r?.algorithm);
    return list.length > 0 && list.every(named) ? list : [];
  }
  return named(result?.algorithm) ? [result.algorithm] : [];
}
