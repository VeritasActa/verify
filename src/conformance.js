/**
 * Conformance tier detection.
 *
 * Tiers indicate which verification capabilities a specific verification
 * exercised. They are reported per-verification (not per-implementation),
 * so a single verifier can emit different tiers for different receipts.
 *
 *   T1 Basic       — Ed25519 + JCS + chain linkage
 *   T2 Disclosure  — T1 + AIP-0002 selective disclosure verification
 *   T3 Attestation — T2 + attestation_mode recognition + anchor_uri field surfaced
 *   T4 Privacy     — T3 + VOPRF token verification + holder_binding surfaced
 *   T5 Full        — T4 + ZK compliance proof verification (v1.0+)
 *
 * References:
 *   - v0.5.0-verifier-plan.md §4.6
 *
 * @module verify-cli/src/conformance
 * @license Apache-2.0
 */

/**
 * @typedef {Object} TierInput
 * @property {string} mode
 * @property {Object} [payloadFields]
 * @property {number} [disclosuresVerified]
 * @property {boolean} [voprfVerified]
 */

/**
 * @param {TierInput} input
 * @returns {{tier: 1|2|3|4|5, label: string, features: string[]}}
 */
export function detectTier(input) {
  const features = [];
  let tier = 1;
  const p = input.payloadFields || {};

  // T1: Ed25519 + JCS + chain. All base modes qualify.
  features.push('ed25519-signature');
  features.push('jcs-canonicalization');
  if (p.previousReceiptHash !== undefined) features.push('chain-linkage');

  // T2: Selective disclosure verified or present
  if (input.disclosuresVerified && input.disclosuresVerified > 0) {
    tier = Math.max(tier, 2);
    features.push('selective-disclosure');
  }

  // T3: Attestation / anchor fields surfaced
  if (p.attestation_mode && p.attestation_mode !== 'software') {
    tier = Math.max(tier, 3);
    features.push(`attestation:${p.attestation_mode}`);
  }
  if (p.anchor_uri) {
    tier = Math.max(tier, 3);
    features.push('anchor-uri');
  }

  // T4: VOPRF verification or holder_binding present
  if (input.mode === 'voprf-token' || input.voprfVerified) {
    tier = Math.max(tier, 4);
    features.push('voprf');
  }
  if (p.holder_binding) {
    tier = Math.max(tier, 4);
    features.push('holder-binding');
  }

  // T5: ZK compliance proof (v1.0+, reserved)
  if (p.compliance_credit_ref) {
    features.push('compliance-credit-ref');
    // Don't yet elevate to T5; that requires full verification of the
    // ZK proof, which is v1.0+.
  }

  const labels = {
    1: 'T1 basic',
    2: 'T2 disclosure',
    3: 'T3 attestation',
    4: 'T4 privacy',
    5: 'T5 full',
  };

  return { tier, label: labels[tier], features };
}
