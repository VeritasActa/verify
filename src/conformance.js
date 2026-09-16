/** Per-verification capabilities. Declared receipt metadata never grants assurance.
 * Tiers identify the highest checked capability, not a cumulative guarantee.
 * @license Apache-2.0
 */
export function detectTier(input) {
  const features = [], declaredFeatures = [];
  const p = input.payloadFields || {};
  if (p.previousReceiptHash !== undefined) declaredFeatures.push('chain-linkage');
  if (p.attestation_mode) declaredFeatures.push(`attestation:${p.attestation_mode}`);
  if (p.anchor_uri) declaredFeatures.push('anchor-uri');
  if (p.holder_binding) declaredFeatures.push('holder-binding');
  if (p.compliance_credit_ref) declaredFeatures.push('compliance-credit-ref');
  let tier = 0;
  if (input.valid === true) {
    tier = 1;
    if (input.signatureVerified === true) features.push('ed25519-signature');
    if (input.jcsVerified === true) features.push('jcs-canonicalization');
    if (input.chainVerified === true) features.push('chain-linkage');
    if (Number.isSafeInteger(input.disclosuresVerified) && input.disclosuresVerified > 0) {
      tier = 2; features.push('selective-disclosure');
    }
    if (input.attestationVerified === true || input.anchorVerified === true) {
      tier = 3;
      if (input.attestationVerified === true) features.push('attestation');
      if (input.anchorVerified === true) features.push('anchor');
    }
    if (input.voprfVerified === true) { tier = 4; features.push('voprf'); }
    if (input.holderBindingVerified === true) features.push('holder-binding');
  }
  const labels = ['T0 not verified', 'T1 basic', 'T2 disclosure', 'T3 attestation', 'T4 privacy'];
  return { tier, label: labels[tier], features, declaredFeatures };
}
