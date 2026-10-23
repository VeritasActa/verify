/**
 * Legate standard files: a signed standard (Proof Request), a signed recipient
 * decision (Admission Decision), and the action assurance bundle a gateway and
 * an approver produce for one action.
 *
 * These run the same verification core the Legate site runs, bundled into this
 * package (src/engines/legate-core.mjs, synced from the web package by
 * packages/legate-verify/scripts/sync.mjs). The independence a reader gets is
 * the open source, not a second implementation: the same bytes that answer on
 * the site answer here, offline, with no account and no server.
 *
 * What a green result means, and does not:
 *   - Proof Request: the standard is intact and signed by the recipient key it
 *     names. Who holds that key is not established here; pin it out of band
 *     with --key, and a standard signed with another key is invalid.
 *   - Admission Decision: the decision is intact, signed by the recipient key,
 *     and bound by digest to one standard and one presented record. Whether
 *     that record was sound is a separate question; supply it to recompute.
 *     --key pins the recipient key, as for a Proof Request.
 *   - Action assurance bundle: the request, approval, and receipt verify and
 *     link to one another. Without --key the signers are reported as unpinned;
 *     with it, the gate request and the receipt must be signed with that key.
 *   - Run manifest: a harness's signed account of a governed run (a benchmark
 *     submission): task set and harness pinned by digest, every attempt with
 *     its receipts and the harness's own test verdict, the receipt chain head.
 *     Alone it verifies as intact. Supply the standard (--standard) and the
 *     gateway's receipt log (--receipts) to check the pins, the policy, the
 *     tool list, the attempts, the time limit, and the chain head against it.
 *     --key pins the harness key that signed the manifest.
 *
 * @module verify-cli/src/engines/legate-standard
 * @license Apache-2.0
 */

import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const LEGATE_STANDARD_TYPES = new Set([
  'scopeblind.proof_request.v1',
  'scopeblind.admission_decision.v1',
  'scopeblind.action_assurance_bundle.v1',
  'scopeblind.run_manifest.v1',
]);

/** Evidence files that verify only beside a decision or a standard. */
export const LEGATE_EVIDENCE_TYPES = new Set([
  'scopeblind.presentation.v1',
  'scopeblind.effect_readback.v1',
  'scopeblind.anchor_witness.v1',
]);

let corePromise = null;
function core() {
  if (!corePromise) {
    const here = dirname(fileURLToPath(import.meta.url));
    corePromise = import(pathToFileURL(join(here, 'legate-core.mjs')).href);
  }
  return corePromise;
}

const checksOf = (list) => list.map((c) => ({ id: c.id, label: c.label, ok: c.ok, detail: c.detail, ...(c.informational ? { informational: true } : {}) }));

/** The key given with --key, in the form the files write keys (lowercase hex), or null. */
const pinOf = (opts) => (typeof opts.publicKey === 'string' && opts.publicKey.trim() ? opts.publicKey.trim().toLowerCase() : null);

/**
 * With --key, the key a file is signed with must be that key (draft §9.5): one that differs makes the file invalid
 * (key_mismatch), never valid against the key the file carries. Before, the core checked the signature against the
 * carried key and --key was not read, so a file re-signed with any key verified with the real key pinned.
 * Returns the check to report, or null when no key was given.
 */
function keyPinCheck(pin, key, label, who) {
  if (pin === null) return null;
  const ok = typeof key === 'string' && key.toLowerCase() === pin;
  return { id: 'key_pin', label, ok, detail: ok ? `${who} is the key given with --key.` : `${who} (${key}) is not the key given with --key.` };
}

/**
 * @param {Record<string, unknown>} input parsed JSON
 * @param {{ publicKey?: string, now?: Date }} opts `publicKey` pins the key the file is signed with: the recipient key
 *   for a standard or a decision, the signer key for a run manifest, the gate key for a bundle
 */
export async function verifyLegateStandard(input, opts = {}) {
  const type = typeof input?.type === 'string' ? input.type : '';
  const base = { format: 'legate-standard', artifact_type: type };
  const now = opts.now instanceof Date ? opts.now : new Date();
  const m = await core();
  const pin = pinOf(opts);

  if (type === 'scopeblind.proof_request.v1') {
    const v = m.verifyProofRequest(input, now);
    const pinCheck = v.shape_valid ? keyPinCheck(pin, input.recipient.verification_key, 'Recipient key pinned', `The recipient key ${input.recipient.key_id} that signed the standard`) : null;
    const mismatch = pinCheck !== null && !pinCheck.ok;
    const valid = v.cryptographically_valid && !mismatch;
    return {
      valid,
      ...base,
      error: valid ? undefined : !v.shape_valid ? 'malformed_artifact' : mismatch ? 'key_mismatch' : !v.digest_valid ? 'digest_mismatch' : 'invalid_signature',
      ...(mismatch ? { detail: pinCheck.detail } : {}),
      artifact_id: input.request_id,
      recipient: input.recipient ? { name: input.recipient.name, organization: input.recipient.organization, key_id: input.recipient.key_id, verification_key: input.recipient.verification_key } : undefined,
      current: v.current,
      enforcement: input.enforcement ? { policy_digest: input.enforcement.policy_digest, tool: input.enforcement.tool, gate_enforced: input.enforcement.gate_enforced } : null,
      checks: checksOf(pinCheck ? [...v.checks, pinCheck] : v.checks),
      in_plain_words: valid ? m.proofRequestReadback(input) : undefined,
      trust: valid ? m.trustProvenance(input.trust).summary : undefined,
      not_established: ['Who holds the recipient key: pin it through a channel you already trust.', 'That any operator can meet the standard, or that meeting it obliges the recipient to anything beyond the stated path.'],
    };
  }

  if (type === 'scopeblind.run_manifest.v1') {
    const standard = opts.standard ?? null;
    const receipts = Array.isArray(opts.receipts) ? opts.receipts : null;
    const calls = Array.isArray(opts.calls) ? opts.calls : null;
    const regrade = opts.regrade ?? null;
    const provenance = opts.provenance ?? null;
    const regrades = Array.isArray(opts.regrades) ? opts.regrades : null;
    const modelCalls = typeof opts.modelCalls === 'string' ? opts.modelCalls : null;
    const modelAttestations = Array.isArray(opts.modelAttestations) ? opts.modelAttestations : null;
    const bytes = opts.bytes && typeof opts.bytes === 'object' ? opts.bytes : null;
    const pins = opts.pins && typeof opts.pins === 'object' ? opts.pins : null;
    const v = m.verifyRunManifest(input, { standard, receipts, calls, regrade, regrades, provenance, modelCalls, modelAttestations, bytes, pins }, now);
    const pinCheck = v.shape_valid ? keyPinCheck(pin, input.signer.verification_key, 'Signer key pinned', `The harness key ${input.signer.key_id} that signed the manifest`) : null;
    const mismatch = pinCheck !== null && !pinCheck.ok;
    const valid = v.cryptographically_valid && !mismatch;
    return {
      valid,
      ...base,
      error: valid ? undefined : !v.shape_valid ? 'malformed_artifact' : mismatch ? 'key_mismatch' : !v.digest_valid ? 'digest_mismatch' : 'invalid_signature',
      ...(mismatch ? { detail: pinCheck.detail } : {}),
      artifact_id: input.run_id,
      binding: mismatch ? 'unbound' : v.binding,
      title: mismatch ? 'Run manifest is not signed by the key given with --key' : v.title,
      summary: input.summary,
      signer: input.signer ? { name: input.signer.name, key_id: input.signer.key_id, verification_key: input.signer.verification_key, demo: m.isDemoRunSignerKey(input.signer.verification_key) } : undefined,
      checks: checksOf(pinCheck ? [...v.checks, pinCheck] : v.checks),
      chain: v.chain ? { count: v.chain.count, all_signatures_valid: v.chain.all_signatures_valid, chain_unbroken: v.chain.chain_unbroken, chain_outcome: v.chain.chain_outcome, allow: v.chain.summary.allow, deny: v.chain.summary.deny } : null,
      in_plain_words: valid ? m.runManifestReadback(input) : undefined,
      establishes: mismatch ? [] : v.establishes,
      not_established: mismatch ? ['Nothing rests on a manifest that is not signed by the key you pinned.'] : v.not_established,
      provenance: v.provenance ?? undefined,
      model_attestation: input.environment?.model_attestation ? { provider: input.environment.model_attestation.provider, model: input.environment.model_attestation.model, reports: input.environment.model_attestation.reports.length, calls: input.model_calls?.count ?? 0, verified: v.checks.some((c) => c.id === 'model_calls_bind' && c.ok && !c.informational) && v.checks.some((c) => c.id === 'model_attestation' && c.ok && !c.informational) } : undefined,
    };
  }

  if (type === 'scopeblind.admission_decision.v1') {
    const v = m.verifyAdmissionDecision(input, {}, now);
    const pinCheck = v.shape_valid ? keyPinCheck(pin, input.recipient.verification_key, 'Recipient key pinned', `The recipient key ${input.recipient.key_id} that signed the decision`) : null;
    const mismatch = pinCheck !== null && !pinCheck.ok;
    const valid = v.cryptographically_valid && !mismatch;
    return {
      valid,
      ...base,
      error: valid ? undefined : !v.shape_valid ? 'malformed_artifact' : mismatch ? 'key_mismatch' : !v.digest_valid ? 'digest_mismatch' : !v.signature_valid ? 'invalid_signature' : 'semantics_invalid',
      ...(mismatch ? { detail: pinCheck.detail } : {}),
      artifact_id: input.decision_id,
      decision: input.decision,
      acknowledged_verdict: input.acknowledged_verdict,
      bound_to: { request: input.proof_request_id, presentation_digest: input.presentation?.bundle_digest },
      current: v.current,
      checks: checksOf(pinCheck ? [...v.checks, pinCheck] : v.checks),
      not_established: ['Whether the presented record was sound: supply the standard and the presentation to recompute the report the decision acknowledges.', 'Who holds the recipient key.'],
    };
  }

  if (type === 'scopeblind.action_assurance_bundle.v1') {
    if (!m.isActionAssuranceBundleV1(input)) return { valid: false, ...base, error: 'malformed_artifact', detail: 'not a complete action assurance bundle (request, decision, receipt)' };
    const pins = pin ? { gate_key: pin, receipt_issuer_key: pin } : {};
    const v = await m.verifyActionAssuranceBundleV1(input, pins, now);
    const cryptographicallyValid = Boolean(v.cryptographically_valid ?? v.valid);
    // --key pins the gate key: the request and the receipt must both be signed with it, and the bundle is valid only
    // when they are (signers_pinned). Before, the core's pin results were not read, so any --key gave a valid bundle
    // reported as pinned.
    const signersPinned = pin !== null && v.request?.key_pinned === true && v.receipt?.key_pinned === true;
    const mismatch = pin !== null && cryptographicallyValid && !signersPinned;
    const valid = cryptographicallyValid && !mismatch;
    return {
      valid,
      ...base,
      error: valid ? undefined : mismatch ? 'key_mismatch' : 'invalid_signature',
      ...(mismatch ? { detail: `The gate request is signed with ${input.request.issuer?.verification_key} and the action receipt with ${input.receipt.issuer?.verification_key}; both must be the key given with --key.` } : {}),
      artifact_id: input.request?.request_id,
      tool: input.request?.action?.tool ?? input.request?.tool,
      decision: input.decision?.decision,
      signers_pinned: signersPinned,
      verification: v,
      not_established: signersPinned ? ['That the approver key belongs to a named person: pin approver keys through a standard.'] : pin !== null ? ['Who holds the gate, approver, and receipt keys: the gate request or the action receipt is not signed with the key given with --key.'] : ['Who holds the gate, approver, and receipt keys: nothing was pinned. Pass --key <gate key hex> or verify against a signed standard on legate.scopeblind.com/verify.'],
    };
  }

  if (LEGATE_EVIDENCE_TYPES.has(type)) {
    return { valid: false, ...base, error: 'unsupported_format', detail: `${type} is evidence a decision was made on, not a decision. Verify the scopeblind.admission_decision.v1 file, then add this beside it on legate.scopeblind.com/verify to recompute the report.` };
  }
  return { valid: false, ...base, error: 'unsupported_format' };
}
