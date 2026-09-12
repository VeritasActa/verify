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
 *     names. Who holds that key is not established here; pin it out of band.
 *   - Admission Decision: the decision is intact, signed by the recipient key,
 *     and bound by digest to one standard and one presented record. Whether
 *     that record was sound is a separate question; supply it to recompute.
 *   - Action assurance bundle: the request, approval, and receipt verify and
 *     link to one another. Without --key the signers are reported as unpinned.
 *   - Run manifest: a harness's signed account of a governed run (a benchmark
 *     submission): task set and harness pinned by digest, every attempt with
 *     its receipts and the harness's own test verdict, the receipt chain head.
 *     Alone it verifies as intact. Supply the standard (--standard) and the
 *     gateway's receipt log (--receipts) to check the pins, the policy, the
 *     tool list, the attempts, the time limit, and the chain head against it.
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

const checksOf = (list) => list.map((c) => ({ id: c.id, label: c.label, ok: c.ok, detail: c.detail }));

/**
 * @param {Record<string, unknown>} input parsed JSON
 * @param {{ publicKey?: string, now?: Date }} opts `publicKey` pins the gate key for a bundle
 */
export async function verifyLegateStandard(input, opts = {}) {
  const type = typeof input?.type === 'string' ? input.type : '';
  const base = { format: 'legate-standard', artifact_type: type };
  const now = opts.now instanceof Date ? opts.now : new Date();
  const m = await core();

  if (type === 'scopeblind.proof_request.v1') {
    const v = m.verifyProofRequest(input, now);
    return {
      valid: v.cryptographically_valid,
      ...base,
      error: v.cryptographically_valid ? undefined : !v.shape_valid ? 'malformed_artifact' : !v.digest_valid ? 'digest_mismatch' : 'invalid_signature',
      artifact_id: input.request_id,
      recipient: input.recipient ? { name: input.recipient.name, organization: input.recipient.organization, key_id: input.recipient.key_id, verification_key: input.recipient.verification_key } : undefined,
      current: v.current,
      enforcement: input.enforcement ? { policy_digest: input.enforcement.policy_digest, tool: input.enforcement.tool, gate_enforced: input.enforcement.gate_enforced } : null,
      checks: checksOf(v.checks),
      in_plain_words: v.cryptographically_valid ? m.proofRequestReadback(input) : undefined,
      trust: v.cryptographically_valid ? m.trustProvenance(input.trust).summary : undefined,
      not_established: ['Who holds the recipient key: pin it through a channel you already trust.', 'That any operator can meet the standard, or that meeting it obliges the recipient to anything beyond the stated path.'],
    };
  }

  if (type === 'scopeblind.run_manifest.v1') {
    const standard = opts.standard ?? null;
    const receipts = Array.isArray(opts.receipts) ? opts.receipts : null;
    const calls = Array.isArray(opts.calls) ? opts.calls : null;
    const regrade = opts.regrade ?? null;
    const provenance = opts.provenance ?? null;
    const v = m.verifyRunManifest(input, { standard, receipts, calls, regrade, provenance }, now);
    return {
      valid: v.cryptographically_valid,
      ...base,
      error: v.cryptographically_valid ? undefined : !v.shape_valid ? 'malformed_artifact' : !v.digest_valid ? 'digest_mismatch' : 'invalid_signature',
      artifact_id: input.run_id,
      binding: v.binding,
      title: v.title,
      summary: input.summary,
      signer: input.signer ? { name: input.signer.name, key_id: input.signer.key_id, verification_key: input.signer.verification_key, demo: m.isDemoRunSignerKey(input.signer.verification_key) } : undefined,
      checks: checksOf(v.checks),
      chain: v.chain ? { count: v.chain.count, all_signatures_valid: v.chain.all_signatures_valid, chain_unbroken: v.chain.chain_unbroken, allow: v.chain.summary.allow, deny: v.chain.summary.deny } : null,
      in_plain_words: v.cryptographically_valid ? m.runManifestReadback(input) : undefined,
      establishes: v.establishes,
      not_established: v.not_established,
      provenance: v.provenance ?? undefined,
    };
  }

  if (type === 'scopeblind.admission_decision.v1') {
    const v = m.verifyAdmissionDecision(input, {}, now);
    return {
      valid: v.cryptographically_valid,
      ...base,
      error: v.cryptographically_valid ? undefined : !v.shape_valid ? 'malformed_artifact' : !v.digest_valid ? 'digest_mismatch' : !v.signature_valid ? 'invalid_signature' : 'semantics_invalid',
      artifact_id: input.decision_id,
      decision: input.decision,
      acknowledged_verdict: input.acknowledged_verdict,
      bound_to: { request: input.proof_request_id, presentation_digest: input.presentation?.bundle_digest },
      current: v.current,
      checks: checksOf(v.checks),
      not_established: ['Whether the presented record was sound: supply the standard and the presentation to recompute the report the decision acknowledges.', 'Who holds the recipient key.'],
    };
  }

  if (type === 'scopeblind.action_assurance_bundle.v1') {
    if (!m.isActionAssuranceBundleV1(input)) return { valid: false, ...base, error: 'malformed_artifact', detail: 'not a complete action assurance bundle (request, decision, receipt)' };
    const pins = opts.publicKey ? { gate_key: opts.publicKey, receipt_issuer_key: opts.publicKey } : {};
    const v = await m.verifyActionAssuranceBundleV1(input, pins, now);
    const valid = Boolean(v.cryptographically_valid ?? v.valid);
    return {
      valid,
      ...base,
      error: valid ? undefined : 'invalid_signature',
      artifact_id: input.request?.request_id,
      tool: input.request?.action?.tool ?? input.request?.tool,
      decision: input.decision?.decision,
      signers_pinned: Boolean(opts.publicKey),
      verification: v,
      not_established: opts.publicKey ? ['That the approver key belongs to a named person: pin approver keys through a standard.'] : ['Who holds the gate, approver, and receipt keys: nothing was pinned. Pass --key <gate key hex> or verify against a signed standard on legate.scopeblind.com/verify.'],
    };
  }

  if (LEGATE_EVIDENCE_TYPES.has(type)) {
    return { valid: false, ...base, error: 'unsupported_format', detail: `${type} is evidence a decision was made on, not a decision. Verify the scopeblind.admission_decision.v1 file, then add this beside it on legate.scopeblind.com/verify to recompute the report.` };
  }
  return { valid: false, ...base, error: 'unsupported_format' };
}
