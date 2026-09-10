/**
 * Legate governed-receipt verifier.
 *
 * The Legate runtime (desktop daemon) and the iPhone co-sign sign a FLAT,
 * pipe-delimited canonical payload — NOT a JSON tuple with a digest field —
 * so the gate-receipt engine does not recognize it. This engine closes that
 * gap so a third party (an allocator, an LP, a counterparty) can re-verify the
 * exact bytes the daemon and phone co-signed with the OPEN tool, holding no
 * ScopeBlind code and trusting no fund-attested wrapper.
 *
 * Canonical signed payload (must stay byte-identical to
 * scopeblind-pm/src/governed-actions.ts:legateReceiptPayload and the desktop
 * daemon + phone):
 *
 *   scopeblind.receipt.v1|<id>|<tool>|<decision>|<input_sha256>|<result_sha256>|<at>
 *
 * The signature is Ed25519 over the UTF-8 bytes of that string directly (it is
 * NOT hashed first), which is what distinguishes this from the Gate receipt
 * tuple (Ed25519 over a SHA-256 payload digest).
 *
 * @module verify-cli/src/engines/legate-governed-receipt
 * @license Apache-2.0
 */

import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes } from '@noble/hashes/utils';
import { hexToBytes } from '../util/hex.js';
import { canonicalize, sha256Hex } from '../util/canonical.js';

/** The canonical payload prefix this engine recognizes (v1). */
export const LEGATE_RECEIPT_TAG = 'scopeblind.receipt.v1';

/**
 * Governed action kinds, keyed by the receipt's `tool`. Kept in sync with
 * scopeblind-pm/src/governed-actions.ts:GOVERNED_RECEIPT_KINDS. `tool`
 * distinguishes the step; every kind is the same Ed25519-over-canonical-payload
 * envelope.
 */
export const GOVERNED_RECEIPT_KINDS = {
  'gate.approve': 'approval',
  'gate.deny': 'denial',
  instruction: 'execution-instruction',
  execution_claim: 'execution-claim',
  'submandate.issue': 'delegation',
  'submandate.revoke': 'revocation',
  'policy.commit': 'mandate-commit',
  'recipe.mint': 'recipe-mint',
  'recipe.run': 'recipe-run',
  'recipe.revoke': 'recipe-revocation',
  'recipe.reconcile': 'recipe-corroboration',
  // Restraint: a gate-signed proof that an out-of-mandate action was BLOCKED
  // before execution (the negative-space artifact). See engines/restraint.js.
  'gate.restrain': 'restraint',
};

const HEX = (s) => typeof s === 'string' && /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0;
const isString = (v) => typeof v === 'string' && v.length > 0;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Re-verify the openable detail of a restraint receipt. A restraint receipt
 * binds the disclosed denial outcome into result_sha256 and the (optionally
 * withheld) proposed order into input_sha256, both via the same canonical
 * hashing the runtime used. Re-hashing here proves the disclosed detail is
 * exactly what was signed — so the receipt proves WHAT was prevented and WHY,
 * not merely that some deny was signed.
 *
 * @param {object} receipt a governed receipt with a `restraint` detail block
 * @returns {{ outcome_bound: boolean, proposed_bound: boolean|null, determining: string[], risk_band: string|null, mandate_digest: string|null, proposed: object|null }}
 */
export function verifyRestraintBindings(receipt) {
  const r = isObject(receipt?.restraint) ? receipt.restraint : {};
  const outcome_bound = isObject(r.outcome) && sha256Hex(canonicalize(r.outcome)) === receipt.result_sha256;
  let proposed_bound = null; // null = position-blind (proposed withheld)
  if (r.proposed != null) {
    proposed_bound = isString(r.salt) && sha256Hex(`${r.salt}|${canonicalize(r.proposed)}`) === receipt.input_sha256;
  }
  return {
    outcome_bound,
    proposed_bound,
    determining: Array.isArray(r.outcome?.determining) ? r.outcome.determining : [],
    risk_band: isString(r.outcome?.risk_band) ? r.outcome.risk_band : null,
    mandate_digest: isString(r.outcome?.mandate_digest) ? r.outcome.mandate_digest : null,
    proposed: r.proposed ?? null,
  };
}

/** Reconstruct the exact bytes the daemon + phone signed. */
export function legateReceiptPayload(r) {
  return [LEGATE_RECEIPT_TAG, r.id, r.tool, r.decision, r.input_sha256, r.result_sha256, r.at].join('|');
}

export const GOVERNED_PROVES = [
  'Authenticity: the receipt was signed by the Ed25519 key it carries (the Legate runtime or phone co-sign key).',
  'Integrity: the action identity — tool, decision, the input and result SHA-256 hashes, and the timestamp — is bound by the signature and unmodified.',
  'Recognition: the receipt declares a known governed-action kind.',
];

export const GOVERNED_LIMITATIONS = [
  'Whether the embedded verification_key is the key your counterparty expects — pin it with --key to bind trust to a known signer.',
  'Correctness of the inputs and results behind input_sha256 / result_sha256 unless those preimages are separately disclosed and re-hashed.',
  'Independent execution corroboration — only a recipe.reconcile receipt carries the custodian-corroborated grade.',
];

/**
 * Verify a single Legate governed receipt.
 *
 * @param {object} receipt flat envelope { id, at, tool, decision, input_sha256, result_sha256, signature, verification_key, type? }
 * @param {{ publicKey?: string }} [opts]
 */
export function verifyLegateGovernedReceipt(receipt, opts = {}) {
  const base = {
    format: 'legate-governed-receipt',
    schema: isString(receipt?.type) ? receipt.type : 'scopeblind.agent_vault.receipt.v1',
    tool: isString(receipt?.tool) ? receipt.tool : undefined,
    kind: undefined,
    kindRecognized: false,
    algorithm: 'ed25519',
  };

  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { valid: false, error: 'unknown_format', ...base, detail: 'receipt is not an object' };
  }

  const kind = GOVERNED_RECEIPT_KINDS[receipt.tool];
  base.kind = kind || (isString(receipt.decision) ? `decision:${receipt.decision}` : 'receipt');
  base.kindRecognized = Boolean(kind);
  base.payloadFields = {
    id: receipt.id,
    tool: receipt.tool,
    decision: receipt.decision,
    input_sha256: receipt.input_sha256,
    result_sha256: receipt.result_sha256,
    at: receipt.at,
  };

  for (const field of ['id', 'tool', 'decision', 'input_sha256', 'result_sha256', 'at']) {
    if (!isString(receipt[field])) return { valid: false, error: 'malformed_payload', ...base, detail: `missing or empty ${field}` };
  }
  if (!isString(receipt.signature)) return { valid: false, error: 'missing_signature', ...base };
  if (!isString(receipt.verification_key)) return { valid: false, error: 'no_public_key', ...base };
  if (!HEX(receipt.signature) || !HEX(receipt.verification_key)) {
    return { valid: false, error: 'malformed_hex', ...base, detail: 'signature and verification_key must be hex' };
  }

  const pinned = isString(opts.publicKey);
  if (pinned && opts.publicKey.toLowerCase() !== receipt.verification_key.toLowerCase()) {
    return { valid: false, error: 'key_mismatch', ...base, publicKey: receipt.verification_key, expectedKey: opts.publicKey };
  }

  const payload = legateReceiptPayload(receipt);
  let ok = false;
  try {
    ok = ed25519.verify(hexToBytes(receipt.signature), utf8ToBytes(payload), hexToBytes(receipt.verification_key));
  } catch (e) {
    return { valid: false, error: 'malformed_hex', ...base, detail: e.message, publicKey: receipt.verification_key };
  }
  if (!ok) {
    return { valid: false, error: 'invalid_signature', ...base, publicKey: receipt.verification_key, signedPayload: payload };
  }

  const result = {
    valid: true,
    ...base,
    publicKey: receipt.verification_key,
    keySource: pinned ? 'embedded-receipt (pinned via --key)' : 'embedded-receipt',
    signedPayload: payload,
    proves: [...GOVERNED_PROVES],
    limitations: [...GOVERNED_LIMITATIONS],
  };

  // Restraint receipts carry openable detail: the disclosed outcome (the rules
  // that blocked the action) and, unless position-blind, the proposed order.
  // Re-hash both and confirm they bind to the signed hashes, so the receipt
  // proves exactly WHAT was prevented and WHY, not merely that a deny was signed.
  if (kind === 'restraint' && isObject(receipt.restraint)) {
    const bindings = verifyRestraintBindings(receipt);
    result.restraint = bindings;
    if (bindings.outcome_bound) {
      result.proves.push(
        'Restraint: the gate blocked this action before it could execute, and the disclosed outcome (the determining rules and risk band) re-hashes to the signed result hash, so it is exactly what was committed.',
      );
    } else {
      result.limitations.push(
        'The disclosed restraint outcome did NOT re-hash to the signed result hash: the detail shown was altered after signing (the signature itself is still valid over the original hashes).',
      );
    }
    if (bindings.proposed_bound === null) {
      result.proves.push(
        'Position-blind: the blocked order is withheld but salt-committed into the signed input hash, so the restraint is provable without disclosing the position.',
      );
    } else if (bindings.proposed_bound === false) {
      result.limitations.push('The disclosed blocked order did NOT re-hash to the signed input hash (the shown order was altered after signing).');
    }
  }

  return result;
}
