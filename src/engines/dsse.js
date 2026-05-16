/**
 * @veritasacta/verify — DSSE envelope wrap/unwrap (Sigstore compat)
 *
 * Produces and consumes Dead Simple Signing Envelopes (DSSE) per the
 * in-toto DSSE spec (https://github.com/secure-systems-lab/dsse).
 *
 * Veritas Acta receipts are wrapped with payloadType
 * `application/vnd.acta.receipt+json` so any DSSE-aware tool (cosign,
 * slsa-verifier, gitlab-attestations, etc.) can see the envelope as a
 * standard in-toto attestation.
 *
 * The signature inside DSSE is computed over the DSSE pre-authentication
 * encoding (PAE), NOT the raw payload:
 *
 *   PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
 *
 * This is an intentional design choice by the DSSE spec so signatures
 * bind to both the type AND the payload.
 *
 * This engine is verify-only at v0.5.2 (parse + validate); signing
 * requires the operator's signing key and ships separately alongside
 * the daemon. The verify path lets any Sigstore-produced DSSE envelope
 * over our predicate types be checked offline by our verifier.
 *
 * @module verify-cli/src/engines/dsse
 * @license Apache-2.0
 */

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';

export const ACTA_RECEIPT_PAYLOAD_TYPE = 'application/vnd.acta.receipt+json';
export const ACTA_KU_PAYLOAD_TYPE       = 'application/vnd.acta.knowledge-unit+json';
export const INTOTO_STATEMENT_TYPE      = 'application/vnd.in-toto+json';

/**
 * @typedef {Object} DSSEEnvelope
 * @property {string} payloadType
 * @property {string} payload        base64-encoded payload bytes
 * @property {Array<{keyid?: string, sig: string}>} signatures  base64 sig
 */

/**
 * @typedef {Object} DSSEVerifyOptions
 * @property {DSSEEnvelope} envelope
 * @property {Object<string,string>} trustAnchors    kid → pubkey hex (Ed25519)
 * @property {boolean} [allowIntoto=true]            accept in-toto statement subjects
 */

/**
 * @typedef {Object} DSSEVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} [payload_type]
 * @property {Object} [payload]                     parsed JSON payload (best-effort)
 * @property {Array<{keyid: string, kid_match: string|null, sig_valid: boolean}>} signatures
 */

/**
 * Build the DSSE pre-authentication encoding.
 *
 *   PAE = "DSSEv1" SP len(type) SP type SP len(body) SP body
 *
 * where lengths are ASCII decimal and SP is a single space byte.
 *
 * @param {string} type
 * @param {Buffer} body
 * @returns {Buffer}
 */
export function dssePAE(type, body) {
  const typeBytes = Buffer.from(type, 'utf-8');
  const header = Buffer.from(
    `DSSEv1 ${typeBytes.length} ${type} ${body.length} `,
    'utf-8'
  );
  return Buffer.concat([header, body]);
}

/**
 * Wrap an Acta receipt (or any JSON body) in a DSSE envelope.
 * The caller supplies a pre-computed signature over dssePAE().
 *
 * @param {Object} receipt            JSON payload (receipt, KU, statement, …)
 * @param {string} payloadType        MIME-like identifier
 * @param {Array<{keyid?: string, sigB64: string}>} signatures
 * @returns {DSSEEnvelope}
 */
export function wrapDSSE(receipt, payloadType, signatures) {
  const bytes = Buffer.from(JSON.stringify(receipt), 'utf-8');
  return {
    payloadType,
    payload: bytes.toString('base64'),
    signatures: signatures.map((s) => ({
      ...(s.keyid ? { keyid: s.keyid } : {}),
      sig: s.sigB64,
    })),
  };
}

/**
 * Unwrap a DSSE envelope. Returns the payload JSON if parseable,
 * otherwise a raw Buffer under `.rawBody`.
 *
 * @param {DSSEEnvelope} envelope
 */
export function unwrapDSSE(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return { ok: false, error: 'dsse_not_object' };
  }
  if (!envelope.payloadType || !envelope.payload) {
    return { ok: false, error: 'dsse_missing_required_fields' };
  }
  let rawBody;
  try {
    rawBody = Buffer.from(envelope.payload, 'base64');
  } catch (err) {
    return { ok: false, error: `dsse_payload_decode:${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf-8'));
  } catch {
    // Non-JSON payloads are allowed; we just can't structurally inspect.
    parsed = undefined;
  }
  return {
    ok: true,
    payload_type: envelope.payloadType,
    payload: parsed,
    rawBody,
  };
}

/**
 * Verify a DSSE envelope's signatures against a trust-anchor map.
 *
 * @param {DSSEVerifyOptions} opts
 * @returns {DSSEVerifyResult}
 */
export function verifyDSSE(opts) {
  const { envelope, trustAnchors, allowIntoto = true } = opts;
  const unwrap = unwrapDSSE(envelope);
  if (!unwrap.ok) return { valid: false, error: unwrap.error, signatures: [] };

  if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    return {
      valid: false,
      error: 'dsse_no_signatures',
      payload_type: unwrap.payload_type,
      payload: unwrap.payload,
      signatures: [],
    };
  }

  if (!isAcceptedType(unwrap.payload_type, allowIntoto)) {
    return {
      valid: false,
      error: `dsse_unsupported_payload_type:${unwrap.payload_type}`,
      payload_type: unwrap.payload_type,
      payload: unwrap.payload,
      signatures: [],
    };
  }

  const pae = dssePAE(envelope.payloadType, unwrap.rawBody);

  const results = [];
  let anyValid = false;

  for (const entry of envelope.signatures) {
    const keyid = entry.keyid || '';
    const hex = trustAnchors && (trustAnchors[keyid] || trustAnchors['*']);
    if (!hex) {
      results.push({ keyid, kid_match: null, sig_valid: false, reason: 'no_trust_anchor' });
      continue;
    }
    const pub = pubkeyFromHex(hex);
    const sigBuf = safeBase64(entry.sig);
    if (!sigBuf) {
      results.push({ keyid, kid_match: keyid, sig_valid: false, reason: 'bad_sig_encoding' });
      continue;
    }
    let ok = false;
    try {
      ok = cryptoVerify(null, pae, pub, sigBuf);
    } catch {
      ok = false;
    }
    results.push({ keyid, kid_match: keyid, sig_valid: ok });
    if (ok) anyValid = true;
  }

  return {
    valid: anyValid,
    error: anyValid ? undefined : 'dsse_signatures_invalid',
    payload_type: unwrap.payload_type,
    payload: unwrap.payload,
    signatures: results,
  };
}

/**
 * Convenience: verify DSSE that wraps an Acta receipt, AND recursively
 * re-run AIP-0001 verification on the unwrapped payload if a verifier
 * callback is supplied.
 *
 * @param {Object} opts
 * @param {DSSEEnvelope} opts.envelope
 * @param {Object<string,string>} opts.trustAnchors
 * @param {(receipt: Object) => Promise<{valid: boolean}>} [opts.verifyInnerReceipt]
 * @returns {Promise<Object>}
 */
export async function verifyDSSEWrappedReceipt(opts) {
  const outer = verifyDSSE({
    envelope: opts.envelope,
    trustAnchors: opts.trustAnchors,
  });
  if (!outer.valid) return { ...outer, inner_valid: null };

  if (opts.verifyInnerReceipt && outer.payload) {
    try {
      const inner = await opts.verifyInnerReceipt(outer.payload);
      return { ...outer, inner_valid: inner.valid, inner };
    } catch (err) {
      return { ...outer, inner_valid: false, inner: { error: err.message } };
    }
  }
  return { ...outer, inner_valid: null };
}

// ───── Helpers ─────

function isAcceptedType(type, allowIntoto) {
  if (type === ACTA_RECEIPT_PAYLOAD_TYPE) return true;
  if (type === ACTA_KU_PAYLOAD_TYPE) return true;
  if (allowIntoto && type === INTOTO_STATEMENT_TYPE) return true;
  return false;
}

function pubkeyFromHex(hex) {
  // Ed25519 raw-32 → SPKI DER.
  if (typeof hex !== 'string' || hex.length !== 64) {
    throw new Error('pubkey_must_be_32_byte_hex');
  }
  const raw = Buffer.from(hex, 'hex');
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  const der = Buffer.concat([prefix, raw]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function safeBase64(b64) {
  if (typeof b64 !== 'string') return null;
  try {
    return Buffer.from(b64, 'base64');
  } catch {
    return null;
  }
}

/**
 * Compute the SHA-256 digest of a DSSE envelope's canonicalized
 * encoding. Useful for anchoring in Rekor / transparency logs.
 *
 * @param {DSSEEnvelope} envelope
 * @returns {string} hex digest
 */
export function dsseDigest(envelope) {
  const body = Buffer.from(JSON.stringify({
    payloadType: envelope.payloadType,
    payload: envelope.payload,
    signatures: envelope.signatures || [],
  }), 'utf-8');
  return createHash('sha256').update(body).digest('hex');
}
