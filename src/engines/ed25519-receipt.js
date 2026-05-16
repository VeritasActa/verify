/**
 * Ed25519 signed-receipt verification engine.
 *
 * Verifies receipts and bundles conforming to
 * draft-farley-acta-signed-receipts-02/03:
 *   - Passport envelope:  { payload, signature: { alg, kid, sig } }
 *   - v2 structured:      { v: 2, kid, issuer, issued_at, payload, signature }
 *   - v1 flat artifact:   { v: 1, type, timestamp, ..., signature }
 *
 * Verification path is pure Ed25519 + JCS canonicalization with AIP-0001
 * ASCII-only keys. No network calls during verification (unless the
 * caller opts into --jwks, which is fetched by the caller and passed
 * in as a resolved key).
 *
 * Embedded keys in the payload are rejected by default (v0.4.0+). An
 * escape hatch (allowEmbeddedKey: true) exists for one release cycle
 * to ease migration; it is deprecated and will be removed in v0.6.
 *
 * References:
 *   - RFC 8032 (EdDSA / Ed25519)
 *   - RFC 8785 (JCS)
 *   - AIP-0001 (receipt format, ASCII-only keys)
 *   - AIP-0002 (selective disclosure — verified in separate engine)
 *   - draft-farley-acta-signed-receipts-03
 *
 * @module verify-cli/src/engines/ed25519-receipt
 * @license Apache-2.0
 */

import { verifyArtifact } from '@veritasacta/artifacts';
import { canonicalize, canonicalHash } from '../util/canonical.js';
import { hexToBytes, bytesToHex } from '../util/hex.js';

const EMBEDDED_KEY_FIELDS = ['public_key', 'verification_key', 'verification_jwk'];

/**
 * @typedef {Object} VerifyReceiptOptions
 * @property {string} [publicKey]    hex-encoded Ed25519 public key (64 chars)
 * @property {boolean} [allowEmbeddedKey]  pre-0.4.0 compat; deprecated
 * @property {string} [mode]         detected or forced mode
 */

/**
 * @typedef {Object} VerifyReceiptResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} format
 * @property {string} [type]
 * @property {string} [kid]
 * @property {string} [issuer]
 * @property {string} [keySource]     'provided' | 'jwks' | 'bundle' | 'embedded-deprecated'
 * @property {string} [publicKey]
 * @property {string} [algorithm]
 * @property {Object} [payloadFields] subset of payload fields surfaced for output
 */

/**
 * Verify a single Ed25519 receipt.
 *
 * @param {Object} input parsed receipt JSON
 * @param {string} detectedMode one of 'ed25519-receipt-v1', 'ed25519-receipt-v2', 'ed25519-passport'
 * @param {VerifyReceiptOptions} [opts]
 * @returns {Promise<VerifyReceiptResult>}
 */
export async function verifyReceipt(input, detectedMode, opts = {}) {
  let format = 'v1';
  let kid = null;
  let issuer = null;
  let algorithm = 'ed25519';
  let artifactToVerify = input;

  if (detectedMode === 'ed25519-passport') {
    format = 'passport';
    kid = input.signature.kid;
    algorithm = input.signature.alg || 'EdDSA';
    // Passport -> flat artifact for verification
    artifactToVerify = { ...input.payload, signature: input.signature.sig };
  } else if (detectedMode === 'ed25519-receipt-v2') {
    format = 'v2';
    kid = input.kid;
    issuer = input.issuer;
    algorithm = input.algorithm || 'ed25519';
  } else if (detectedMode === 'ed25519-receipt-v1') {
    format = 'v1';
  }

  // Algorithm agility: detect hybrid post-quantum variants early.
  if (typeof algorithm === 'string' && algorithm.toLowerCase().includes('ml-dsa')) {
    return {
      valid: false,
      error: 'unsupported_algorithm',
      format,
      type: input.type || input.payload?.type,
      kid,
      issuer,
      algorithm,
    };
  }

  // Key resolution with embedded-key rejection.
  let publicKey = opts.publicKey;
  let keySource = publicKey ? 'provided' : null;

  if (!publicKey) {
    const payload = input.payload || input;
    const embeddedFields = EMBEDDED_KEY_FIELDS.filter((f) =>
      typeof payload[f] === 'string' || (payload[f] && typeof payload[f] === 'object'),
    );

    if (embeddedFields.length > 0) {
      if (opts.allowEmbeddedKey) {
        // Deprecated path; extract the first embedded key form we recognize.
        if (typeof payload.public_key === 'string' && payload.public_key.length === 64) {
          publicKey = payload.public_key;
          keySource = 'embedded-deprecated';
        } else if (typeof payload.verification_key === 'string' && payload.verification_key.length === 64) {
          publicKey = payload.verification_key;
          keySource = 'embedded-deprecated';
        } else if (payload.verification_jwk?.x) {
          // base64url(raw) -> hex
          const raw = Buffer.from(payload.verification_jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
          publicKey = raw.toString('hex');
          keySource = 'embedded-deprecated';
        }
      } else {
        return {
          valid: false,
          error: 'embedded_key_rejected',
          format,
          type: payload.type,
          kid,
          issuer,
          algorithm,
        };
      }
    }
  }

  if (!publicKey) {
    return {
      valid: false,
      error: 'no_public_key',
      format,
      type: input.type || input.payload?.type,
      kid,
      issuer,
      algorithm,
    };
  }

  // Delegate the actual cryptographic verification to @veritasacta/artifacts.
  // This keeps the low-level crypto in one audited module.
  let result;
  try {
    result = verifyArtifact(artifactToVerify, publicKey);
  } catch (e) {
    return {
      valid: false,
      error: 'malformed_hex',
      format,
      type: input.type || input.payload?.type,
      kid,
      issuer,
      algorithm,
      detail: e.message,
    };
  }

  const payload = input.payload || input;
  const payloadFields = collectPayloadFields(payload);

  // Normalize upstream error codes to our canonical registry.
  let normalizedError;
  if (!result.valid) {
    const upstream = (result.error || '').toLowerCase();
    if (upstream === 'verification_error' || upstream === 'sig_invalid' || upstream.includes('signature')) {
      normalizedError = 'invalid_signature';
    } else if (upstream.includes('missing')) {
      normalizedError = 'missing_signature';
    } else {
      normalizedError = 'invalid_signature'; // default for any verification failure
    }
  }

  return {
    valid: Boolean(result.valid),
    error: normalizedError,
    format,
    type: payload.type || input.type,
    kid,
    issuer,
    keySource,
    publicKey,
    algorithm,
    payloadFields,
    hash: result.hash,
  };
}

/**
 * Collect the subset of payload fields the verifier surfaces in output.
 * This is a read-only projection; the verifier does not interpret these
 * fields (they are spec-level metadata).
 *
 * Fields harvested (all optional, per draft-03):
 *   disclosure_mode, holder_binding, annex_hash, attestation_mode,
 *   anchor_uri, decision, nullifier, scope, compliance_credit_ref,
 *   transport_hint, verifier_salt_kid, policy_id, policy_hash,
 *   skill_version_hash, delegation_chain_root
 *
 * @param {Object} payload
 * @returns {Object}
 */
function collectPayloadFields(payload) {
  const fields = {};
  const keys = [
    'decision', 'policy_id', 'policy_hash',
    'disclosure_mode', 'holder_binding', 'annex_hash', 'attestation_mode',
    'anchor_uri', 'nullifier', 'scope', 'compliance_credit_ref',
    'transport_hint', 'verifier_salt_kid',
    'skill_version_hash', 'parent_skill_version_hash', 'delegation_chain_root',
    'tool_name', 'agent_id', 'session_id', 'sequence', 'spec',
    'previousReceiptHash',
  ];
  for (const k of keys) {
    if (payload[k] !== undefined && payload[k] !== null) fields[k] = payload[k];
  }
  return fields;
}

/**
 * Verify an audit bundle: multiple receipts + a verification block with
 * signing_keys.
 *
 * @param {Object} bundle
 * @param {VerifyReceiptOptions} [opts]
 * @returns {Promise<Object>}
 */
export async function verifyBundle(bundle, opts = {}) {
  const results = {
    valid: true,
    total: 0,
    passed: 0,
    failed: 0,
    errors: [],
    receipts: [],
  };

  if (!Array.isArray(bundle.receipts)) {
    return { valid: false, error: 'unknown_format', detail: 'bundle missing receipts array' };
  }

  // Build key lookup from bundle.verification.signing_keys (JWK -> hex).
  const keyMap = new Map();
  if (Array.isArray(bundle.verification?.signing_keys)) {
    for (const jwk of bundle.verification.signing_keys) {
      if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x) {
        const raw = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const hex = bytesToHex(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength));
        if (jwk.kid) keyMap.set(jwk.kid, hex);
        if (!keyMap.has('default')) keyMap.set('default', hex);
      }
    }
  }

  for (const receipt of bundle.receipts) {
    results.total++;
    let key = opts.publicKey;
    if (!key) {
      const receiptKid = receipt.kid || receipt.signature?.kid;
      key = keyMap.get(receiptKid) || keyMap.get('default');
    }

    // Detect format of this sub-receipt and recurse.
    const { detectFormat } = await import('../detect.js');
    const detected = detectFormat(receipt);
    const subOpts = { ...opts, publicKey: key };
    const r = await verifyReceipt(receipt, detected.mode, subOpts);
    results.receipts.push(r);
    if (r.valid) {
      results.passed++;
    } else {
      results.failed++;
      results.valid = false;
      results.errors.push(`Receipt ${results.total}: ${r.error}`);
    }
  }

  // Verify anchors if present.
  if (Array.isArray(bundle.anchors)) {
    for (const anchor of bundle.anchors) {
      results.total++;
      const key = opts.publicKey || keyMap.get(anchor.kid) || keyMap.get('default');
      const { detectFormat } = await import('../detect.js');
      const detected = detectFormat(anchor);
      const r = await verifyReceipt(anchor, detected.mode, { ...opts, publicKey: key });
      results.receipts.push(r);
      if (r.valid) {
        results.passed++;
      } else {
        results.failed++;
        results.valid = false;
        results.errors.push(`Anchor: ${r.error}`);
      }
    }
  }

  return results;
}
