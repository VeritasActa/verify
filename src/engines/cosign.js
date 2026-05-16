/**
 * @veritasacta/verify — bilateral (and N-ary) co-signature engine.
 *
 * Adds an optional envelope-level `cosignatures` array to any AIP-0001
 * receipt. Each cosignature is the same shape as `signature`:
 *
 *   { alg: "EdDSA", kid: "<string>", sig: "<hex|base64|base64url>" }
 *
 * Cosignatures sign the SAME canonical payload bytes as the primary
 * `signature`. Semantics:
 *
 *   - The primary `signature` continues to be the authoritative
 *     "who produced this receipt" signature (AIP-0001 unchanged).
 *   - Each cosignature is independent additional evidence (the server
 *     that executed the call, a policy oracle, a multi-party signer,
 *     a notary, etc.).
 *   - A "bilateral" receipt is one with exactly one cosignature in
 *     addition to the primary signature — typically agent + server.
 *
 * This is purely additive. Existing receipts without `cosignatures`
 * verify identically. Verifiers that don't implement this engine
 * simply ignore the field.
 *
 * @module verify-cli/src/engines/cosign
 * @license Apache-2.0
 */

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

/**
 * @typedef {Object} CosignVerifyOptions
 * @property {Object} envelope                     Receipt envelope with optional `cosignatures`.
 * @property {Object<string,string>} trustAnchors  Map: kid → hex-encoded Ed25519 public key (64 chars).
 * @property {boolean} [requireAllValid=true]      Fail if any cosignature fails.
 * @property {boolean} [requireAllResolved=true]   Fail if any cosignature's kid is absent from trust anchors.
 */

/**
 * @typedef {Object} CosignVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {number} total
 * @property {number} valid_count
 * @property {Array<{kid: string, alg: string, sig_valid: boolean, reason?: string}>} signatures
 */

/**
 * Verify all cosignatures on an envelope against a caller-supplied
 * trust-anchor map. Does NOT verify the primary `signature` —
 * that's the Ed25519 receipt engine's job.
 *
 * @param {CosignVerifyOptions} opts
 * @returns {CosignVerifyResult}
 */
export function verifyCosignatures(opts) {
  const { envelope, trustAnchors, requireAllValid = true, requireAllResolved = true } = opts;

  const cos = envelope && Array.isArray(envelope.cosignatures) ? envelope.cosignatures : [];
  if (cos.length === 0) {
    return {
      valid: true,   // vacuous truth: no cosignatures = nothing to verify
      total: 0,
      valid_count: 0,
      signatures: [],
    };
  }

  const payloadBytes = canonicalize(envelope.payload);
  const results = [];
  let validCount = 0;

  for (const entry of cos) {
    if (!entry || typeof entry !== 'object' || !entry.kid || !entry.sig) {
      results.push({
        kid: (entry && entry.kid) || '(missing)',
        alg: (entry && entry.alg) || '(missing)',
        sig_valid: false,
        reason: 'malformed_cosignature_entry',
      });
      continue;
    }
    const kid = entry.kid;
    const pubHex = trustAnchors && trustAnchors[kid];
    if (!pubHex) {
      results.push({
        kid,
        alg: entry.alg || 'unknown',
        sig_valid: false,
        reason: 'no_trust_anchor',
      });
      continue;
    }

    let pub;
    try {
      pub = pubkeyFromHex(pubHex);
    } catch (err) {
      results.push({
        kid,
        alg: entry.alg || 'unknown',
        sig_valid: false,
        reason: `bad_trust_anchor_key:${err.message}`,
      });
      continue;
    }

    const sigBuf = decodeSig(entry.sig);
    if (!sigBuf) {
      results.push({
        kid,
        alg: entry.alg || 'unknown',
        sig_valid: false,
        reason: 'bad_sig_encoding',
      });
      continue;
    }

    let ok = false;
    try {
      ok = cryptoVerify(null, payloadBytes, pub, sigBuf);
    } catch {
      ok = false;
    }
    results.push({
      kid,
      alg: entry.alg || 'EdDSA',
      sig_valid: ok,
      ...(ok ? {} : { reason: 'signature_invalid' }),
    });
    if (ok) validCount++;
  }

  const anyInvalid = results.some((r) => !r.sig_valid);
  const anyUnresolved = results.some((r) => r.reason === 'no_trust_anchor');

  if (requireAllResolved && anyUnresolved) {
    return {
      valid: false,
      error: 'cosignature_no_trust_anchor',
      total: cos.length,
      valid_count: validCount,
      signatures: results,
    };
  }
  if (requireAllValid && anyInvalid) {
    return {
      valid: false,
      error: 'cosignature_invalid',
      total: cos.length,
      valid_count: validCount,
      signatures: results,
    };
  }
  return {
    valid: true,
    total: cos.length,
    valid_count: validCount,
    signatures: results,
  };
}

/**
 * Attach a cosignature to an envelope in-place. Does NOT produce the
 * signature itself — the caller is expected to have signed the
 * canonicalized payload with their own private key. This is a pure
 * envelope-mutation helper.
 *
 * @param {Object} envelope
 * @param {{alg: string, kid: string, sig: string}} cosig
 */
export function attachCosignature(envelope, cosig) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('attachCosignature: envelope must be an object');
  }
  if (!cosig || !cosig.kid || !cosig.sig) {
    throw new Error('attachCosignature: cosig must have { alg, kid, sig }');
  }
  if (!Array.isArray(envelope.cosignatures)) {
    envelope.cosignatures = [];
  }
  envelope.cosignatures.push({
    alg: cosig.alg || 'EdDSA',
    kid: cosig.kid,
    sig: cosig.sig,
  });
}

// ───── helpers ─────

function pubkeyFromHex(hex) {
  if (typeof hex !== 'string' || hex.length !== 64) {
    throw new Error('pubkey_must_be_32_byte_hex');
  }
  const raw = Buffer.from(hex, 'hex');
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    raw,
  ]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

function decodeSig(str) {
  if (typeof str !== 'string') return null;
  if (/^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0) {
    return Buffer.from(str, 'hex');
  }
  try {
    return Buffer.from(str, 'base64');
  } catch {
    return null;
  }
}
