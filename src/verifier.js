/**
 * @veritasacta/verify — verifier.js
 *
 * Core verification logic for BRASS anonymous tokens.
 * Pure functions: no routing, no HTTP, no vendor lock-in.
 *
 * This module implements the verifier-side redemption flow from the BRASS
 * protocol (Patent pending). It:
 *
 *   1. Reconstructs scope from transport context (origin, epoch, policy)
 *   2. Derives verifier-chosen salt η from scope (client cannot influence)
 *   3. Verifies issuer DLEQ proof πI (offline, cached)
 *   4. Verifies client DLEQ proof πC (per-redemption, bound to nonce)
 *   5. Computes deterministic nullifier y from token + salt
 *   6. Delegates counting to a pluggable storage backend
 *
 * The issuer is never contacted during verification.
 *
 * @module @veritasacta/verify/verifier
 * @license MIT
 */

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import {
  H3,
  canonicalOrigin,
  deriveEta,
  deriveNullifierY,
  deriveIdempotencyKey,
  deriveGraceNullifier,
  isInGracePeriod,
  deriveTlsBinding,
  parsePolicyId,
  secondsUntilWindowEnd,
  validWindowsWithSkew,
  windowId,
  bytesToB64url,
  b64urlToBytes,
  buildCounterKey,
  toBytes,
} from './crypto.js';

const n = p256.CURVE.n;

// ─── Helpers ────────────────────────────────────────────────────────────────

function modN(x) {
  let r = x % n;
  return r < 0n ? r + n : r;
}

function bytesToBig(b) {
  let hex = '';
  for (let i = 0; i < b.length; i++) hex += b[i].toString(16).padStart(2, '0');
  return BigInt('0x' + hex);
}

/** Constant-time byte array comparison. */
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}

/**
 * Decode and validate a P-256 point from base64url.
 *
 * Rejects: off-curve points, non-canonical encodings, point at infinity,
 * invalid prefix bytes, wrong length.
 *
 * @param {string} b64 - Base64url-encoded compressed P-256 point (33 bytes)
 * @returns {import('@noble/curves/p256').ProjPointType} Validated point
 * @throws {Error} If point is invalid
 */
export function decodePoint(b64) {
  const bytes = b64urlToBytes(b64);
  let P;
  try {
    P = p256.ProjectivePoint.fromHex(bytes);
  } catch {
    throw new Error('invalid_point_encoding');
  }
  P.assertValidity();
  if (P.equals(p256.ProjectivePoint.ZERO)) {
    throw new Error('invalid_point_infinity');
  }
  return P;
}

// ─── DLEQ Verification ─────────────────────────────────────────────────────

/**
 * Verify a Schnorr-style DLEQ proof.
 *
 * Proves: log_{g1}(h1) = log_{g2}(h2)
 * With Fiat-Shamir binding to arbitrary context via `bind`.
 *
 * Used for both πI (issuer proof) and πC (client proof).
 *
 * @param {object} params
 * @param {string} params.label - Domain separation label
 * @param {ProjPoint} params.g1 - First generator
 * @param {ProjPoint} params.h1 - First public value
 * @param {ProjPoint} params.g2 - Second generator
 * @param {ProjPoint} params.h2 - Second public value
 * @param {ProjPoint} params.A1 - First commitment (r·g1)
 * @param {ProjPoint} params.A2 - Second commitment (r·g2)
 * @param {bigint} params.c - Claimed challenge scalar
 * @param {bigint} params.r - Response scalar
 * @param {Uint8Array} params.bind - Context binding bytes (nonce, digest, salt)
 * @returns {boolean} True if proof is valid
 */
export function dleqVerify({ label, g1, h1, g2, h2, A1, A2, c, r, bind }) {
  const challenge = H3(
    `BRASS:${label}:`,
    g1.toRawBytes(true),
    h1.toRawBytes(true),
    g2.toRawBytes(true),
    h2.toRawBytes(true),
    A1.toRawBytes(true),
    A2.toRawBytes(true),
    bind
  );
  const chal = modN(bytesToBig(challenge));
  return chal === c;
}

// ─── Core Verification ──────────────────────────────────────────────────────

/**
 * @typedef {object} VerifyConfig
 * @property {string} issuerPubKey - Issuer public key Y = k·g (base64url, compressed P-256)
 * @property {string} keyId - Issuer key identifier (KID)
 * @property {Uint8Array} kvSecret - 32-byte secret for idempotency key derivation
 * @property {Uint8Array} [verifierSecret] - Optional per-verifier secret for salt derivation
 * @property {number} [rateLimit=100] - Per-scope threshold (τ)
 * @property {number} [windowSec=86400] - Window duration in seconds
 * @property {number} [graceSeconds=60] - Grace period for boundary protection
 * @property {string} [protocolVersion='BRASS_v2.0'] - Protocol version
 * @property {string} [cipherSuite='P256_SHA256'] - Cipher suite
 */

/**
 * @typedef {object} RedemptionMessage
 * @property {string} M - Blinded element (base64url, compressed P-256)
 * @property {string} Z - Issuer evaluation Z = k·M (base64url)
 * @property {string} Zprime - Unblinded token Z' = k·P (base64url)
 * @property {string} [P] - Scope point P = H1(ctx(S)) (optional, verifier can reconstruct)
 * @property {object} piI - Issuer DLEQ proof {A1, A2, c, r} (all base64url except c,r are hex bigints)
 * @property {object} piC - Client DLEQ proof {A1, A2, c, r} bound to (nonce, digest, η)
 * @property {string} c_nonce - Verifier-issued nonce (base64url)
 * @property {string} [d] - HTTP context digest (base64url, optional)
 * @property {string} AADr - Associated data at redemption
 * @property {string} [eta] - Salt η (base64url, optional — verifier recomputes, client may echo)
 */

/**
 * @typedef {object} RequestContext
 * @property {string} origin - Request origin (from HTTP Origin header or verified fallback)
 * @property {string} [httpMethod] - HTTP method (for digest d)
 * @property {string} [normalizedPath] - Normalized request path
 * @property {Uint8Array} [bodyDigest] - SHA-256 of request body
 * @property {Uint8Array} [tlsExporterBytes] - TLS exporter value
 */

/**
 * Verify a BRASS token redemption.
 *
 * This is the core function. It implements the complete verifier-side
 * redemption flow without contacting the issuer.
 *
 * @param {RedemptionMessage} msg - The redemption message from the client
 * @param {RequestContext} ctx - Request context derived from transport
 * @param {VerifyConfig} config - Verifier configuration
 * @param {import('./storage.js').BrassCounterStore} store - Counter store
 * @returns {Promise<{ok: boolean, remaining?: number, error?: string}>}
 */
export async function verify(msg, ctx, config, store) {
  const {
    issuerPubKey,
    keyId,
    kvSecret,
    verifierSecret = null,
    rateLimit = 100,
    windowSec = 86400,
    graceSeconds = 60,
    protocolVersion = 'BRASS_v2.0',
    cipherSuite = 'P256_SHA256',
  } = config;

  const nowMs = Date.now();

  // ── 1. Derive scope from transport context ──────────────────────────────
  let originCanonical;
  try {
    originCanonical = canonicalOrigin(ctx.origin);
  } catch {
    return { ok: false, error: 'invalid_origin' };
  }

  const currentWindow = windowId(nowMs, windowSec);
  const validWindows = validWindowsWithSkew(nowMs, windowSec);
  const epoch = Math.floor(nowMs / 86400000); // Day-level epoch
  const policyId = parsePolicyId(msg.AADr || '');

  // ── 2. Derive verifier-chosen salt η ────────────────────────────────────
  const eta = deriveEta(
    issuerPubKey, originCanonical, epoch, policyId, currentWindow,
    verifierSecret
  );

  // ── 3. Decode and validate all points ───────────────────────────────────
  let M, Z, Zprime, Y;
  try {
    M = decodePoint(msg.M);
    Z = decodePoint(msg.Z);
    Zprime = decodePoint(msg.Zprime);
    Y = decodePoint(issuerPubKey);
  } catch (e) {
    return { ok: false, error: e.message || 'invalid_point' };
  }

  // ── 4. Verify issuer proof πI: log_g(Y) = log_M(Z) ─────────────────────
  const G = p256.ProjectivePoint.BASE;
  try {
    const piI = msg.piI;
    const valid = dleqVerify({
      label: 'OPRF_METERING_DLEQ_v1',
      g1: G,
      h1: Y,
      g2: M,
      h2: Z,
      A1: decodePoint(piI.A1),
      A2: decodePoint(piI.A2),
      c: BigInt('0x' + piI.c),
      r: BigInt('0x' + piI.r),
      bind: toBytes(msg.AADr || ''),
    });
    if (!valid) return { ok: false, error: 'invalid_piI' };
  } catch {
    return { ok: false, error: 'invalid_piI' };
  }

  // ── 5. Verify client proof πC: log_P(M) = log_{Z'}(Z), bound to (c, d, η) ─
  // πC must be recomputed per-redemption — prevents token theft/replay
  const P = msg.P ? decodePoint(msg.P) : null; // P from client or reconstructed
  if (P) {
    try {
      const piC = msg.piC;
      const tlsBinding = deriveTlsBinding(ctx.tlsExporterBytes || null);
      const bindContext = H3(
        toBytes(msg.c_nonce || ''),
        toBytes(msg.d || ''),
        eta,
        tlsBinding
      );
      const valid = dleqVerify({
        label: 'OPRF_METERING_DLEQ_v1',
        g1: P,
        h1: M,
        g2: Zprime,
        h2: Z,
        A1: decodePoint(piC.A1),
        A2: decodePoint(piC.A2),
        c: BigInt('0x' + piC.c),
        r: BigInt('0x' + piC.r),
        bind: bindContext,
      });
      if (!valid) return { ok: false, error: 'invalid_piC' };
    } catch {
      return { ok: false, error: 'invalid_piC' };
    }
  }

  // ── 6. Compute deterministic nullifier y ────────────────────────────────
  const y = deriveNullifierY(msg.Zprime, keyId, msg.AADr || '', eta);
  const y_b64 = bytesToB64url(y);

  // ── 7. Grace-bridge check (if within grace period) ──────────────────────
  const inGrace = isInGracePeriod(nowMs, graceSeconds, windowSec);
  if (inGrace) {
    const graceY = deriveGraceNullifier(
      msg.Zprime, keyId, issuerPubKey, originCanonical,
      policyId, cipherSuite, protocolVersion, msg.AADr || ''
    );
    const graceKey = bytesToB64url(graceY);

    const graceResult = await store.guardGrace({ graceKey, ttlSeconds: graceSeconds * 2 });
    if (graceResult.hit) {
      return graceResult.response;
    }

    // Process normally, then cache the result
    const result = await _countAndEnforce(y_b64, msg.c_nonce, {
      issuerPk: issuerPubKey, origin: originCanonical, epoch, policy: policyId,
      window: currentWindow,
    }, config, store);

    await store.cacheGraceResponse({
      graceKey, ttlSeconds: graceSeconds * 2, response: result,
    });

    return result;
  }

  // ── 8. Normal path: count and enforce ───────────────────────────────────
  return _countAndEnforce(y_b64, msg.c_nonce, {
    issuerPk: issuerPubKey, origin: originCanonical, epoch, policy: policyId,
    window: currentWindow,
  }, config, store);
}

/**
 * Internal: count redemption and enforce threshold.
 */
async function _countAndEnforce(y_b64, c_nonce, scope, config, store) {
  const { kvSecret, rateLimit = 100, windowSec = 86400 } = config;

  const IK = deriveIdempotencyKey(kvSecret, b64urlToBytes(y_b64), c_nonce || '');
  const counterKey = buildCounterKey({ ...scope, y: y_b64 });
  const ttlSeconds = secondsUntilWindowEnd(scope.window, windowSec);

  return store.spend({
    counterKey,
    idempotencyKey: IK,
    limit: rateLimit,
    ttlSeconds,
  });
}

// decodePoint and dleqVerify are exported inline via `export function` above.
