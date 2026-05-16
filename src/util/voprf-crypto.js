/**
 * VOPRF crypto primitives for @veritasacta/verify.
 *
 * P-256 point validation, base64url encoding, plain-concat SHA-256
 * hashing (matching the production BRASS scheme emitted by the
 * issuer Cloudflare Worker), and Schnorr DLEQ verification with
 * (c, r)-only wire proofs.
 *
 * Protocol compatibility:
 *
 *   - Matches the production BRASS protocol as deployed by the
 *     issuer at `api.scopeblind.com` (Apache-2.0 worker source at
 *     brass-proof/worker/issuer-cloudflare.js). Tokens issued by
 *     that worker verify byte-compatibly here.
 *   - Matches the `strict-verifier.js` Cloudflare Worker behavior.
 *   - Does NOT match the length-prefixed scheme of the earlier
 *     veritasacta-verify/src/verifier.js reference. That reference
 *     had three errors (length-prefix in H, non-empty bind for \u03c0I,
 *     wrong \u03c0C reconstruction) and should not be relied on.
 *
 * References:
 *
 *   RFC 9497     VOPRF (Verifiable Oblivious Pseudorandom Functions)
 *   RFC 8785     JSON Canonicalization Scheme (used elsewhere in
 *                @veritasacta/verify for receipt canonicalization;
 *                BRASS itself does NOT use JCS)
 *   Provisional  AU Patent #1 (VOPRF metering), #2 (verifier
 *                nullifiers)
 *
 * @module verify-cli/src/util/voprf-crypto
 * @license Apache-2.0
 */

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

// ─── Constants ───────────────────────────────────────────────────────────────

/** P-256 base point. */
export const G = p256.ProjectivePoint.BASE;

/** P-256 group order. */
const N = p256.CURVE.n;

/** Domain-separation label used by the BRASS DLEQ hash. */
export const DLEQ_LABEL = 'OPRF_METERING_DLEQ_v1';

/** Domain-separation label for the server-side nullifier derivation. */
export const Y_LABEL = 'OPRF_METERING_Y_v1';

/** Fiat-Shamir transcript binder label for \u03c0C. */
export const BIND_LABEL = 'BRASS_BIND_v1';

// ─── Modular + encoding helpers ──────────────────────────────────────────────

export function modN(x) {
  const r = x % N;
  return r >= 0n ? r : r + N;
}

export function bytesToBig(b) {
  let n = 0n;
  for (const byte of b) n = (n << 8n) | BigInt(byte);
  return n;
}

function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return utf8ToBytes(v);
  throw new TypeError('toBytes: expected string or Uint8Array');
}

// ─── Base64url ───────────────────────────────────────────────────────────────

export function b64urlEncode(bytes) {
  const base64 = typeof Buffer !== 'undefined'
    ? Buffer.from(bytes).toString('base64')
    : btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s) {
  if (s == null) throw new Error('b64urlDecode: input cannot be null/undefined');
  let base64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// ─── BRASS hash primitives ───────────────────────────────────────────────────

/**
 * H: Plain concatenation SHA-256 used by the production BRASS
 * protocol. Inputs are UTF-8-encoded if strings, otherwise passed
 * as Uint8Array. NO length-prefixing.
 *
 * This matches the issuer Cloudflare Worker exactly. For new
 * protocols we would prefer length-prefixing for collision safety;
 * see the v0.6.0 roadmap for BRASS v2.
 */
export function H(...parts) {
  const byteParts = parts.map(toBytes);
  let total = 0;
  for (const p of byteParts) total += p.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of byteParts) {
    buf.set(p, off);
    off += p.length;
  }
  return sha256(buf);
}

/**
 * Hlabel: Prefixed hash used for label-separated derivations.
 * Concatenates `BRASS:<label>:` as a prefix before the variadic
 * parts and then applies H.
 */
export function Hlabel(label, ...parts) {
  return H(`BRASS:${label}:`, ...parts);
}

// ─── P-256 point handling ────────────────────────────────────────────────────

/**
 * Decode and validate a base64url-encoded compressed P-256 point.
 *
 * Rejects off-curve points, non-canonical encodings, point at
 * infinity, invalid prefix bytes, and wrong lengths.
 *
 * @param {string} b64
 * @returns {import('@noble/curves/p256').ProjPointType}
 */
export function decodePoint(b64) {
  const bytes = b64urlDecode(b64);
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

/** Encode a compressed P-256 point as base64url. */
export function encodePoint(P) {
  return b64urlEncode(P.toRawBytes(true));
}

// ─── Schnorr DLEQ verification ───────────────────────────────────────────────

/**
 * Verify a Schnorr-style discrete-log equality (DLEQ) proof in the
 * production BRASS wire format.
 *
 * Wire: proof = { c, r } where c, r are base64url-encoded 32-byte
 * scalars. The verifier reconstructs the commitments from (r, c)
 * before recomputing the challenge:
 *
 *   A1 := r\u00b7g1 + c\u00b7h1
 *   A2 := r\u00b7g2 + c\u00b7h2   (or A2 := G for single-variable variant)
 *   c' := H(BRASS:<label>:, g1, h1, g2, h2, A1, A2, bind)
 *   accept iff c' == c
 *
 * For the \u03c0I (issuer) proof, the standard two-variable shape is
 * used: g1=G, h1=Y, g2=M, h2=Z, no bind.
 *
 * For the \u03c0C (client) proof, the BRASS production scheme uses a
 * single-variable variant with g2=h2=G and A2=G hardcoded. This
 * proves knowledge of the blinding scalar r such that M = r\u00b7P
 * without introducing redundant generators. The helper
 * `dleqVerifyClient` below exposes this variant.
 *
 * @param {Object} params
 * @param {string} params.label
 * @param {import('@noble/curves/p256').ProjPointType} params.g1
 * @param {import('@noble/curves/p256').ProjPointType} params.h1
 * @param {import('@noble/curves/p256').ProjPointType} params.g2
 * @param {import('@noble/curves/p256').ProjPointType} params.h2
 * @param {bigint} params.c
 * @param {bigint} params.r
 * @param {Uint8Array} [params.bind]
 * @param {import('@noble/curves/p256').ProjPointType} [params.A2Override]
 *   When provided, A2 is not reconstructed from (r, c, h2) but
 *   taken as-is from this override. Used by \u03c0C (A2=G hardcoded).
 * @returns {boolean}
 */
export function dleqVerify({
  label, g1, h1, g2, h2, c, r, bind, A2Override,
}) {
  const bindBytes = bind || new Uint8Array(0);

  // Reconstruct commitments from (r, c). Standard Schnorr: A = r\u00b7g + c\u00b7h.
  const A1 = g1.multiply(r).add(h1.multiply(c));
  const A2 = A2Override !== undefined
    ? A2Override
    : g2.multiply(r).add(h2.multiply(c));

  const challenge = Hlabel(
    label,
    g1.toRawBytes(true),
    h1.toRawBytes(true),
    g2.toRawBytes(true),
    h2.toRawBytes(true),
    A1.toRawBytes(true),
    A2.toRawBytes(true),
    bindBytes
  );
  const chal = modN(bytesToBig(challenge));
  return chal === c;
}

/**
 * Verify \u03c0I (issuer DLEQ proof).
 *
 * Proves: log_G(Y) = log_M(Z) = k (issuer secret).
 * Matches the issuer at /brass-proof-public/worker/issuer-cloudflare.js.
 *
 * @param {Object} params
 * @param {import('@noble/curves/p256').ProjPointType} params.Y  issuer public key
 * @param {import('@noble/curves/p256').ProjPointType} params.M  blinded element
 * @param {import('@noble/curves/p256').ProjPointType} params.Z  issuer evaluation (k\u00b7M)
 * @param {bigint} params.c
 * @param {bigint} params.r
 * @returns {boolean}
 */
export function dleqVerifyIssuer({ Y, M, Z, c, r }) {
  return dleqVerify({
    label: DLEQ_LABEL,
    g1: G, h1: Y,
    g2: M, h2: Z,
    c, r,
    bind: new Uint8Array(0),
  });
}

/**
 * Verify \u03c0C (client DLEQ proof).
 *
 * Proves: client knows blinding scalar b such that M = b\u00b7P.
 * Uses the BRASS single-variable-in-DLEQ-clothing shape with
 * g2=h2=G and A2=G hardcoded. bindContext is the
 * length-sensitive H(BRASS_BIND_v1, y, c_nonce, d, AADr, KID, eta,
 * tlsHash) transcript tag.
 *
 * @param {Object} params
 * @param {import('@noble/curves/p256').ProjPointType} params.P  scope point
 * @param {import('@noble/curves/p256').ProjPointType} params.M  blinded element
 * @param {bigint} params.c
 * @param {bigint} params.r
 * @param {Uint8Array} params.bindContext
 * @returns {boolean}
 */
export function dleqVerifyClient({ P, M, c, r, bindContext }) {
  return dleqVerify({
    label: DLEQ_LABEL,
    g1: P, h1: M,
    g2: G, h2: G,
    c, r,
    bind: bindContext,
    A2Override: G,
  });
}

// ─── Nullifier derivation ────────────────────────────────────────────────────

/**
 * Derive the deterministic server-side nullifier y used for
 * deduplication of redemptions within a scope.
 *
 *   y := H(BRASS:OPRF_METERING_Y_v1:, Zprime, KID, AADr, eta)
 *
 * Matches the production verifier's ySrv computation in
 * strict-verifier.js line 137.
 *
 * @param {Uint8Array} Zprime - raw bytes (NOT base64url)
 * @param {string} KID
 * @param {string} AADr
 * @param {Uint8Array} eta - raw bytes
 * @returns {Uint8Array} 32-byte nullifier
 */
export function deriveNullifier(Zprime, KID, AADr, eta) {
  return Hlabel(Y_LABEL, Zprime, KID, AADr, eta);
}

/**
 * Build the \u03c0C Fiat-Shamir bind transcript tag.
 *
 *   bindContext := H(BRASS_BIND_v1, y, c_nonce, d, AADr, KID, eta,
 *                    tlsHash)
 *
 * y, c_nonce, d, eta, tlsHash are passed as raw bytes.
 * AADr and KID are passed as UTF-8 strings.
 *
 * @param {Object} params
 * @param {Uint8Array} params.y
 * @param {Uint8Array} params.cNonce
 * @param {Uint8Array} params.d
 * @param {string} params.AADr
 * @param {string} params.KID
 * @param {Uint8Array} params.eta
 * @param {Uint8Array} params.tlsHash
 * @returns {Uint8Array}
 */
export function buildClientBindContext({ y, cNonce, d, AADr, KID, eta, tlsHash }) {
  return H(BIND_LABEL, y, cNonce, d, AADr, KID, eta, tlsHash);
}

// ─── Sentinel TLS hash for non-TLS environments ──────────────────────────────

/**
 * Sentinel tlsHash value matching the client fallback when no TLS
 * exporter is available. Used by demos and test harnesses.
 *
 *   sha256('BRASS:TLS_EXPORTER_v1:NO_TLS_EXPORTER_v1')
 */
export function sentinelTlsHash() {
  return sha256(utf8ToBytes('BRASS:TLS_EXPORTER_v1:NO_TLS_EXPORTER_v1'));
}
