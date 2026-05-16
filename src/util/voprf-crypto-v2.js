/**
 * BRASS v2 crypto hardening scaffold.
 *
 * Introduces three changes from the production v1 scheme
 * (see src/util/voprf-crypto.js):
 *
 *   1. Length-prefixed hashing (H_LP) — every variable-length input is
 *      preceded by its 4-byte big-endian length. This eliminates the
 *      concat-collision surface in the piC bind where AADr and KID are
 *      both variable-length strings. Under v1, an attacker who can
 *      influence AADr and KID could in principle find (A, B) and
 *      (A', B') such that A||B == A'||B'; under v2 this is infeasible
 *      because the length prefixes force unambiguous parsing.
 *
 *   2. Nullifier derivation bound to issuer public key Y. Under v1 the
 *      nullifier is derived from (kid || ...) alone; if two issuers
 *      ever collided on kid strings, their nullifier spaces would
 *      overlap. v2 adds Y's encoded point bytes as the first input so
 *      distinct issuer keypairs ALWAYS produce distinct nullifier
 *      spaces, even under kid collision.
 *
 *   3. Single-variable πC restatement — the production BRASS piC uses
 *      a DLEQ shape with A2=G hardcoded, which is cryptographically
 *      equivalent to a single-variable Schnorr but reads as degenerate
 *      to external reviewers. v2 restates it as a plain Schnorr PoK of
 *      `r` satisfying `M = r·P`, keeping the wire (c, r) unchanged.
 *
 * Wire format stays identical across v1 and v2. The difference is
 * WHICH hash function is used in the challenge derivation. Dual-mode
 * verifiers MUST accept either during the v0.6.0–v0.7.0 transition
 * window and emit a tier warning when a v1-derived token is accepted.
 *
 * Target release: `@veritasacta/verify@0.6.0`.
 * Status in 0.5.2: scaffold only — not wired into the default
 * verification path. Exercised by unit tests and surfaced via
 * `cli.js --brass-v2` flag in a later release.
 *
 * @module verify-cli/src/util/voprf-crypto-v2
 * @license Apache-2.0
 */

import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

import {
  G, modN, bytesToBig, b64urlEncode, DLEQ_LABEL, BIND_LABEL, Y_LABEL,
} from './voprf-crypto.js';

/**
 * Length-prefixed hash. Each variadic argument is converted to bytes
 * and prefixed with its 4-byte big-endian length before concatenation.
 *
 * Format: `LP(p_1, …, p_n) = len32(p_1) || p_1 || … || len32(p_n) || p_n`
 *
 * Digest is SHA-256 of the concatenation.
 */
export function H_LP(...parts) {
  const bufs = [];
  let total = 0;

  for (const p of parts) {
    const b = toBytes(p);
    const len = new Uint8Array(4);
    // Big-endian 4-byte length.
    len[0] = (b.length >>> 24) & 0xff;
    len[1] = (b.length >>> 16) & 0xff;
    len[2] = (b.length >>> 8) & 0xff;
    len[3] = (b.length) & 0xff;
    bufs.push(len, b);
    total += 4 + b.length;
  }

  const combined = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    combined.set(b, off);
    off += b.length;
  }
  return sha256(combined);
}

/**
 * Labelled length-prefixed hash. Prefixes with `BRASS:v2:<label>:`.
 */
export function H_LPlabel(label, ...parts) {
  return H_LP(`BRASS:v2:${label}:`, ...parts);
}

/**
 * v2 nullifier derivation — binds to the issuer's encoded public key Y.
 *
 * Under v1 (production): nullifier = H(BRASS:Y-label:, kid, …)
 * Under v2: nullifier = H_LP(BRASS:v2:Y-label:, Yenc, kid, …)
 *
 * The kid collision surface is neutralised: two issuers with the
 * same kid string but distinct keypairs produce DISJOINT nullifier
 * domains.
 *
 * @param {import('@noble/curves/p256').ProjPointType} Y   Issuer public key
 * @param {string} kid
 * @param {...(string|Uint8Array)} extra
 * @returns {Uint8Array} 32-byte nullifier
 */
export function deriveNullifier_v2(Y, kid, ...extra) {
  const Yenc = Y.toRawBytes(true);
  return H_LPlabel(Y_LABEL, Yenc, kid, ...extra);
}

/**
 * v2 πI challenge recomputation. Identical wire to v1 but uses H_LP.
 *
 * Inputs:
 *   label, g1, h1, g2, h2, A1, A2, bind
 *
 * Returns the recomputed challenge c' as a bigint mod N.
 */
export function piIChallenge_v2({
  label, g1, h1, g2, h2, A1, A2, bind,
}) {
  const bindBytes = bind || new Uint8Array(0);
  const digest = H_LPlabel(
    label,
    g1.toRawBytes(true),
    h1.toRawBytes(true),
    g2.toRawBytes(true),
    h2.toRawBytes(true),
    A1.toRawBytes(true),
    A2.toRawBytes(true),
    bindBytes
  );
  return modN(bytesToBig(digest));
}

/**
 * v2 single-variable πC verifier. Restates the degenerate two-var
 * DLEQ (A2=G) as a plain Schnorr: prove knowledge of r such that
 * M = r·P, bound to AADr and KID via the transcript.
 *
 * Wire: proof = { c, r }.
 * Reconstruct: A := r·P + c·M. Challenge:
 *   c' := H_LP(BRASS:v2:BIND_LABEL:, Pencode, Mencode, Aencode, AADr, kid)
 *
 * Accept iff c' == c.
 *
 * @param {Object} params
 * @param {import('@noble/curves/p256').ProjPointType} params.P   Hashed request point
 * @param {import('@noble/curves/p256').ProjPointType} params.M   Client blinded request (r·P)
 * @param {bigint} params.c
 * @param {bigint} params.r
 * @param {Uint8Array|string} params.AADr
 * @param {string} params.kid
 * @returns {boolean}
 */
export function piCVerify_v2({ P, M, c, r, AADr, kid }) {
  // A = r·P + c·M
  const A = P.multiply(r).add(M.multiply(c));
  const digest = H_LPlabel(
    BIND_LABEL,
    P.toRawBytes(true),
    M.toRawBytes(true),
    A.toRawBytes(true),
    AADr || new Uint8Array(0),
    kid
  );
  const chal = modN(bytesToBig(digest));
  return chal === c;
}

/**
 * Translation helper: given an inner v1 token, produce the v2 challenge
 * digest for comparison. Used by the dual-mode verifier to decide which
 * path was used by the issuer.
 */
export function v2DigestForWireInputs(label, inputs) {
  return H_LPlabel(label, ...inputs);
}

// ───── internal helpers ─────

function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return utf8ToBytes(v);
  if (typeof v === 'number' || typeof v === 'bigint') {
    // Big-endian encoding of numeric inputs (not typically used in BRASS
    // but handled for safety).
    const n = BigInt(v);
    const bytes = [];
    let tmp = n;
    while (tmp > 0n) {
      bytes.unshift(Number(tmp & 0xffn));
      tmp >>= 8n;
    }
    return bytes.length > 0 ? Uint8Array.from(bytes) : new Uint8Array([0]);
  }
  throw new TypeError(`v2.toBytes: unsupported input type ${typeof v}`);
}

// Re-export v1 labels so callers can use them consistently against v2.
export { DLEQ_LABEL, BIND_LABEL, Y_LABEL, G, b64urlEncode };
