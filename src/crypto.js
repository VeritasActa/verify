/**
 * @veritasacta/verify — crypto.js
 *
 * Deterministic cryptographic primitives for the BRASS protocol.
 * Domain-separated hashing, nullifier derivation, salt computation,
 * and window management for privacy-preserving rate limiting.
 *
 * All functions are pure (no side effects, no I/O).
 *
 * References:
 *   RFC 9497 — VOPRF (Verifiable Oblivious Pseudorandom Functions)
 *   RFC 9380 — Hashing to Elliptic Curves
 *
 * @module @veritasacta/verify/crypto
 * @license MIT
 */

import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { utf8ToBytes } from '@noble/hashes/utils';

// ─── Encoding helpers ───────────────────────────────────────────────────────

/** Convert a string to UTF-8 bytes, pass Uint8Array through unchanged. */
export function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return utf8ToBytes(v);
  if (typeof v === 'number') return numberToU32BE(v);
  throw new TypeError('toBytes: expected string, Uint8Array, or number');
}

/** Encode a number as 4-byte big-endian. */
function numberToU32BE(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/**
 * Length-prefix a byte array (4-byte BE length ∥ data).
 * Prevents cross-field collisions in hash inputs.
 */
function lengthPrefix(bytes) {
  const len = numberToU32BE(bytes.length);
  const out = new Uint8Array(4 + bytes.length);
  out.set(len, 0);
  out.set(bytes, 4);
  return out;
}

/**
 * Concatenate multiple Uint8Arrays efficiently (single allocation).
 * @param {Uint8Array[]} arrays
 * @returns {Uint8Array}
 */
function concat(arrays) {
  let totalLen = 0;
  for (let i = 0; i < arrays.length; i++) totalLen += arrays[i].length;
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], offset);
    offset += arrays[i].length;
  }
  return out;
}

// ─── Base64URL ──────────────────────────────────────────────────────────────

/** Encode bytes to base64url (no padding). */
export function bytesToB64url(b) {
  // Works in Node 18+, Cloudflare Workers, Deno, browsers
  const base64 = typeof Buffer !== 'undefined'
    ? Buffer.from(b).toString('base64')
    : btoa(String.fromCharCode(...b));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode base64url to bytes. */
export function b64urlToBytes(s) {
  if (s == null) throw new Error('b64urlToBytes: input cannot be null/undefined');
  let base64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// ─── Core hash functions ────────────────────────────────────────────────────

/**
 * H3: Domain-separated, length-prefixed SHA-256.
 *
 * Each input is converted to bytes, length-prefixed, then concatenated.
 * This prevents:
 *   - Cross-field collisions: H3("ab", "c") ≠ H3("a", "bc")
 *   - Type confusion: H3(0x01) ≠ H3("\x01")
 *
 * @param {...(string|Uint8Array|number)} parts - Inputs to hash
 * @returns {Uint8Array} 32-byte SHA-256 digest
 */
export function H3(...parts) {
  const prefixed = parts.map(p => lengthPrefix(toBytes(p)));
  return sha256(concat(prefixed));
}

/**
 * H2: Nullifier derivation hash.
 * Identical to H3 — separate name for protocol clarity.
 * Future: may use HKDF-Expand with a distinct label.
 */
export function H2(...parts) {
  return H3(...parts);
}

// ─── Origin canonicalization ────────────────────────────────────────────────

/**
 * Canonicalize a web origin for scope binding.
 *
 * Rules:
 *   - HTTPS only (rejects http://)
 *   - No path, query, or fragment
 *   - Lowercase hostname with IDNA normalization
 *   - Default port 443 elided
 *   - Trailing dots stripped
 *
 * @param {string} originUrl - Full origin URL (e.g., "https://api.example.com")
 * @returns {string} Canonical origin (e.g., "https://api.example.com")
 * @throws {Error} If origin is invalid or not HTTPS
 */
export function canonicalOrigin(originUrl) {
  try {
    const u = new URL(originUrl);
    if (u.protocol !== 'https:') throw new Error('origin_must_be_https');
    if (u.pathname !== '/' || u.search !== '' || u.hash !== '') {
      throw new Error('origin_must_not_contain_path');
    }
    if (!u.hostname) throw new Error('invalid_hostname');
    const host = u.hostname.toLowerCase().replace(/\.+$/, '');
    if (!host) throw new Error('invalid_hostname');
    const isDefaultPort = (u.port === '' || u.port === '443');
    return `https://${host}${isDefaultPort ? '' : ':' + u.port}`;
  } catch (e) {
    if (e.message.startsWith('origin_') || e.message.startsWith('invalid_')) throw e;
    throw new Error('invalid_origin');
  }
}

// ─── Time / window functions ────────────────────────────────────────────────

/** Current UTC day index (epoch days). */
export function currentEpochDays(nowMs = Date.now()) {
  return Math.floor(nowMs / 86400000);
}

/**
 * Compute window ID for a given timestamp and window duration.
 *
 * @param {number} nowMs - Current time in milliseconds
 * @param {number} windowSec - Window duration in seconds (default: 86400 = 1 day)
 * @returns {number} Window identifier
 */
export function windowId(nowMs = Date.now(), windowSec = 86400) {
  return Math.floor(nowMs / (windowSec * 1000));
}

/** Clock skew tolerance in milliseconds. */
const WINDOW_SKEW_MS = 30_000;

/**
 * Valid windows for the current time, accounting for ±30s clock skew.
 *
 * @param {number} nowMs - Current time in milliseconds
 * @param {number} windowSec - Window duration in seconds (default: 86400)
 * @returns {number[]} Array of valid window IDs (current, and optionally previous)
 */
export function validWindowsWithSkew(nowMs = Date.now(), windowSec = 86400) {
  const windowMs = windowSec * 1000;
  const current = Math.floor(nowMs / windowMs);
  const windows = [current];
  const msIntoWindow = nowMs % windowMs;
  if (msIntoWindow < WINDOW_SKEW_MS) {
    windows.push(current - 1);
  }
  return windows;
}

/**
 * Seconds remaining until the current window ends.
 *
 * @param {number} windowStart - Window start identifier
 * @param {number} windowSec - Window duration in seconds (default: 86400)
 * @returns {number} Seconds remaining (minimum 1)
 */
export function secondsUntilWindowEnd(windowStart, windowSec = 86400) {
  const windowMs = windowSec * 1000;
  const windowEnd = (Number(windowStart) + 1) * windowMs;
  return Math.max(1, Math.floor((windowEnd - Date.now()) / 1000));
}

// ─── Grace-bridge (UTC boundary protection) ─────────────────────────────────

/**
 * Check if current time is within the grace period around a window boundary.
 *
 * During the grace period, the verifier uses a window-agnostic nullifier
 * to prevent double-spend across the boundary transition.
 *
 * @param {number} nowMs - Current time in milliseconds
 * @param {number} graceSeconds - Grace period in seconds (default: 60)
 * @param {number} windowSec - Window duration in seconds (default: 86400)
 * @returns {boolean} True if within grace period
 */
export function isInGracePeriod(nowMs, graceSeconds = 60, windowSec = 86400) {
  const graceMs = graceSeconds * 1000;
  const windowMs = windowSec * 1000;
  const msIntoWindow = nowMs % windowMs;
  // Boundaries are exclusive: [0, graceMs) after and (windowMs - graceMs, windowMs) before
  return msIntoWindow < graceMs || msIntoWindow > (windowMs - graceMs);
}

// ─── BRASS derivation functions ─────────────────────────────────────────────

/**
 * Derive deterministic salt η from service-side context.
 *
 * η is computed exclusively by the verifier from public scope parameters.
 * The client CANNOT choose or influence η (Patent 2/3 core innovation).
 *
 * If a verifier secret is provided, it is mixed into η to prevent:
 *   - Precomputation attacks (attacker cannot derive η without the secret)
 *   - Cross-verifier nullifier collisions (two verifiers for same origin)
 *
 * @param {string} issuerPK_b64 - Issuer public key (base64url)
 * @param {string} originCanonical - Canonical origin (from canonicalOrigin())
 * @param {number} epoch - Epoch identifier (e.g., day index)
 * @param {string} policyId - Policy identifier (e.g., "default", "comments")
 * @param {number} window - Window identifier
 * @param {Uint8Array|null} [verifierSecret=null] - Optional per-verifier secret
 * @returns {Uint8Array} 32-byte salt
 */
export function deriveEta(issuerPK_b64, originCanonical, epoch, policyId, window, verifierSecret = null) {
  const parts = [
    'BRASS_SALT_v1',
    toBytes(issuerPK_b64),
    toBytes(originCanonical),
    toBytes(String(epoch)),
    toBytes(String(policyId)),
    toBytes(String(window)),
  ];
  if (verifierSecret) {
    parts.push(verifierSecret);
  }
  return H3(...parts);
}

/**
 * Derive deterministic nullifier y from token and salt.
 *
 * y is the per-scope, per-window uniqueness key.
 * Same (token, scope, window) → same y.
 * Different window → different y (cross-window unlinkability).
 *
 * @param {string} encZprime_b64 - Canonical encoding of unblinded token Z' (base64url)
 * @param {string} KID - Issuer key identifier
 * @param {string} AADr - Associated data at redemption (includes policy, window config)
 * @param {Uint8Array} eta - Verifier-derived salt
 * @returns {Uint8Array} 32-byte nullifier
 */
export function deriveNullifierY(encZprime_b64, KID, AADr, eta) {
  return H2(
    'BRASS_NULLIFIER_v1',
    toBytes(encZprime_b64),
    toBytes(KID),
    toBytes(AADr),
    eta
  );
}

/**
 * Derive idempotency key for at-most-once request counting.
 *
 * IK = HMAC-SHA256(verifierSecret, len(y) ∥ y ∥ len(c) ∥ c)
 *
 * @param {Uint8Array} kvSecret - Verifier-side secret (32 bytes)
 * @param {Uint8Array} y - Nullifier
 * @param {string} c_b64 - Nonce from verifier (base64url)
 * @returns {string} Idempotency key (base64url)
 */
export function deriveIdempotencyKey(kvSecret, y, c_b64) {
  if (!(kvSecret instanceof Uint8Array)) {
    throw new Error('kvSecret must be Uint8Array');
  }
  if (typeof c_b64 !== 'string') {
    throw new Error('c_b64 must be base64url string');
  }
  const cBytes = b64urlToBytes(c_b64);
  const message = concat([lengthPrefix(y), lengthPrefix(cBytes)]);
  const mac = hmac(sha256, kvSecret, message);
  return bytesToB64url(mac);
}

/**
 * Derive grace-bridge nullifier (window-agnostic).
 *
 * Used during the grace period around window boundaries to prevent
 * double-spend across the transition. Excludes window ID from inputs.
 *
 * @param {string} encZprime_b64 - Token Z' encoding
 * @param {string} KID - Key identifier
 * @param {string} issuerPK_b64 - Issuer public key
 * @param {string} originID - Canonical origin
 * @param {string} policyId - Policy identifier
 * @param {string} suite - Cipher suite (e.g., 'P256_SHA256')
 * @param {string} version - Protocol version (e.g., 'BRASS_v2.0')
 * @param {string} AADr - Associated data at redemption
 * @returns {Uint8Array} 32-byte grace nullifier
 */
export function deriveGraceNullifier(encZprime_b64, KID, issuerPK_b64, originID, policyId, suite, version, AADr) {
  return H2(
    'BRASS_GRACE_v2',
    toBytes(encZprime_b64),
    toBytes(KID),
    toBytes(issuerPK_b64),
    toBytes(originID),
    toBytes(policyId),
    toBytes(suite),
    toBytes(version),
    toBytes(AADr)
  );
}

/**
 * Derive TLS channel binding from exporter bytes or fallback.
 *
 * Binds the verification proof to a specific TLS session when available.
 * Falls back to a domain-separated constant when TLS exporter is not accessible.
 *
 * @param {Uint8Array|null} [tlsExporterBytes=null] - TLS exporter value (RFC 5705/8446)
 * @returns {Uint8Array} 32-byte binding value
 */
export function deriveTlsBinding(tlsExporterBytes = null) {
  if (tlsExporterBytes && tlsExporterBytes.length > 0) {
    return H3('tls_exporter', tlsExporterBytes);
  }
  return H3('no_exporter');
}

/**
 * Extract policy ID from associated data string.
 *
 * @param {string} AADr - Associated data at redemption
 * @returns {string} Policy identifier (default: "default")
 */
export function parsePolicyId(AADr) {
  const m = /policy=([A-Za-z0-9_-]+)/.exec(AADr);
  return m ? m[1] : 'default';
}

/**
 * Build the counter key tuple for storage lookups.
 *
 * @param {object} params
 * @param {string} params.issuerPk - Issuer public key (base64url)
 * @param {string} params.origin - Canonical origin
 * @param {number} params.epoch - Epoch identifier
 * @param {string} params.policy - Policy identifier
 * @param {number} params.window - Window identifier
 * @param {string} params.y - Nullifier (base64url)
 * @param {string} [params.namespace] - Optional namespace for multi-tenant isolation
 * @returns {string} Composite key for storage
 */
export function buildCounterKey({ issuerPk, origin, epoch, policy, window, y, namespace }) {
  const prefix = namespace ? `ns:${namespace}|` : '';
  return `${prefix}${issuerPk}|${origin}|${epoch}|${policy}|${window}|${y}`;
}
