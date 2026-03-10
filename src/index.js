/**
 * @veritasacta/verify
 *
 * Open-source anonymous credential verification using VOPRF (RFC 9497).
 * Issuer-blind, offline, deterministic.
 *
 * @module @veritasacta/verify
 * @license MIT
 */

// ─── Core verification ───────────────────────────────────────────────────────
export { verify, decodePoint, dleqVerify } from './verifier.js';

// ─── Cryptographic primitives ────────────────────────────────────────────────
export {
  H2,
  H3,
  toBytes,
  bytesToB64url,
  b64urlToBytes,
  canonicalOrigin,
  currentEpochDays,
  windowId,
  validWindowsWithSkew,
  secondsUntilWindowEnd,
  isInGracePeriod,
  deriveEta,
  deriveNullifierY,
  deriveIdempotencyKey,
  deriveGraceNullifier,
  deriveTlsBinding,
  parsePolicyId,
  buildCounterKey,
} from './crypto.js';

// ─── Storage interface ───────────────────────────────────────────────────────
export { BrassCounterStore } from './storage.js';
