/**
 * Sigil operations engine.
 *
 * Implements two capabilities:
 *   1. Claim 1 — Visual cryptographic commitment derivation.
 *      Deterministically derives an 11x11 visual pattern from
 *      (public_key, policy_hash, nonce). Used for canonical-release
 *      verification ("verify the verifier").
 *
 *   2. Claim 2 — Live-context verification (NEW in v0.5.0).
 *      Verifies that a Sigil's policy evaluates true under live context
 *      values (clock drift, geofence, sensor readings) obtained at the
 *      verifier at verification time. Context values are not shared with
 *      or derivable by the Sigil publisher.
 *
 * References:
 *   - Provisional patent #5 (Sigil visual commitment)
 *     Claim 1: derivation of the visual artifact
 *     Claim 2: verification under live context values
 *   - packages/verify-cli/sigil.json (the committed Sigil)
 *
 * @module verify-cli/src/engines/sigil
 * @license Apache-2.0
 */

import { createHash } from 'node:crypto';

const SIGIL_DOMAIN_V1 = 'scopeblind:sigil:v1';
const SIGIL_DOMAIN_V2 = 'scopeblind:sigil:v2';
const SIGIL_SEGMENTS = 6;

/* ──────────────────────────────────────────────────────────────────
 * Claim 1 — Derivation
 * ──────────────────────────────────────────────────────────────── */

/**
 * Derive the Sigil hash from (public_key, policy_hash, nonce).
 * Matches the canonical Veritas Acta Sigil derivation.
 *
 * @param {string} projectPublicKeyHex
 * @param {string} policyHashHex
 * @param {number} [nonce=0]
 * @returns {string} hex-encoded Sigil hash
 */
export function deriveSigilHash(projectPublicKeyHex, policyHashHex, nonce = 0) {
  const domain = Buffer.from(SIGIL_DOMAIN_V2);
  const pubKey = Buffer.from(projectPublicKeyHex, 'hex');
  const policyBuf = Buffer.from(policyHashHex, 'hex');
  const nonceBuf = Buffer.from([nonce & 0xff]);
  const input = Buffer.concat([domain, pubKey, policyBuf, nonceBuf]);
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Derive the 11x11 Sigil grid from a hash (for visual rendering).
 * Pure function: deterministic.
 *
 * @param {Buffer|Uint8Array} hash
 * @returns {Object} grid specification (diamond, surround, innerRing, midRing, outerRing, corners)
 */
export function deriveSigilGrid(hash) {
  const extHash = createHash('sha256').update(Buffer.from('ext:')).update(hash).digest();
  const b = (i) => (i < 32 ? hash[i] : extHash[i - 32]);
  let idx = 0;

  const diamond = {
    top: b(idx++) % 3,
    right: b(idx++) % 3,
    bottom: b(idx++) % 3,
    left: b(idx++) % 3,
  };
  const surround = [];
  for (let i = 0; i < 4; i++) surround.push(b(idx++) % 3);
  const innerRing = [];
  for (let i = 0; i < SIGIL_SEGMENTS; i++) innerRing.push(b(idx++) % 3);
  const midRing = [];
  for (let i = 0; i < SIGIL_SEGMENTS; i++) midRing.push(b(idx++) % 3);
  const outerRing = [];
  for (let i = 0; i < SIGIL_SEGMENTS; i++) outerRing.push(b(idx++) % 3);
  const corners = [];
  for (let i = 0; i < 8; i++) corners.push(b(idx++) % 3);

  return { diamond, surround, innerRing, midRing, outerRing, corners };
}

/**
 * Test that a grid passes the visual-distinctiveness filter.
 * (Sigils that are too sparse or too dense are rejected at generation
 * time; the filter ensures readable artifacts.)
 *
 * @param {Object} g grid spec
 * @returns {boolean}
 */
export function sigilPassesFilter(g) {
  const all = [
    g.diamond.top, g.diamond.right, g.diamond.bottom, g.diamond.left,
    ...g.surround, ...g.innerRing, ...g.midRing, ...g.outerRing, ...g.corners,
  ];
  let primary = 0;
  let secondary = 0;
  for (const v of all) {
    if (v === 1) primary++;
    if (v === 2) secondary++;
  }
  const filled = primary + secondary;
  return primary >= 4 && secondary >= 4 && filled >= 10 && filled <= 28;
}

/**
 * Derive the canonical (filter-passing) Sigil grid from a public key hex.
 * Finds the smallest nonce that produces a grid passing the filter.
 *
 * @param {string} publicKeyHex
 * @returns {{grid: Object, fingerprint: string, nonce: number}}
 */
export function deriveFilteredSigil(publicKeyHex) {
  let nonce = 0;
  const keyBuf = Buffer.from(publicKeyHex, 'hex');
  while (nonce < 256) {
    const hash = nonce === 0
      ? createHash('sha256').update(SIGIL_DOMAIN_V1).update(keyBuf).digest()
      : createHash('sha256').update(SIGIL_DOMAIN_V1).update(keyBuf).update(Buffer.from([nonce])).digest();
    const grid = deriveSigilGrid(hash);
    if (sigilPassesFilter(grid)) {
      return { grid, fingerprint: hash.toString('hex').slice(0, 8), nonce };
    }
    nonce++;
  }
  // Fallback — unlikely to hit for real keys.
  const hash = createHash('sha256').update(SIGIL_DOMAIN_V1).update(keyBuf).digest();
  return { grid: deriveSigilGrid(hash), fingerprint: hash.toString('hex').slice(0, 8), nonce: -1 };
}

/* ──────────────────────────────────────────────────────────────────
 * Self-check (verify the verifier)
 * ──────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} SelfCheckResult
 * @property {boolean} canonical
 * @property {string} [name]
 * @property {string} [fingerprint]
 * @property {string} [version]
 * @property {string} [pkg]
 * @property {boolean} sourceMatches
 * @property {boolean} policyMatches
 * @property {boolean} sigilMatches
 * @property {string} [installedSourceHash]
 * @property {string} [committedSourceHash]
 * @property {string} [rederivedSigilHash]
 */

/**
 * Perform the "verify the verifier" self-check.
 * Compares the installed cli.js (and v0.5.0+ : src/engines) to the
 * commitments in sigil.json, re-derives the Sigil hash, and confirms
 * everything matches the canonical release.
 *
 * @param {Object} args
 * @param {Object} args.sigil parsed sigil.json
 * @param {Buffer} args.installedSourceBytes combined bytes of cli.js + monitored engine files (deterministic order)
 * @returns {SelfCheckResult}
 */
export function selfCheck({ sigil, installedSourceBytes }) {
  const result = {
    canonical: false,
    name: sigil?.name,
    fingerprint: sigil?.fingerprint,
    version: sigil?.policy?.package_version,
    pkg: sigil?.policy?.package,
    sourceMatches: false,
    policyMatches: false,
    sigilMatches: false,
  };
  if (!sigil || !sigil.policy) return result;

  const installedSourceHash = createHash('sha256').update(installedSourceBytes).digest('hex');
  result.installedSourceHash = installedSourceHash;
  result.committedSourceHash = sigil.policy.source_hash;
  result.sourceMatches = installedSourceHash === sigil.policy.source_hash;

  const policyJson = JSON.stringify(sigil.policy);
  const policyHash = createHash('sha256').update(policyJson).digest('hex');
  result.policyMatches = policyHash === sigil.policy_hash;

  const rederived = deriveSigilHash(sigil.project_public_key, policyHash, 0);
  result.rederivedSigilHash = rederived;
  result.sigilMatches = rederived === sigil.sigil_hash;

  result.canonical = result.sourceMatches && result.policyMatches && result.sigilMatches;
  return result;
}

/* ──────────────────────────────────────────────────────────────────
 * Claim 2 — Live-context verification
 * ──────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} ContextPredicate
 * @property {string} kind  'clock' | 'geofence' | 'sensor' | 'biometric' | 'feed'
 * @property {string} expr  predicate expression (kind-specific)
 * @property {Object} [options]
 */

/**
 * @typedef {Object} ContextEvaluationResult
 * @property {boolean} allSatisfied
 * @property {Array<{kind: string, expr: string, satisfied: boolean, detail: string}>} checks
 */

/**
 * Evaluate a set of live-context predicates.
 * Each predicate is resolved by the live-context module; this engine
 * aggregates results and reports which passed / failed.
 *
 * @param {ContextPredicate[]} predicates
 * @param {Object} [contextProvider] optional override for testing
 * @returns {Promise<ContextEvaluationResult>}
 */
export async function evaluateLiveContext(predicates, contextProvider = null) {
  const provider = contextProvider || (await import('../context/live-context.js')).defaultProvider;
  const checks = [];
  let allSatisfied = true;

  for (const p of predicates) {
    let result;
    try {
      result = await provider.evaluate(p);
    } catch (e) {
      result = { satisfied: false, detail: `error: ${e.message}` };
    }
    checks.push({
      kind: p.kind,
      expr: p.expr,
      satisfied: Boolean(result.satisfied),
      detail: result.detail || '',
    });
    if (!result.satisfied) allSatisfied = false;
  }

  return { allSatisfied, checks };
}
