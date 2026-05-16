/**
 * Canonical attestation and verification-receipt emission.
 *
 * Produces shareable cryptographic artifacts that:
 *
 * 1. A "canonical attestation" — proof that the operator ran the
 *    canonical unmodified verifier at time T. Composable network-effect
 *    artifact: orgs publish these to demonstrate they run the real
 *    verifier. Bundled with the Sigil fingerprint + verifier version.
 *
 * 2. A "verification receipt" — proof that the verifier checked a
 *    specific receipt and the signature was valid. Useful for
 *    transparency-log anchoring; an auditor can prove "at time T, the
 *    canonical verifier confirmed this receipt verifies."
 *
 * Both artifacts are signed with an attester-held Ed25519 key. The key
 * is generated on first use and stored in `~/.veritasacta-verify/attester.json`
 * unless a custom path is provided via --attest-key.
 *
 * Neither artifact phones home. Everything is local, offline, user-controlled.
 * Publication is the user's responsibility (stdout by default; user pipes
 * wherever they want it).
 *
 * @module verify-cli/src/engines/attestation
 * @license Apache-2.0
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import {
  generateKeyPairSync,
  sign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  createHash,
} from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

const DEFAULT_ATTESTER_KEY_DIR = join(homedir(), '.veritasacta-verify');
const DEFAULT_ATTESTER_KEY_FILE = join(DEFAULT_ATTESTER_KEY_DIR, 'attester.json');

/**
 * Ensure an Ed25519 attester key exists at the given path.
 * Generates a new keypair on first use.
 *
 * @param {string} [keyPath]
 * @returns {{privateKey: import('node:crypto').KeyObject, pubHex: string, kid: string}}
 */
export function loadOrCreateAttesterKey(keyPath) {
  const path = keyPath || DEFAULT_ATTESTER_KEY_FILE;

  if (existsSync(path)) {
    const data = JSON.parse(readFileSync(path, 'utf-8'));
    return {
      privateKey: createPrivateKey({ key: Buffer.from(data.privateDer, 'hex'), format: 'der', type: 'pkcs8' }),
      pubHex: data.pubHex,
      kid: data.kid,
    };
  }

  // Generate
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  const pubHex = pubRaw.subarray(pubRaw.length - 32).toString('hex');
  const kid = `attester:${pubHex.slice(0, 12)}`;

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    JSON.stringify({ pubHex, kid, privateDer: privDer.toString('hex'), created_at: new Date().toISOString() }, null, 2),
    { mode: 0o600 },
  );

  return { privateKey, pubHex, kid };
}

/**
 * Sign a payload with an Ed25519 key using JCS canonicalization.
 */
function signCanonical(privateKey, payload) {
  const canonical = canonicalize(payload);
  const sig = sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
  return sig.toString('hex');
}

/**
 * @typedef {Object} CanonicalAttestationOptions
 * @property {Object} sigil         parsed sigil.json
 * @property {boolean} canonical    result of selfCheck
 * @property {string} [org]         optional org name
 * @property {string} [keyPath]     override attester key location
 * @property {string} [expiry]      ISO-8601 validity expiry (defaults to +7 days)
 */

/**
 * Produce a canonical attestation for this verifier run.
 * Returns a signed JSON object the user can publish anywhere.
 *
 * @param {CanonicalAttestationOptions} opts
 * @returns {Object}
 */
export function buildCanonicalAttestation(opts) {
  const { sigil, canonical, org, keyPath } = opts;
  const attester = loadOrCreateAttesterKey(keyPath);

  const now = new Date();
  const expiry = opts.expiry || new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const payload = {
    type: 'veritasacta:verifier-attestation',
    spec: 'draft-farley-acta-signed-receipts-03',
    sigil_fingerprint: sigil.fingerprint,
    sigil_name: sigil.name,
    sigil_hash: sigil.sigil_hash,
    verifier_package: sigil.policy.package,
    verifier_version: sigil.policy.package_version,
    verifier_ietf_draft: sigil.policy.ietf_draft,
    verifier_conformance_tier: sigil.policy.conformance_tier,
    canonical: Boolean(canonical),
    issued_at: now.toISOString(),
    expires_at: expiry,
    attester_kid: attester.kid,
  };
  if (org) payload.attester_org = org;

  const sig = signCanonical(attester.privateKey, payload);

  return {
    payload,
    signature: {
      alg: 'EdDSA',
      kid: attester.kid,
      sig,
    },
    verification: {
      attester_pubkey: attester.pubkey || attester.pubHex,
    },
  };
}

/**
 * Produce a verification receipt: a signed attestation that the
 * canonical verifier checked a specific subject-receipt and it verified.
 *
 * @param {Object} args
 * @param {Object} args.subjectResult        result from a verifier engine
 * @param {Object} args.sigil                parsed sigil.json
 * @param {string} [args.keyPath]            attester key override
 * @returns {Object}
 */
export function buildVerificationReceipt({ subjectResult, sigil, keyPath }) {
  const attester = loadOrCreateAttesterKey(keyPath);

  // Hash the canonical form of the subject (what was verified)
  const subjectHash = subjectResult.hash
    || createHash('sha256').update(JSON.stringify(subjectResult)).digest('hex');

  const payload = {
    type: 'veritasacta:verification-receipt',
    spec: 'draft-farley-acta-signed-receipts-03',
    subject: {
      hash: `sha256:${subjectHash}`,
      kid: subjectResult.kid || null,
      format: subjectResult.format || null,
      algorithm: subjectResult.algorithm || null,
    },
    verification: {
      valid: Boolean(subjectResult.valid),
      tier: subjectResult.tier?.tier || null,
      tier_label: subjectResult.tier?.label || null,
    },
    verifier: {
      sigil_fingerprint: sigil.fingerprint,
      sigil_name: sigil.name,
      version: sigil.policy.package_version,
    },
    issued_at: new Date().toISOString(),
    attester_kid: attester.kid,
  };
  if (subjectResult.error) payload.verification.error = subjectResult.error;

  const sig = signCanonical(attester.privateKey, payload);

  return {
    payload,
    signature: {
      alg: 'EdDSA',
      kid: attester.kid,
      sig,
    },
    verification: {
      attester_pubkey: attester.pubHex || attester.pubkey,
    },
  };
}

/**
 * Verify an attestation artifact (the inverse of buildCanonicalAttestation).
 * Used for verifying that a published attestation came from its stated
 * attester.
 *
 * @param {Object} attestation
 * @param {string} attesterPubHex
 * @returns {boolean}
 */
export function verifyAttestation(attestation, attesterPubHex) {
  try {
    // Build the SPKI wrapper for raw Ed25519 pubkey
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const pubRaw = Buffer.from(attesterPubHex, 'hex');
    const spki = Buffer.concat([spkiPrefix, pubRaw]);
    const pubKeyObj = createPublicKey({ key: spki, format: 'der', type: 'spki' });

    const canonical = canonicalize(attestation.payload);
    const sig = Buffer.from(attestation.signature.sig, 'hex');
    return cryptoVerify(null, Buffer.from(canonical, 'utf-8'), pubKeyObj, sig);
  } catch {
    return false;
  }
}
