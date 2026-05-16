/**
 * Commitment-mode verification engine (draft-farley-acta-signed-receipts-01).
 *
 * Verifies receipts that carry a `committed_fields_root` field: a single
 * SHA-256 Merkle root over RFC 6962-domain-separated leaves of
 * (name, salt, value) tuples.
 *
 * When the caller provides a disclosure object containing a Merkle
 * inclusion proof, this engine:
 *   1. Reconstructs the leaf hash from the disclosed (name, salt, value)
 *   2. Walks the inclusion proof
 *   3. Compares the reconstructed root against committed_fields_root
 *
 * This engine is distinct from the legacy AIP-0002 selective-disclosure
 * engine (which handles the older _commitments-map shape, kept for
 * backwards compatibility). The two formats do not overlap; routing is
 * by the presence of `committed_fields_root` (this engine) vs
 * `_commitments` (the legacy engine).
 *
 * References:
 *   - draft-farley-acta-signed-receipts-01 §commitment-mode
 *   - RFC 6962 §2.1 (Merkle tree construction)
 *   - RFC 8785 (JCS canonicalization)
 *
 * @module verify-cli/src/engines/commitment-mode
 * @license Apache-2.0
 */

import { hashLeaf, encodeLeaf, verifyProof, base64urlDecode } from '../util/merkle.js';

/**
 * @typedef {Object} CommittedDisclosure
 * @property {string} parent_receipt_hash canonical hash of the receipt
 * @property {string} name field name
 * @property {unknown} value cleartext value
 * @property {string} salt  base64url-encoded salt (no padding)
 * @property {{index: number, treeSize: number, siblings: string[]}} proof
 */

/**
 * @typedef {Object} CommitmentVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {number} disclosuresVerified
 * @property {Array<{name: string, ok: boolean, reason?: string}>} checks
 */

/**
 * Verify a committed-mode receipt against zero or more disclosures.
 *
 * If disclosures is empty, the function returns valid=true with
 * disclosuresVerified=0: the receipt's existence and committed_fields_root
 * are not in scope here (the outer signature engine handles that).
 *
 * If disclosures are provided, each is checked against the receipt's
 * committed_fields_root. All must verify for the result to be valid.
 *
 * @param {Object} receipt the parsed receipt with committed_fields_root
 * @param {CommittedDisclosure[]} disclosures
 * @returns {CommitmentVerifyResult}
 */
export function verifyCommittedReceipt(receipt, disclosures = []) {
  if (!receipt || typeof receipt !== 'object') {
    return {
      valid: false,
      error: 'malformed_receipt',
      disclosuresVerified: 0,
      checks: [],
    };
  }

  let rootHex = receipt.committed_fields_root;
  if (typeof rootHex !== 'string' || rootHex.length === 0) {
    return {
      valid: false,
      error: 'missing_committed_fields_root',
      disclosuresVerified: 0,
      checks: [],
    };
  }
  // Strip optional "sha256:" prefix.
  if (rootHex.startsWith('sha256:')) rootHex = rootHex.slice(7);
  if (!/^[0-9a-fA-F]{64}$/.test(rootHex)) {
    return {
      valid: false,
      error: 'malformed_committed_fields_root',
      disclosuresVerified: 0,
      checks: [],
    };
  }

  if (!Array.isArray(disclosures) || disclosures.length === 0) {
    return {
      valid: true,
      disclosuresVerified: 0,
      checks: [],
    };
  }

  const checks = [];
  let allValid = true;

  for (const d of disclosures) {
    const fieldName = d?.name;
    if (typeof fieldName !== 'string' || !fieldName) {
      checks.push({ name: '<unknown>', ok: false, reason: 'disclosure_missing_name' });
      allValid = false;
      continue;
    }

    if (typeof d.salt !== 'string' || !d.salt) {
      checks.push({ name: fieldName, ok: false, reason: 'disclosure_missing_salt' });
      allValid = false;
      continue;
    }

    if (!d.proof || typeof d.proof !== 'object') {
      checks.push({ name: fieldName, ok: false, reason: 'disclosure_missing_proof' });
      allValid = false;
      continue;
    }

    let leafHash;
    try {
      // Validate base64url decode by attempting it (doesn't need the bytes
      // here, just sanity-checks). Then encode the canonical leaf using
      // the salt as it appears in the disclosure (base64url string).
      base64urlDecode(d.salt);
      const leafBytes = encodeLeaf(fieldName, d.salt, d.value);
      leafHash = hashLeaf(leafBytes);
    } catch (err) {
      checks.push({
        name: fieldName,
        ok: false,
        reason: `leaf_encoding_failed: ${err?.message ?? 'unknown'}`,
      });
      allValid = false;
      continue;
    }

    const ok = verifyProof(rootHex, leafHash, d.proof);
    checks.push({
      name: fieldName,
      ok,
      reason: ok ? undefined : 'merkle_proof_does_not_reconstruct_root',
    });
    if (!ok) allValid = false;
  }

  return {
    valid: allValid,
    error: allValid ? undefined : 'commitment_mismatch',
    disclosuresVerified: disclosures.length,
    checks,
  };
}

/**
 * Load disclosure objects from a JSON file. Accepts either:
 *   - A single disclosure object: { parent_receipt_hash, name, value, salt, proof }
 *   - An array of such objects: [ {...}, {...} ]
 *   - A wrapper object: { disclosures: [ {...} ] }
 *
 * @param {string} jsonText raw file contents
 * @returns {CommittedDisclosure[]}
 */
export function loadDisclosuresFromText(jsonText) {
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new Error(`disclosure file is not valid JSON: ${err?.message ?? 'parse error'}`);
  }
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.disclosures)) return parsed.disclosures;
  if (parsed && typeof parsed === 'object' && 'name' in parsed && 'proof' in parsed) {
    return [parsed];
  }
  throw new Error(
    'disclosure file must be a single disclosure object, an array, or a {disclosures: [...]} wrapper',
  );
}
