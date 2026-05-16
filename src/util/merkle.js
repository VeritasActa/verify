/**
 * RFC 6962-style Merkle tree verification helpers.
 *
 * Domain separation (RFC 6962 §2.1):
 *   leaf_hash     = SHA-256(0x00 || leaf_bytes)
 *   internal_hash = SHA-256(0x01 || left_child_hash || right_child_hash)
 *
 * Without domain separation a leaf hash could collide with an internal
 * node hash, allowing forged inclusion proofs. The 0x00 / 0x01 prefix
 * is the standard fix used by Certificate Transparency, Sigstore Rekor,
 * and every production Merkle log.
 *
 * Non-power-of-two leaf counts are handled by recursive split on the
 * largest power of two strictly less than n (RFC 6962 §2.1).
 *
 * Compatible with draft-farley-acta-signed-receipts-01 §commitment-mode
 * and protect-mcp@>=0.6.0 commitment-mode signing.
 *
 * @module verify-cli/src/util/merkle
 * @license Apache-2.0
 */

import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';

/** Domain-separation byte for a Merkle leaf, per RFC 6962 §2.1. */
export const DOMAIN_LEAF = 0x00;

/** Domain-separation byte for a Merkle internal node, per RFC 6962 §2.1. */
export const DOMAIN_INTERNAL = 0x01;

/**
 * @typedef {Object} MerkleProof
 * @property {number} index    zero-based index of the leaf
 * @property {number} treeSize total leaf count
 * @property {string[]} siblings hex-encoded SHA-256 siblings, bottom-up
 */

/**
 * Hash a leaf with RFC 6962 domain separation.
 * @param {Buffer|Uint8Array} leafBytes canonical leaf bytes (no prefix)
 * @returns {Buffer} 32-byte SHA-256(0x00 || leafBytes)
 */
export function hashLeaf(leafBytes) {
  const buf = Buffer.alloc(leafBytes.length + 1);
  buf[0] = DOMAIN_LEAF;
  Buffer.from(leafBytes).copy(buf, 1);
  return createHash('sha256').update(buf).digest();
}

/**
 * Hash an internal node with RFC 6962 domain separation.
 * @param {Buffer} left  32-byte left-child hash
 * @param {Buffer} right 32-byte right-child hash
 * @returns {Buffer} 32-byte SHA-256(0x01 || left || right)
 */
export function hashInternal(left, right) {
  const buf = Buffer.alloc(left.length + right.length + 1);
  buf[0] = DOMAIN_INTERNAL;
  left.copy(buf, 1);
  right.copy(buf, 1 + left.length);
  return createHash('sha256').update(buf).digest();
}

/**
 * Largest power of two strictly less than n. Defined for n >= 2.
 * @param {number} n
 * @returns {number}
 */
function largestPowerOfTwoLessThan(n) {
  if (n < 2) {
    throw new Error(`largestPowerOfTwoLessThan: n must be >= 2 (got ${n})`);
  }
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Recursively reconstruct the Merkle root from a leaf hash, its index,
 * the tree size, and the inclusion-proof siblings (bottom-up order).
 *
 * Siblings are consumed from the END of the array (last appended =
 * outermost level) so the recursion peels off the outermost sibling at
 * each level and recurses into the subtree containing the leaf.
 *
 * @param {Buffer} leafHash
 * @param {number} index
 * @param {number} treeSize
 * @param {string[]} siblings hex-encoded SHA-256 sibling hashes
 * @returns {Buffer} reconstructed root
 */
function reconstructRoot(leafHash, index, treeSize, siblings) {
  if (treeSize === 1) {
    if (siblings.length !== 0) {
      throw new Error('reconstructRoot: extra siblings at single-leaf level');
    }
    return leafHash;
  }
  if (siblings.length === 0) {
    throw new Error('reconstructRoot: ran out of siblings before single-leaf');
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  const outermostSibling = Buffer.from(siblings[siblings.length - 1], 'hex');
  const innerSiblings = siblings.slice(0, -1);
  if (index < k) {
    const leftHash = reconstructRoot(leafHash, index, k, innerSiblings);
    return hashInternal(leftHash, outermostSibling);
  } else {
    const rightHash = reconstructRoot(
      leafHash,
      index - k,
      treeSize - k,
      innerSiblings,
    );
    return hashInternal(outermostSibling, rightHash);
  }
}

/**
 * Verify a Merkle inclusion proof against an expected root.
 *
 * @param {string} expectedRootHex lowercase hex SHA-256 root
 * @param {Buffer} leafHash 32-byte domain-separated leaf hash
 *   (use hashLeaf to produce from leaf bytes)
 * @param {MerkleProof} proof
 * @returns {boolean} true iff the proof reconstructs the expected root
 */
export function verifyProof(expectedRootHex, leafHash, proof) {
  if (!proof || typeof proof !== 'object') return false;
  if (!Array.isArray(proof.siblings)) return false;
  if (typeof proof.index !== 'number' || typeof proof.treeSize !== 'number') {
    return false;
  }
  if (proof.index < 0 || proof.index >= proof.treeSize) return false;
  if (proof.treeSize === 1) {
    return (
      proof.siblings.length === 0 &&
      leafHash.toString('hex').toLowerCase() === expectedRootHex.toLowerCase()
    );
  }
  let result;
  try {
    result = reconstructRoot(leafHash, proof.index, proof.treeSize, proof.siblings);
  } catch {
    return false;
  }
  return result.toString('hex').toLowerCase() === expectedRootHex.toLowerCase();
}

/**
 * Encode a single committed field as canonical leaf bytes.
 * Per draft-farley-acta-signed-receipts-01 §commitment-leaf-layout:
 *   canonical_leaf_bytes = JCS({"name": ..., "salt": base64url(salt), "value": ...})
 *
 * @param {string} name field name
 * @param {string} saltB64Url base64url-encoded salt (no padding)
 * @param {unknown} value original (cleartext) field value
 * @returns {Buffer} canonical leaf bytes ready to feed into hashLeaf
 */
export function encodeLeaf(name, saltB64Url, value) {
  const obj = { name, salt: saltB64Url, value };
  const canonical = canonicalize(obj);
  return Buffer.from(canonical, 'utf8');
}

/**
 * Decode a base64url string (with or without padding) to bytes.
 * @param {string} s
 * @returns {Buffer}
 */
export function base64urlDecode(s) {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  const standard = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(standard, 'base64');
}
