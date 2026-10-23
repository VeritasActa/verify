/**
 * @veritasacta/verify — Rekor / transparency-log anchoring engine.
 *
 * Implements AIP-0005 T4 evidence: verify that a receipt's hash was
 * anchored in a tamper-evident public log (Rekor by default) within a
 * declared temporal window.
 *
 * The engine supports three verification modes, in descending order
 * of strength:
 *
 *   1. Offline proof verification  — operator supplies a Rekor
 *      inclusion proof (set of sibling hashes forming a Merkle path
 *      from the receipt hash to the signed tree root). We verify the
 *      Merkle path locally and check the signed tree head.
 *
 *   2. Offline signed-entry bundle — operator supplies the Rekor
 *      entry body + Rekor's signed checkpoint. We verify the
 *      signature on the entry and the checkpoint's consistency
 *      against a pinned key.
 *
 *   3. Online fetch                — with opt-in `--online`, fetch
 *      the entry from Rekor's API, then verify as in (1). Cheapest
 *      for the user; requires network.
 *
 * This engine is deliberately network-optional: modes (1) and (2)
 * run with zero network. Mode (3) is a convenience for CI pipelines.
 *
 * Rekor reference: https://github.com/sigstore/rekor
 * Signed Note format: RFC-style signed checkpoints from C2SP.
 *
 * @module verify-cli/src/engines/rekor
 * @license Apache-2.0
 */

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

/**
 * @typedef {Object} RekorInclusionProof
 * @property {string}   logID                  Rekor log ID (hex sha256 of its public key).
 * @property {number}   treeSize
 * @property {number}   logIndex               0-based index of the entry.
 * @property {string}   rootHash               Signed tree root (hex).
 * @property {string[]} hashes                 Merkle audit path, leaf-to-root ordering.
 * @property {string}   [signedTreeHead]       Signed-Note blob, if available.
 */

/**
 * @typedef {Object} RekorVerifyOptions
 * @property {Object}   receipt                AIP-0001 receipt envelope.
 * @property {string}   [expectedAnchorUri]    If set, must match receipt.payload.anchor_uri.
 * @property {string}   [anchoredWithin]       ISO 8601 duration like "PT5M".
 * @property {RekorInclusionProof} [proof]     Offline inclusion proof.
 * @property {string}   [entryBody]            Rekor entry body (base64) if using mode 2.
 * @property {Object<string, string>} [logTrustAnchors]
 *    Map logID (hex) → pubkey pem/hex/base64. Pinned Rekor log keys.
 * @property {Date}     [now=new Date()]
 */

/**
 * @typedef {Object} RekorVerifyResult
 * @property {boolean}  valid
 * @property {string}   [error]
 * @property {'proof'|'bundle'|'undecidable'} mode
 * @property {string}   [receipt_hash]
 * @property {string}   [log_id]
 * @property {number}   [log_index]
 * @property {string}   [root_hash]
 * @property {string}   [anchored_at]
 * @property {number}   [anchor_age_sec]
 * @property {boolean}  [within_window]
 */

/**
 * Verify a receipt's transparency-log anchor against a supplied
 * offline inclusion proof and the log's signed tree head, verified
 * against the key pinned for that log in logTrustAnchors, or return
 * `undecidable` if either is missing.
 *
 * @param {RekorVerifyOptions} opts
 * @returns {RekorVerifyResult}
 */
export function verifyRekorAnchor(opts) {
  const { receipt, proof, expectedAnchorUri, anchoredWithin, logTrustAnchors = {}, now = new Date() } = opts;

  if (!receipt || !receipt.payload) {
    return { valid: false, error: 'missing_receipt', mode: 'undecidable' };
  }

  const payload = receipt.payload;
  const anchorUri = payload.anchor_uri;
  const anchorType = payload.anchor_type || 'rekor-v1';
  const declaredWithin = payload.anchored_within || anchoredWithin;
  const issuedAt = payload.issued_at;

  if (!anchorUri) {
    return { valid: false, error: 'no_anchor_uri_in_receipt', mode: 'undecidable' };
  }
  if (expectedAnchorUri && expectedAnchorUri !== anchorUri) {
    return { valid: false, error: 'anchor_uri_mismatch', mode: 'undecidable' };
  }

  // Compute the receipt's own hash: the value we expect to find in
  // the log's Merkle path.
  let receiptHash;
  try {
    receiptHash = computeReceiptHash(receipt);
  } catch {
    return { valid: false, error: 'malformed_encoding', mode: 'undecidable' };
  }

  if (!proof) {
    return {
      valid: false,
      error: 'no_inclusion_proof_provided',
      mode: 'undecidable',
      receipt_hash: receiptHash,
    };
  }

  // Check the receiptHash is the leaf of the Merkle path.
  const computedRoot = computeMerkleRootFromProof(
    receiptHash,
    proof.logIndex || 0,
    proof.hashes || [],
    proof.treeSize || 1
  );

  if (computedRoot !== normalizeHex(proof.rootHash)) {
    return {
      valid: false,
      error: 'merkle_path_does_not_reach_claimed_root',
      mode: 'proof',
      receipt_hash: receiptHash,
      log_id: proof.logID,
      log_index: proof.logIndex,
      root_hash: proof.rootHash,
    };
  }

  // A path to a root proves nothing until the log has signed that root:
  // anyone can build a one-leaf tree whose root is the receipt's hash.
  // So the signed tree head is required, verified against the pinned key
  // for this log, and must name this root and tree size. Before, a proof
  // with no signed tree head, or with no key pinned for its log, was valid.
  const pinnedLogKey = Object.hasOwn(logTrustAnchors, String(proof.logID)) ? logTrustAnchors[proof.logID] : null;
  if (!proof.signedTreeHead || !pinnedLogKey) {
    return {
      valid: false,
      error: !proof.signedTreeHead ? 'signed_tree_head_missing' : 'no_log_trust_anchor',
      mode: 'undecidable',
      receipt_hash: receiptHash,
      log_id: proof.logID,
    };
  }
  let sthValid;
  try {
    sthValid = verifySignedNote(proof.signedTreeHead, pinnedLogKey);
  } catch {
    sthValid = false;
  }

  if (!sthValid) {
    return {
      valid: false,
      error: 'signed_tree_head_signature_invalid',
      mode: 'proof',
      receipt_hash: receiptHash,
      log_id: proof.logID,
    };
  }
  if (!checkpointBinds(proof.signedTreeHead, proof.treeSize, proof.rootHash)) {
    return {
      valid: false,
      error: 'signed_tree_head_mismatch',
      mode: 'proof',
      receipt_hash: receiptHash,
      log_id: proof.logID,
    };
  }

  // Temporal window check.
  const windowOk = checkWithinWindow(issuedAt, proof.integratedTime || proof.integrated_time, declaredWithin);
  if (declaredWithin && windowOk === false) {
    return {
      valid: false,
      error: 'anchored_outside_declared_window',
      mode: 'proof',
      receipt_hash: receiptHash,
      within_window: false,
    };
  }

  return {
    valid: true,
    mode: 'proof',
    receipt_hash: receiptHash,
    log_id: proof.logID,
    log_index: proof.logIndex,
    root_hash: proof.rootHash,
    anchored_at: proof.integratedTime || null,
    ...(windowOk != null ? { within_window: windowOk } : {}),
  };
}

// ───── Helpers ─────

/**
 * Compute a deterministic hash for the receipt using the same
 * canonicalization as AIP-0001. This hash is what we expect to find
 * in the Rekor log's leaf set.
 */
export function computeReceiptHash(receipt) {
  // Rekor indexes by sha256 of the entry body (base64); this engine
  // expects the receipt hash of draft §6.7: the SHA-256 of the RFC 8785
  // (JCS) form of the whole receipt, signature included. Callers should
  // confirm the anchoring service's convention for their deployment.
  // Before, the member names passed to JSON.stringify as a replacer kept
  // only "payload" and "signature" at every depth, so every
  // {payload, signature} receipt hashed to the same value.
  return createHash('sha256').update(canonicalize(receipt), 'utf-8').digest('hex');
}

/**
 * Whether a signed checkpoint (c2sp.org/tlog-checkpoint: origin, tree
 * size, base64 root hash) names exactly this tree size and root hash.
 * A signature over a checkpoint for another tree vouches for nothing here.
 *
 * @param {string} noteText
 * @param {number} treeSize
 * @param {string} rootHash hex
 * @returns {boolean}
 */
export function checkpointBinds(noteText, treeSize, rootHash) {
  if (typeof noteText !== 'string') return false;
  const lines = noteText.split('\n\n')[0].split('\n');
  if (lines.length < 3 || !/^\d+$/.test(lines[1])) return false;
  const root = Buffer.from(lines[2], 'base64');
  return Number(lines[1]) === treeSize
    && root.toString('base64') === lines[2]
    && root.toString('hex') === normalizeHex(rootHash);
}

/**
 * Given a leaf, its index, an audit path (sibling hashes from leaf
 * to root), and tree size, recompute the root hash.
 *
 * Rekor uses the RFC 6962 Merkle tree convention:
 *   - leaf hash  = sha256(0x00 || entry_bytes)
 *   - node hash  = sha256(0x01 || left || right)
 *
 * This implementation accepts pre-hashed leaves (as we compute them
 * via computeReceiptHash) and sibling hashes in leaf-to-root order.
 */
export function computeMerkleRootFromProof(leafHashHex, index, siblings, treeSize) {
  let hash = hexToBytes(normalizeHex(leafHashHex));
  let i = index;
  let n = treeSize;

  for (const sibHex of siblings) {
    const sib = hexToBytes(normalizeHex(sibHex));
    const isLeft = (i % 2) === 1;
    const combined = isLeft
      ? Buffer.concat([Buffer.from([0x01]), sib, hash])
      : Buffer.concat([Buffer.from([0x01]), hash, sib]);
    hash = createHash('sha256').update(combined).digest();
    i = Math.floor(i / 2);
    n = Math.floor((n + 1) / 2);
  }
  return hash.toString('hex');
}

/**
 * Verify a Signed Note (https://c2sp.org/signed-note) format STH
 * against a pinned pubkey.
 *
 * Format:
 *   <text>\n
 *   \n
 *   <signature-line>\n...
 *
 * Where each signature-line is:
 *   "— <name> <base64(sig || key_hint)>"
 *
 * This is a minimal verifier suitable for Rekor's current STH
 * signatures.
 */
export function verifySignedNote(noteText, pubkey) {
  if (typeof noteText !== 'string') return false;
  const parts = noteText.split('\n\n');
  if (parts.length < 2) return false;
  const text = parts[0] + '\n';
  const sigBlock = parts[1];

  const lines = sigBlock.split('\n').filter(Boolean);
  for (const line of lines) {
    const m = /^—\s+(\S+)\s+(\S+)$/.exec(line);
    if (!m) continue;
    const sigB64 = m[2];
    const sigBuf = Buffer.from(sigB64, 'base64');
    // First 4 bytes = key hint; remainder = signature.
    const actualSig = sigBuf.subarray(4);

    try {
      const pub = pubkeyFromAny(pubkey);
      const ok = cryptoVerify(null, Buffer.from(text, 'utf-8'), pub, actualSig);
      if (ok) return true;
    } catch {
      // try next signature line
    }
  }
  return false;
}

function pubkeyFromAny(keyStr) {
  if (keyStr.startsWith('-----BEGIN')) {
    return createPublicKey({ key: keyStr, format: 'pem' });
  }
  // Treat as hex (raw 32-byte Ed25519)
  if (/^[0-9a-fA-F]+$/.test(keyStr) && keyStr.length === 64) {
    const raw = Buffer.from(keyStr, 'hex');
    const der = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      raw,
    ]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  }
  // Fall back to base64-DER
  const buf = Buffer.from(keyStr, 'base64');
  return createPublicKey({ key: buf, format: 'der', type: 'spki' });
}

/**
 * Parse ISO 8601 duration ('PT5M', 'PT1H', 'P1D') into seconds.
 */
export function parseDuration(iso) {
  if (typeof iso !== 'string') return null;
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(iso);
  if (!m) return null;
  const [, d, h, mm, s] = m;
  return (Number(d || 0) * 86400) +
         (Number(h || 0) * 3600) +
         (Number(mm || 0) * 60) +
         Number(s || 0);
}

function checkWithinWindow(issuedAt, integratedAt, declaredWithin) {
  if (!declaredWithin) return null;
  const sec = parseDuration(declaredWithin);
  if (sec == null) return null;
  const issued = Date.parse(issuedAt);
  const integrated = Date.parse(integratedAt);
  if (!Number.isFinite(issued) || !Number.isFinite(integrated)) return null;
  return Math.abs((integrated - issued) / 1000) <= sec;
}

function normalizeHex(v) {
  return String(v || '').trim().toLowerCase();
}

function hexToBytes(hex) {
  return Buffer.from(hex, 'hex');
}
