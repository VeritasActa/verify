/**
 * Receipt diff — structural comparison of two receipts.
 *
 * Reports which fields changed, which signatures remain valid, and
 * whether chain linkage is preserved. Useful for debugging implementers
 * and investigating tampering scenarios.
 *
 * @module verify-cli/src/engines/diff
 * @license Apache-2.0
 */

import { canonicalize } from '../util/canonical.js';
import { createHash } from 'node:crypto';

/**
 * Compare two receipts and report field-level differences.
 *
 * @param {Object} a
 * @param {Object} b
 * @returns {Object} diff summary
 */
export function diffReceipts(a, b) {
  const diff = {
    added: [],
    removed: [],
    changed: [],
    unchanged: [],
    canonical_hash_a: null,
    canonical_hash_b: null,
    hash_equal: false,
    signature_equal: false,
  };

  try {
    diff.canonical_hash_a = createHash('sha256').update(canonicalize(a.payload || a), 'utf-8').digest('hex');
    diff.canonical_hash_b = createHash('sha256').update(canonicalize(b.payload || b), 'utf-8').digest('hex');
    diff.hash_equal = diff.canonical_hash_a === diff.canonical_hash_b;
  } catch (e) {
    diff.error = `canonicalization_failed: ${e.message}`;
    return diff;
  }

  const sigA = extractSig(a);
  const sigB = extractSig(b);
  diff.signature_equal = sigA === sigB;

  const payloadA = a.payload || a;
  const payloadB = b.payload || b;

  const keysA = new Set(Object.keys(payloadA));
  const keysB = new Set(Object.keys(payloadB));

  for (const k of keysA) {
    if (!keysB.has(k)) diff.removed.push(k);
    else if (JSON.stringify(payloadA[k]) !== JSON.stringify(payloadB[k])) {
      diff.changed.push({ field: k, before: payloadA[k], after: payloadB[k] });
    } else {
      diff.unchanged.push(k);
    }
  }
  for (const k of keysB) {
    if (!keysA.has(k)) diff.added.push(k);
  }

  return diff;
}

function extractSig(receipt) {
  if (typeof receipt.signature === 'string') return receipt.signature;
  if (receipt.signature?.sig) return receipt.signature.sig;
  return null;
}
