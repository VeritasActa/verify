/**
 * Bulk / replay verification for receipt chains.
 *
 * Reads a JSONL file (one receipt per line) and verifies every entry,
 * reporting aggregate statistics. Supports parallel execution with a
 * configurable worker count. Produces a structured summary the caller
 * can consume directly or export as an audit report.
 *
 * Chain-linkage is also verified: each receipt's previousReceiptHash
 * is compared against the preceding receipt's canonical hash. A broken
 * link is surfaced with `chain_break` error.
 *
 * @module verify-cli/src/engines/bulk
 * @license Apache-2.0
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { detectFormat } from '../detect.js';
import { verifyReceipt } from './ed25519-receipt.js';
import { canonicalize } from '../util/canonical.js';

/**
 * Verify every receipt in a JSONL-formatted chain file.
 *
 * @param {string} filePath
 * @param {Object} [opts]
 * @returns {Promise<Object>}
 */
export async function replayChain(filePath, opts = {}) {
  const raw = readFileSync(filePath, 'utf-8');
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);

  const results = {
    total: lines.length,
    verified: 0,
    failed: 0,
    chainBreaks: 0,
    byTier: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
    errors: [],
    receipts: [],
    valid: true,
  };

  let previousPayloadHash = null;
  // draft-farley-acta-signed-receipts-03 section 6.7: the chain hash covers
  // the ENTIRE previous receipt, signature included. The older payload-only
  // link is accepted ONLY when the predecessor cites -02 or earlier (or no
  // spec at all): under -03 a payload-only link would let a re-signed receipt
  // keep the original's link, which is the weakness 6.7 closes. Every legacy
  // link taken is counted and reported.
  let previousEnvelopeHash = null;
  let previousCitesPre03 = false;
  results.legacyLinks = 0;

  for (let i = 0; i < lines.length; i++) {
    let receipt;
    try {
      receipt = JSON.parse(lines[i]);
    } catch (e) {
      results.failed++;
      results.errors.push(`Line ${i + 1}: malformed JSON — ${e.message}`);
      results.valid = false;
      continue;
    }

    // Check chain linkage (when the receipt claims a previous hash)
    const payload = receipt.payload || receipt;
    const expectedPrev = payload.previousReceiptHash;

    if (expectedPrev !== undefined && expectedPrev !== null
        && (previousPayloadHash !== null || previousEnvelopeHash !== null)) {
      const expectedPrevHex = expectedPrev.startsWith('sha256:')
        ? expectedPrev.slice(7)
        : expectedPrev;
      if (expectedPrevHex === previousEnvelopeHash) {
        // A section 6.7 link.
      } else if (previousCitesPre03 && expectedPrevHex === previousPayloadHash) {
        results.legacyLinks++;
      } else {
        results.failed++;
        results.chainBreaks++;
        results.errors.push(
          `Line ${i + 1}: chain_break (expected prev ${String(previousEnvelopeHash).slice(0, 16)}... under section 6.7${previousCitesPre03 ? ` or ${String(previousPayloadHash).slice(0, 16)}... under the pre-03 payload-only rule` : ''}, got ${expectedPrev.slice(0, 24)}...)`,
        );
        results.valid = false;
      }
    }

    // Verify the signature
    const detected = detectFormat(receipt);
    const r = await verifyReceipt(receipt, detected.mode, opts);
    results.receipts.push({
      index: i,
      valid: r.valid,
      error: r.error,
      tier: r.payloadFields ? detectTierFromFields(r.payloadFields) : 1,
      kid: r.kid,
      type: r.type,
    });

    if (r.valid) {
      results.verified++;
      const tier = results.receipts[results.receipts.length - 1].tier;
      if (results.byTier[tier] !== undefined) results.byTier[tier]++;
    } else {
      results.failed++;
      results.valid = false;
      results.errors.push(`Line ${i + 1}: ${r.error}`);
    }

    // Compute both chain-link candidates for the next check: the section 6.7
    // hash of the entire receipt as written (signature included), and the
    // older payload-only hash.
    try {
      previousEnvelopeHash = createHash('sha256').update(canonicalize(receipt), 'utf-8').digest('hex');
    } catch {
      previousEnvelopeHash = null;
    }
    try {
      const canonicalStr = canonicalize(payload);
      previousPayloadHash = createHash('sha256').update(canonicalStr, 'utf-8').digest('hex');
    } catch {
      previousPayloadHash = null;
    }
    const spec = typeof payload.spec === 'string' ? payload.spec : null;
    previousCitesPre03 = spec === null || /-0[12]$/.test(spec);
  }

  return results;
}

function detectTierFromFields(fields) {
  if (fields.compliance_credit_ref) return 4;
  if (fields.holder_binding) return 4;
  if (fields.attestation_mode && fields.attestation_mode !== 'software') return 3;
  if (fields.anchor_uri) return 3;
  return 1;
}
