/**
 * Bulk / replay verification for receipt chains.
 *
 * Reads a JSONL file (one receipt per line), verifies every entry in turn,
 * and reports aggregate statistics. Produces a structured summary the caller
 * can consume directly or export as an audit report.
 *
 * Chain linkage is also verified: each receipt's previousReceiptHash is
 * compared with the draft-farley-acta-signed-receipts-03 §6.7 hash of the
 * receipt before it, the SHA-256 of the JCS of the whole receipt, signature
 * included. A link that does not match is a `chain_break`. A receipt after
 * the first with no link starts a new chain (draft §2.2): it is counted in
 * `chains` and named in `warnings`, never read as linked to the receipt
 * before it.
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
 * Verify every receipt in a JSONL-formatted chain file, and the links between them.
 *
 * @param {string} filePath
 * @param {Object} [opts]  passed to the receipt verifier (publicKey and the rest), plus:
 * @param {boolean} [opts.allowPayloadOnlyLinks]  read a link over the previous receipt's payload alone as a legacy
 *   link, counted in legacyLinks and named in warnings, instead of refusing it as a chain_break
 * @returns {Promise<Object>} counts, errors and per-receipt results. `chains` counts the chains the file holds: one
 *   for the first receipt and one for each later receipt with no link. `warnings` names every chain start after the
 *   first, every legacy link read, and every warning the receipt verifier gave.
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

  // Draft-farley-acta-signed-receipts-03 section 6.7: the chain hash covers the ENTIRE previous receipt, signature
  // included, as "sha256:" and lowercase hex, or the bare hex of earlier revisions. -02 section 5.7 defined the same
  // preimage, and no revision defines a link over the payload alone: hashing the payload gives a re-signed receipt
  // the original's link, which is the weakness 6.7 closes. So a payload-only link is a chain_break, whatever the
  // previous receipt's spec says. allowPayloadOnlyLinks reads one as a legacy link instead, for chains written by
  // the proxy and daemon of @veritasacta/verify 0.9.3 and earlier; every one read that way is counted in
  // legacyLinks and named in warnings.
  const allowPayloadOnly = opts.allowPayloadOnlyLinks === true;
  let previousEnvelopeHash = null;
  let previousPayloadHash = null;
  let previousLine = null;
  results.legacyLinks = 0;
  results.chains = 0;
  results.warnings = [];

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

    // Check chain linkage
    const payload = receipt.payload || receipt;
    const expectedPrev = payload.previousReceiptHash;
    const hasLink = expectedPrev !== undefined && expectedPrev !== null;

    if (previousLine === null || !hasLink) {
      // Draft section 2.2: a receipt without a link is a chain genesis or an unchained receipt, and a verifier must not
      // infer chain membership from the absence. So a later one starts a new chain here instead of being read as
      // linked to the receipt before it. A null link, which 0.9.3 wrote on a chain's first receipt, is read the same
      // way, and the receipt verifier names it with its own warning.
      results.chains++;
      if (previousLine !== null) {
        results.warnings.push(
          `Line ${i + 1}: starts a new chain: ${expectedPrev === null ? 'its previousReceiptHash is null' : 'it has no previousReceiptHash'}, so it is not linked to line ${previousLine} (draft §2.2).`,
        );
      }
    } else if (previousPayloadHash !== null || previousEnvelopeHash !== null) {
      const shown = typeof expectedPrev === 'string' ? expectedPrev : JSON.stringify(expectedPrev);
      const expectedPrevHex = typeof expectedPrev !== 'string' ? null
        : expectedPrev.startsWith('sha256:') ? expectedPrev.slice(7) : expectedPrev;
      const payloadOnly = expectedPrevHex !== null && expectedPrevHex !== previousEnvelopeHash
        && expectedPrevHex === previousPayloadHash;
      if (expectedPrevHex !== null && expectedPrevHex === previousEnvelopeHash) {
        // A section 6.7 link.
      } else if (payloadOnly && allowPayloadOnly) {
        results.legacyLinks++;
        results.warnings.push(
          `Line ${i + 1}: payload-only link to line ${previousLine}, read as a legacy link because --allow-payload-only-links was given. It hashes that receipt's payload alone, so a re-signed copy would carry the same link; draft-03 §6.7 links the whole receipt.`,
        );
      } else {
        results.failed++;
        results.chainBreaks++;
        results.errors.push(payloadOnly
          ? `Line ${i + 1}: chain_break (previousReceiptHash is the SHA-256 of line ${previousLine}'s payload alone. Draft-03 §6.7 links the whole receipt, signature included, and no revision defines a payload-only link. --allow-payload-only-links reads it as a legacy link.)`
          : `Line ${i + 1}: chain_break (expected prev ${String(previousEnvelopeHash).slice(0, 16)}... under section 6.7, got ${shown.slice(0, 24)}...)`,
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
      ...(r.warning ? { warning: r.warning } : {}),
    });
    // The receipt verifier's own warnings (a null link, a historical encoding) are reported here as for one receipt.
    if (r.warning) results.warnings.push(`Line ${i + 1}: ${r.warning}`);

    if (r.valid) {
      results.verified++;
      const tier = results.receipts[results.receipts.length - 1].tier;
      if (results.byTier[tier] !== undefined) results.byTier[tier]++;
    } else {
      results.failed++;
      results.valid = false;
      results.errors.push(`Line ${i + 1}: ${r.error}`);
    }

    // The values the next receipt's link is compared with: the section 6.7 hash of the entire receipt as written,
    // signature included, and the payload-only hash, which is read only with allowPayloadOnlyLinks and otherwise
    // named in the refusal.
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
    previousLine = i + 1;
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
