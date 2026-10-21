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
 * before it. Each line, and the file, has one of three outcomes: valid,
 * invalid or undecidable (§5.3 of the -04 editor's copy, VeritasActa/drafts).
 *
 * @module verify-cli/src/engines/bulk
 * @license Apache-2.0
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { detectFormat } from '../detect.js';
import { verifyReceipt, checkChainLinkSyntax, combineChecks } from './ed25519-receipt.js';
import { canonicalize } from '../util/canonical.js';
import { checkKeyWindow, receiptIssuedAt, keyWindowCheck } from '../util/key-window.js';

const sha256Hex = (text) => createHash('sha256').update(text, 'utf-8').digest('hex');

/**
 * What every link read under --allow-payload-only-links is called, wherever it is read: -04 §6.7.1 says a verifier
 * must not accept a payload-only link, so the flag is a compatibility reading for chains written by the proxy and
 * daemon of 0.9.3 and earlier, never a conformant one.
 */
export const COMPATIBILITY_NOTE = 'read under a compatibility mode, not conformant to draft §6.7';

/**
 * Check one receipt's link against a predecessor the caller supplies (--previous), which asserts that the receipt
 * follows it. The receipt must name the draft §6.7 hash of that receipt: the SHA-256 of the JCS of the whole
 * receipt, signature included, as "sha256:" and lowercase hex or the bare hex of earlier revisions. A receipt whose
 * previousReceiptHash is absent, null or any other value does not follow the supplied receipt, and that is a
 * chain_break. This differs from --replay-chain, which reads the order from the file and does not assert it: there a
 * receipt with no link starts a new chain (§2.2).
 *
 * The link is read where --replay-chain reads it: in the payload of an envelope, or in the receipt itself.
 *
 * @param {Object} receipt the receipt being verified
 * @param {Object} previous the receipt the caller says comes before it
 * @param {{ allowPayloadOnlyLinks?: boolean }} [opts] read a link over the previous receipt's payload alone as a
 *   legacy link, with a warning, instead of refusing it
 * @returns {{ result: string, expected: string, link: *, form?: string, error?: string, detail: string,
 *   warning?: string }} result is linked, legacy-payload, absent, null, mismatch, payload-only, malformed or
 *   unsupported; error, when there is one, is the code the receipt fails with
 */
export function checkPreviousLink(receipt, previous, opts = {}) {
  const expectedHex = sha256Hex(canonicalize(previous));
  const expected = `sha256:${expectedHex}`;
  const carrier = receipt && typeof receipt.payload === 'object' && receipt.payload !== null ? receipt.payload : receipt;
  const hasLink = !!carrier && typeof carrier === 'object' && Object.hasOwn(carrier, 'previousReceiptHash');
  const link = hasLink ? carrier.previousReceiptHash : undefined;
  const out = (result, detail, extra = {}) => ({ result, expected, link: hasLink ? link : undefined, detail, ...extra });

  if (!hasLink) {
    return out('absent', `The receipt has no previousReceiptHash, so it does not follow the receipt given with --previous, whose draft §6.7 link is ${expected}.`, { error: 'chain_break' });
  }
  if (link === null) {
    return out('null', `The receipt's previousReceiptHash is null, so it does not follow the receipt given with --previous, whose draft §6.7 link is ${expected}.`, { error: 'chain_break' });
  }
  const syntax = checkChainLinkSyntax({ previousReceiptHash: link });
  if (syntax.error) {
    return out(syntax.error === 'unsupported_chain_hash_algorithm' ? 'unsupported' : 'malformed',
      syntax.error === 'unsupported_chain_hash_algorithm'
        ? 'previousReceiptHash names a hash algorithm other than sha256, so it cannot be checked against the receipt given with --previous (draft §6.7).'
        : 'previousReceiptHash is not "sha256:" and 64 lowercase hex characters, nor the bare digest of earlier revisions, so it names no receipt (draft §6.7).',
      { error: syntax.error });
  }
  const hex = link.startsWith('sha256:') ? link.slice('sha256:'.length) : link;
  if (hex === expectedHex) return out('linked', `previousReceiptHash is the draft §6.7 link of the receipt given with --previous.`, { form: syntax.form });
  let payloadHex = null;
  try {
    payloadHex = sha256Hex(canonicalize(previous && typeof previous.payload === 'object' && previous.payload !== null ? previous.payload : previous));
  } catch { /* a payload that does not canonicalize names nothing */ }
  if (hex === payloadHex) {
    if (opts.allowPayloadOnlyLinks === true) {
      return out('legacy-payload', `previousReceiptHash hashes the payload alone of the receipt given with --previous. It is read as a legacy link because --allow-payload-only-links was given: ${COMPATIBILITY_NOTE}.`, {
        form: syntax.form,
        warning: `previousReceiptHash hashes the payload alone of the receipt given with --previous, read as a legacy link because --allow-payload-only-links was given: ${COMPATIBILITY_NOTE}. A re-signed copy of that receipt would carry the same link; draft-03 §6.7 links the whole receipt.`,
      });
    }
    return out('payload-only', `previousReceiptHash is the SHA-256 of the payload alone of the receipt given with --previous. Draft-03 §6.7 links the whole receipt, signature included, and no revision defines a payload-only link. --allow-payload-only-links reads it as a legacy link, ${COMPATIBILITY_NOTE}.`, { form: syntax.form, error: 'chain_break' });
  }
  return out('mismatch', `previousReceiptHash names ${link.startsWith('sha256:') ? link : `sha256:${link}`}, not the receipt given with --previous, whose draft §6.7 link is ${expected}.`, { form: syntax.form, error: 'chain_break' });
}

/**
 * Verify every receipt in a JSONL-formatted chain file, and the links between them.
 *
 * Each line has the checks one receipt has (signing input, signature, link syntax, key window) and, when it carries a
 * link and is not the first, the check of that link against the line before it, as for a predecessor the caller
 * supplies (-04 §6.7.1). They combine as -04 §5.3 has them (combineChecks): a line is invalid if any check ran and
 * failed, undecidable if none failed and one could not run (no key, a window that cannot be applied, a link naming
 * another hash algorithm), and valid otherwise. The file's outcome is invalid if any line is invalid or any link
 * breaks, else undecidable if any line is, else valid.
 *
 * @param {string} filePath
 * @param {Object} [opts]  passed to the receipt verifier (publicKey and the rest), plus:
 * @param {boolean} [opts.allowPayloadOnlyLinks]  read a link over the previous receipt's payload alone as a legacy
 *   link, counted in legacyLinks and named in warnings, instead of refusing it as a chain_break. That reading is a
 *   compatibility mode, not conformant to draft §6.7: the result then carries conformant: false.
 * @param {(kid: string|undefined) => {key: string|null, error: string|null, window?: Object|null}} [opts.keyResolver]
 *   the key for each receipt by its kid (--jwks), used when no publicKey is given
 * @param {boolean} [opts.requireKeyWindow]  a key with no validity window is undecidable
 * @returns {Promise<Object>} counts, errors and per-receipt results. verified, failed and undecidable count lines by
 *   outcome; chainBreaks counts links that break. `chains` counts the chains the file holds: one for the first receipt
 *   and one for each later receipt with no link. `warnings` names every chain start after the first, every legacy link
 *   read, and every warning the receipt verifier gave. `outcome` is valid, invalid or undecidable.
 */
export async function replayChain(filePath, opts = {}) {
  const raw = readFileSync(filePath, 'utf-8');
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);

  const results = {
    total: lines.length,
    verified: 0,
    failed: 0,
    undecidable: 0,
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
  // legacyLinks and named in warnings, and the result is marked conformant: false.
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
      // -04 §5.3: input that is not well-formed JSON cannot be checked, so the line is undecidable.
      results.undecidable++;
      results.errors.push(`Line ${i + 1}: malformed JSON: ${e.message}`);
      results.receipts.push({ index: i, valid: false, outcome: 'undecidable', error: 'malformed_json' });
      continue;
    }

    // Check chain linkage
    const payload = receipt.payload || receipt;
    const expectedPrev = payload.previousReceiptHash;
    const hasLink = expectedPrev !== undefined && expectedPrev !== null;
    let linkCheck = null;

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
      if (checkChainLinkSyntax({ previousReceiptHash: expectedPrev }).error === 'unsupported_chain_hash_algorithm') {
        // Draft §6.7: a link naming another hash algorithm is not compared, so whether this line follows the one before
        // is undecided rather than broken. The receipt verifier reports the code for the line.
        linkCheck = { result: 'undecidable', code: 'unsupported_chain_hash_algorithm' };
        results.warnings.push(
          `Line ${i + 1}: previousReceiptHash ${shown.slice(0, 24)}... names a hash algorithm other than sha256, so whether it follows line ${previousLine} is not decided (draft §6.7).`,
        );
      } else if (expectedPrevHex !== null && expectedPrevHex === previousEnvelopeHash) {
        // A section 6.7 link.
        linkCheck = { result: 'pass' };
      } else if (payloadOnly && allowPayloadOnly) {
        results.legacyLinks++;
        linkCheck = { result: 'pass' };
        results.warnings.push(
          `Line ${i + 1}: payload-only link to line ${previousLine}, read as a legacy link because --allow-payload-only-links was given: ${COMPATIBILITY_NOTE}. It hashes that receipt's payload alone, so a re-signed copy would carry the same link; draft-03 §6.7 links the whole receipt.`,
        );
      } else {
        results.chainBreaks++;
        linkCheck = { result: 'fail', code: 'chain_break' };
        results.errors.push(payloadOnly
          ? `Line ${i + 1}: chain_break (previousReceiptHash is the SHA-256 of line ${previousLine}'s payload alone. Draft-03 §6.7 links the whole receipt, signature included, and no revision defines a payload-only link. --allow-payload-only-links reads it as a legacy link, ${COMPATIBILITY_NOTE}.)`
          : `Line ${i + 1}: chain_break (expected prev ${String(previousEnvelopeHash).slice(0, 16)}... under section 6.7, got ${shown.slice(0, 24)}...)`,
        );
      }
    }

    // The key: the one given with --key, or the one --jwks gives for this receipt's kid, with its validity window.
    let key = opts.publicKey;
    let keySource = key ? 'provided' : null;
    let keyWindow = null;
    let jwksError = null;
    if (!key && typeof opts.keyResolver === 'function') {
      const resolved = opts.keyResolver(receipt.kid || receipt.signature?.kid);
      if (resolved.key) {
        key = resolved.key;
        keySource = 'jwks';
        keyWindow = resolved.window || null;
      } else {
        jwksError = resolved.error;
      }
    }

    // Verify the signature, then the checks that do not depend on it, and combine them (-04 §5.3).
    const detected = detectFormat(receipt);
    const r = await verifyReceipt(receipt, detected.mode, { ...opts, publicKey: key, ...(key ? { keySource } : {}), ...(jwksError ? { allowEmbeddedKey: false } : {}) });
    const checks = { ...(r.checks || {}) };
    if (jwksError) checks.signature = { result: 'undecidable', code: 'jwks_fetch_failed' };
    const kw = checkKeyWindow({ window: keyWindow, issuedAt: receiptIssuedAt(receipt), keySource: jwksError ? null : keySource || r.keySource, require: opts.requireKeyWindow });
    checks.key_window = keyWindowCheck(kw);
    if (linkCheck) checks.previous = linkCheck;
    const combined = combineChecks(checks);
    results.receipts.push({
      index: i,
      valid: combined.valid,
      outcome: combined.outcome,
      error: combined.error,
      tier: r.payloadFields ? detectTierFromFields(r.payloadFields) : 1,
      kid: r.kid,
      type: r.type,
      checks,
      keyStatus: kw.report,
      ...(r.warning ? { warning: r.warning } : {}),
      ...(r.payloadNotes ? { payloadNotes: r.payloadNotes } : {}),
    });
    // The receipt verifier's own warnings (a null link, a historical encoding) are reported here as for one receipt.
    if (r.warning) results.warnings.push(`Line ${i + 1}: ${r.warning}`);

    if (combined.outcome === 'valid') {
      results.verified++;
      const tier = results.receipts[results.receipts.length - 1].tier;
      if (results.byTier[tier] !== undefined) results.byTier[tier]++;
    } else {
      if (combined.outcome === 'invalid') results.failed++;
      else results.undecidable++;
      // A chain break is already named above, with the links it compared.
      if (combined.error !== 'chain_break') {
        results.errors.push(`Line ${i + 1}: ${combined.error}${jwksError && combined.error === 'jwks_fetch_failed' ? ` (${jwksError})` : ''}`);
      }
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

  // -04 §5.3: the file is invalid if any line is, or any link breaks; else undecidable if any line could not be
  // checked; else valid.
  results.outcome = results.failed > 0 || results.chainBreaks > 0 ? 'invalid' : results.undecidable > 0 ? 'undecidable' : 'valid';
  results.valid = results.outcome === 'valid';
  if (results.legacyLinks > 0) results.conformant = false;
  return results;
}

function detectTierFromFields(fields) {
  if (fields.compliance_credit_ref) return 4;
  if (fields.holder_binding) return 4;
  if (fields.attestation_mode && fields.attestation_mode !== 'software') return 3;
  if (fields.anchor_uri) return 3;
  return 1;
}
