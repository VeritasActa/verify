/**
 * Knowledge Unit bundle verification engine.
 *
 * A Knowledge Unit (KU) is a self-contained, verifiable record of
 * multi-model deliberation. Each model response has its own signed
 * receipt; the KU aggregates those receipts with structured metadata
 * (topic, rounds, consensus, dissent).
 *
 * This engine validates:
 *   - KU envelope structure (required fields per the JSON Schema)
 *   - Every embedded receipt individually (via Ed25519 engine); a KU with no
 *     receipts, or with one this verifier cannot check, is undecidable
 *
 * It does not check the aggregate receipt_sig over receipt_hash (draft §8),
 * nor the consensus and dissent accounting, and its result says so. Since
 * §11 requires that chain to be recomputed, a KU is never valid here: it is
 * invalid when a receipt fails, and undecidable otherwise.
 *
 * References:
 *   - draft-farley-acta-knowledge-units-00 (IETF)
 *   - specs/knowledge-unit.schema.json
 *   - specs/draft-farley-acta-knowledge-units-00.md
 *
 * @module verify-cli/src/engines/knowledge-unit
 * @license Apache-2.0
 */

/**
 * @typedef {Object} KuVerifyOptions
 * @property {string} [publicKey]
 */

/**
 * @typedef {Object} KuVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} format
 * @property {string} [topic]
 * @property {string[]} [models]
 * @property {number} [rounds]
 * @property {number} [totalReceipts]
 * @property {number} [verifiedReceipts]
 * @property {number} [failedReceipts]
 * @property {string[]} [dissentingModels]
 * @property {string} [consensusLevel]
 * @property {string[]} [errors]
 */

/** The receipt formats checked inside a KU, as on the command line; anything else is not checked. */
const RECEIPT_MODES = new Set(['ed25519-passport', 'ed25519-receipt-v2', 'ed25519-receipt-v1', 'ed25519-browser-legacy']);

// Required fields in a conformant KU per knowledge-unit.schema.json
const REQUIRED_FIELDS = [
  'id',
  'version',
  'canonical_question',
  'consensus_level',
  'agreed',
  'models_used',
  'process_template',
  'status',
  'fresh_until',
  'receipt_sig',
  'receipt_kid',
  'receipt_hash',
];

/**
 * Verify a Knowledge Unit bundle.
 *
 * @param {Object} bundle
 * @param {KuVerifyOptions} [opts]
 * @returns {Promise<KuVerifyResult>}
 */
export async function verifyKnowledgeUnit(bundle, opts = {}) {
  // Structural validation against required fields.
  const missing = REQUIRED_FIELDS.filter((f) => bundle[f] === undefined);
  if (missing.length > 0) {
    return {
      valid: false,
      error: 'unknown_format',
      format: 'knowledge-unit',
      errors: [`Missing required KU fields: ${missing.join(', ')}`],
    };
  }

  // Validate version
  if (bundle.version !== 1) {
    return {
      valid: false,
      error: 'unsupported_algorithm',
      format: 'knowledge-unit',
      errors: [`Unsupported KU schema version: ${bundle.version}`],
    };
  }

  // ID pattern: ku-[a-z0-9]{12}
  if (!/^ku-[a-z0-9]{12}$/.test(bundle.id)) {
    return {
      valid: false,
      error: 'unknown_format',
      format: 'knowledge-unit',
      errors: [`Invalid KU id format: ${bundle.id}`],
    };
  }

  // Verify the embedded receipts. The outcome combines theirs as §5.3 of the -04 editor's copy (VeritasActa/drafts)
  // combines checks: invalid if any receipt is invalid, else undecidable if there is none or any could not be checked
  // (a receipt in a format this verifier does not read included), else valid. Before, a KU with no receipts, or whose
  // receipts were all skipped as unknown, was valid with nothing verified, and one checked with no key was invalid.
  const { verifyReceipt } = await import('./ed25519-receipt.js');
  const { detectFormat } = await import('../detect.js');
  const { exitCodeFor } = await import('../errors.js');

  const receiptList = Array.isArray(bundle.receipts) ? bundle.receipts : [];
  const errors = [];
  let verifiedReceipts = 0;
  let failedReceipts = 0;
  let uncheckedReceipts = 0;
  let firstFailure = null;
  let firstUnchecked = receiptList.length === 0 ? 'no_receipts' : null;

  for (let i = 0; i < receiptList.length; i++) {
    const receipt = receiptList[i];
    const detected = detectFormat(receipt);
    if (!RECEIPT_MODES.has(detected.mode)) {
      uncheckedReceipts++;
      firstUnchecked ||= 'unknown_format';
      errors.push(`Receipt ${i + 1}: not checked: not a receipt this verifier reads (${detected.mode})`);
      continue;
    }
    const r = await verifyReceipt(receipt, detected.mode, opts);
    if (r.valid) verifiedReceipts++;
    else if ((r.outcome ?? (exitCodeFor(r.error) === 1 ? 'invalid' : 'undecidable')) === 'invalid') {
      failedReceipts++;
      firstFailure ||= r.error;
      errors.push(`Receipt ${i + 1}: ${r.error}`);
    } else {
      uncheckedReceipts++;
      firstUnchecked ||= r.error || 'unknown_format';
      errors.push(`Receipt ${i + 1}: not checked: ${r.error}`);
    }
  }

  const dissentingModels = Array.isArray(bundle.dissent)
    ? bundle.dissent.map((d) => d.model).filter(Boolean)
    : [];

  // The aggregate signature, receipt_sig over receipt_hash (draft-farley-acta-knowledge-units-00 §8 Receipt Binding),
  // is not checked, because §8 does not define its preimage unambiguously: a KU has no member that says which of its
  // receipts are which round's and slot (round 2 records carry no slot), receipt_hash is bare hex in §3.6 and
  // "sha256:"-prefixed in the §10 example, and §8 does not say whether receipt_sig signs the digest's bytes or its text.
  // §11 (Receipt Replay) requires recomputing that chain before the content is relied on, so a KU whose receipt_sig and
  // receipt_hash are present and not checked is undecidable, never valid; a receipt that fails still makes it invalid.
  // Before, a KU whose receipts verified was valid with its aggregate unchecked.
  const outcome = failedReceipts > 0 ? 'invalid' : 'undecidable';
  const overallValid = false;
  const error = outcome === 'invalid' ? firstFailure : firstUnchecked || 'receipt_binding_not_checked';
  const detail = error === 'no_receipts' ? 'The Knowledge Unit carries no receipts, so nothing in it was verified.'
    : error === 'receipt_binding_not_checked' ? `receipt_sig and receipt_hash were not checked: draft-farley-acta-knowledge-units-00 §8 (Receipt Binding) does not say which receipts form each round, whether receipt_hash is bare hex or "sha256:"-prefixed, or whether receipt_sig signs the digest's bytes or its text. Nothing here binds the KU's question, answers or consensus to its receipts.`
      : undefined;

  return {
    valid: overallValid,
    outcome,
    error,
    ...(detail ? { detail } : {}),
    notChecked: [`receipt_sig and receipt_hash: the Knowledge Unit's aggregate signature over its receipt chain (draft-farley-acta-knowledge-units-00 §8) is not checked, so nothing here binds its question, answer or consensus to its receipts, and the KU is undecidable${bundle.receipt_sig === '' ? ' (receipt_sig is empty)' : ''}.`],
    format: 'knowledge-unit',
    topic: bundle.canonical_question,
    models: bundle.models_used,
    rounds: bundle.rounds || receiptList.length,
    totalReceipts: receiptList.length,
    verifiedReceipts,
    failedReceipts,
    uncheckedReceipts,
    dissentingModels,
    consensusLevel: bundle.consensus_level,
    errors: errors.length ? errors : undefined,
    kid: bundle.receipt_kid,
  };
}
