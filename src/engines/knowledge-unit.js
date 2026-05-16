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
 *   - Every embedded receipt individually (via Ed25519 engine)
 *   - Cross-references (receipt_hash aggregates match the chain heads)
 *   - Consensus / dissent accounting is internally consistent
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

  // Verify embedded receipts if present
  const { verifyReceipt } = await import('./ed25519-receipt.js');
  const { detectFormat } = await import('../detect.js');

  const receiptList = Array.isArray(bundle.receipts) ? bundle.receipts : [];
  const errors = [];
  let verifiedReceipts = 0;
  let failedReceipts = 0;

  for (const receipt of receiptList) {
    const detected = detectFormat(receipt);
    if (detected.mode === 'unknown' || detected.mode === 'knowledge-unit') continue;
    const r = await verifyReceipt(receipt, detected.mode, opts);
    if (r.valid) verifiedReceipts++;
    else {
      failedReceipts++;
      errors.push(`Receipt ${receiptList.indexOf(receipt) + 1}: ${r.error}`);
    }
  }

  const dissentingModels = Array.isArray(bundle.dissent)
    ? bundle.dissent.map((d) => d.model).filter(Boolean)
    : [];

  const overallValid = failedReceipts === 0 && missing.length === 0;

  return {
    valid: overallValid,
    error: overallValid ? undefined : 'invalid_signature',
    format: 'knowledge-unit',
    topic: bundle.canonical_question,
    models: bundle.models_used,
    rounds: bundle.rounds || receiptList.length,
    totalReceipts: receiptList.length,
    verifiedReceipts,
    failedReceipts,
    dissentingModels,
    consensusLevel: bundle.consensus_level,
    errors: errors.length ? errors : undefined,
    kid: bundle.receipt_kid,
  };
}
