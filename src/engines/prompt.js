/**
 * @veritasacta/verify — prompt engine
 *
 * Verify the provenance of an agent instruction file (SKILLS.md,
 * CLAUDE.md, system_prompt.md, AGENTS.md, or any plain-text prompt
 * artefact) against either:
 *
 *   1. A Veritas Acta receipt asserting the SHA-256 of the file's bytes
 *      (receipt.payload.prompt_hash === "sha256:<hex>").
 *
 *   2. A Sigstore attestation bundle (DSSE envelope over an in-toto
 *      statement with predicate type scopeblind.decision or sigstore's
 *      own predicate types naming the file hash).
 *
 * This closes the supply-chain attack vector where an attacker modifies
 * CLAUDE.md or SKILLS.md between the time an operator wrote it and the
 * time an agent runs with it loaded. Cryptographic provenance of the
 * exact prompt bytes lets downstream auditors prove the agent operated
 * under an unmodified set of instructions.
 *
 * @module verify-cli/src/engines/prompt
 * @license Apache-2.0
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

import { canonicalHash } from '../util/canonical.js';

/**
 * @typedef {Object} PromptVerifyOptions
 * @property {string} promptPath        Path to the prompt file to verify.
 * @property {string} [receiptPath]     Path to a Veritas Acta receipt file
 *                                      asserting the prompt hash.
 * @property {string} [sigstoreBundle]  Path to a Sigstore bundle (JSON).
 * @property {string} [expectedHash]    Alternative: a specific SHA-256 hex
 *                                      the caller expects to match.
 */

/**
 * @typedef {Object} PromptVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} format             "prompt-verify"
 * @property {string} prompt_path
 * @property {string} prompt_hash
 * @property {string} [expected_hash]
 * @property {string} [source]           "receipt" | "sigstore" | "expected-hash"
 * @property {Object} [receipt_summary]  If source=receipt, a summary of the
 *                                      referenced receipt.
 * @property {Object} [bundle_summary]   If source=sigstore.
 */

/**
 * Compute SHA-256 of a file's raw bytes, hex-encoded with "sha256:" prefix.
 */
export function hashPromptFile(path) {
  const bytes = readFileSync(path);
  const hex = createHash('sha256').update(bytes).digest('hex');
  return `sha256:${hex}`;
}

/**
 * Verify a prompt against one of the three accepted sources.
 *
 * Sources are tried in order: expectedHash (fast path), receipt, Sigstore
 * bundle. The first source that decides (pass or fail) wins.
 *
 * @param {PromptVerifyOptions} opts
 * @returns {Promise<PromptVerifyResult>}
 */
export async function verifyPrompt(opts) {
  const { promptPath, receiptPath, sigstoreBundle, expectedHash } = opts;

  let promptHash;
  try {
    promptHash = hashPromptFile(promptPath);
  } catch (err) {
    return {
      valid: false,
      error: `cannot_read_prompt_file:${err.code || err.message}`,
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: '',
    };
  }

  // 1. Expected hash (fastest path; caller knows what it should be)
  if (expectedHash) {
    const normalised = expectedHash.startsWith('sha256:')
      ? expectedHash
      : `sha256:${expectedHash}`;
    const ok = normalised === promptHash;
    return {
      valid: ok,
      error: ok ? undefined : 'hash_mismatch',
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: promptHash,
      expected_hash: normalised,
      source: 'expected-hash',
    };
  }

  // 2. Veritas Acta receipt
  if (receiptPath) {
    return verifyViaReceipt({ promptPath, promptHash, receiptPath });
  }

  // 3. Sigstore bundle
  if (sigstoreBundle) {
    return verifyViaSigstore({ promptPath, promptHash, bundlePath: sigstoreBundle });
  }

  return {
    valid: false,
    error: 'missing_source:provide_receipt_or_sigstore_or_expected-hash',
    format: 'prompt-verify',
    prompt_path: promptPath,
    prompt_hash: promptHash,
  };
}

function verifyViaReceipt({ promptPath, promptHash, receiptPath }) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(receiptPath, 'utf-8'));
  } catch (err) {
    return {
      valid: false,
      error: `cannot_read_receipt:${err.code || err.message}`,
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: promptHash,
      source: 'receipt',
    };
  }

  const payload = receipt.payload || receipt;
  const asserted =
    payload.prompt_hash ||
    payload.instruction_hash ||
    payload.artifact_hash ||
    (payload.artifacts &&
      payload.artifacts.find((a) => a.path === promptPath || a.name === promptPath)
        ?.hash);

  if (!asserted) {
    return {
      valid: false,
      error: 'receipt_missing_prompt_hash_field',
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: promptHash,
      source: 'receipt',
      receipt_summary: receipt_summary(receipt),
    };
  }

  const normalised = asserted.startsWith('sha256:') ? asserted : `sha256:${asserted}`;
  const ok = normalised === promptHash;
  return {
    valid: ok,
    error: ok ? undefined : 'hash_mismatch',
    format: 'prompt-verify',
    prompt_path: promptPath,
    prompt_hash: promptHash,
    expected_hash: normalised,
    source: 'receipt',
    receipt_summary: receipt_summary(receipt),
  };
}

function verifyViaSigstore({ promptPath, promptHash, bundlePath }) {
  let bundle;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, 'utf-8'));
  } catch (err) {
    return {
      valid: false,
      error: `cannot_read_sigstore_bundle:${err.code || err.message}`,
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: promptHash,
      source: 'sigstore',
    };
  }

  // Sigstore bundles carry the DSSE envelope + in-toto statement. The
  // in-toto statement's subject is an array of { name, digest: { sha256: ... }}.
  // We look for a subject digest matching our computed promptHash.
  const subjects = extractSigstoreSubjects(bundle);
  if (!subjects || subjects.length === 0) {
    return {
      valid: false,
      error: 'sigstore_bundle_missing_subjects',
      format: 'prompt-verify',
      prompt_path: promptPath,
      prompt_hash: promptHash,
      source: 'sigstore',
      bundle_summary: bundle_summary(bundle),
    };
  }

  const target = promptHash.replace(/^sha256:/, '');
  const matched = subjects.find((s) => (s.digest && (s.digest.sha256 === target)));
  const ok = Boolean(matched);
  return {
    valid: ok,
    error: ok ? undefined : 'sigstore_subject_hash_mismatch',
    format: 'prompt-verify',
    prompt_path: promptPath,
    prompt_hash: promptHash,
    expected_hash: matched ? `sha256:${matched.digest.sha256}` : undefined,
    source: 'sigstore',
    bundle_summary: bundle_summary(bundle),
  };
}

function receipt_summary(receipt) {
  const p = receipt.payload || receipt;
  return {
    type: p.type,
    issuer_id: p.issuer_id,
    agent_id: p.agent_id,
    issued_at: p.issued_at,
    kid: receipt.signature && receipt.signature.kid,
  };
}

function bundle_summary(bundle) {
  return {
    media_type: bundle.mediaType || bundle.media_type,
    kind: bundle.kind,
    verification_material_present: Boolean(bundle.verificationMaterial || bundle.verification_material),
    subject_count: (extractSigstoreSubjects(bundle) || []).length,
  };
}

function extractSigstoreSubjects(bundle) {
  // Bundles can carry the statement in a few locations depending on version.
  // We try: bundle.dsseEnvelope.payload (base64-encoded in-toto statement),
  // bundle.statement (inline), bundle.attestations[0].statement.
  let statement = bundle.statement || bundle.in_toto_statement;

  if (!statement && bundle.dsseEnvelope && bundle.dsseEnvelope.payload) {
    try {
      const payload = Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf-8');
      statement = JSON.parse(payload);
    } catch {
      // fall through
    }
  }

  if (!statement && Array.isArray(bundle.attestations) && bundle.attestations[0]) {
    statement = bundle.attestations[0].statement || bundle.attestations[0];
  }

  return statement && Array.isArray(statement.subject) ? statement.subject : null;
}
