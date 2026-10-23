/**
 * Append-only audit log for verification events.
 *
 * Writes a single JSON-lines record per verification to a user-chosen
 * file path. Never phones home; this is purely a local operator record.
 * Useful for SIEM integration, compliance archival, and forensic review.
 *
 * Each record contains: timestamp, verifier version + Sigil, subject
 * hash, verification result, optional org identifier, and (when signing
 * is enabled) a signature by the attester key so the log itself is
 * tamper-evident.
 *
 * @module verify-cli/src/util/audit-log
 * @license Apache-2.0
 */

import { appendFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parseJsonStrict } from './strict-json.js';

/**
 * The _chain_hash of the last entry in an audit log, for the next entry to chain to; the empty string for a log
 * that does not exist yet or holds no entry. Throws when the last entry cannot be read or carries no chain hash, so
 * an entry is never appended as if it started a new chain.
 *
 * @param {string} filePath
 * @returns {string}
 */
export function lastChainHash(filePath) {
  let text;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return '';
    throw e;
  }
  const lines = text.split('\n').filter((l) => l.trim());
  if (lines.length === 0) return '';
  const last = parseJsonStrict(lines[lines.length - 1]);
  if (typeof last?._chain_hash !== 'string' || !/^[0-9a-f]{64}$/.test(last._chain_hash)) {
    throw new Error('the last entry carries no _chain_hash, so a new entry cannot be chained to it');
  }
  return last._chain_hash;
}

/**
 * @typedef {Object} AuditEntry
 * @property {string} timestamp
 * @property {string} verifier_version
 * @property {string} sigil_fingerprint
 * @property {string} [subject_hash]
 * @property {string} [subject_kid]
 * @property {string} [mode]
 * @property {boolean} valid
 * @property {string} [error]
 * @property {number} [tier]
 * @property {string} [org]
 */

/**
 * Append a verification event to an audit log file.
 *
 * @param {string} filePath
 * @param {Object} result       the verifier result
 * @param {Object} context      { sigil, org }
 * @returns {AuditEntry}        the record written
 */
export function appendAuditEntry(filePath, result, context = {}) {
  const { sigil, org } = context;
  const entry = {
    timestamp: new Date().toISOString(),
    verifier_version: sigil?.policy?.package_version || 'unknown',
    sigil_fingerprint: sigil?.fingerprint || 'unknown',
    subject_hash: result.hash ? `sha256:${result.hash}` : undefined,
    subject_kid: result.kid,
    mode: result.modeLabel || result.format,
    valid: Boolean(result.valid),
    error: result.error,
    tier: result.tier?.tier,
  };
  if (org) entry.org = org;

  // Compute a chain hash so the log is append-only-verifiable.
  // Chain: hash = sha256(prev_hash || canonical(entry))
  // First entry's prev_hash is the empty string.
  // The user can detect log tampering by re-computing the chain.
  const canonicalEntry = JSON.stringify(entry, Object.keys(entry).sort());
  const chainInput = `${context.prevHash || ''}${canonicalEntry}`;
  const chainHash = createHash('sha256').update(chainInput).digest('hex');
  entry._chain_hash = chainHash;

  appendFileSync(filePath, JSON.stringify(entry) + '\n', { flag: 'a' });
  return entry;
}
