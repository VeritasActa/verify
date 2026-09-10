/**
 * Trusted Context Pack verifier (TCB v1).
 *
 * A fund's desktop runtime turns an approved file (a positions export, a blotter,
 * a mandate, a research folder) into a SIGNED TrustedContextPack before any agent
 * or gate operates over it. This engine lets a third party (an allocator, an LP,
 * an auditor) re-verify that pack offline, holding only this open tool and no
 * ScopeBlind code: the digest is recomputed over the canonical payload and the
 * Ed25519 signature is checked over that digest against the embedded (or pinned)
 * key, exactly like a Gate receipt tuple.
 *
 * The TCB-specific check is the relabel guard: gate_status MUST equal the status
 * derived from the signed confidence and freshness. A pack cannot be re-signed to
 * claim a low-confidence or stale parse is `usable`. This is what makes the
 * confidence-gating trustworthy to someone who did not produce the pack.
 *
 * What a verified pack proves: these exact bytes, with this file hash, parsed to
 * this context at this confidence and freshness, signed by this key. What it does
 * NOT prove: that the source file is authentic, complete, or the fund's true book.
 * That requires a custodian-signed feed or a DKIM/PAdES source (a stronger tier).
 *
 * @module verify-cli/src/engines/trusted-context-pack
 * @license Apache-2.0
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { sortKeysDeep } from '../util/canonical.js';
import { hexToBytes, bytesToHex } from '../util/hex.js';

export const TCB_SCHEMA = 'scopeblind.trusted_context_pack.v1';
const TCB_USABLE_THRESHOLD = 0.75;
const HEX_64 = /^[0-9a-f]{64}$/;
const SOURCE_TYPES = new Set(['book_positions', 'nav_account', 'blotter', 'risk_report', 'mandate_limits', 'research', 'operations', 'unknown']);
const GATE_STATUSES = new Set(['usable', 'needs_approval', 'blocked']);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isString = (v) => typeof v === 'string' && v.length > 0;
const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);

export function canonicalTcbJSON(payload) {
  return JSON.stringify(sortKeysDeep(payload));
}

/** The single source of truth for the gate decision (kept in sync with
 *  scopeblind-pm/src/trusted-context.ts:gateStatusFor). */
export function gateStatusFor(confidence, freshness) {
  if (confidence <= 0) return 'blocked';
  if (confidence < TCB_USABLE_THRESHOLD || freshness?.stale === true) return 'needs_approval';
  return 'usable';
}

export const TCB_PROVES = [
  'Authenticity: the pack was signed by the Ed25519 key it carries (the fund runtime that built it).',
  'Integrity: the file hash, parsed context, confidence, freshness, and gate decision are bound by the signature and unmodified.',
  'Honest gating: gate_status matches the confidence and freshness, so a low-confidence or stale parse cannot be relabeled usable.',
];

export const TCB_LIMITATIONS = [
  'That the source file is authentic, complete, or the fund\'s true book; a pack attests the parse, not the provenance.',
  'Correctness of the original file behind file_hash unless its bytes are separately disclosed and re-hashed.',
  'Whether the embedded verification_key is the runtime you expect; pin it with --key to bind trust to a known signer.',
  'A stronger source tier (custodian-signed feed, DKIM or PAdES) is needed to attest where the data came from.',
];

function collectFields(payload) {
  const out = {};
  for (const k of ['source_type', 'source_format', 'source_lineage', 'file_name', 'file_hash', 'parser_version', 'confidence', 'gate_status', 'workspace_id', 'source_id']) {
    if (payload[k] !== undefined && payload[k] !== null) out[k] = payload[k];
  }
  if (isObject(payload.freshness)) out.freshness = { as_of: payload.freshness.as_of ?? null, stale: payload.freshness.stale === true };
  if (Array.isArray(payload.warnings)) out.warnings = payload.warnings;
  if (isObject(payload.summary)) out.summary = payload.summary;
  return out;
}

function schemaErrors(payload) {
  const errors = [];
  for (const f of ['workspace_id', 'source_id', 'source_format', 'file_hash', 'parser_version']) {
    if (!isString(payload[f])) errors.push(`missing or empty ${f}`);
  }
  if (!SOURCE_TYPES.has(payload.source_type)) errors.push(`invalid source_type ${JSON.stringify(payload.source_type)}`);
  if (!GATE_STATUSES.has(payload.gate_status)) errors.push(`invalid gate_status ${JSON.stringify(payload.gate_status)}`);
  if (!HEX_64.test(payload.file_hash || '')) errors.push('file_hash must be 64 lowercase hex characters');
  if (!isNumber(payload.confidence) || payload.confidence < 0 || payload.confidence > 1) errors.push('confidence must be a number in [0,1]');
  if (!Array.isArray(payload.warnings)) errors.push('warnings must be an array');
  if (!isObject(payload.parsed_artifacts)) errors.push('parsed_artifacts must be an object');
  if (!isObject(payload.freshness) || !isString(payload.freshness.ingested_at)) errors.push('freshness.ingested_at is required');
  else if (typeof payload.freshness.stale !== 'boolean') errors.push('freshness.stale must be a boolean');
  // The relabel guard: gate_status must follow from the signed confidence/freshness.
  if (errors.length === 0) {
    const expected = gateStatusFor(payload.confidence, payload.freshness);
    if (payload.gate_status !== expected) errors.push(`gate_status ${JSON.stringify(payload.gate_status)} does not match the signed confidence and freshness (expected ${expected})`);
  }
  return errors;
}

/**
 * Verify a TrustedContextPack tuple { payload, digest, signature, verification_key }.
 *
 * @param {object} tuple
 * @param {{ publicKey?: string }} [opts]
 */
export function verifyTrustedContextPack(tuple, opts = {}) {
  const base = { format: 'trusted-context-pack', schema: null, schemaRecognized: false, algorithm: 'ed25519' };
  if (!isObject(tuple)) return { valid: false, error: 'unknown_format', ...base, detail: 'pack is not an object' };
  const payload = tuple.payload;
  if (!isObject(payload)) return { valid: false, error: 'missing_payload', ...base };
  const schema = isString(payload.schema) ? payload.schema : null;
  base.schema = schema;
  base.schemaRecognized = schema === TCB_SCHEMA;
  base.payloadFields = collectFields(payload);
  if (schema !== TCB_SCHEMA) return { valid: false, error: 'unknown_format', ...base, detail: `expected schema ${TCB_SCHEMA}` };

  if (!isString(tuple.signature)) return { valid: false, error: 'missing_signature', ...base };
  if (!isString(tuple.digest) || !HEX_64.test(tuple.digest)) return { valid: false, error: 'malformed_hex', ...base, detail: 'digest must be 64 lowercase hex characters' };
  if (!isString(tuple.verification_key)) return { valid: false, error: 'no_public_key', ...base };

  const pinned = isString(opts.publicKey);
  if (pinned && opts.publicKey.toLowerCase() !== tuple.verification_key.toLowerCase()) {
    return { valid: false, error: 'key_mismatch', ...base, publicKey: tuple.verification_key, expectedKey: opts.publicKey };
  }

  const recomputed = bytesToHex(sha256(utf8ToBytes(canonicalTcbJSON(payload))));
  if (recomputed !== tuple.digest) return { valid: false, error: 'digest_mismatch', ...base, digest: tuple.digest, recomputedDigest: recomputed, publicKey: tuple.verification_key };

  let ok = false;
  try {
    ok = ed25519.verify(hexToBytes(tuple.signature), hexToBytes(tuple.digest), hexToBytes(tuple.verification_key));
  } catch (e) {
    return { valid: false, error: 'malformed_hex', ...base, digest: tuple.digest, detail: e.message, publicKey: tuple.verification_key };
  }
  if (!ok) return { valid: false, error: 'invalid_signature', ...base, digest: tuple.digest, publicKey: tuple.verification_key };

  const semanticErrors = schemaErrors(payload);
  if (semanticErrors.length) return { valid: false, error: 'schema_invalid', ...base, digest: tuple.digest, publicKey: tuple.verification_key, detail: semanticErrors.join('; '), semanticErrors };

  return {
    valid: true,
    ...base,
    digest: tuple.digest,
    publicKey: tuple.verification_key,
    keySource: pinned ? 'embedded-tuple (pinned via --key)' : 'embedded-tuple',
    gateStatus: payload.gate_status,
    confidence: payload.confidence,
    sourceType: payload.source_type,
    proves: TCB_PROVES,
    limitations: TCB_LIMITATIONS,
  };
}
