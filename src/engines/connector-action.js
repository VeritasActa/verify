/**
 * Connector-action profile (draft-farley-acta-connector-action-00).
 *
 * A decision receipt may carry a `connector` member: the grant an agent
 * platform presented with the call, what the recording gate could check about
 * it, the digest of the call as received, and what the service read back.
 *
 * This engine checks the member as a whole. It never takes the gate's word for
 * the platform signature: given a platform key from outside the receipt it
 * re-verifies the presented signature over JCS(context); without one it says
 * so. A member that fails the schema, or whose recorded check the supplied key
 * contradicts, makes the receipt invalid under the profile. A verifier that
 * does not implement the profile ignores the member; this one does not.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../util/canonical.js';
import { hexToBytes } from '../util/hex.js';

export const CONNECTOR_PROFILE = 'draft-farley-acta-connector-action-00';
export const CONNECTOR_CONTEXT_TYPE = 'acta:connector-context';
export const GRANT_TYPES = ['one_time', 'session', 'task', 'time_bounded', 'perpetual'];
export const CONTEXT_CHECKS = ['valid', 'invalid', 'unsigned', 'unverifiable'];
export const EFFECT_STATUSES = ['confirmed', 'refused', 'not_observed'];

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SHA256_PREFIXED = /^sha256:[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SHORT = 200;
const PURPOSE = 500;

const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && !CONTROL.test(v);
const at = (v) => typeof v === 'string' && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const only = (v, keys) => Object.keys(v).every((k) => keys.includes(k));

function grantErrors(g) {
  const e = [];
  if (!isObject(g)) return ['grant is not an object'];
  if (!only(g, ['type', 'id', 'purpose', 'issued_at', 'expires_at'])) e.push('grant carries an unknown member');
  if (!GRANT_TYPES.includes(g.type)) e.push(`grant.type is not one of ${GRANT_TYPES.join(', ')}`);
  if (g.id !== undefined && !text(g.id, SHORT)) e.push('grant.id is malformed');
  if (g.purpose !== undefined && !text(g.purpose, PURPOSE)) e.push('grant.purpose is malformed or longer than 500 characters');
  if (g.issued_at !== undefined && !at(g.issued_at)) e.push('grant.issued_at is not an RFC 3339 UTC timestamp');
  if (g.expires_at !== undefined && !at(g.expires_at)) e.push('grant.expires_at is not an RFC 3339 UTC timestamp');
  if (at(g.issued_at) && at(g.expires_at) && Date.parse(g.expires_at) <= Date.parse(g.issued_at)) e.push('grant.expires_at is not after grant.issued_at');
  return e;
}

function contextErrors(c) {
  const e = [];
  if (!isObject(c)) return ['context is not an object'];
  if (!only(c, ['type', 'platform', 'agent', 'grant', 'mandate_digest', 'issued_at', 'issuer_id'])) e.push('context carries an unknown member');
  if (c.type !== CONNECTOR_CONTEXT_TYPE) e.push(`context.type is not ${CONNECTOR_CONTEXT_TYPE}`);
  if (!text(c.platform, SHORT) || !/^[a-z0-9][a-z0-9.-]*$/.test(c.platform)) e.push('context.platform is not a lowercase dotted name');
  if (!text(c.agent, SHORT)) e.push('context.agent is malformed');
  e.push(...grantErrors(c.grant).map((x) => `context.${x}`));
  if (c.mandate_digest !== undefined && !SHA256_PREFIXED.test(c.mandate_digest)) e.push('context.mandate_digest is not sha256:<hex>');
  if (c.issued_at !== undefined && !at(c.issued_at)) e.push('context.issued_at is not an RFC 3339 UTC timestamp');
  if (c.issuer_id !== undefined && !text(c.issuer_id, SHORT)) e.push('context.issuer_id is malformed');
  return e;
}

function signatureErrors(s) {
  if (!isObject(s)) return ['context_signature is not an object'];
  const e = [];
  if (!only(s, ['alg', 'kid', 'sig'])) e.push('context_signature carries an unknown member');
  if (s.alg !== 'EdDSA') e.push('context_signature.alg is not EdDSA');
  if (!text(s.kid, SHORT)) e.push('context_signature.kid is malformed');
  if (!HEX128.test(s.sig)) e.push('context_signature.sig is not 128 hex characters');
  return e;
}

function effectErrors(f) {
  if (!isObject(f)) return ['effect is not an object'];
  const e = [];
  if (!only(f, ['status', 'readback_digest', 'observed_at'])) e.push('effect carries an unknown member');
  if (!EFFECT_STATUSES.includes(f.status)) e.push(`effect.status is not one of ${EFFECT_STATUSES.join(', ')}`);
  if (f.readback_digest !== undefined && !HEX64.test(f.readback_digest)) e.push('effect.readback_digest is not a sha256 hex digest');
  if (f.status === 'confirmed' && !HEX64.test(f.readback_digest || '')) e.push('effect.status is confirmed without a readback_digest');
  if (f.observed_at !== undefined && !at(f.observed_at)) e.push('effect.observed_at is not an RFC 3339 UTC timestamp');
  return e;
}

/**
 * Schema errors of a recorded connector member. Empty means well formed.
 * @param {unknown} c
 * @returns {string[]}
 */
export function connectorSchemaErrors(c) {
  if (!isObject(c)) return ['connector is not an object'];
  const e = [];
  if (!only(c, ['v', 'context', 'context_signature', 'context_check', 'platform_kid', 'request_digest', 'effect'])) e.push('connector carries an unknown member');
  if (c.v !== 1) e.push('connector.v is not 1');
  e.push(...contextErrors(c.context).map((x) => `connector.${x}`));
  if (c.context_signature !== undefined) e.push(...signatureErrors(c.context_signature).map((x) => `connector.${x}`));
  if (!CONTEXT_CHECKS.includes(c.context_check)) e.push(`connector.context_check is not one of ${CONTEXT_CHECKS.join(', ')}`);
  if (c.context_check === 'unsigned' && c.context_signature !== undefined) e.push('connector.context_check says unsigned but a signature is present');
  if (c.context_check !== 'unsigned' && c.context_signature === undefined) e.push(`connector.context_check says ${String(c.context_check)} without a signature`);
  if (c.context_check === 'valid' && !text(c.platform_kid, SHORT)) e.push('connector.context_check is valid without platform_kid');
  if (c.context_check !== 'valid' && c.platform_kid !== undefined) e.push('connector.platform_kid is present although the check is not valid');
  if (c.context_check === 'valid' && isObject(c.context_signature) && c.platform_kid !== c.context_signature.kid) e.push('connector.platform_kid differs from the signature kid');
  if (isObject(c.context_signature) && isObject(c.context) && c.context.issuer_id !== c.context_signature.kid) e.push('connector.context.issuer_id differs from the signature kid');
  if (!HEX64.test(c.request_digest)) e.push('connector.request_digest is not a sha256 hex digest');
  if (c.effect !== undefined) e.push(...effectErrors(c.effect).map((x) => `connector.${x}`));
  return e;
}

/**
 * Check a receipt payload's connector member.
 *
 * @param {object} payload  the receipt payload (already signature-checked by the caller)
 * @param {{platformKeys?: Record<string,string>}} [opts]  platform key identifiers to hex Ed25519 public keys, from outside the receipt
 * @returns {null | {profile:string, valid:boolean, errors:string[], warnings:string[], platform_signature:'absent'|'unverifiable'|'valid'|'invalid', context_check?:string, platform?:string, agent?:string, grant_type?:string, purpose?:string, effect?:string|null, request_digest?:string, platform_kid?:string}}
 *   null when the payload carries no connector member
 */
export function checkConnectorAction(payload, opts = {}) {
  if (!isObject(payload) || payload.connector === undefined) return null;
  const c = payload.connector;
  const errors = connectorSchemaErrors(c);
  const out = {
    profile: CONNECTOR_PROFILE,
    valid: errors.length === 0,
    errors,
    warnings: [],
    platform_signature: 'absent',
    context_check: isObject(c) ? c.context_check : undefined,
    platform: isObject(c) && isObject(c.context) ? c.context.platform : undefined,
    agent: isObject(c) && isObject(c.context) ? c.context.agent : undefined,
    grant_type: isObject(c) && isObject(c.context) && isObject(c.context.grant) ? c.context.grant.type : undefined,
    purpose: isObject(c) && isObject(c.context) && isObject(c.context.grant) ? c.context.grant.purpose : undefined,
    effect: isObject(c) && isObject(c.effect) ? c.effect.status : null,
    request_digest: isObject(c) ? c.request_digest : undefined,
    platform_kid: isObject(c) ? c.platform_kid : undefined,
  };
  if (!out.valid || !isObject(c.context_signature)) return out;

  const kid = c.context_signature.kid;
  const key = opts.platformKeys && opts.platformKeys[kid];
  if (!key || !HEX64.test(key)) {
    out.platform_signature = 'unverifiable';
    out.warnings.push(`no platform key supplied for ${kid}; the recorded check (${c.context_check}) is the gate's word, pass --platform-key ${kid}=<hex> to test it`);
    return out;
  }
  let ok = false;
  try { ok = ed25519.verify(hexToBytes(c.context_signature.sig), utf8ToBytes(canonicalize(c.context)), hexToBytes(key)); } catch { ok = false; }
  out.platform_signature = ok ? 'valid' : 'invalid';
  if (!ok) {
    out.valid = false;
    out.errors.push(`the platform signature over the context does not verify under the supplied key for ${kid}; the recorded context is not what the platform signed`);
  } else if (c.context_check === 'invalid') {
    out.warnings.push('the gate recorded the signature as invalid, but it verifies under the supplied key; the gate held a different key for this kid');
  } else if (c.context_check === 'unverifiable') {
    out.warnings.push('the gate held no key for this kid; the signature verifies under the key supplied here');
  }
  return out;
}
