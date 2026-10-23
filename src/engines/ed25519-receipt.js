/**
 * Ed25519 signed-receipt verification engine.
 *
 * Verifies receipts and bundles conforming to
 * draft-farley-acta-signed-receipts-02/03:
 *   - Passport envelope:  { payload, signature: { alg, kid, sig } }
 *   - v2 structured:      { v: 2, kid, issuer, issued_at, payload, signature }
 *   - v1 flat artifact:   { v: 1, type, timestamp, ..., signature }
 *
 * Verification path is pure Ed25519 + JCS canonicalization with AIP-0001
 * ASCII-only keys. No network calls during verification (unless the
 * caller opts into --jwks, which is fetched by the caller and passed
 * in as a resolved key).
 *
 * Embedded keys in the payload are rejected by default (v0.4.0+). An
 * escape hatch (allowEmbeddedKey: true) exists for one release cycle
 * to ease migration; it is deprecated and will be removed in v0.6.
 * When a key is supplied from outside the receipt, a key the signed
 * bytes carry must be that key, or the receipt is invalid (0.10.27).
 *
 * References:
 *   - RFC 8032 (EdDSA / Ed25519)
 *   - RFC 8785 (JCS)
 *   - AIP-0001 (receipt format, ASCII-only keys)
 *   - AIP-0002 (selective disclosure, verified in separate engine)
 *   - draft-farley-acta-signed-receipts-03
 *
 * @module verify-cli/src/engines/ed25519-receipt
 * @license Apache-2.0
 */

import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize, canonicalHash, legacyCanonicalize } from '../util/canonical.js';
import { hexToBytes, bytesToHex } from '../util/hex.js';
import { checkConnectorAction } from './connector-action.js';
import { exitCodeFor } from '../errors.js';
import { checkKeyWindow, receiptIssuedAt, keyWindowCheck } from '../util/key-window.js';

const EMBEDDED_KEY_FIELDS = ['public_key', 'verification_key', 'verification_jwk'];

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Base64 or base64url text as bytes, or null. atob, not Buffer, so the browser bundle can run it too. */
function base64Bytes(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  let binary;
  try {
    binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  } catch {
    return null;
  }
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

/**
 * A carried key as 64 lowercase hex characters, or null when the value is not an Ed25519 public key in a form read
 * here: 64 hex characters, the 32 bytes in base64 or base64url, or an OKP / Ed25519 JWK.
 */
function carriedKeyHex(value) {
  if (typeof value === 'string') {
    if (/^[0-9a-fA-F]{64}$/.test(value)) return value.toLowerCase();
    if (/^[A-Za-z0-9+/_-]{43}=?$/.test(value)) {
      const bytes = base64Bytes(value);
      return bytes && bytes.length === 32 ? bytesToHex(bytes) : null;
    }
    return null;
  }
  if (isObject(value) && value.kty === 'OKP' && value.crv === 'Ed25519' && typeof value.x === 'string') {
    return /^[A-Za-z0-9_-]{43}$/.test(value.x) ? carriedKeyHex(value.x) : null;
  }
  return null;
}

/**
 * The carried-key check (-04 editor's copy, VeritasActa/drafts, §5.3 and §9.5, as the rule is now being written): a
 * carried key is the value of a public_key, verification_key or verification_jwk member of the signed bytes (the
 * signed object, and in the v2 shape its payload). A verifier never verifies with one; and when a key from a trust
 * anchor outside the receipt is used, a carried key that is not that key makes the receipt invalid (key_mismatch).
 * Before 0.10.27 the signed bytes were searched for such members only when no key was supplied, so a receipt signed
 * by the anchored key while naming another key as its own verified.
 *
 * @param {unknown} signed the object the signature covers
 * @param {string} anchoredKey the hex key the receipt is verified with, from --key, --jwks or a trusted bundle
 * @returns {{ result: string, code?: string } | null} null when the signed bytes carry no key, or there is no key to
 *   compare with
 */
export function carriedKeyCheck(signed, anchoredKey) {
  if (typeof anchoredKey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(anchoredKey)) return null;
  const carriers = [signed, isObject(signed) ? signed.payload : null].filter(isObject);
  const carried = [];
  for (const carrier of carriers) {
    for (const name of EMBEDDED_KEY_FIELDS) {
      const value = carrier[name];
      if (typeof value === 'string' || isObject(value)) carried.push({ name, value });
    }
  }
  if (carried.length === 0) return null;
  const anchored = anchoredKey.toLowerCase();
  const other = carried.find(({ value }) => carriedKeyHex(value) !== anchored);
  if (!other) return { result: 'pass' };
  const hex = carriedKeyHex(other.value);
  return {
    result: 'fail',
    code: 'key_mismatch',
    detail: hex
      ? `The signed bytes carry ${other.name} ${hex.slice(0, 16)}..., which is not the key the receipt was verified with (${anchored.slice(0, 16)}...). A carried key that is not the trust-anchored key makes the receipt invalid (§5.3 and §9.5 of the -04 editor's copy, VeritasActa/drafts).`
      : `The signed bytes carry ${other.name}, which is not an Ed25519 public key in a form this verifier reads (64 hex characters, 32 bytes in base64url, or an OKP JWK), so it is not the key the receipt was verified with. A carried key that is not the trust-anchored key makes the receipt invalid (§5.3 and §9.5 of the -04 editor's copy, VeritasActa/drafts).`,
  };
}

/**
 * What the declared receipt types of the -04 editor's copy (VeritasActa/drafts, §3.1.1 and §3.2.1) require of their
 * payload: the REQUIRED members, and the closed sets their values come from.
 */
const DECLARED_TYPES = {
  'protectmcp:decision': {
    section: '§3.1.1',
    required: ['tool_name', 'decision'],
    values: { decision: ['allow', 'deny', 'rate_limit', 'require_approval'], agent_tier: ['unknown', 'signed-known', 'evidenced', 'privileged'] },
  },
  'protectmcp:restraint': {
    section: '§3.2.1',
    required: ['agent_id', 'agent_manifest_version', 'tool_name', 'decision'],
    values: { decision: ['allow', 'deny'], denial_type: ['policy-block', 'agent-refusal'] },
  },
};

/**
 * The issuer check of an envelope (§2.2 of the -04 editor's copy, VeritasActa/drafts: issuer_id "MUST match the kid
 * field in the signature object"), as the draft now reads it: a payload that names an issuer_id names the signer, and
 * when that is not signature.kid, or the signature object has no kid to match, the receipt is invalid
 * (issuer_kid_mismatch). A payload with no issuer_id is not checked here; envelopePayloadNotes names the gap. Before
 * 0.10.27 the two were never compared, so a receipt whose signed payload named one issuer and whose signature named
 * another key verified.
 *
 * @param {unknown} payload the envelope's payload
 * @param {unknown} signature the envelope's signature object
 * @returns {{ result: string, code?: string, detail?: string } | null} null when the payload names no issuer_id
 */
export function issuerKidCheck(payload, signature) {
  if (!isObject(payload) || !Object.hasOwn(payload, 'issuer_id')) return null;
  const draft = "§2.2 of the -04 editor's copy (VeritasActa/drafts)";
  if (!isObject(signature) || !Object.hasOwn(signature, 'kid')) {
    return {
      result: 'fail',
      code: 'issuer_kid_mismatch',
      detail: `The payload names issuer_id ${JSON.stringify(payload.issuer_id)}, and the signature object has no kid for it to match; ${draft} says issuer_id MUST match the kid, so the receipt is invalid.`,
    };
  }
  if (payload.issuer_id === signature.kid) return { result: 'pass' };
  return {
    result: 'fail',
    code: 'issuer_kid_mismatch',
    detail: `The payload's issuer_id ${JSON.stringify(payload.issuer_id)} is not signature.kid ${JSON.stringify(signature.kid)}; ${draft} says it MUST match, so the receipt is invalid.`,
  };
}

/**
 * Notes on an envelope's payload, reported beside the result and never counted in its outcome: a member -04 §2.2
 * makes REQUIRED of every payload that is missing (type, issued_at, issuer_id), a missing kid when no issuer_id names
 * one (§2.1.1), and the members and values the declared type requires (§3). An issuer_id that does not match the kid
 * is not a note: issuerKidCheck makes it invalid. The flat shapes, still being settled with implementers, get none.
 *
 * @param {unknown} payload
 * @param {unknown} signature the envelope's signature object
 * @returns {string[]}
 */
export function envelopePayloadNotes(payload, signature) {
  if (!isObject(payload)) return [];
  const notes = [];
  const draft = "of the -04 editor's copy (VeritasActa/drafts)";
  const either = (names) => (names.length === 1 ? names[0] : `${names.slice(0, -1).join(', ')} or ${names[names.length - 1]}`);
  const missing = ['type', 'issued_at', 'issuer_id'].filter((name) => !Object.hasOwn(payload, name));
  if (missing.length) notes.push(`The payload has no ${either(missing)}, which §2.2 ${draft} makes REQUIRED of every payload.`);
  if (!Object.hasOwn(payload, 'issuer_id') && !(isObject(signature) && Object.hasOwn(signature, 'kid'))) {
    notes.push(`The signature object has no kid, which §2.1.1 ${draft} makes REQUIRED.`);
  }
  const declared = typeof payload.type === 'string' && Object.hasOwn(DECLARED_TYPES, payload.type) ? DECLARED_TYPES[payload.type] : undefined;
  if (declared) {
    const absent = declared.required.filter((name) => !Object.hasOwn(payload, name));
    if (absent.length) notes.push(`This ${payload.type} payload has no ${either(absent)}, which ${declared.section} ${draft} makes REQUIRED for the type.`);
    for (const [name, allowed] of Object.entries(declared.values)) {
      if (Object.hasOwn(payload, name) && !allowed.includes(payload[name])) {
        notes.push(`The payload's ${name} ${JSON.stringify(payload[name])} is not one of ${allowed.join(', ')}, the values ${declared.section} ${draft} allows for ${payload.type}.`);
      }
    }
  }
  return notes;
}

// Draft §6.7: a chain link is "sha256:" followed by 64 lowercase hex characters. A prefix naming another algorithm
// is refused rather than read as SHA-256 from its length, and the bare 64-character digest of earlier revisions is
// accepted on read. Anything else is malformed, and is refused whether or not the predecessor is at hand.
const CHAIN_LINK = /^sha256:[0-9a-f]{64}$/;
const LEGACY_CHAIN_LINK = /^[0-9a-f]{64}$/;
const ALGORITHM_PREFIX = /^([A-Za-z0-9][A-Za-z0-9._+-]*):/;

/**
 * Check the syntax of every previousReceiptHash inside the signed bytes: the signed object itself and, in the v2
 * shape, its payload.
 *
 * @param {Object} signed the object the signature covers
 * @returns {{error?: string, form?: 'sha256' | 'legacy-bare-hex' | 'null', warning?: string}}
 */
export function checkChainLinkSyntax(signed) {
  const carriers = [signed, signed && typeof signed === 'object' ? signed.payload : null]
    .filter((c) => c && typeof c === 'object' && !Array.isArray(c) && Object.hasOwn(c, 'previousReceiptHash'));
  let form;
  let warning;
  for (const carrier of carriers) {
    const link = carrier.previousReceiptHash;
    if (link === null) {
      // Draft §2.2: the first receipt omits the member. Earlier tools wrote null instead, so null is accepted and named.
      form = form || 'null';
      warning = 'previousReceiptHash is null; draft §2.2 says the first receipt in a chain omits the member.';
      continue;
    }
    if (typeof link !== 'string') return { error: 'malformed_chain_link' };
    if (CHAIN_LINK.test(link)) { form = 'sha256'; continue; }
    if (LEGACY_CHAIN_LINK.test(link)) { form = form === 'sha256' ? form : 'legacy-bare-hex'; continue; }
    const prefix = ALGORITHM_PREFIX.exec(link);
    if (prefix && prefix[1].toLowerCase() !== 'sha256') return { error: 'unsupported_chain_hash_algorithm' };
    return { error: 'malformed_chain_link' };
  }
  return { form, warning };
}

/**
 * The checks one receipt can be put through, in the order a result names them. A failure reported is the first in
 * this order, and so is a check that could not run when none failed. Two are made only when they apply (0.10.27):
 * carried_key, when a key from outside the receipt is used and the signed bytes carry a key; and issuer_kid, when an
 * envelope's payload names an issuer_id.
 */
export const CHECK_ORDER = Object.freeze(['signing_input', 'signature', 'carried_key', 'issuer_kid', 'chain_link', 'connector', 'key_window', 'previous']);

/**
 * Combine the checks a verification made into one outcome, as §5.3 of the -04 editor's copy (VeritasActa/drafts) has it: invalid if any check ran and failed,
 * even when another could not run; undecidable if none failed and at least one could not run; valid only when every
 * check that applies ran and passed. A check whose result is anything else (not_run, absent, not_established) does
 * not move the outcome: it did not apply, or it was not reached because of a result already counted.
 *
 * @param {Record<string, {result: string, code?: string}>} checks
 * @returns {{ valid: boolean, outcome: 'valid'|'invalid'|'undecidable', error?: string, check?: string }}
 */
export function combineChecks(checks) {
  const ran = CHECK_ORDER.filter((name) => checks[name]).map((name) => [name, checks[name]]);
  const failed = ran.find(([, c]) => c.result === 'fail');
  if (failed) return { valid: false, outcome: 'invalid', error: failed[1].code, check: failed[0] };
  const open = ran.find(([, c]) => c.result === 'undecidable');
  if (open) return { valid: false, outcome: 'undecidable', error: open[1].code, check: open[0] };
  return { valid: true, outcome: 'valid' };
}

/** The chain-link syntax result as a check: absent when there is no link (or a null one, warned), else pass or not. */
function chainLinkCheck(syntax) {
  if (syntax.error) return { result: syntax.error === 'unsupported_chain_hash_algorithm' ? 'undecidable' : 'fail', code: syntax.error };
  return { result: syntax.form && syntax.form !== 'null' ? 'pass' : 'absent' };
}

/** A result that is not valid, as a check: failed when the registry classes its code as tampering, else undecidable. */
const signatureCheck = (code) => ({ result: exitCodeFor(code) === 1 ? 'fail' : 'undecidable', code });

/**
 * @typedef {Object} VerifyReceiptOptions
 * @property {string} [publicKey]    hex-encoded Ed25519 public key (64 chars)
 * @property {string} [keySource]    where publicKey came from: 'provided' (the default), 'jwks' or 'bundle'
 * @property {boolean} [allowEmbeddedKey]  pre-0.4.0 compat; deprecated
 * @property {boolean} [trustBundleKeys]  verifyBundle: check receipts with the keys the bundle carries (--trust-bundle-keys)
 * @property {string} [mode]         detected or forced mode
 */

/**
 * @typedef {Object} VerifyReceiptResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} format
 * @property {string} [type]
 * @property {string} [kid]
 * @property {string} [issuer]
 * @property {string} [keySource]     'provided' | 'jwks' | 'bundle' | 'embedded-deprecated'
 * @property {string} [publicKey]
 * @property {string} [algorithm]
 * @property {Object} [payloadFields] subset of payload fields surfaced for output
 */

/**
 * Verify a single Ed25519 receipt.
 *
 * @param {Object} input parsed receipt JSON
 * @param {string} detectedMode one of 'ed25519-receipt-v1', 'ed25519-receipt-v2', 'ed25519-passport'
 * @param {VerifyReceiptOptions} [opts]
 * @returns {Promise<VerifyReceiptResult>}
 */
export async function verifyReceipt(input, detectedMode, opts = {}) {
  let format = 'v1';
  let kid = null;
  let issuer = null;
  let algorithm = 'ed25519';
  let signedPayload = Object.fromEntries(Object.entries(input).filter(([key]) => key !== 'signature'));
  let signature = input.signature;

  if (detectedMode === 'ed25519-browser-legacy') {
    format = 'legacy-browser-1.0';
    signedPayload = Object.fromEntries(Object.entries(input).filter(([key]) => !['signature', 'public_key'].includes(key)));
  } else if (detectedMode === 'ed25519-passport') {
    format = 'passport';
    kid = input.signature.kid;
    algorithm = input.signature.alg || 'EdDSA';
    // Passport -> flat artifact for verification
    signedPayload = input.payload;
    signature = input.signature.sig;
  } else if (detectedMode === 'ed25519-receipt-v2') {
    format = 'v2';
    kid = input.kid;
    issuer = input.issuer;
    algorithm = input.algorithm || 'ed25519';
  } else if (detectedMode === 'ed25519-receipt-v1') {
    format = 'v1';
  }

  // Draft §6.7: the syntax of the link is a property of the bytes, so it is checked on every receipt, whatever else can
  // or cannot be checked; combineChecks decides what it means beside the rest.
  const chainLink = checkChainLinkSyntax(signedPayload);
  const linkCheck = chainLinkCheck(chainLink);
  // With a key from outside the receipt, a key the signed bytes carry must be that key (§5.3 and §9.5 of the -04
  // editor's copy, VeritasActa/drafts). It needs no signature, so it is checked beside the rest, like the link.
  const carried = carriedKeyCheck(signedPayload, opts.publicKey);
  // An envelope whose payload names an issuer_id must name the signature's kid (§2.2 of the -04 editor's copy). It is a
  // property of the bytes, so it too is checked beside the rest.
  const issuerCheck = format === 'passport' ? issuerKidCheck(input.payload, input.signature) : null;
  const asCheck = (c) => ({ result: c.result, ...(c.code ? { code: c.code } : {}) });
  const extraChecks = { ...(carried ? { carried_key: asCheck(carried) } : {}), ...(issuerCheck ? { issuer_kid: asCheck(issuerCheck) } : {}) };
  // Each check's detail, by check name, kept on the result as a property JSON output never shows; cli.js reads it.
  const checkDetails = { ...(carried?.detail ? { carried_key: carried.detail } : {}), ...(issuerCheck?.detail ? { issuer_kid: issuerCheck.detail } : {}) };
  const decidedDetail = (combined) => (checkDetails[combined.check] ? { detail: checkDetails[combined.check] } : {});
  // Notes on an envelope's payload (§2.2 and §3 of the -04 editor's copy), reported and never counted in the outcome.
  const notes = format === 'passport' ? envelopePayloadNotes(input.payload, input.signature) : [];
  const unchecked = notCheckedMembers(input, signedPayload);
  const noteFields = { ...(notes.length ? { payloadNotes: notes } : {}), ...(unchecked.length ? { notChecked: unchecked } : {}) };
  // An outcome reached before the signature could be checked, with the link's syntax beside it.
  const early = (signature, fields, signingInput = { result: 'pass' }) => {
    const checks = { signing_input: signingInput, signature, ...extraChecks, chain_link: linkCheck };
    const combined = combineChecks(checks);
    const details = { ...checkDetails, ...(typeof fields.detail === 'string' ? { signature: fields.detail } : {}) };
    return withCheckDetails({
      valid: false, error: combined.error, outcome: combined.outcome, checks, format, kid, issuer, algorithm, ...fields,
      ...decidedDetail(combined),
      chainLink: chainLink.form, ...(chainLink.warning ? { warning: chainLink.warning } : {}), ...noteFields,
    }, details);
  };

  // Draft §6.6: the object canonicalized never carries a signature member, not even as null or the empty string. A
  // signature over such bytes can still verify, so the receipt is refused before the signature is checked.
  if (signedPayload && typeof signedPayload === 'object' && Object.hasOwn(signedPayload, 'signature')) {
    return early({ result: 'not_run' }, { type: signedPayload.type }, { result: 'fail', code: 'signature_in_signing_input' });
  }

  // Algorithm agility: detect hybrid post-quantum variants early.
  if (typeof algorithm === 'string' && algorithm.toLowerCase().includes('ml-dsa')) {
    return early(signatureCheck('unsupported_algorithm'), { type: input.type || input.payload?.type });
  }

  // Key resolution with embedded-key rejection. A key given by the caller is labelled with where it came from:
  // --key ('provided'), --jwks ('jwks') or a bundle trusted with --trust-bundle-keys ('bundle').
  let publicKey = opts.publicKey;
  let keySource = publicKey ? (opts.keySource || 'provided') : null;

  if (!publicKey) {
    const payload = input.payload || input;
    // A key can be carried inside the payload or, in the v2 and flat shapes, beside it at the top level. Either way it
    // is inside the signed bytes, so it is found and refused the same way in every shape (draft §9.5).
    const carriers = [input.payload && typeof input.payload === 'object' ? input.payload : null, input].filter(Boolean);
    const carried = (f) => carriers.map((c) => c[f]).find((v) => typeof v === 'string' || (v && typeof v === 'object'));
    const embeddedFields = EMBEDDED_KEY_FIELDS.filter((f) => carried(f) !== undefined);

    if (embeddedFields.length > 0) {
      if (opts.allowEmbeddedKey) {
        // Deprecated path; extract the first embedded key form we recognize.
        const pk = carried('public_key');
        const vk = carried('verification_key');
        const jwk = carried('verification_jwk');
        if (typeof pk === 'string' && pk.length === 64) {
          publicKey = pk;
          keySource = 'embedded-deprecated';
        } else if (typeof vk === 'string' && vk.length === 64) {
          publicKey = vk;
          keySource = 'embedded-deprecated';
        } else if (jwk?.x) {
          // base64url(raw) -> hex
          const raw = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
          publicKey = raw.toString('hex');
          keySource = 'embedded-deprecated';
        }
      } else {
        return early(signatureCheck('embedded_key_rejected'), { type: payload.type });
      }
    }
  }

  if (!publicKey) {
    return early(signatureCheck('no_public_key'), { type: input.type || input.payload?.type });
  }

  // Verify the actual wire preimage directly. The older artifacts dependency
  // rebuilds objects and does not preserve JCS order for numeric-looking keys.
  let result;
  try {
    if (!signature) result = { valid: false, error: 'missing_signature' };
    else if (!['ed25519', 'eddsa'].includes(String(algorithm).toLowerCase())) result = { valid: false, error: 'unsupported_algorithm' };
    else {
      const encoded = canonicalize(signedPayload);
      const valid = ed25519.verify(hexToBytes(signature), utf8ToBytes(encoded), hexToBytes(publicKey));
      result = { valid, hash: canonicalHash(signedPayload), canonicalization: 'jcs', ...(valid ? {} : {error: 'invalid_signature'}) };
      // Diagnose a historical signature, but never accept a member the old
      // serializer ignored. Compatibility is deliberate and always labelled.
      const hasProto = (v) => v && typeof v === 'object' && (Object.hasOwn(v, '__proto__') || Object.values(v).some(hasProto));
      if (!valid && !hasProto(signedPayload)) {
        const old = legacyCanonicalize(signedPayload);
        if (old !== encoded && ed25519.verify(hexToBytes(signature), utf8ToBytes(old), hexToBytes(publicKey))) {
          const allow = opts.allowLegacyCanonicalization === true;
          result = {valid:allow, canonicalization:'legacy-numeric-key-order', legacySignatureValid:true,
            error:allow?undefined:'legacy_non_jcs_signature', warning:'Historical non-JCS key order; this is not RFC 8785 conformance.'};
        }
      }
    }
  } catch (e) {
    return early(signatureCheck('malformed_encoding'), { detail: e.message });
  }

  const payload = input.payload || input;
  const payloadFields = collectPayloadFields(payload);

  // Connector-action profile: the grant a platform presented with the call,
  // checked as a whole and, given a platform key from outside the receipt,
  // re-verified rather than taken on the gate's word.
  const connectorAction = checkConnectorAction(payload, { platformKeys: opts.platformKeys });

  // Evidence grade: a Legate governed receipt carries an honest grade and its
  // limitations. Surface them so a valid signature is never mistaken for proof
  // that the underlying action actually happened.
  const evidenceBlock = payload.evidence || payload.result?.governance?.evidence || null;
  const evidenceGrade = evidenceBlock && typeof evidenceBlock.grade === 'string' ? evidenceBlock.grade : undefined;
  const evidenceLimitations = evidenceBlock && Array.isArray(evidenceBlock.limitations) ? evidenceBlock.limitations : undefined;
  const entitlementVerifiedByRuntime = Boolean(evidenceBlock?.claims?.entitlement_verified_by_runtime);
  const entitlementAttested = entitlementVerifiedByRuntime
    || Boolean(evidenceBlock?.claims?.entitlement_attested);

  // Normalize upstream error codes to our canonical registry.
  let normalizedError;
  if (!result.valid) {
    const upstream = (result.error || '').toLowerCase();
    if (['legacy_non_jcs_signature', 'unsupported_algorithm'].includes(upstream)) normalizedError = upstream;
    else
    if (upstream === 'verification_error' || upstream === 'sig_invalid' || upstream.includes('signature')) {
      normalizedError = 'invalid_signature';
    } else if (upstream.includes('missing')) {
      normalizedError = 'missing_signature';
    } else {
      normalizedError = 'invalid_signature'; // default for any verification failure
    }
  }

  // The checks combine as -04 §5.3 has them (combineChecks): the link's syntax, a carried key and the issuer count
  // whatever the signature's result, and the first failure in CHECK_ORDER is the one reported, so a tampered receipt still reports
  // invalid_signature. The connector-action profile is checked once the receipt's own checks pass.
  const checks = {
    signing_input: { result: 'pass' },
    signature: result.valid ? { result: 'pass' } : signatureCheck(normalizedError),
    ...extraChecks,
    chain_link: linkCheck,
  };
  if (connectorAction) {
    checks.connector = !combineChecks(checks).valid ? { result: 'not_run' }
      : connectorAction.valid ? { result: 'pass' }
        : signatureCheck(connectorAction.platform_signature === 'invalid' ? 'connector_context_signature_invalid' : 'connector_schema_invalid');
  }
  const combined = combineChecks(checks);
  if (!combined.valid) normalizedError = combined.error;

  return withCheckDetails({
    valid: combined.valid,
    outcome: combined.outcome,
    checks,
    error: normalizedError,
    ...decidedDetail(combined),
    ...noteFields,
    connectorAction,
    format,
    type: payload.type || input.type,
    kid,
    issuer,
    keySource,
    publicKey,
    algorithm,
    payloadFields,
    evidenceGrade,
    evidenceLimitations,
    entitlementAttested,
    entitlementVerifiedByRuntime,
    hash: result.hash,
    canonicalization: result.canonicalization,
    legacySignatureValid: result.legacySignatureValid,
    chainLink: chainLink.form,
    warning: [result.warning, chainLink.warning, format === 'legacy-browser-1.0'
      ? 'Historical website format: public_key is outside the signed payload. Not draft-03 conformance.' : null].filter(Boolean).join(' ') || undefined,
  }, checkDetails);
}

/**
 * What a receipt carries that this verifier does not check: envelope cosignatures, and an authorization's
 * delegation_chain (AIP-0006). Reported so a valid result is never read as covering them; they never change the
 * outcome. Before, the output said nothing of either, though the 0.5.3 changelog said delegation chains were walked.
 *
 * @param {Object} input the receipt
 * @param {Object} signedPayload the object the signature covers
 * @returns {string[]}
 */
export function notCheckedMembers(input, signedPayload) {
  const notes = [];
  const cosignatures = input && Array.isArray(input.cosignatures) ? input.cosignatures : [];
  if (cosignatures.length > 0) notes.push(`cosignatures: ${cosignatures.length} present, not checked; only the primary signature was verified.`);
  const chain = signedPayload && typeof signedPayload === 'object' ? signedPayload.authorization?.delegation_chain : undefined;
  if (chain !== undefined && chain !== null) notes.push(`authorization.delegation_chain: ${Array.isArray(chain) ? `${chain.length} delegation(s) named` : 'present'}, not checked; nothing here establishes who authorized the action.`);
  return notes;
}

/** Attach each check's detail to a result as a property that JSON output and object spreads leave out. */
function withCheckDetails(result, details) {
  Object.defineProperty(result, 'checkDetails', { value: details, enumerable: false });
  return result;
}

/**
 * Collect the subset of payload fields the verifier surfaces in output.
 * This is a read-only projection; the verifier does not interpret these
 * fields (they are spec-level metadata).
 *
 * Fields harvested (all optional, per draft-03):
 *   disclosure_mode, holder_binding, annex_hash, attestation_mode,
 *   anchor_uri, decision, nullifier, scope, compliance_credit_ref,
 *   transport_hint, verifier_salt_kid, policy_id, policy_hash,
 *   skill_version_hash, delegation_chain_root
 *
 * @param {Object} payload
 * @returns {Object}
 */
function collectPayloadFields(payload) {
  const fields = {};
  const keys = [
    'decision', 'policy_id', 'policy_hash',
    'disclosure_mode', 'holder_binding', 'annex_hash', 'attestation_mode',
    'anchor_uri', 'nullifier', 'scope', 'compliance_credit_ref',
    'transport_hint', 'verifier_salt_kid',
    'skill_version_hash', 'parent_skill_version_hash', 'delegation_chain_root',
    'tool_name', 'agent_id', 'session_id', 'sequence', 'spec',
    'previousReceiptHash',
  ];
  for (const k of keys) {
    if (payload[k] !== undefined && payload[k] !== null) fields[k] = payload[k];
  }
  return fields;
}

/**
 * Verify an audit bundle: several receipts (and anchors), and a verification block whose signing_keys name keys for
 * them.
 *
 * The keys in verification.signing_keys arrive in the file being verified, so they are not a trust anchor: anyone who
 * can write a bundle can name a key there for any receipts (§9.5 of the -04 editor's copy, VeritasActa/drafts). Each
 * receipt is checked with the key the caller gives, and without one it is undecidable (no_public_key): --key
 * (publicKey) for every receipt, or --jwks (keyResolver), whose key set gives each receipt the key its own kid names,
 * with that key's validity window applied to the receipt's signed issued_at, as for a single file. A kid the set lacks
 * leaves that receipt undecidable (jwks_fetch_failed). trustBundleKeys (--trust-bundle-keys) opts in to the bundle's
 * own keys, used only when neither is given: each receipt is then checked with the key its kid names there, or the
 * bundle's first key, and reported with keySource 'bundle'. Before 0.10.27 those keys were used by default and
 * reported as 'provided', so a bundle carrying its own key verified, exit 0, for any receipts; and --jwks gave every
 * receipt the key set's first Ed25519 key, whatever its kid.
 *
 * The bundle's outcome combines its receipts' as -04 §5.3 combines checks: invalid if any receipt is invalid, else
 * undecidable if any receipt could not be checked, else valid. `error` is the code of the first receipt with that
 * outcome; `failed` counts invalid receipts and `undecidable` the ones that could not be checked.
 *
 * @param {Object} bundle
 * @param {VerifyReceiptOptions} [opts]
 * @returns {Promise<Object>}
 */
export async function verifyBundle(bundle, opts = {}) {
  const results = {
    valid: true,
    total: 0,
    passed: 0,
    failed: 0,
    undecidable: 0,
    errors: [],
    receipts: [],
  };

  if (!Array.isArray(bundle.receipts)) {
    return { valid: false, error: 'unknown_format', detail: 'bundle missing receipts array' };
  }

  // A key set from --jwks, read once by the caller: each receipt's key is the one its kid names.
  const resolver = !opts.publicKey && typeof opts.keyResolver === 'function' ? opts.keyResolver : null;
  // The bundle's own keys (JWK -> hex), read only when the caller opts in to them and gives no key of its own.
  const trustBundleKeys = opts.trustBundleKeys === true && !opts.publicKey && !resolver;
  const keyMap = new Map();
  if (trustBundleKeys && Array.isArray(bundle.verification?.signing_keys)) {
    for (const jwk of bundle.verification.signing_keys) {
      if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
        const raw = base64Bytes(jwk.x);
        if (!raw) continue;
        const hex = bytesToHex(raw);
        if (jwk.kid) keyMap.set(jwk.kid, hex);
        if (!keyMap.has('default')) keyMap.set('default', hex);
      }
    }
  }

  const { detectFormat } = await import('../detect.js');
  const check = async (item, label) => {
    results.total++;
    let key = opts.publicKey;
    let keySource = opts.keySource;
    let keyWindow = null;
    let jwksError = null;
    if (resolver) {
      const resolved = resolver(item?.kid || item?.signature?.kid);
      if (resolved.key) {
        key = resolved.key;
        keySource = 'jwks';
        keyWindow = resolved.window || null;
      } else {
        jwksError = resolved.error || 'the key set gives no key for this receipt';
      }
    } else if (!key && trustBundleKeys) {
      key = keyMap.get(item?.kid || item?.signature?.kid) || keyMap.get('default');
      keySource = key ? 'bundle' : undefined;
    }
    const detected = detectFormat(item);
    const r = await verifyReceipt(item, detected.mode, { ...opts, publicKey: key, keySource, ...(jwksError ? { allowEmbeddedKey: false } : {}) });
    if (resolver) {
      // As for a single file: the key the set gave, or the reason it gave none, and that key's window (-04 §5.5).
      const checks = { ...(r.checks || {}) };
      if (jwksError) checks.signature = { result: 'undecidable', code: 'jwks_fetch_failed' };
      const kw = checkKeyWindow({ window: keyWindow, issuedAt: receiptIssuedAt(item), keySource: jwksError ? null : keySource, require: opts.requireKeyWindow });
      checks.key_window = keyWindowCheck(kw);
      const combined = combineChecks(checks);
      r.checks = checks;
      r.keyStatus = kw.report;
      r.valid = combined.valid;
      r.outcome = combined.outcome;
      r.error = combined.error;
      if (jwksError && combined.check === 'signature') r.detail = jwksError;
      else if (combined.check === 'key_window') r.detail = kw.detail;
    }
    results.receipts.push(r);
    if (r.valid) {
      results.passed++;
    } else {
      if (r.outcome === 'invalid') results.failed++;
      else results.undecidable++;
      results.errors.push(`${label}: ${r.error}${jwksError && r.error === 'jwks_fetch_failed' ? ` (${jwksError})` : ''}`);
    }
  };

  for (const receipt of bundle.receipts) await check(receipt, `Receipt ${results.total + 1}`);
  // Verify anchors if present.
  if (Array.isArray(bundle.anchors)) {
    for (const anchor of bundle.anchors) await check(anchor, 'Anchor');
  }

  results.outcome = results.failed > 0 ? 'invalid' : results.undecidable > 0 ? 'undecidable' : 'valid';
  results.valid = results.outcome === 'valid';
  const deciding = results.receipts.find((r) => !r.valid && r.outcome === results.outcome);
  if (deciding) results.error = deciding.error;
  results.keySource = opts.publicKey ? (opts.keySource || 'provided') : resolver ? 'jwks' : trustBundleKeys ? 'bundle' : null;
  if (!opts.publicKey && !resolver && !trustBundleKeys && results.undecidable > 0) {
    results.detail = 'No key was given. The keys in verification.signing_keys arrive in the file being verified, so they are not a trust anchor. Give the issuer\'s key with --key or --jwks, or pass --trust-bundle-keys to check the receipts with the keys the bundle carries.';
  }
  if (trustBundleKeys) {
    results.warning = 'Keys taken from the bundle itself (--trust-bundle-keys): a valid result shows that the receipts match keys carried in the same file, not that those keys are the issuer\'s.';
  }
  return results;
}
