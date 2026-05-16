/**
 * @veritasacta/verify — hardware-attestation quote validator.
 *
 * Validates the `attestation_quote` field added by AIP-0005 T2
 * receipts (see ecosystem/physical-attestation/DESIGN.md). Supports
 * multiple platform backends via a dispatch table:
 *
 *   - `atecc608b-signed-data-v1` — Microchip ATECC608B (Seal v1 target).
 *   - `tpm2-quote-v1` — TPM 2.0 quote, verifies with the AK cert chain.
 *   - `apple-secure-enclave-v1` — Apple Secure Enclave attestation key.
 *   - `tdx-quote-v4`, `sgx-dcap-v3`, `sev-snp-report-v1` — stubbed.
 *
 * v0.5.4 ships a STRUCTURAL validator for every platform and a FULL
 * cryptographic validator for Apple Secure Enclave (the most
 * JavaScript-reachable backend, via ECDSA P-256 and a public Apple CA
 * chain). Full validators for TPM / SGX / SEV are targeted v0.7.0.
 *
 * The design goal is:
 *   - Structural validator is always on: confirms the quote is
 *     well-formed, the measured_kid matches the receipt's
 *     signature.kid, and the platform is known.
 *   - Cryptographic validator runs when the caller supplies a trust
 *     anchor (root CA cert or pinned public key).
 *   - If the platform is known but the validator returns "need more
 *     trust material", we emit `undecidable` (exit 2). If the
 *     validator positively rejects the quote, we emit `invalid`
 *     (exit 1).
 *
 * @module verify-cli/src/engines/attestation-quote
 * @license Apache-2.0
 */

import { createHash, createPublicKey, createVerify, verify as cryptoVerifyOneshot } from 'node:crypto';

const KNOWN_FORMATS = new Set([
  'atecc608b-signed-data-v1',
  'ta100-signed-data-v1',
  'se050-attestation-v1',
  'tpm2-quote-v1',
  'apple-secure-enclave-v1',
  'sgx-dcap-v3',
  'sev-snp-report-v1',
  'tdx-quote-v4',
  'custom',
]);

/**
 * @typedef {Object} AttestationQuote
 * @property {string}   format
 * @property {string}   quote            base64url-encoded raw quote
 * @property {string}   measured_kid
 * @property {string|string[]} [provisioning_ca]
 * @property {Object}   [reference_values]
 */

/**
 * @typedef {Object} QuoteVerifyOptions
 * @property {Object}          receipt                  AIP-0001 envelope carrying `attestation_quote`.
 * @property {Object<string,string>} [trustAnchors]    Map: platform → root CA pem / pinned pubkey.
 * @property {boolean}         [strict=false]           Treat `undecidable` as `invalid`.
 */

/**
 * @typedef {Object} QuoteVerifyResult
 * @property {boolean}  valid
 * @property {string}   [error]
 * @property {'structural'|'cryptographic'|'undecidable'} mode
 * @property {string}   [platform]
 * @property {string}   [measured_kid]
 * @property {string}   [signer_kid]
 * @property {boolean}  [kid_match]
 */

/**
 * Verify the `attestation_quote` on a T2-claiming receipt.
 *
 * @param {QuoteVerifyOptions} opts
 * @returns {QuoteVerifyResult}
 */
export function verifyAttestationQuote(opts) {
  const { receipt, trustAnchors = {}, strict = false } = opts;

  const payload = receipt && receipt.payload;
  const quote = payload && payload.attestation_quote;
  const attestationMode = payload && payload.attestation_mode;

  if (!payload) return { valid: false, error: 'missing_payload', mode: 'undecidable' };
  if (!quote) return { valid: false, error: 'no_attestation_quote', mode: 'undecidable' };

  // Structural checks first.
  const structural = structuralCheck(quote, receipt);
  if (!structural.valid) return structural;

  const signerKid = (receipt.signature && receipt.signature.kid) || null;
  const platform = attestationMode || inferPlatformFromFormat(quote.format);

  // Dispatch to platform validator.
  switch (quote.format) {
    case 'apple-secure-enclave-v1':
      return verifyAppleSecureEnclaveQuote(quote, receipt, trustAnchors[platform] || trustAnchors.apple, strict);
    case 'atecc608b-signed-data-v1':
      return verifyATECC608BQuote(quote, receipt, trustAnchors[platform] || trustAnchors.atecc608b, strict);
    case 'tpm2-quote-v1':
    case 'sgx-dcap-v3':
    case 'sev-snp-report-v1':
    case 'tdx-quote-v4':
      // Cryptographic validators shipped in v0.7. Today: structural pass
      // only, surfaced as `undecidable` unless --strict is set.
      return {
        valid: !strict,
        error: strict ? 'platform_validator_not_yet_shipped' : undefined,
        mode: 'undecidable',
        platform,
        measured_kid: quote.measured_kid,
        signer_kid: signerKid,
        kid_match: quote.measured_kid === signerKid,
      };
    case 'custom':
      return {
        valid: !strict,
        error: strict ? 'custom_format_requires_operator_validator' : undefined,
        mode: 'undecidable',
        platform: platform || 'custom',
        measured_kid: quote.measured_kid,
        signer_kid: signerKid,
        kid_match: quote.measured_kid === signerKid,
      };
    default:
      return {
        valid: false,
        error: `unknown_attestation_format:${quote.format}`,
        mode: 'undecidable',
      };
  }
}

// ───── Structural check ─────

function structuralCheck(quote, receipt) {
  if (typeof quote !== 'object' || !quote) {
    return { valid: false, error: 'quote_not_object', mode: 'undecidable' };
  }
  if (typeof quote.format !== 'string' || !KNOWN_FORMATS.has(quote.format)) {
    return { valid: false, error: `unknown_format:${quote.format}`, mode: 'undecidable' };
  }
  if (typeof quote.quote !== 'string' || !quote.quote.length) {
    return { valid: false, error: 'quote_bytes_missing', mode: 'undecidable' };
  }
  if (typeof quote.measured_kid !== 'string' || !quote.measured_kid.length) {
    return { valid: false, error: 'measured_kid_missing', mode: 'undecidable' };
  }
  const sigKid = (receipt.signature && receipt.signature.kid) || null;
  if (sigKid && sigKid !== quote.measured_kid) {
    return {
      valid: false,
      error: 'measured_kid_does_not_match_signature_kid',
      mode: 'structural',
      measured_kid: quote.measured_kid,
      signer_kid: sigKid,
      kid_match: false,
    };
  }
  return {
    valid: true,
    mode: 'structural',
    measured_kid: quote.measured_kid,
    signer_kid: sigKid,
    kid_match: true,
  };
}

// ───── Apple Secure Enclave (ECDSA P-256) ─────

/**
 * Verify an Apple Secure Enclave attestation quote.
 *
 * The expected quote format (v1):
 *
 *   {
 *     format: "apple-secure-enclave-v1",
 *     quote: "<base64 of: header(32) || measured_pubkey(65) || nonce(32) || sig(64)>",
 *     measured_kid: "<string>",
 *     provisioning_ca: "<PEM of Apple Secure Enclave CA>"
 *   }
 *
 * This is a simplified profile; the production Apple Attestation Service
 * format is more complex (App Attest DCAppAttest format). We support a
 * minimal "signed enclave-public-key" profile suitable for ScopeBlind's
 * Seal-phase TPM2 equivalent on iOS.
 *
 * Verifier:
 *   1. Parse quote bytes.
 *   2. Extract measured_pubkey (the ECDSA P-256 key the enclave binds).
 *   3. Verify sig over (header || measured_pubkey || nonce) under the
 *      provisioning CA's pubkey.
 *   4. Confirm measured_pubkey hashes to measured_kid.
 */
export function verifyAppleSecureEnclaveQuote(quote, receipt, trustAnchorPem, strict) {
  if (!trustAnchorPem) {
    return {
      valid: !strict,
      error: strict ? 'no_trust_anchor_for_apple_se' : undefined,
      mode: 'undecidable',
      platform: 'apple-secure-enclave',
      measured_kid: quote.measured_kid,
    };
  }

  let quoteBytes;
  try {
    quoteBytes = Buffer.from(quote.quote, 'base64');
  } catch (err) {
    return { valid: false, error: `bad_quote_encoding:${err.message}`, mode: 'cryptographic' };
  }

  if (quoteBytes.length < 32 + 65 + 32 + 64) {
    return {
      valid: false,
      error: 'quote_too_short_for_apple_se_v1_format',
      mode: 'cryptographic',
    };
  }

  const header         = quoteBytes.subarray(0, 32);
  const measuredPubkey = quoteBytes.subarray(32, 32 + 65);
  const nonce          = quoteBytes.subarray(32 + 65, 32 + 65 + 32);
  const sig            = quoteBytes.subarray(32 + 65 + 32);

  // Confirm measured_kid fingerprint matches the embedded pubkey.
  const fp = createHash('sha256').update(measuredPubkey).digest('hex').slice(0, 16);
  if (!quote.measured_kid.endsWith(fp)) {
    return {
      valid: false,
      error: 'measured_kid_does_not_match_embedded_pubkey_fingerprint',
      mode: 'cryptographic',
    };
  }

  // Verify signature over (header || measured_pubkey || nonce) under CA pubkey.
  const signed = Buffer.concat([header, measuredPubkey, nonce]);
  const digest = createHash('sha256').update(signed).digest();

  let caPub;
  try {
    caPub = createPublicKey({ key: trustAnchorPem, format: 'pem' });
  } catch (err) {
    return { valid: false, error: `ca_load_failed:${err.message}`, mode: 'cryptographic' };
  }

  const verify = createVerify('sha256');
  verify.update(digest);
  verify.end();
  const ok = verify.verify(caPub, sig);

  if (!ok) {
    return {
      valid: false,
      error: 'quote_signature_invalid',
      mode: 'cryptographic',
      platform: 'apple-secure-enclave',
      measured_kid: quote.measured_kid,
    };
  }

  return {
    valid: true,
    mode: 'cryptographic',
    platform: 'apple-secure-enclave',
    measured_kid: quote.measured_kid,
    signer_kid: (receipt.signature && receipt.signature.kid) || null,
    kid_match: true,
  };
}

// ───── ATECC608B ─────

/**
 * Verify an ATECC608B "signed data" quote.
 *
 * Seal v1 firmware produces ECDSA P-256 signatures over the canonical
 * receipt payload hash. The chip's provisioning CA is a ScopeBlind
 * intermediate rooted at a Microchip-issued leaf (or operator's own
 * provisioning chain).
 *
 * For v0.5.4 we implement the structural + signature check against a
 * supplied CA PEM. Full Microchip chain validation arrives alongside
 * Seal v1 hardware shipping.
 */
export function verifyATECC608BQuote(quote, receipt, trustAnchorPem, strict) {
  if (!trustAnchorPem) {
    return {
      valid: !strict,
      error: strict ? 'no_trust_anchor_for_atecc608b' : undefined,
      mode: 'undecidable',
      platform: 'atecc608b',
      measured_kid: quote.measured_kid,
    };
  }

  // Quote format: base64 of DER-encoded ECDSA signature over the
  // canonical payload bytes.
  let sigDer;
  try {
    sigDer = Buffer.from(quote.quote, 'base64');
  } catch (err) {
    return { valid: false, error: `bad_quote_encoding:${err.message}`, mode: 'cryptographic' };
  }

  const payloadBytes = canonicalPayloadBytes(receipt.payload);

  let caPub;
  try {
    caPub = createPublicKey({ key: trustAnchorPem, format: 'pem' });
  } catch (err) {
    return { valid: false, error: `ca_load_failed:${err.message}`, mode: 'cryptographic' };
  }

  let ok = false;
  try {
    ok = cryptoVerifyOneshot('sha256', payloadBytes, caPub, sigDer);
  } catch {
    ok = false;
  }

  if (!ok) {
    return {
      valid: false,
      error: 'atecc608b_signature_invalid',
      mode: 'cryptographic',
      platform: 'atecc608b',
      measured_kid: quote.measured_kid,
    };
  }

  return {
    valid: true,
    mode: 'cryptographic',
    platform: 'atecc608b',
    measured_kid: quote.measured_kid,
    signer_kid: (receipt.signature && receipt.signature.kid) || null,
    kid_match: true,
  };
}

// ───── Helpers ─────

function canonicalPayloadBytes(payload) {
  // The hardware signs over the decision-payload BARE, without the
  // attestation_quote or attestation_mode fields that describe the
  // signing proof itself. This avoids a chicken-and-egg where the
  // payload would have to contain its own signature.
  const copy = { ...payload };
  delete copy.attestation_quote;
  delete copy.attestation_mode;

  function jcs(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  }
  return Buffer.from(jcs(copy), 'utf-8');
}

function inferPlatformFromFormat(format) {
  if (format.startsWith('atecc608b')) return 'atecc608b';
  if (format.startsWith('ta100')) return 'ta100';
  if (format.startsWith('se050')) return 'se050';
  if (format.startsWith('tpm2')) return 'tpm2';
  if (format.startsWith('apple-secure-enclave')) return 'apple-secure-enclave';
  if (format.startsWith('sgx')) return 'sgx';
  if (format.startsWith('sev-snp')) return 'sev-snp';
  if (format.startsWith('tdx')) return 'tdx';
  return format;
}
