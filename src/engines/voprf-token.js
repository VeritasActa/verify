/**
 * @veritasacta/verify — VOPRF token engine.
 *
 * Verifies VOPRF tokens in the production BRASS wire format using
 * full Schnorr DLEQ verification for both the issuer proof (\u03c0I) and
 * the client proof (\u03c0C). An envelope either verifies cryptographically
 * or it does not; there is no structural-only partial mode.
 *
 * Wire format (as emitted by the production issuer and client at
 * brass-proof-public/worker/issuer-cloudflare.js and
 * client/src/lib/brass-strict-client.js):
 *
 *   {
 *     algorithm: "voprf-p256-sha256",
 *     kid:       <issuer key identifier (KID)>,
 *     scope:     { origin, epoch, sub?, policy? } OR flat origin/epoch,
 *     issuer_public_key: <base64url compressed P-256 point Y>,
 *     KID, AADr, origin, epoch,
 *     P, M, Z, Zprime:         <base64url compressed P-256 points>,
 *     piI: { c, r },           // issuer DLEQ: log_G(Y) = log_M(Z)
 *     piC: { c, r },           // client DLEQ: knows b s.t. M = b\u00b7P
 *     y, eta, c:               <base64url 32-byte scalars>
 *     d_client, tlsHash:       <base64url SHA-256 digests>
 *   }
 *
 * \u03c0I verification reconstructs A1 = r_I\u00b7G + c_I\u00b7Y, A2 = r_I\u00b7M + c_I\u00b7Z,
 * recomputes the challenge over (G, Y, M, Z, A1, A2), and accepts
 * iff the computed challenge equals c_I. No bind context for \u03c0I.
 *
 * \u03c0C verification reconstructs A1 = r_C\u00b7P + c_C\u00b7M and uses A2=G
 * (single-variable variant), recomputing the challenge over
 * (P, M, G, G, A1, G, bind) where bind = H(BRASS_BIND_v1, y, c, d,
 * AADr, KID, eta, tlsHash).
 *
 * @module verify-cli/src/engines/voprf-token
 * @license Apache-2.0
 */

import {
  G,
  H,
  Y_LABEL,
  b64urlEncode,
  b64urlDecode,
  bytesToBig,
  buildClientBindContext,
  decodePoint,
  deriveNullifier,
  dleqVerifyClient,
  dleqVerifyIssuer,
  sentinelTlsHash,
} from '../util/voprf-crypto.js';

/**
 * @typedef {Object} VoprfVerifyOptions
 * @property {string} [issuerPublicKey]  override issuer public key (base64url)
 * @property {string} [verifierSalt]     unused here; nullifier surfaces from token's eta
 * @property {string} [expectedScope]    require a specific scope origin
 * @property {boolean} [requireClientProof] when true, reject tokens
 *   without a \u03c0C field. Default false (issuer-only verification is
 *   permitted; a token without \u03c0C has only been attested-as-issued,
 *   not attested-as-redeemed).
 */

/**
 * @typedef {Object} VoprfVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {string} format
 * @property {string} algorithm
 * @property {Object} [scope]
 * @property {string} [nullifier]        base64url-encoded y
 * @property {string} [kid]
 * @property {string} [transport_hint]
 * @property {Object} [dleq]             {issuer: bool, client: bool|null}
 */

/**
 * Verify a VOPRF token.
 *
 * @param {Object} input
 * @param {VoprfVerifyOptions} [opts]
 * @returns {Promise<VoprfVerifyResult>}
 */
export async function verifyVoprfToken(input, opts = {}) {
  const algorithm = input.algorithm || 'voprf-p256-sha256';
  if (algorithm !== 'voprf-p256-sha256') {
    return {
      valid: false,
      error: 'unsupported_algorithm',
      format: 'voprf-token',
      algorithm,
    };
  }

  const issuerPubKey = opts.issuerPublicKey || input.issuer_public_key;
  if (!issuerPubKey) {
    return {
      valid: false,
      error: 'missing_issuer_public_key',
      format: 'voprf-token',
      algorithm,
    };
  }

  const required = ['M', 'Z', 'Zprime', 'piI'];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null) {
      return {
        valid: false,
        error: `missing_field:${f}`,
        format: 'voprf-token',
        algorithm,
      };
    }
  }
  if (!input.piI || input.piI.c === undefined || input.piI.r === undefined) {
    return {
      valid: false,
      error: 'malformed_piI',
      format: 'voprf-token',
      algorithm,
    };
  }

  // Decode and validate points.
  let M, Z, Zprime, Y;
  try {
    M = decodePoint(input.M);
    Z = decodePoint(input.Z);
    Zprime = decodePoint(input.Zprime);
    Y = decodePoint(issuerPubKey);
  } catch (err) {
    return {
      valid: false,
      error: err && err.message ? err.message : 'invalid_point',
      format: 'voprf-token',
      algorithm,
    };
  }

  // \u03c0I: issuer proof.
  let piIValid;
  try {
    const cI = bytesToBig(b64urlDecode(input.piI.c));
    const rI = bytesToBig(b64urlDecode(input.piI.r));
    piIValid = dleqVerifyIssuer({ Y, M, Z, c: cI, r: rI });
  } catch {
    piIValid = false;
  }
  if (!piIValid) {
    return {
      valid: false,
      error: 'invalid_piI',
      format: 'voprf-token',
      algorithm,
      kid: input.kid || input.KID,
      dleq: { issuer: false, client: null },
    };
  }

  // \u03c0C: client proof (optional unless requireClientProof is set).
  let piCValid = null;
  if (input.piC) {
    if (!input.P) {
      return {
        valid: false,
        error: 'piC_requires_P',
        format: 'voprf-token',
        algorithm,
      };
    }
    if (input.piC.c === undefined || input.piC.r === undefined) {
      return {
        valid: false,
        error: 'malformed_piC',
        format: 'voprf-token',
        algorithm,
      };
    }
    let P;
    try {
      P = decodePoint(input.P);
    } catch (err) {
      return {
        valid: false,
        error: err && err.message ? err.message : 'invalid_point_P',
        format: 'voprf-token',
        algorithm,
      };
    }

    // Build the Fiat-Shamir bind transcript tag.
    const KID = input.KID || input.kid || '';
    const AADr = input.AADr || '';
    const y = input.y ? b64urlDecode(input.y) : new Uint8Array(0);
    const cNonce = input.c ? b64urlDecode(input.c) : new Uint8Array(0);
    const d = input.d_client
      ? b64urlDecode(input.d_client)
      : (input.d ? b64urlDecode(input.d) : new Uint8Array(0));
    const eta = input.eta ? b64urlDecode(input.eta) : new Uint8Array(0);
    const tlsHash = input.tlsHash ? b64urlDecode(input.tlsHash) : sentinelTlsHash();

    const bindContext = buildClientBindContext({
      y, cNonce, d, AADr, KID, eta, tlsHash,
    });

    try {
      const cC = bytesToBig(b64urlDecode(input.piC.c));
      const rC = bytesToBig(b64urlDecode(input.piC.r));
      piCValid = dleqVerifyClient({ P, M, c: cC, r: rC, bindContext });
    } catch {
      piCValid = false;
    }

    if (!piCValid) {
      return {
        valid: false,
        error: 'invalid_piC',
        format: 'voprf-token',
        algorithm,
        kid: input.kid || input.KID,
        dleq: { issuer: true, client: false },
      };
    }
  } else if (opts.requireClientProof) {
    return {
      valid: false,
      error: 'missing_piC',
      format: 'voprf-token',
      algorithm,
      kid: input.kid || input.KID,
      dleq: { issuer: true, client: null },
    };
  }

  // Derive nullifier.
  const KID = input.KID || input.kid || '';
  const AADr = input.AADr || '';
  const eta = input.eta ? b64urlDecode(input.eta) : new Uint8Array(0);
  const ZprimeBytes = b64urlDecode(input.Zprime);
  const nullifierBytes = deriveNullifier(ZprimeBytes, KID, AADr, eta);
  const nullifier = b64urlEncode(nullifierBytes);

  // Scope and scope check.
  const scope = input.scope || {
    origin: input.origin,
    epoch: input.epoch,
    sub: input.sub,
  };

  if (opts.expectedScope) {
    const actual = scope.origin || JSON.stringify(scope);
    const expected = typeof opts.expectedScope === 'string'
      ? opts.expectedScope
      : JSON.stringify(opts.expectedScope);
    if (actual !== expected) {
      return {
        valid: false,
        error: 'scope_mismatch',
        format: 'voprf-token',
        algorithm,
        scope,
      };
    }
  }

  return {
    valid: true,
    format: 'voprf-token',
    algorithm,
    scope,
    nullifier,
    kid: input.kid || input.KID,
    transport_hint: input.transport_hint || 'direct',
    dleq: {
      issuer: true,
      client: piCValid === null ? null : piCValid,
    },
  };
}
