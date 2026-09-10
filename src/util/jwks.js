/**
 * JWKS (JSON Web Key Set) resolution utility.
 *
 * Fetches a JWKS from a URL and extracts an Ed25519 public key for
 * a given kid, returning the hex-encoded raw key for use by the
 * receipt verifier.
 *
 * This is the only path in the verifier that may make a network
 * request. It is opt-in: the caller must pass --jwks <url>.
 *
 * References:
 *   - RFC 7517 (JWK)
 *   - RFC 7638 (JWK Thumbprint)
 *   - RFC 8037 (OKP Key Type for Ed25519)
 *
 * @module verify-cli/src/util/jwks
 * @license Apache-2.0
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64urlToBytes, bytesToHex } from './hex.js';

/**
 * @typedef {Object} JwksResolveResult
 * @property {string|null} key  hex-encoded raw key, or null on failure
 * @property {string|null} error
 * @property {string} [kid]
 * @property {{type: 'file'|'url', resolved: string}} [source]
 */

async function loadJwks(source) {
  let parsed;
  try {
    parsed = new URL(source);
  } catch {
    const resolved = resolve(source);
    return {
      jwks: JSON.parse(await readFile(resolved, 'utf8')),
      source: { type: 'file', resolved },
    };
  }

  if (parsed.protocol === 'file:') {
    const resolved = fileURLToPath(parsed);
    return {
      jwks: JSON.parse(await readFile(resolved, 'utf8')),
      source: { type: 'file', resolved },
    };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`Unsupported JWKS URL scheme: ${parsed.protocol}`);
  }

  const response = await fetch(parsed);
  if (!response.ok) throw new Error(`JWKS fetch failed: HTTP ${response.status}`);
  return {
    jwks: await response.json(),
    source: { type: 'url', resolved: parsed.href },
  };
}

/**
 * Fetch a JWKS endpoint and return the Ed25519 public key matching kid.
 * If kid is not supplied, returns the first Ed25519 key found.
 *
 * @param {string} url
 * @param {string} [kid]
 * @returns {Promise<JwksResolveResult>}
 */
export async function resolveFromJwks(url, kid) {
  try {
    const { jwks, source } = await loadJwks(url);
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];

    let jwk;
    if (kid) {
      jwk = keys.find((k) => k.kid === kid);
      if (!jwk) return { key: null, error: `No key with kid "${kid}" in JWKS`, source };
    } else {
      jwk = keys.find((k) => k.kty === 'OKP' && k.crv === 'Ed25519');
      if (!jwk) return { key: null, error: 'No Ed25519 key found in JWKS', source };
    }

    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      return { key: null, error: `Key "${kid}" is not Ed25519 (kty=${jwk.kty}, crv=${jwk.crv})`, source };
    }

    const raw = base64urlToBytes(jwk.x);
    return { key: bytesToHex(raw), error: null, kid: jwk.kid, source };
  } catch (e) {
    return { key: null, error: `JWKS fetch error: ${e.message}` };
  }
}
