/**
 * JWKS (JSON Web Key Set) resolution utility.
 *
 * Resolves a JWKS from HTTP(S), file://, or a bare filesystem path and
 * extracts an Ed25519 public key for a given kid, returning the hex-encoded
 * raw key for use by the receipt verifier.
 *
 * Network resolution is opt-in: only HTTP(S) JWKS locators call fetch.
 * Bare paths and file:// URLs are resolved from local disk for offline CI
 * and test-vector workflows.
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
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { base64urlToBytes, bytesToHex } from './hex.js';

/**
 * @typedef {Object} JwksResolveResult
 * @property {string|null} key hex-encoded raw key, or null on failure
 * @property {string|null} error
 * @property {string} [kid]
 * @property {{type: 'http'|'file', locator: string, resolved?: string}} [source]
 */

/**
 * Resolve a JWKS locator to parsed JSON.
 *
 * @param {string} locator HTTP(S) URL, file:// URL, or filesystem path
 * @returns {Promise<{jwks: Object|null, error: string|null, source?: JwksResolveResult['source']}>}
 */
async function loadJwks(locator) {
  if (typeof locator !== 'string' || locator.trim() === '') {
    return { jwks: null, error: 'JWKS locator is empty' };
  }

  const raw = locator.trim();
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    parsed = null;
  }

  if (parsed?.protocol === 'http:' || parsed?.protocol === 'https:') {
    try {
      const response = await fetch(raw);
      if (!response.ok) {
        return { jwks: null, error: `JWKS fetch failed: HTTP ${response.status}` };
      }
      return {
        jwks: await response.json(),
        error: null,
        source: { type: 'http', locator: raw },
      };
    } catch (e) {
      return { jwks: null, error: `JWKS fetch error: ${e.message}` };
    }
  }

  let path;
  try {
    if (parsed?.protocol === 'file:') {
      path = fileURLToPath(parsed);
    } else if (parsed?.protocol) {
      return { jwks: null, error: `Unsupported JWKS URL scheme: ${parsed.protocol}` };
    } else {
      path = raw;
    }
  } catch (e) {
    return { jwks: null, error: `JWKS file URL parse error: ${e.message}` };
  }

  const resolved = isAbsolute(path) ? path : resolve(process.cwd(), path);
  try {
    const text = await readFile(resolved, 'utf8');
    return {
      jwks: JSON.parse(text),
      error: null,
      source: { type: 'file', locator: raw, resolved },
    };
  } catch (e) {
    return { jwks: null, error: `JWKS file read error (${resolved}): ${e.message}` };
  }
}

/**
 * Resolve a JWKS locator and return the Ed25519 public key matching kid.
 * If kid is not supplied, returns the first Ed25519 key found.
 *
 * @param {string} locator HTTP(S) URL, file:// URL, or filesystem path
 * @param {string} [kid]
 * @returns {Promise<JwksResolveResult>}
 */
export async function resolveFromJwks(locator, kid) {
  const loaded = await loadJwks(locator);
  if (!loaded.jwks) return { key: null, error: loaded.error };

  try {
    const keys = Array.isArray(loaded.jwks.keys) ? loaded.jwks.keys : [];

    let jwk;
    if (kid) {
      jwk = keys.find((k) => k.kid === kid);
      if (!jwk) return { key: null, error: `No key with kid "${kid}" in JWKS`, source: loaded.source };
    } else {
      jwk = keys.find((k) => k.kty === 'OKP' && k.crv === 'Ed25519');
      if (!jwk) return { key: null, error: 'No Ed25519 key found in JWKS', source: loaded.source };
    }

    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      return {
        key: null,
        error: `Key "${kid}" is not Ed25519 (kty=${jwk.kty}, crv=${jwk.crv})`,
        source: loaded.source,
      };
    }

    const raw = base64urlToBytes(jwk.x);
    return { key: bytesToHex(raw), error: null, kid: jwk.kid, source: loaded.source };
  } catch (e) {
    return { key: null, error: `JWKS parse error: ${e.message}`, source: loaded.source };
  }
}
