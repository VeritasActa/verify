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
import { windowOf } from './key-window.js';

/**
 * @typedef {Object} JwksResolveResult
 * @property {string|null} key  hex-encoded raw key, or null on failure
 * @property {string|null} error
 * @property {string} [kid]
 * @property {{type: 'file'|'url', resolved: string}} [source]
 * @property {{valid_from: string|null, valid_until: string|null}|null} [window]  the key's validity window, when the JWK carries one (§9.2)
 */

/**
 * Decide whether a --jwks argument names a local file or a URL. A Windows path such as C:\keys\acta-keys.json parses
 * as a URL whose scheme is "c:", so a single letter and a colon at the start are read as a drive letter: no URL scheme
 * in use is one letter long. Anything else that does not parse as a URL is a path, and a file: URL is a path too.
 *
 * @param {string} source
 * @returns {{type: 'file', path: string} | {type: 'url', url: URL}}
 */
export function classifyJwksSource(source) {
  if (/^[A-Za-z]:/.test(source)) return { type: 'file', path: source };
  let parsed;
  try {
    parsed = new URL(source);
  } catch {
    return { type: 'file', path: source };
  }
  if (parsed.protocol === 'file:') return { type: 'file', path: fileURLToPath(parsed) };
  return { type: 'url', url: parsed };
}

async function loadJwks(source) {
  const target = classifyJwksSource(source);
  if (target.type === 'file') {
    const resolved = resolve(target.path);
    return {
      jwks: JSON.parse(await readFile(resolved, 'utf8')),
      source: { type: 'file', resolved },
    };
  }

  const parsed = target.url;
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
 * The Ed25519 key a loaded key set gives for kid, or the first Ed25519 key when no kid is given.
 *
 * @returns {JwksResolveResult}
 */
function keyFromSet(jwks, source, kid) {
  try {
    const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];

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
    return { key: bytesToHex(raw), error: null, kid: jwk.kid, source, window: windowOf(jwk) };
  } catch (e) {
    return { key: null, error: `JWKS fetch error: ${e.message}` };
  }
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
  let loaded;
  try {
    loaded = await loadJwks(url);
  } catch (e) {
    return { key: null, error: `JWKS fetch error: ${e.message}` };
  }
  return keyFromSet(loaded.jwks, loaded.source, kid);
}

/**
 * Load a JWKS once, from a URL or a file, and return a resolver that gives the key for each kid, with its validity
 * window, as resolveFromJwks does for one receipt. For --replay-chain, so a file of receipts reads the key set once.
 *
 * @param {string} url
 * @returns {Promise<{ error: string|null, source?: Object, resolve: ((kid?: string) => JwksResolveResult) | null }>}
 */
export async function loadJwksResolver(url) {
  let loaded;
  try {
    loaded = await loadJwks(url);
  } catch (e) {
    return { error: `JWKS fetch error: ${e.message}`, resolve: null };
  }
  return { error: null, source: loaded.source, resolve: (kid) => keyFromSet(loaded.jwks, loaded.source, kid) };
}
