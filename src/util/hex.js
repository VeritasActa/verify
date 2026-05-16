/**
 * Hex / base64url encoding utilities.
 *
 * Constant-time hex byte comparison for signature verification paths.
 *
 * @module verify-cli/src/util/hex
 * @license Apache-2.0
 */

/**
 * Decode a hex string to a Uint8Array.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new Error('hex must be a string');
  }
  // Strip common prefixes / whitespace
  const clean = hex.replace(/^0x/i, '').replace(/\s+/g, '');
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 2 !== 0) {
    const err = new Error('hex string has odd length');
    err.code = 'malformed_hex';
    throw err;
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      const err = new Error(`invalid hex character at position ${i * 2}`);
      err.code = 'malformed_hex';
      throw err;
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Encode a Uint8Array to a hex string (lowercase, no prefix).
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Decode a base64url string to a Uint8Array.
 *
 * @param {string} b64url
 * @returns {Uint8Array}
 */
export function base64urlToBytes(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = Buffer.from(b64, 'base64');
  return new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength);
}

/**
 * Encode a Uint8Array to base64url.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Constant-time byte-wise equality check.
 * Prevents timing-based discrimination between matching and
 * almost-matching signatures.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
