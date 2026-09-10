/**
 * Known-issuer labels.
 *
 * Verifying a signature proves the bytes were signed by a given key, not WHO holds
 * it (the engines say this in their limitations). A known-issuers map turns a raw
 * hex key into a human label in the output ("Signer: Meridian Global Macro Desk")
 * so a reader who has pinned trust to a known desk sees the name, not just hex. It
 * is a display aid layered on top of `--key` pinning, never a trust shortcut: an
 * unlabeled key still verifies, and a labeled key is only as trustworthy as the map
 * the verifier chose to load.
 *
 * @module verify-cli/src/util/known-issuers
 * @license Apache-2.0
 */
import { readFileSync } from 'node:fs';

/**
 * Load and merge issuer label maps (hex public key -> label). A bundled default is
 * overlaid with an optional user file (the user file wins). Keys are normalized to
 * lowercase hex. Unreadable or malformed files are ignored (labels are non-critical).
 *
 * @param {string|undefined} userPath path passed via --known-issuers
 * @param {string|undefined} bundledPath path to the package's known-issuers.json
 * @returns {Record<string,string>} lowercase-hex key -> label
 */
export function loadKnownIssuers(userPath, bundledPath) {
  const merged = {};
  for (const p of [bundledPath, userPath]) {
    if (!p) continue;
    try {
      const obj = JSON.parse(readFileSync(p, 'utf8'));
      if (obj && typeof obj === 'object') {
        for (const [k, v] of Object.entries(obj)) {
          if (k.startsWith('_')) continue; // _comment / _note keys are documentation
          if (typeof v === 'string' && /^[0-9a-fA-F]+$/.test(k)) merged[k.toLowerCase()] = v;
        }
      }
    } catch { /* labels are non-critical; ignore unreadable/malformed files */ }
  }
  return merged;
}

/** Resolve a label for a hex key, or null. Case-insensitive. */
export function labelFor(key, issuers) {
  if (typeof key !== 'string' || !issuers) return null;
  return issuers[key.toLowerCase()] || null;
}
