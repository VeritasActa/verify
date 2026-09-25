/**
 * Key validity windows for signed receipts.
 *
 * draft-farley-acta-signed-receipts-03 §9.2 has issuers publish rotated keys
 * with a valid_from / valid_until window in the JWK metadata, and verifiers
 * check it when available. This module applies that window to a receipt's
 * issued_at and says, in every case, what was established:
 *
 *   inside        the key source carried a window and issued_at falls in it
 *   outside       it carried a window and issued_at falls outside it
 *   no_window     the key source carried no window, so key validity at
 *                 issuance was not established (never reported as valid)
 *   unverifiable  it carried a window that cannot be applied: malformed
 *                 bounds, or a receipt with no readable issued_at
 *   not_applicable the key was pinned directly (--key), not from a key source
 *
 * The window is [valid_from, valid_until): a receipt issued exactly at
 * valid_until is outside it, the way RFC 7519 §4.1.4 treats `exp` ("on or
 * after which ... MUST NOT be accepted"). A missing bound is open on that side.
 *
 * issued_at is asserted by the signer, so a window catches a key still in use
 * after an honest rotation, not a compromised key backdated into the window.
 *
 * @module verify-cli/src/util/key-window
 * @license Apache-2.0
 */

/**
 * The window a JWK carries, or null when it carries none.
 *
 * @param {Record<string, unknown>} jwk
 * @returns {{ valid_from: string|null, valid_until: string|null } | null}
 */
export function windowOf(jwk) {
  if (!jwk || typeof jwk !== 'object') return null;
  const from = jwk.valid_from;
  const until = jwk.valid_until;
  if (from === undefined && until === undefined) return null;
  return {
    valid_from: from === undefined || from === null ? null : String(from),
    valid_until: until === undefined || until === null ? null : String(until),
  };
}

/**
 * A receipt's issued_at, whatever its shape: the draft's envelope
 * ({ payload, signature }), the v2 structure (issued_at beside the payload),
 * or the v1 flat artifact (issued_at or timestamp at the top).
 *
 * @param {Record<string, any>} receipt
 * @returns {string|null}
 */
export function receiptIssuedAt(receipt) {
  if (!receipt || typeof receipt !== 'object') return null;
  const candidates = [
    receipt.payload && typeof receipt.payload === 'object' ? receipt.payload.issued_at : undefined,
    receipt.issued_at,
    receipt.payload && typeof receipt.payload === 'object' ? receipt.payload.timestamp : undefined,
    receipt.timestamp,
  ];
  for (const value of candidates) {
    if (typeof value === 'string' && value) return value;
    if (typeof value === 'number' && Number.isFinite(value)) return new Date(value > 1e12 ? value : value * 1000).toISOString();
  }
  return null;
}

const ms = (value) => (value === null ? null : Date.parse(value));

/**
 * Apply a key's validity window to a receipt.
 *
 * @param {Object} args
 * @param {{ valid_from: string|null, valid_until: string|null } | null} args.window  from the key source
 * @param {string|null} args.issuedAt   the receipt's issued_at
 * @param {string|null} args.keySource  'jwks', 'provided', ...
 * @param {boolean} [args.require]      --require-key-window: no window is a failure
 * @returns {{ status: string, error: string|null, detail: string, report: Object }}
 */
export function checkKeyWindow({ window, issuedAt, keySource, require = false }) {
  const report = { source: keySource || null, window: window || null, issued_at: issuedAt || null, applied: false };
  const done = (status, error, detail) => ({ status, error, detail, report: { ...report, result: status, detail } });

  if (!window) {
    if (keySource !== 'jwks') {
      if (require) return done('no_window', 'key_window_missing', 'The key was given directly, so it carries no validity window.');
      return done('not_applicable', null, 'The key was given directly; no validity window applies.');
    }
    if (require) return done('no_window', 'key_window_missing', 'The key source carries no valid_from / valid_until window for this key.');
    return done('no_window', null, 'The key source carries no validity window, so the key\'s validity at issuance is not established.');
  }

  const from = ms(window.valid_from);
  const until = ms(window.valid_until);
  if ((window.valid_from !== null && Number.isNaN(from)) || (window.valid_until !== null && Number.isNaN(until))) {
    return done('unverifiable', 'key_window_unverifiable', 'The key\'s validity window is not a pair of readable timestamps.');
  }
  if (from !== null && until !== null && until <= from) {
    return done('unverifiable', 'key_window_unverifiable', 'The key\'s validity window ends before it starts.');
  }
  const at = issuedAt ? Date.parse(issuedAt) : NaN;
  if (Number.isNaN(at)) {
    return done('unverifiable', 'key_window_unverifiable', 'The receipt has no readable issued_at, so the key window cannot be applied.');
  }
  report.applied = true;
  if (from !== null && at < from) {
    return done('outside', 'key_outside_validity_window', `issued_at ${issuedAt} is before the key's valid_from ${window.valid_from}.`);
  }
  if (until !== null && at >= until) {
    return done('outside', 'key_outside_validity_window', `issued_at ${issuedAt} is at or after the key's valid_until ${window.valid_until}.`);
  }
  return done('inside', null, `issued_at ${issuedAt} is inside the key's validity window.`);
}

/**
 * One line for the terminal report.
 *
 * @param {{ result?: string, window?: { valid_from: string|null, valid_until: string|null } | null } | undefined} ks
 * @returns {string|null}
 */
export function keyWindowLine(ks) {
  if (!ks || !ks.result) return null;
  const span = ks.window ? `${ks.window.valid_from || 'open'} to ${ks.window.valid_until || 'open'}` : '';
  switch (ks.result) {
    case 'inside': return `  Key window: applied (${span}); issued_at is inside it.`;
    case 'outside': return `  Key window: applied (${span}); issued_at is OUTSIDE it.`;
    case 'no_window': return '  Key window: none in the key source; key validity at issuance not established.';
    case 'unverifiable': return `  Key window: present but could not be applied (${ks.detail || 'see detail'}).`;
    default: return null;
  }
}
