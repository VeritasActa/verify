/**
 * Key validity windows for signed receipts.
 *
 * draft-farley-acta-signed-receipts-03 §9.2 has issuers publish rotated keys
 * with a valid_from / valid_until window in the JWK metadata, and verifiers
 * check it when available. This module applies that window to a receipt's
 * issued_at and says, in every case, what was established:
 *
 *   inside          the key source carried a window and issued_at falls in it
 *   outside         it carried a window and issued_at falls outside it
 *   no_window       the key source carried no window, so key validity at
 *                   issuance was not established (never reported as valid)
 *   unverifiable    it carried a window that cannot be applied: a bound that
 *                   is not a timestamp (null included), bounds in the wrong
 *                   order, or a receipt with no valid issued_at
 *   not_established the key was given directly (--key), so no key source
 *                   gives it a window, and its validity at issuance is not
 *                   established either
 *   not_run         no key was resolved, so there was no key to have a window
 *
 * The window is [valid_from, valid_until): a receipt issued exactly at
 * valid_until is outside it, the way RFC 7519 §4.1.4 treats `exp` ("on or
 * after which ... MUST NOT be accepted"). A bound the key set leaves out is open
 * on that side; a bound it gives as null is not a timestamp, so the window
 * cannot be applied.
 *
 * Every time is an RFC 3339 date-time with its offset written out: "Z" or
 * ±hh:mm. Date.parse reads a time with no offset in the machine's own time
 * zone, so the same receipt could fall inside a window on one machine and
 * outside it on another; such a time, a date alone or prose cannot be placed
 * on a time line without a guess, and a window that needs one is not applied.
 *
 * issued_at is asserted by the signer, so a window catches a key still in use
 * after an honest rotation, not a compromised key backdated into the window.
 *
 * @module verify-cli/src/util/key-window
 * @license Apache-2.0
 */

/**
 * The window a JWK carries, each bound as the key set wrote it, or null when it carries neither bound. A bound the
 * key set leaves out is left out here too (open on that side); one it writes as null stays null, and cannot be applied.
 *
 * @param {Record<string, unknown>} jwk
 * @returns {{ valid_from?: unknown, valid_until?: unknown } | null}
 */
export function windowOf(jwk) {
  if (!jwk || typeof jwk !== 'object') return null;
  const has = (name) => Object.hasOwn(jwk, name);
  if (!has('valid_from') && !has('valid_until')) return null;
  const window = {};
  if (has('valid_from')) window.valid_from = jwk.valid_from;
  if (has('valid_until')) window.valid_until = jwk.valid_until;
  return window;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
const LOCAL_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Read an RFC 3339 date-time that writes its offset out ("Z" or ±hh:mm), as milliseconds since the epoch, or say why
 * it cannot be read. The calendar fields are checked, so a day that does not exist (31 April, 30 February) or an hour
 * of 24 is refused, not rolled into the next day as Date.parse rolls it.
 *
 * @param {unknown} value
 * @returns {{ ms: number } | { cause: string }}
 */
export function parseTimestamp(value) {
  if (value === null) return { cause: 'is null, not a timestamp' };
  if (typeof value !== 'string') return { cause: `is a ${Array.isArray(value) ? 'list' : typeof value}, not a timestamp` };
  const m = RFC3339.exec(value);
  if (!m) {
    if (LOCAL_DATE_TIME.test(value)) return { cause: 'has no UTC offset ("Z" or ±hh:mm), so its time zone would be a guess' };
    if (DATE_ONLY.test(value)) return { cause: 'is a date without a time and UTC offset' };
    return { cause: 'is not an RFC 3339 date-time with a UTC offset' };
  }
  const [, y, mo, d, h, mi, sec, frac, offset] = m;
  const year = Number(y), month = Number(mo), day = Number(d), hour = Number(h), minute = Number(mi), second = Number(sec);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  // RFC 3339 allows a leap second (:60); it is read as the instant after :59.
  if (!monthDays || day < 1 || day > monthDays || hour > 23 || minute > 59 || second > 60) {
    return { cause: 'is not a date and time that exists' };
  }
  let offsetMinutes = 0;
  if (offset !== 'Z' && offset !== 'z') {
    const oh = Number(offset.slice(1, 3)), om = Number(offset.slice(4, 6));
    if (oh > 23 || om > 59) return { cause: 'has a UTC offset that does not exist' };
    offsetMinutes = (offset[0] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  const base = new Date(0);
  base.setUTCFullYear(year, month - 1, day);
  base.setUTCHours(hour, minute, second, frac ? Math.floor(Number(`0${frac}`) * 1000) : 0);
  return { ms: base.getTime() - offsetMinutes * 60000 };
}

const quoted = (value) => (typeof value === 'string' ? `"${value}"` : JSON.stringify(value));

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

/**
 * Apply a key's validity window to a receipt.
 *
 * @param {Object} args
 * @param {{ valid_from?: unknown, valid_until?: unknown } | null} args.window  from the key source (windowOf)
 * @param {string|null} args.issuedAt   the receipt's issued_at
 * @param {string|null} args.keySource  'jwks', 'provided', ...; null when no key was resolved
 * @param {boolean} [args.require]      --require-key-window: no window is undecidable
 * @returns {{ status: string, error: string|null, detail: string, report: Object }}
 */
export function checkKeyWindow({ window, issuedAt, keySource, require = false }) {
  const report = { source: keySource || null, window: window || null, issued_at: issuedAt || null, applied: false };
  const done = (status, error, detail) => ({ status, error, detail, report: { ...report, result: status, detail } });

  if (!window) {
    if (!keySource) return done('not_run', null, 'No key was resolved, so no validity window applies.');
    if (keySource !== 'jwks') {
      if (require) return done('no_window', 'key_window_missing', 'The key was given directly, so it carries no validity window.');
      return done('not_established', null, 'The key was given directly, so no key source gives it a validity window: its validity at issuance is not established.');
    }
    if (require) return done('no_window', 'key_window_missing', 'The key source carries no valid_from / valid_until window for this key.');
    return done('no_window', null, 'The key source carries no validity window, so the key\'s validity at issuance is not established.');
  }

  const bounds = {};
  for (const name of ['valid_from', 'valid_until']) {
    if (!Object.hasOwn(window, name)) { bounds[name] = null; continue; }
    const parsed = parseTimestamp(window[name]);
    if (parsed.cause) {
      return done('unverifiable', 'key_window_unverifiable', `The key's ${name} ${quoted(window[name])} ${parsed.cause}, so the window cannot be applied.`);
    }
    bounds[name] = parsed.ms;
  }
  const from = bounds.valid_from;
  const until = bounds.valid_until;
  if (from !== null && until !== null && until <= from) {
    return done('unverifiable', 'key_window_unverifiable', 'The key\'s validity window ends before it starts.');
  }
  if (issuedAt === null || issuedAt === undefined || issuedAt === '') {
    return done('unverifiable', 'key_window_unverifiable', 'The receipt has no issued_at, so the key window cannot be applied.');
  }
  const at = parseTimestamp(issuedAt);
  if (at.cause) {
    return done('unverifiable', 'key_window_unverifiable', `The receipt's issued_at ${quoted(issuedAt)} ${at.cause}, so the key window cannot be applied.`);
  }
  report.applied = true;
  if (from !== null && at.ms < from) {
    return done('outside', 'key_outside_validity_window', `issued_at ${issuedAt} is before the key's valid_from ${window.valid_from}.`);
  }
  if (until !== null && at.ms >= until) {
    return done('outside', 'key_outside_validity_window', `issued_at ${issuedAt} is at or after the key's valid_until ${window.valid_until}.`);
  }
  return done('inside', null, `issued_at ${issuedAt} is inside the key's validity window.`);
}

/**
 * A key-window status as one of a verification's checks (combineChecks): inside passes, outside fails, a window that
 * cannot be applied or a required window that is absent is undecidable. Without a window the key's validity at
 * issuance is reported as not established, which is not a failure; without a key the check did not run.
 *
 * @param {{ status: string, error: string|null }} kw  checkKeyWindow's result
 * @returns {{ result: string, code?: string }}
 */
export function keyWindowCheck(kw) {
  if (kw.status === 'inside') return { result: 'pass' };
  if (kw.status === 'outside') return { result: 'fail', code: kw.error };
  if (kw.error) return { result: 'undecidable', code: kw.error };
  return { result: kw.status === 'not_run' ? 'not_run' : 'not_established' };
}

/**
 * One line for the terminal report.
 *
 * @param {{ result?: string, window?: { valid_from: string|null, valid_until: string|null } | null } | undefined} ks
 * @returns {string|null}
 */
export function keyWindowLine(ks) {
  if (!ks || !ks.result) return null;
  const span = ks.window ? `${ks.window.valid_from ?? 'open'} to ${ks.window.valid_until ?? 'open'}` : '';
  switch (ks.result) {
    case 'inside': return `  Key window: applied (${span}); issued_at is inside it.`;
    case 'outside': return `  Key window: applied (${span}); issued_at is OUTSIDE it.`;
    case 'no_window': return '  Key window: none in the key source; key validity at issuance not established.';
    case 'not_established': return '  Key window: none for a key given directly; key validity at issuance not established.';
    case 'unverifiable': return `  Key window: present but could not be applied (${ks.detail || 'see detail'}).`;
    default: return null;
  }
}
