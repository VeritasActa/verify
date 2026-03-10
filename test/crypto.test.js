/**
 * @veritasacta/verify: Crypto primitives test suite
 *
 * Tests deterministic derivation functions, encoding, canonicalization,
 * window management, and grace period detection.
 *
 * Run: npx vitest run test/crypto.test.js
 */

import { describe, it, expect } from 'vitest';
import {
  H2,
  H3,
  toBytes,
  bytesToB64url,
  b64urlToBytes,
  canonicalOrigin,
  currentEpochDays,
  windowId,
  validWindowsWithSkew,
  secondsUntilWindowEnd,
  isInGracePeriod,
  deriveEta,
  deriveNullifierY,
  deriveIdempotencyKey,
  deriveGraceNullifier,
  deriveTlsBinding,
  parsePolicyId,
  buildCounterKey,
} from '../src/crypto.js';

// ─── H3: Domain-separated hashing ──────────────────────────────────────────

describe('H3 — domain-separated hash', () => {
  it('returns 32-byte digest', () => {
    const hash = H3('test');
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it('is deterministic', () => {
    const a = H3('hello', 'world');
    const b = H3('hello', 'world');
    expect(bytesToB64url(a)).toBe(bytesToB64url(b));
  });

  it('produces different outputs for different inputs', () => {
    const a = H3('hello', 'world');
    const b = H3('helloworld');
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('length-prefixing prevents cross-field collisions', () => {
    // H3("ab", "c") ≠ H3("a", "bc") even though concatenation is the same
    const a = H3('ab', 'c');
    const b = H3('a', 'bc');
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('handles Uint8Array inputs', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const hash = H3(bytes);
    expect(hash.length).toBe(32);
  });

  it('handles number inputs', () => {
    const hash = H3(42);
    expect(hash.length).toBe(32);
    // Different numbers produce different hashes
    const hash2 = H3(43);
    expect(bytesToB64url(hash)).not.toBe(bytesToB64url(hash2));
  });

  it('H2 and H3 produce identical output (by design)', () => {
    const a = H2('test', 'input');
    const b = H3('test', 'input');
    expect(bytesToB64url(a)).toBe(bytesToB64url(b));
  });
});

// ─── Base64URL encoding ────────────────────────────────────────────────────

describe('base64url encoding', () => {
  it('round-trips correctly', () => {
    const original = new Uint8Array([0, 1, 2, 255, 254, 253]);
    const encoded = bytesToB64url(original);
    const decoded = b64urlToBytes(encoded);
    expect(decoded).toEqual(original);
  });

  it('produces URL-safe characters', () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const encoded = bytesToB64url(bytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });

  it('rejects null/undefined', () => {
    expect(() => b64urlToBytes(null)).toThrow();
    expect(() => b64urlToBytes(undefined)).toThrow();
  });

  it('handles empty input', () => {
    const bytes = new Uint8Array(0);
    const encoded = bytesToB64url(bytes);
    const decoded = b64urlToBytes(encoded);
    expect(decoded.length).toBe(0);
  });
});

// ─── toBytes helper ────────────────────────────────────────────────────────

describe('toBytes', () => {
  it('passes through Uint8Array unchanged', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(toBytes(bytes)).toBe(bytes); // same reference
  });

  it('converts strings to UTF-8', () => {
    const bytes = toBytes('hello');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(5);
  });

  it('converts numbers to 4-byte big-endian', () => {
    const bytes = toBytes(256);
    expect(bytes.length).toBe(4);
    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0);
    expect(bytes[2]).toBe(1);
    expect(bytes[3]).toBe(0);
  });

  it('throws for invalid types', () => {
    expect(() => toBytes({})).toThrow();
    expect(() => toBytes(true)).toThrow();
  });
});

// ─── Origin canonicalization ──────────────────────────────────────────────

describe('canonicalOrigin', () => {
  it('normalizes HTTPS origins', () => {
    expect(canonicalOrigin('https://Example.COM')).toBe('https://example.com');
  });

  it('elides default port 443', () => {
    expect(canonicalOrigin('https://example.com:443')).toBe('https://example.com');
  });

  it('preserves non-default ports', () => {
    expect(canonicalOrigin('https://example.com:8443')).toBe('https://example.com:8443');
  });

  it('strips trailing dots', () => {
    expect(canonicalOrigin('https://example.com.')).toBe('https://example.com');
  });

  it('rejects HTTP origins', () => {
    expect(() => canonicalOrigin('http://example.com')).toThrow('origin_must_be_https');
  });

  it('rejects origins with path', () => {
    expect(() => canonicalOrigin('https://example.com/path')).toThrow();
  });

  it('rejects origins with query', () => {
    expect(() => canonicalOrigin('https://example.com?q=1')).toThrow();
  });

  it('rejects origins with fragment', () => {
    expect(() => canonicalOrigin('https://example.com#frag')).toThrow();
  });

  it('rejects empty/missing hostname', () => {
    expect(() => canonicalOrigin('')).toThrow();
  });

  it('rejects garbage input', () => {
    expect(() => canonicalOrigin('not-a-url')).toThrow();
  });
});

// ─── Window functions ──────────────────────────────────────────────────────

describe('windowId', () => {
  it('computes day-level windows by default', () => {
    const nowMs = 1741401600000; // 2025-03-08T00:00:00.000Z
    const wid = windowId(nowMs, 86400);
    expect(wid).toBe(Math.floor(nowMs / 86400000));
  });

  it('supports sub-day windows', () => {
    const nowMs = 1741401600000;
    const hourWindow = windowId(nowMs, 3600);
    expect(hourWindow).toBe(Math.floor(nowMs / 3600000));
  });

  it('minute-level windows', () => {
    const nowMs = 1741401660000; // 60s into some minute
    const minuteWindow = windowId(nowMs, 60);
    expect(minuteWindow).toBe(Math.floor(nowMs / 60000));
  });
});

describe('validWindowsWithSkew', () => {
  it('returns one window normally', () => {
    // Middle of a day — not near boundary
    const noon = 86400000 * 20000 + 43200000; // day 20000, noon
    const windows = validWindowsWithSkew(noon, 86400);
    expect(windows).toEqual([Math.floor(noon / 86400000)]);
  });

  it('returns two windows near boundary', () => {
    // 10 seconds into a new day
    const justAfterMidnight = 86400000 * 20000 + 10000;
    const windows = validWindowsWithSkew(justAfterMidnight, 86400);
    expect(windows.length).toBe(2);
    expect(windows[1]).toBe(windows[0] - 1);
  });
});

describe('currentEpochDays', () => {
  it('returns integer day count', () => {
    const days = currentEpochDays(86400000 * 5);
    expect(days).toBe(5);
  });

  it('floors fractional days', () => {
    const days = currentEpochDays(86400000 * 5 + 1000);
    expect(days).toBe(5);
  });
});

// ─── Grace period detection ─────────────────────────────────────────────────

describe('isInGracePeriod', () => {
  const DAY_MS = 86400000;

  it('detects grace period just after midnight (day boundary)', () => {
    const justAfterMidnight = DAY_MS * 100 + 30000; // 30s into day
    expect(isInGracePeriod(justAfterMidnight, 60, 86400)).toBe(true);
  });

  it('detects grace period just before midnight', () => {
    const justBeforeMidnight = DAY_MS * 100 + DAY_MS - 30000; // 30s before midnight
    expect(isInGracePeriod(justBeforeMidnight, 60, 86400)).toBe(true);
  });

  it('not in grace period at midday', () => {
    const midday = DAY_MS * 100 + DAY_MS / 2;
    expect(isInGracePeriod(midday, 60, 86400)).toBe(false);
  });

  it('boundary: exactly at grace limit is NOT in grace (exclusive boundary)', () => {
    // At exactly 60s, should NOT be in grace (grace is [0, 60s))
    const exactly60 = DAY_MS * 100 + 60000;
    expect(isInGracePeriod(exactly60, 60, 86400)).toBe(false);
  });

  it('supports configurable grace period', () => {
    const tenSecondsIn = DAY_MS * 100 + 10000;
    expect(isInGracePeriod(tenSecondsIn, 5, 86400)).toBe(false); // 10s > 5s grace
    expect(isInGracePeriod(tenSecondsIn, 15, 86400)).toBe(true); // 10s < 15s grace
  });

  it('supports sub-day windows', () => {
    // Hourly window (3600s), 20s into the hour
    const hourMs = 3600000;
    const twentySecsIn = hourMs * 500 + 20000;
    expect(isInGracePeriod(twentySecsIn, 30, 3600)).toBe(true); // 20s < 30s grace
    expect(isInGracePeriod(twentySecsIn, 10, 3600)).toBe(false); // 20s > 10s grace
  });
});

// ─── BRASS derivation functions ──────────────────────────────────────────────

describe('deriveEta — salt derivation', () => {
  const issuerPK = 'Ah1234567890abcdefghijklmnopqrstuvwx'; // dummy PK
  const origin = 'https://example.com';
  const epoch = 20000;
  const policy = 'default';
  const window = 20000;

  it('is deterministic', () => {
    const a = deriveEta(issuerPK, origin, epoch, policy, window);
    const b = deriveEta(issuerPK, origin, epoch, policy, window);
    expect(bytesToB64url(a)).toBe(bytesToB64url(b));
  });

  it('changes with different origins', () => {
    const a = deriveEta(issuerPK, 'https://a.com', epoch, policy, window);
    const b = deriveEta(issuerPK, 'https://b.com', epoch, policy, window);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('changes with different windows', () => {
    const a = deriveEta(issuerPK, origin, epoch, policy, 1);
    const b = deriveEta(issuerPK, origin, epoch, policy, 2);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('changes with different policies', () => {
    const a = deriveEta(issuerPK, origin, epoch, 'comments', window);
    const b = deriveEta(issuerPK, origin, epoch, 'search', window);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('changes with verifier secret', () => {
    const secret = new Uint8Array(32);
    crypto.getRandomValues(secret);
    const withoutSecret = deriveEta(issuerPK, origin, epoch, policy, window);
    const withSecret = deriveEta(issuerPK, origin, epoch, policy, window, secret);
    expect(bytesToB64url(withoutSecret)).not.toBe(bytesToB64url(withSecret));
  });

  it('different verifier secrets produce different salts', () => {
    const secret1 = new Uint8Array(32);
    const secret2 = new Uint8Array(32);
    secret1.fill(1);
    secret2.fill(2);
    const a = deriveEta(issuerPK, origin, epoch, policy, window, secret1);
    const b = deriveEta(issuerPK, origin, epoch, policy, window, secret2);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });
});

describe('deriveNullifierY', () => {
  it('is deterministic', () => {
    const eta = H3('test_salt');
    const a = deriveNullifierY('Zprime_b64', 'kid-001', 'policy=default', eta);
    const b = deriveNullifierY('Zprime_b64', 'kid-001', 'policy=default', eta);
    expect(bytesToB64url(a)).toBe(bytesToB64url(b));
  });

  it('changes with different Z-prime', () => {
    const eta = H3('test_salt');
    const a = deriveNullifierY('Zprime_A', 'kid-001', '', eta);
    const b = deriveNullifierY('Zprime_B', 'kid-001', '', eta);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('changes with different salt', () => {
    const eta1 = H3('salt_1');
    const eta2 = H3('salt_2');
    const a = deriveNullifierY('Zprime', 'kid-001', '', eta1);
    const b = deriveNullifierY('Zprime', 'kid-001', '', eta2);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });
});

describe('deriveIdempotencyKey', () => {
  it('is deterministic', () => {
    const secret = new Uint8Array(32);
    secret.fill(42);
    const y = new Uint8Array([1, 2, 3, 4]);
    const nonce = bytesToB64url(new Uint8Array([5, 6, 7, 8]));
    const a = deriveIdempotencyKey(secret, y, nonce);
    const b = deriveIdempotencyKey(secret, y, nonce);
    expect(a).toBe(b);
  });

  it('changes with different secrets', () => {
    const y = new Uint8Array([1, 2, 3]);
    const nonce = bytesToB64url(new Uint8Array([4, 5, 6]));
    const secret1 = new Uint8Array(32).fill(1);
    const secret2 = new Uint8Array(32).fill(2);
    const a = deriveIdempotencyKey(secret1, y, nonce);
    const b = deriveIdempotencyKey(secret2, y, nonce);
    expect(a).not.toBe(b);
  });

  it('changes with different nonces', () => {
    const secret = new Uint8Array(32).fill(42);
    const y = new Uint8Array([1, 2, 3]);
    const a = deriveIdempotencyKey(secret, y, bytesToB64url(new Uint8Array([1])));
    const b = deriveIdempotencyKey(secret, y, bytesToB64url(new Uint8Array([2])));
    expect(a).not.toBe(b);
  });

  it('rejects non-Uint8Array secret', () => {
    expect(() =>
      deriveIdempotencyKey('not-bytes', new Uint8Array([1]), 'AA')
    ).toThrow('kvSecret must be Uint8Array');
  });

  it('rejects non-string nonce', () => {
    expect(() =>
      deriveIdempotencyKey(new Uint8Array(32), new Uint8Array([1]), 123)
    ).toThrow('c_b64 must be base64url string');
  });
});

describe('deriveGraceNullifier', () => {
  it('is deterministic', () => {
    const a = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://a.com', 'default', 'P256_SHA256', 'BRASS_v2.0', '');
    const b = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://a.com', 'default', 'P256_SHA256', 'BRASS_v2.0', '');
    expect(bytesToB64url(a)).toBe(bytesToB64url(b));
  });

  it('differs across origins (tenant isolation)', () => {
    const a = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://a.com', 'default', 'P256_SHA256', 'BRASS_v2.0', '');
    const b = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://b.com', 'default', 'P256_SHA256', 'BRASS_v2.0', '');
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });

  it('differs across cipher suites (domain separation)', () => {
    const a = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://a.com', 'default', 'P256_SHA256', 'BRASS_v2.0', '');
    const b = deriveGraceNullifier('Zp', 'kid', 'pk', 'https://a.com', 'default', 'P384_SHA384', 'BRASS_v2.0', '');
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });
});

// ─── TLS channel binding ────────────────────────────────────────────────────

describe('deriveTlsBinding', () => {
  it('produces domain-separated fallback when no exporter', () => {
    const binding = deriveTlsBinding(null);
    expect(binding.length).toBe(32);
  });

  it('uses exporter bytes when provided', () => {
    const exporter = new Uint8Array(32);
    crypto.getRandomValues(exporter);
    const binding = deriveTlsBinding(exporter);
    expect(binding.length).toBe(32);
  });

  it('exporter binding differs from fallback', () => {
    const exporter = new Uint8Array(32);
    exporter.fill(0xab);
    const withExporter = deriveTlsBinding(exporter);
    const withoutExporter = deriveTlsBinding(null);
    expect(bytesToB64url(withExporter)).not.toBe(bytesToB64url(withoutExporter));
  });

  it('different exporters produce different bindings', () => {
    const exp1 = new Uint8Array(32).fill(1);
    const exp2 = new Uint8Array(32).fill(2);
    const a = deriveTlsBinding(exp1);
    const b = deriveTlsBinding(exp2);
    expect(bytesToB64url(a)).not.toBe(bytesToB64url(b));
  });
});

// ─── Policy parsing ─────────────────────────────────────────────────────────

describe('parsePolicyId', () => {
  it('extracts policy from AADr', () => {
    expect(parsePolicyId('policy=comments')).toBe('comments');
  });

  it('returns "default" when no policy', () => {
    expect(parsePolicyId('')).toBe('default');
    expect(parsePolicyId('other=value')).toBe('default');
  });

  it('handles policy with dashes and underscores', () => {
    expect(parsePolicyId('policy=my-api_v2')).toBe('my-api_v2');
  });
});

// ─── Counter key building ───────────────────────────────────────────────────

describe('buildCounterKey', () => {
  it('builds deterministic key', () => {
    const key = buildCounterKey({
      issuerPk: 'pk123',
      origin: 'https://example.com',
      epoch: 20000,
      policy: 'default',
      window: 20000,
      y: 'nullifier_b64',
    });
    expect(key).toBe('pk123|https://example.com|20000|default|20000|nullifier_b64');
  });

  it('supports namespace for multi-tenant isolation', () => {
    const key = buildCounterKey({
      issuerPk: 'pk123',
      origin: 'https://example.com',
      epoch: 20000,
      policy: 'default',
      window: 20000,
      y: 'nullifier_b64',
      namespace: 'tenant-abc',
    });
    expect(key).toContain('ns:tenant-abc|');
  });

  it('no namespace prefix when unset', () => {
    const key = buildCounterKey({
      issuerPk: 'pk',
      origin: 'https://a.com',
      epoch: 1,
      policy: 'default',
      window: 1,
      y: 'y',
    });
    expect(key).not.toContain('ns:');
  });
});
