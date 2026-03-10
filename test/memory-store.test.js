/**
 * @veritasacta/verify: MemoryStore test suite
 *
 * Tests spend counting, idempotency, rate limiting, and grace guard.
 *
 * Run: npx vitest run test/memory-store.test.js
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore } from '../src/adapters/memory-store.js';

describe('MemoryStore', () => {
  let store;

  beforeEach(() => {
    store = new MemoryStore();
  });

  // ─── Basic spend ──────────────────────────────────────────────────────────

  describe('spend', () => {
    it('accepts first request', async () => {
      const result = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:1',
        limit: 10,
        ttlSeconds: 60,
      });
      expect(result.ok).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('decrements remaining on each call', async () => {
      for (let i = 0; i < 5; i++) {
        await store.spend({
          counterKey: 'counter:1',
          idempotencyKey: `ik:${i}`,
          limit: 10,
          ttlSeconds: 60,
        });
      }
      const result = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:5',
        limit: 10,
        ttlSeconds: 60,
      });
      expect(result.ok).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it('rejects when limit reached', async () => {
      // Exhaust the limit
      for (let i = 0; i < 3; i++) {
        await store.spend({
          counterKey: 'counter:1',
          idempotencyKey: `ik:${i}`,
          limit: 3,
          ttlSeconds: 60,
        });
      }
      const result = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:overflow',
        limit: 3,
        ttlSeconds: 60,
      });
      expect(result.ok).toBe(false);
      expect(result.error).toBe('rate_limited');
      expect(result.remaining).toBe(0);
    });

    it('isolates different counter keys', async () => {
      await store.spend({
        counterKey: 'counter:A',
        idempotencyKey: 'ik:A',
        limit: 1,
        ttlSeconds: 60,
      });
      // Different counter key should not be affected
      const result = await store.spend({
        counterKey: 'counter:B',
        idempotencyKey: 'ik:B',
        limit: 1,
        ttlSeconds: 60,
      });
      expect(result.ok).toBe(true);
    });
  });

  // ─── Idempotency ──────────────────────────────────────────────────────────

  describe('idempotency', () => {
    it('returns cached result for duplicate IK', async () => {
      const first = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:same',
        limit: 10,
        ttlSeconds: 60,
      });
      expect(first.ok).toBe(true);
      expect(first.remaining).toBe(9);

      // Same IK — should return cached, NOT decrement counter
      const second = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:same',
        limit: 10,
        ttlSeconds: 60,
      });
      expect(second.ok).toBe(true);
      expect(second.remaining).toBe(9); // Same as first
      expect(second.idempotent).toBe(true);
    });

    it('does not double-count idempotent requests', async () => {
      // Send same IK 5 times
      for (let i = 0; i < 5; i++) {
        await store.spend({
          counterKey: 'counter:1',
          idempotencyKey: 'ik:same',
          limit: 10,
          ttlSeconds: 60,
        });
      }
      // Should still be at 9 remaining (only counted once)
      const result = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:different',
        limit: 10,
        ttlSeconds: 60,
      });
      expect(result.remaining).toBe(8); // 10 - 2 = 8 (one real + one new)
    });
  });

  // ─── Grace guard ──────────────────────────────────────────────────────────

  describe('grace guard', () => {
    it('returns hit: false on first check', async () => {
      const result = await store.guardGrace({ graceKey: 'grace:1', ttlSeconds: 120 });
      expect(result.hit).toBe(false);
    });

    it('returns cached response after cacheGraceResponse', async () => {
      const response = { ok: true, remaining: 42 };
      await store.cacheGraceResponse({
        graceKey: 'grace:1',
        ttlSeconds: 120,
        response,
      });

      const result = await store.guardGrace({ graceKey: 'grace:1', ttlSeconds: 120 });
      expect(result.hit).toBe(true);
      expect(result.response).toEqual(response);
    });

    it('isolates different grace keys', async () => {
      await store.cacheGraceResponse({
        graceKey: 'grace:A',
        ttlSeconds: 120,
        response: { ok: true },
      });

      const result = await store.guardGrace({ graceKey: 'grace:B', ttlSeconds: 120 });
      expect(result.hit).toBe(false);
    });
  });

  // ─── Clear ────────────────────────────────────────────────────────────────

  describe('clear', () => {
    it('resets all state', async () => {
      await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:1',
        limit: 1,
        ttlSeconds: 60,
      });
      await store.cacheGraceResponse({
        graceKey: 'grace:1',
        ttlSeconds: 60,
        response: { ok: true },
      });

      store.clear();

      // Counter should be reset
      const result = await store.spend({
        counterKey: 'counter:1',
        idempotencyKey: 'ik:2',
        limit: 1,
        ttlSeconds: 60,
      });
      expect(result.ok).toBe(true);

      // Grace should be reset
      const grace = await store.guardGrace({ graceKey: 'grace:1', ttlSeconds: 60 });
      expect(grace.hit).toBe(false);
    });
  });
});
