/**
 * @veritasacta/verify — adapters/memory-store.js
 *
 * In-process counter store for testing and single-instance deployments.
 * NOT suitable for distributed deployments (no cross-process synchronization).
 *
 * Features:
 *   - Automatic TTL expiry via setTimeout
 *   - Idempotency key deduplication
 *   - Grace-bridge caching
 *   - Zero dependencies
 *
 * @module @veritasacta/verify/adapters/memory
 * @license FSL-1.1-MIT
 */

import { BrassCounterStore } from '../storage.js';

export class MemoryStore extends BrassCounterStore {
  constructor() {
    super();
    /** @type {Map<string, {value: number, expiresAt: number}>} */
    this.counters = new Map();
    /** @type {Map<string, {response: object, expiresAt: number}>} */
    this.idempotency = new Map();
    /** @type {Map<string, {response: object, expiresAt: number}>} */
    this.graceCache = new Map();
  }

  async spend({ counterKey, idempotencyKey, limit, ttlSeconds }) {
    const now = Date.now();

    // Purge expired entries (lazy cleanup)
    this._purge(now);

    // 1. Idempotency check
    const cached = this.idempotency.get(idempotencyKey);
    if (cached && cached.expiresAt > now) {
      return { ...cached.response, idempotent: true };
    }

    // 2. Read counter
    const entry = this.counters.get(counterKey);
    const currentValue = (entry && entry.expiresAt > now) ? entry.value : 0;

    // 3. Threshold check
    if (currentValue >= limit) {
      const deny = { ok: false, error: 'rate_limited', remaining: 0 };
      this.idempotency.set(idempotencyKey, {
        response: deny,
        expiresAt: now + ttlSeconds * 1000,
      });
      return deny;
    }

    // 4. Increment counter
    const newValue = currentValue + 1;
    const remaining = Math.max(0, limit - newValue);
    this.counters.set(counterKey, {
      value: newValue,
      expiresAt: now + ttlSeconds * 1000,
    });

    // 5. Cache accept response
    const accept = { ok: true, remaining };
    this.idempotency.set(idempotencyKey, {
      response: accept,
      expiresAt: now + ttlSeconds * 1000,
    });

    return accept;
  }

  async guardGrace({ graceKey, ttlSeconds }) {
    const now = Date.now();
    const cached = this.graceCache.get(graceKey);
    if (cached && cached.expiresAt > now) {
      return { hit: true, response: cached.response };
    }
    return { hit: false };
  }

  async cacheGraceResponse({ graceKey, ttlSeconds, response }) {
    this.graceCache.set(graceKey, {
      response,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  /** Remove expired entries. Called lazily on each spend(). */
  _purge(now) {
    // Only purge if maps are getting large (> 10K entries)
    if (this.counters.size + this.idempotency.size < 10_000) return;
    for (const [k, v] of this.counters) {
      if (v.expiresAt <= now) this.counters.delete(k);
    }
    for (const [k, v] of this.idempotency) {
      if (v.expiresAt <= now) this.idempotency.delete(k);
    }
    for (const [k, v] of this.graceCache) {
      if (v.expiresAt <= now) this.graceCache.delete(k);
    }
  }

  /** Clear all state (useful in tests). */
  clear() {
    this.counters.clear();
    this.idempotency.clear();
    this.graceCache.clear();
  }
}
