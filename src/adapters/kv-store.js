/**
 * @veritasacta/verify — adapters/kv-store.js
 *
 * Cloudflare KV-backed counter store for BRASS verifiers.
 *
 * ⚠️ Eventually consistent — users CAN bypass quotas by hitting different
 * edge locations within the replication window (~60s). Overspend is bounded
 * by (E - 1) * λ * w where E = edge count, λ = per-edge rate, w = replication lag.
 *
 * Suitable for: free tiers, low-stakes rate limiting, shadow/observe mode.
 * For strict enforcement, use Durable Objects or any CAS-capable backend.
 *
 * @module @veritasacta/verify/adapters/kv
 * @license FSL-1.1-MIT
 */

import { BrassCounterStore } from '../storage.js';

export class KVStore extends BrassCounterStore {
  /**
   * @param {KVNamespace} kvNamespace - Cloudflare KV namespace binding
   */
  constructor(kvNamespace) {
    super();
    this.kv = kvNamespace;
  }

  async spend({ counterKey, idempotencyKey, limit, ttlSeconds }) {
    const ikKey = `ik:${idempotencyKey}`;

    // 1. Idempotency check
    const existing = await this.kv.get(ikKey, 'json');
    if (existing) {
      return { ...existing, idempotent: true };
    }

    // 2. Read counter (eventually consistent)
    const data = await this.kv.get(counterKey, 'json');
    const currentValue = data ? parseFloat(data.value || 0) : 0;

    // 3. Threshold check
    if (currentValue >= limit) {
      const deny = { ok: false, error: 'rate_limited', remaining: 0 };
      await this.kv.put(ikKey, JSON.stringify(deny), { expirationTtl: ttlSeconds });
      return deny;
    }

    // 4. Increment counter
    const newValue = currentValue + 1;
    const remaining = Math.max(0, limit - newValue);
    await this.kv.put(counterKey, JSON.stringify({
      value: newValue,
      lastUpdated: Date.now(),
    }), { expirationTtl: ttlSeconds });

    // 5. Cache response
    const accept = { ok: true, remaining };
    await this.kv.put(ikKey, JSON.stringify(accept), { expirationTtl: ttlSeconds });
    return accept;
  }

  async guardGrace({ graceKey, ttlSeconds }) {
    const key = `grace:${graceKey}`;
    const cached = await this.kv.get(key, 'json');
    return cached ? { hit: true, response: cached } : { hit: false };
  }

  async cacheGraceResponse({ graceKey, ttlSeconds, response }) {
    await this.kv.put(`grace:${graceKey}`, JSON.stringify(response), {
      expirationTtl: ttlSeconds,
    });
  }
}
