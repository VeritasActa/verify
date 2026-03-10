/**
 * @veritasacta/verify — storage.js
 *
 * Abstract storage interface and counter key builder for BRASS verifiers.
 * Implementations must provide atomic or best-effort spend enforcement.
 *
 * Two reference implementations are provided:
 *   - MemoryStore: In-process (testing, single-instance deployments)
 *   - KVStore: Cloudflare KV (eventually consistent, free tier)
 *
 * For strongly consistent deployments, use Cloudflare Durable Objects
 * or any backend that provides compare-and-swap (CAS) semantics.
 *
 * @module @veritasacta/verify/storage
 * @license FSL-1.1-MIT
 */

/**
 * Abstract counter store interface.
 *
 * Verifiers call spend() for each redeemed token. Implementations must:
 *   1. Check idempotency key (reject replays)
 *   2. Check counter against threshold (enforce rate limit)
 *   3. Atomically insert nullifier + increment counter
 *   4. Return remaining quota
 *
 * @abstract
 */
export class BrassCounterStore {
  /**
   * Attempt to count a token redemption.
   *
   * @param {object} params
   * @param {string} params.counterKey - Composite key from buildCounterKey()
   * @param {string} params.idempotencyKey - IK from deriveIdempotencyKey()
   * @param {number} params.limit - Per-scope threshold (τ)
   * @param {number} params.ttlSeconds - TTL for counter/IK storage (= window duration)
   * @returns {Promise<SpendResult>}
   *
   * @typedef {object} SpendResult
   * @property {boolean} ok - True if accepted, false if denied
   * @property {number} remaining - Remaining quota in this window
   * @property {boolean} [idempotent] - True if this is a replayed request
   * @property {string} [error] - Error code if denied ('rate_limited' | 'replay')
   */
  async spend(params) {
    throw new Error('spend() must be implemented by subclass');
  }

  /**
   * Grace guard: check if a grace-bridge nullifier has been seen.
   *
   * @param {object} params
   * @param {string} params.graceKey - Grace nullifier (base64url)
   * @param {number} params.ttlSeconds - Grace cache TTL
   * @returns {Promise<{hit: boolean, response?: object}>}
   */
  async guardGrace({ graceKey, ttlSeconds }) {
    return { hit: false }; // Safe default: no caching
  }

  /**
   * Cache a response for the grace guard.
   *
   * @param {object} params
   * @param {string} params.graceKey - Grace nullifier (base64url)
   * @param {number} params.ttlSeconds - Grace cache TTL
   * @param {object} params.response - Response to cache
   */
  async cacheGraceResponse({ graceKey, ttlSeconds, response }) {
    // Default: no-op
  }
}
