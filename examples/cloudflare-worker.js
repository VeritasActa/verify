/**
 * @veritasacta/verify: Cloudflare Worker example
 *
 * Minimal Cloudflare Worker that verifies BRASS anonymous tokens
 * using KV for storage. Deploy with Wrangler.
 *
 * wrangler.toml:
 *   [[kv_namespaces]]
 *   binding = "BRASS_KV"
 *   id = "your-kv-namespace-id"
 *
 *   [vars]
 *   ISSUER_PUB_KEY = "base64url-encoded-compressed-P256-point"
 *   KEY_ID = "kid-001"
 *   RATE_LIMIT = "100"
 *
 *   # Secrets (set via `wrangler secret put`):
 *   # KV_SECRET - 32-byte base64url for idempotency
 *   # VERIFIER_SECRET - optional per-verifier salt hardening
 *
 * @license MIT
 */

import { verify, b64urlToBytes } from '@veritasacta/verify';
import { KVStore } from '@veritasacta/verify/adapters/kv';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return Response.json({ ok: true });
    }

    // Only verify POST requests to /verify
    if (request.method !== 'POST' || url.pathname !== '/verify') {
      return new Response('Not Found', { status: 404 });
    }

    // Parse redemption message from request body
    let msg;
    try {
      msg = await request.json();
    } catch {
      return Response.json(
        { error: 'invalid_json' },
        { status: 400 }
      );
    }

    // Build request context from CF headers
    const ctx = {
      origin: request.headers.get('Origin') || `https://${url.hostname}`,
    };

    // Configuration from environment
    const config = {
      issuerPubKey: env.ISSUER_PUB_KEY,
      keyId: env.KEY_ID || 'kid-001',
      kvSecret: b64urlToBytes(env.KV_SECRET),
      verifierSecret: env.VERIFIER_SECRET
        ? b64urlToBytes(env.VERIFIER_SECRET)
        : null,
      rateLimit: parseInt(env.RATE_LIMIT || '100', 10),
      windowSec: parseInt(env.WINDOW_SEC || '86400', 10),
      graceSeconds: 60,
    };

    // Storage: Cloudflare KV
    const store = new KVStore(env.BRASS_KV);

    // Verify
    const result = await verify(msg, ctx, config, store);

    if (!result.ok) {
      const status = result.error === 'rate_limited' ? 429 : 403;
      return Response.json(result, { status });
    }

    return Response.json(result, {
      headers: { 'X-Brass-Remaining': String(result.remaining) },
    });
  },
};
