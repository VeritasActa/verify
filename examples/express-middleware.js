/**
 * @veritasacta/verify: Express middleware example
 *
 * Demonstrates how to integrate BRASS anonymous token verification
 * into a standard Node.js API server. The issuer is never contacted —
 * all verification happens locally using elliptic curve math.
 *
 * Usage:
 *   npm install @veritasacta/verify express
 *   ISSUER_PUB_KEY=<base64url> KV_SECRET=<base64url> node express-middleware.js
 *
 * @license MIT
 */

import express from 'express';
import { verify, b64urlToBytes } from '@veritasacta/verify';
import { MemoryStore } from '@veritasacta/verify/adapters/memory';

// ─── Configuration ───────────────────────────────────────────────────────────

const config = {
  // Issuer's public key Y = k·G (base64url-encoded compressed P-256 point)
  // Get this from your issuer deployment
  issuerPubKey: process.env.ISSUER_PUB_KEY,

  // Key identifier — must match the issuer's KID
  keyId: process.env.KEY_ID || 'kid-001',

  // 32-byte secret for idempotency key derivation (base64url)
  kvSecret: b64urlToBytes(process.env.KV_SECRET),

  // Optional: per-verifier secret for salt hardening (recommended for production)
  // If set, η becomes unpredictable to attackers who don't know this secret
  verifierSecret: process.env.VERIFIER_SECRET
    ? b64urlToBytes(process.env.VERIFIER_SECRET)
    : null,

  // Rate limit: 100 requests per window per scope
  rateLimit: parseInt(process.env.RATE_LIMIT || '100', 10),

  // Window duration: 1 day (86400 seconds)
  windowSec: parseInt(process.env.WINDOW_SEC || '86400', 10),

  // Grace period around window boundaries: 60 seconds
  graceSeconds: 60,
};

// ─── Storage ─────────────────────────────────────────────────────────────────
//
// MemoryStore is for single-process deployments and testing.
// For production, use:
//   - KVStore (Cloudflare Workers KV) — eventually consistent, free
//   - A custom BrassCounterStore backed by Redis, DynamoDB, etc.
//

const store = new MemoryStore();

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * Express middleware that verifies BRASS anonymous tokens.
 *
 * Expects the token in the `X-Brass-Proof` header as a JSON string.
 * Sets `req.brass` with the verification result on success.
 *
 * @param {object} [options]
 * @param {boolean} [options.required=true] - If false, unauthenticated requests pass through
 * @returns {Function} Express middleware
 */
function brassMiddleware(options = {}) {
  const { required = true } = options;

  return async (req, res, next) => {
    const proofHeader = req.headers['x-brass-proof'];

    // No proof provided
    if (!proofHeader) {
      if (!required) return next();
      return res.status(401).json({
        error: 'missing_brass_proof',
        message: 'X-Brass-Proof header required',
      });
    }

    // Parse the redemption message
    let msg;
    try {
      msg = JSON.parse(proofHeader);
    } catch {
      return res.status(400).json({
        error: 'invalid_brass_proof',
        message: 'X-Brass-Proof must be valid JSON',
      });
    }

    // Build request context from the HTTP transport
    const ctx = {
      origin: `https://${req.hostname}`,
      httpMethod: req.method,
      normalizedPath: req.path,
    };

    // Verify the token
    const result = await verify(msg, ctx, config, store);

    if (!result.ok) {
      const status = result.error === 'rate_limited' ? 429 : 403;
      return res.status(status).json({
        error: result.error,
        ...(result.remaining != null && { remaining: result.remaining }),
      });
    }

    // Attach result to request for downstream handlers
    req.brass = {
      remaining: result.remaining,
      idempotent: result.idempotent || false,
    };

    // Expose remaining quota in response header
    res.setHeader('X-Brass-Remaining', String(result.remaining));

    next();
  };
}

// ─── Example API ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Health check (no BRASS required)
app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// Protected endpoint: require valid BRASS token
app.post('/api/comments', brassMiddleware(), (req, res) => {
  const { comment } = req.body;

  // req.brass.remaining tells you how many requests are left in this window
  res.status(201).json({
    id: crypto.randomUUID(),
    comment,
    remaining: req.brass.remaining,
  });
});

// Optional protection: allow unauthenticated but track usage
app.get('/api/articles', brassMiddleware({ required: false }), (req, res) => {
  res.json({
    articles: [{ id: 1, title: 'Hello World' }],
    brass: req.brass ? { remaining: req.brass.remaining } : null,
  });
});

// ─── Start ───────────────────────────────────────────────────────────────────

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`BRASS-protected API listening on port ${port}`);
  console.log(`  Issuer PK: ${config.issuerPubKey?.slice(0, 12)}...`);
  console.log(`  Rate limit: ${config.rateLimit} per ${config.windowSec}s window`);
  console.log(`  Store: MemoryStore (single-process)`);
});

export { brassMiddleware };
