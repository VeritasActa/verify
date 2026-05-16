/**
 * Sidecar daemon: unix socket API for receipt signing.
 *
 * Usage:
 *   veritasacta daemon [--socket /tmp/veritasacta.sock] [--key ~/.veritasacta/attester.json]
 *
 * The daemon listens on a Unix domain socket for HTTP-like POST requests
 * and signs decision receipts on demand. Any agent in the same user
 * context (in any language) can emit receipts by POSTing a JSON body to
 * `/sign`; the socket handles chain linkage and key management in one
 * place, without requiring the agent to embed a signing SDK.
 *
 * Endpoints (HTTP-over-unix-socket):
 *   POST /sign          body: { tool, args, decision, policy_id, metadata }
 *                       returns signed receipt JSON
 *   GET  /pubkey        returns the daemon's signing pubkey (for verifier config)
 *   GET  /stats         returns { total, chain_head, uptime_seconds }
 *   GET  /health        returns "ok"
 *
 * The daemon is intentionally minimal: no auth (unix socket perms are
 * the auth), no persistence beyond receipt files, no clustering. For
 * multi-host deployments use the managed ScopeBlind gateway.
 *
 * @module verify-cli/src/engines/daemon
 * @license Apache-2.0
 */

import { createServer } from 'node:http';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { sign, createPrivateKey, createHash } from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

function loadKey(keyPath) {
  if (!existsSync(keyPath)) {
    throw new Error(`No signing key at ${keyPath}. Run \`veritasacta init\` to create one.`);
  }
  const data = JSON.parse(readFileSync(keyPath, 'utf-8'));
  return {
    kid: data.kid,
    privateKey: createPrivateKey({
      key: Buffer.from(data.privateDer, 'hex'),
      format: 'der',
      type: 'pkcs8',
    }),
    pubHex: data.pubHex,
  };
}

function signPayload(privateKey, payload) {
  const canonical = canonicalize(payload);
  const sig = sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
  return sig.toString('hex');
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}')); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

/**
 * Start the daemon.
 * @param {Object} opts
 * @param {string} [opts.socket]         unix socket path
 * @param {string} [opts.key]            key file path
 * @param {string} [opts.receiptsDir]    where to write signed receipts
 * @returns {Promise<void>}
 */
export async function runDaemon(opts = {}) {
  const socketPath = opts.socket || join('/tmp', `veritasacta-${process.getuid?.() || 'user'}.sock`);
  const keyPath = opts.key || join(homedir(), '.veritasacta-verify', 'attester.json');
  const receiptsDir = opts.receiptsDir || join(process.cwd(), '.veritasacta', 'receipts');

  const key = loadKey(keyPath);
  mkdirSync(receiptsDir, { recursive: true });

  let sequence = 0;
  let previousReceiptHash = null;
  const startedAt = Date.now();

  const server = createServer(async (req, res) => {
    const respond = (status, body, contentType = 'application/json') => {
      res.writeHead(status, { 'content-type': contentType });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };

    try {
      if (req.method === 'GET' && req.url === '/health') return respond(200, 'ok', 'text/plain');
      if (req.method === 'GET' && req.url === '/pubkey') return respond(200, { kid: key.kid, pubkey: key.pubHex });
      if (req.method === 'GET' && req.url === '/stats') {
        return respond(200, {
          total: sequence,
          chain_head: previousReceiptHash,
          uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
          kid: key.kid,
        });
      }

      if (req.method === 'POST' && req.url === '/sign') {
        const body = await readBody(req);
        const tool = body.tool || body.tool_name || 'unknown';
        const args = body.args || body.tool_args || {};
        const decision = body.decision || 'allow';
        const policyId = body.policy_id || 'veritasacta:daemon:default';

        sequence++;
        const argStr = JSON.stringify(args, Object.keys(args).sort ? Object.keys(args).sort() : undefined);
        const toolInputHash = 'sha256:' + createHash('sha256').update(argStr, 'utf-8').digest('hex');

        const payload = {
          type: 'veritasacta:daemon:decision',
          spec: 'draft-farley-acta-signed-receipts-03',
          tool_name: tool,
          tool_input_hash: toolInputHash,
          decision,
          policy_id: policyId,
          issued_at: new Date().toISOString(),
          issuer_id: key.kid,
          sequence,
          previousReceiptHash,
          ...(body.metadata ? { metadata: body.metadata } : {}),
        };

        const sig = signPayload(key.privateKey, payload);
        const receipt = {
          payload,
          signature: { alg: 'EdDSA', kid: key.kid, sig },
        };

        const canonical = canonicalize(payload);
        previousReceiptHash = 'sha256:' + createHash('sha256').update(canonical, 'utf-8').digest('hex');

        const receiptFile = join(receiptsDir, `rcpt_${String(sequence).padStart(6, '0')}.json`);
        writeFileSync(receiptFile, JSON.stringify(receipt, null, 2));

        return respond(200, receipt);
      }

      respond(404, { error: 'not_found' });
    } catch (err) {
      respond(500, { error: 'internal_error', detail: err.message });
    }
  });

  // Clean up an existing socket file
  if (existsSync(socketPath)) {
    try { unlinkSync(socketPath); } catch {}
  }

  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      process.stderr.write(`[veritasacta daemon] listening on ${socketPath} (kid=${key.kid})\n`);
      process.stderr.write(`[veritasacta daemon] receipts → ${receiptsDir}\n`);
      process.stderr.write(`[veritasacta daemon] example: curl --unix-socket ${socketPath} http://_/stats\n`);
    });

    const shutdown = () => {
      server.close(() => {
        try { unlinkSync(socketPath); } catch {}
        resolve();
      });
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });
}
