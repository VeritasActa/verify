/**
 * @veritasacta/verify — local-first dashboard server.
 *
 * Spins up a tiny HTTP server on 127.0.0.1:<port> that serves the
 * static dashboard bundle (ecosystem/dashboard/) and, optionally, a
 * JSON feed of a receipts directory at /api/receipts.
 *
 * Binds to loopback only. No TLS. No auth. No telemetry. If you run
 * it, receipts stay on your machine.
 *
 * @module verify-cli/src/engines/dashboard
 * @license Apache-2.0
 */

import { createServer } from 'node:http';
import {
  readFileSync, statSync, readdirSync, existsSync,
} from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.mjs':  'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.txt':  'text/plain; charset=utf-8',
};

/**
 * @typedef {Object} DashboardOptions
 * @property {number} [port=3847]
 * @property {string} [bind='127.0.0.1']
 * @property {string} [receiptsDir]
 * @property {string} [root]            Override the static-bundle root.
 */

/**
 * Start the dashboard HTTP server.
 *
 * @param {DashboardOptions} opts
 * @returns {Promise<{url: string, close: () => Promise<void>}>}
 */
export async function startDashboard(opts = {}) {
  const port = opts.port || 3847;
  const bind = opts.bind || '127.0.0.1';
  const root = resolve(
    opts.root ||
    join(__dirname, '..', '..', 'ecosystem', 'dashboard')
  );
  const receiptsDir = opts.receiptsDir ? resolve(opts.receiptsDir) : null;

  if (!existsSync(root)) {
    throw new Error(`dashboard root not found: ${root}`);
  }

  const server = createServer((req, res) => {
    try {
      handleRequest(req, res, { root, receiptsDir });
    } catch (err) {
      res.statusCode = 500;
      res.end(`Internal error: ${err.message}`);
    }
  });

  await new Promise((resolveStart, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(port, bind, () => resolveStart());
  });

  const url = `http://${bind}:${port}/`;
  return {
    url,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

function handleRequest(req, res, ctx) {
  const { root, receiptsDir } = ctx;

  // Loopback-only: reject non-localhost Host headers as a defense in
  // depth against DNS-rebinding attacks that could surface receipts
  // to a third-party origin.
  const host = (req.headers.host || '').split(':')[0];
  if (host && host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]') {
    res.statusCode = 403;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end('Dashboard refuses non-loopback Host header (DNS rebinding defense).');
    return;
  }

  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.statusCode = 400;
    res.end('bad_url');
    return;
  }

  // JSON API: receipts feed
  if (urlPath === '/api/receipts') {
    if (!receiptsDir) {
      res.statusCode = 404;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ error: 'no_receipts_dir_configured' }));
      return;
    }
    try {
      const list = readReceiptsDir(receiptsDir);
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.setHeader('cache-control', 'no-store');
      res.end(JSON.stringify({ receipts: list }));
    } catch (err) {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ error: `cannot_read_receipts:${err.message}` }));
    }
    return;
  }

  // Static files
  const filename = urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, '');
  const fullPath = resolve(join(root, filename));

  // Path-traversal defense: the resolved file MUST live under root.
  if (!fullPath.startsWith(root + '/') && fullPath !== root) {
    res.statusCode = 403;
    res.end('path_traversal_refused');
    return;
  }

  let st;
  try { st = statSync(fullPath); } catch {
    res.statusCode = 404;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end('not_found');
    return;
  }
  if (!st.isFile()) {
    res.statusCode = 404;
    res.end('not_a_file');
    return;
  }
  const mime = MIME[extname(fullPath).toLowerCase()] || 'application/octet-stream';
  res.statusCode = 200;
  res.setHeader('content-type', mime);
  res.setHeader('cache-control', 'no-store');
  res.end(readFileSync(fullPath));
}

function readReceiptsDir(dir) {
  const out = [];
  const entries = readdirSync(dir);
  for (const entry of entries) {
    if (!entry.endsWith('.json')) continue;
    const p = join(dir, entry);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (!st.isFile()) continue;
    try {
      const parsed = JSON.parse(readFileSync(p, 'utf-8'));
      if (parsed && parsed.payload && parsed.signature) out.push(parsed);
    } catch { /* skip */ }
  }
  return out;
}
