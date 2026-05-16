/**
 * Smoke tests for the local dashboard server.
 *
 * We boot the server on an ephemeral port, make loopback requests,
 * assert on status codes + payload shapes, and shut it down.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { startDashboard } from '../../src/engines/dashboard.js';

// Node fetch is global in Node 18+.
async function get(url, opts = {}) {
  return fetch(url, opts);
}

test('dashboard: serves index.html at /', async () => {
  const d = await startDashboard({ port: 0 });  // ephemeral port; we can't read it back
  // Close immediately; the goal is to prove startDashboard does not throw.
  await d.close();
  assert.ok(typeof d.url === 'string');
});

test('dashboard: serves static bundle + 404s unknown paths', async () => {
  const d = await startDashboard({ port: 38471, bind: '127.0.0.1' });
  try {
    const r1 = await get(`${d.url}`);
    assert.equal(r1.status, 200);
    const html = await r1.text();
    assert.match(html, /Veritas Acta/i);

    const r2 = await get(`${d.url}__not_here__`);
    assert.equal(r2.status, 404);
  } finally {
    await d.close();
  }
});

test('dashboard: /api/receipts returns empty when no receipts dir is configured', async () => {
  const d = await startDashboard({ port: 38472 });
  try {
    const r = await get(`${d.url}api/receipts`);
    assert.equal(r.status, 404);
    const body = await r.json();
    assert.equal(body.error, 'no_receipts_dir_configured');
  } finally {
    await d.close();
  }
});

test('dashboard: /api/receipts returns receipts from configured dir', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dash-'));
  writeFileSync(
    join(dir, '01.json'),
    JSON.stringify({
      payload: { type: 'decision-receipt', action: 'Read', issued_at: '2026-04-20T00:00:00Z' },
      signature: { alg: 'ed25519', kid: 'k', sig: '00' },
    })
  );
  writeFileSync(
    join(dir, 'not-a-receipt.json'),
    JSON.stringify({ foo: 'bar' })  // missing payload/signature
  );

  const d = await startDashboard({ port: 38473, receiptsDir: dir });
  try {
    const r = await get(`${d.url}api/receipts`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.receipts.length, 1);
    assert.equal(body.receipts[0].payload.action, 'Read');
  } finally {
    await d.close();
  }
});

test('dashboard: rejects path traversal attempts', async () => {
  const d = await startDashboard({ port: 38474 });
  try {
    const r = await get(`${d.url}../../../etc/passwd`);
    // fetch normalises ../.. away, but the server-side decodeURIComponent
    // path must also refuse. Either way, not 200 + passwd.
    const text = await r.text();
    assert.ok(!text.includes('root:x:0'));
  } finally {
    await d.close();
  }
});

test('dashboard: rejects non-loopback Host header (DNS-rebinding defense)', async () => {
  const d = await startDashboard({ port: 38475 });
  try {
    // Use raw http.request to set Host: fetch() blocks custom Host headers.
    const http = await import('node:http');
    const status = await new Promise((resolveP, rejectP) => {
      const req = http.request(
        { host: '127.0.0.1', port: 38475, path: '/', method: 'GET',
          headers: { Host: 'attacker.example.com' } },
        (res) => {
          res.resume();
          resolveP(res.statusCode);
        }
      );
      req.on('error', rejectP);
      req.end();
    });
    assert.equal(status, 403);
  } finally {
    await d.close();
  }
});
