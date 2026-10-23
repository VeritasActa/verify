/**
 * verify daemon: each receipt's tool_input_hash binds the full arguments, as the proxy's does: the SHA-256 of their
 * RFC 8785 canonical form, recorded as tool_input_hash_method jcs-sha256-v1. Before, the daemon passed the top-level
 * member names to JSON.stringify as a replacer, which keeps only those names at every depth, so
 * {query:{sql:"DROP TABLE users"}}, {query:{}} and {query:{sql:"SELECT 1"}} hashed the same, and one receipt covered
 * a harmless call and a destructive one.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync, verify as edVerify } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../src/util/canonical.js';
import { hashToolInput } from '../../src/engines/proxy.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));

function post(socketPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request({ socketPath, path: '/sign', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    });
    req.on('error', reject);
    req.end(data);
  });
}

test('daemon: nested arguments that differ hash differently, as the proxy hashes them (jcs-sha256-v1)', async () => {
  // A short working directory keeps the socket path under the platform limit.
  const dir = mkdtempSync(join(tmpdir(), 'acta-daemon-'));
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const keyPath = join(dir, 'attester.json');
  writeFileSync(keyPath, JSON.stringify({ kid: 'daemon-test-kid', privateDer: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'), pubHex: 'unused' }));
  chmodSync(keyPath, 0o600);
  const daemon = spawn(process.execPath, [cli, 'daemon', '--socket', 'd.sock', '--attest-key', keyPath, '--receipts-dir', join(dir, 'receipts')], { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] });
  const socketPath = join(dir, 'd.sock');
  try {
    for (let i = 0; i < 100 && !existsSync(socketPath); i++) await new Promise((r) => setTimeout(r, 50));
    assert.ok(existsSync(socketPath), 'the daemon listens');
    const cases = [
      { query: { sql: 'DROP TABLE users' } },
      { query: {} },
      { query: { sql: 'SELECT 1' } },
      { cmd: { argv: ['rm', '-rf', '/'] } },
      { cmd: { argv: ['ls'] } },
    ];
    const hashes = [];
    for (const args of cases) {
      const receipt = await post(socketPath, { tool: 'db.query', args });
      assert.equal(receipt.payload.tool_input_hash, hashToolInput(args), JSON.stringify(args));
      assert.equal(receipt.payload.tool_input_hash_method, 'jcs-sha256-v1');
      assert.ok(edVerify(null, Buffer.from(canonicalize(receipt.payload), 'utf8'), publicKey, Buffer.from(receipt.signature.sig, 'hex')), 'the receipt is signed');
      hashes.push(receipt.payload.tool_input_hash);
    }
    assert.equal(new Set(hashes).size, cases.length, 'every argument set has its own hash');
  } finally {
    daemon.kill('SIGTERM');
    await new Promise((r) => daemon.once('exit', r));
  }
});
