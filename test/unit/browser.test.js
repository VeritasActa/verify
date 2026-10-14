import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifyReceiptText } from '../../src/browser.js';
import { verifyReceiptText as bundled } from '../../browser/receipt-verifier.js';
import { verifyReceipt } from '../../src/engines/ed25519-receipt.js';
import { detectFormat } from '../../src/detect.js';
import { parseReceiptJson } from '../../src/util/strict-json.js';
import { ed25519 } from '@noble/curves/ed25519';
import { canonicalize } from '../../src/util/canonical.js';
const current = JSON.parse(readFileSync(new URL('../../samples/current-receipt.json', import.meta.url)));
const legacy = JSON.parse(readFileSync(new URL('../fixtures/browser/legacy-receipt.json', import.meta.url)));
const key = current.payload.public_key;

test('v1 and v2 receipts retain JCS parity, including numeric-looking keys', async () => {
  const privateKey = new Uint8Array(32).fill(12);
  const pin = Buffer.from(ed25519.getPublicKey(privateKey)).toString('hex');
  for (const payload of [
    { v: 1, type: 'decision_receipt', timestamp: '2026-01-01T00:00:00Z', '10': 'ten', '2': 'two' },
    { v: 2, kid: 'test', issuer: 'test', issued_at: '2026-01-01T00:00:00Z', payload: { decision: 'allow', '10': 'ten', '2': 'two' } },
  ]) {
    const receipt = { ...payload, signature: Buffer.from(ed25519.sign(new TextEncoder().encode(canonicalize(payload)), privateKey)).toString('hex') };
    const result = await bundled(JSON.stringify(receipt), pin);
    assert.equal(result.status, 'valid');
    assert.deepEqual(result, await verifyReceiptText(JSON.stringify(receipt), pin));
    assert.equal((await verifyReceipt(receipt, detectFormat(receipt).mode, { publicKey: pin })).valid, true);
  }
});

test('release manifest, bundle and README agree', () => {
  const manifest = JSON.parse(readFileSync('release-manifest.json'));
  const pkg = JSON.parse(readFileSync('package.json'));
  const build = JSON.parse(readFileSync('browser/build.json'));
  assert.equal(manifest.verifier.version, pkg.version);
  assert.equal(build.version, pkg.version);
  assert.match(readFileSync('README.md','utf8'), new RegExp(`Verifier: \\*\\*\\[${pkg.version.replaceAll('.', '\\.')}`));
  assert.match(readFileSync('README.md','utf8'), /expired 2026-10-08/);
});

for (const [name, receipt, pin] of [['current envelope', current, key], ['historical website', legacy, legacy.public_key]]) {
  test(`${name}: browser bundle and CLI engine agree`, async () => {
    const text = JSON.stringify(receipt), result = await verifyReceiptText(text, pin);
    assert.equal(result.status, 'valid');
    assert.deepEqual(await bundled(text, pin), result);
    assert.equal((await verifyReceipt(receipt, detectFormat(receipt).mode, { publicKey: pin })).valid, true);
    if (name.startsWith('historical')) assert.match(result.warning, /Not draft-03/);
  });
}
test('mutation fails; unavailable keys and unsupported profiles are not failed signatures', async () => {
  const mutated = structuredClone(current); mutated.payload.decision = 'deny';
  assert.equal((await bundled(JSON.stringify(mutated), key)).status, 'invalid');
  assert.equal((await bundled(JSON.stringify(current), '11'.repeat(32))).status, 'invalid');
  assert.equal((await bundled(JSON.stringify(current))).status, 'not_checked');
  assert.equal((await bundled('{"hello":1}', key)).error, 'unsupported_format');
  const pq = structuredClone(current); pq.signature.alg = 'ed25519+ml-dsa-65';
  assert.equal((await bundled(JSON.stringify(pq), key)).status, 'not_checked');
});
test('legacy verification never trusts or silently changes an embedded key', async () => {
  const r = await bundled(JSON.stringify(legacy));
  assert.equal(r.error, 'embedded_key_rejected');
  const changed = { ...legacy, public_key: '22'.repeat(32) };
  assert.equal((await bundled(JSON.stringify(changed))).status, 'not_checked');
  // That field was never signed in this historical format; only the supplied pin is authoritative.
  assert.equal((await bundled(JSON.stringify(changed), legacy.public_key)).status, 'valid');
});
test('duplicate names, including escaped names and nested members, are rejected', async () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":[{"a":1,"a":2}]}']) {
    assert.throws(() => parseReceiptJson(text), { code: 'duplicate_key' });
    assert.equal((await bundled(text, key)).status, 'not_checked');
  }
});
test('parser bounds and syntax errors fail closed', async () => {
  assert.throws(() => parseReceiptJson(' '.repeat(1048577)), { code: 'input_too_large' });
  assert.throws(() => parseReceiptJson('['.repeat(70)+'0'+']'.repeat(70)), { code: 'input_too_deep' });
  for (const text of ['{"x":1,}', '[1,]', '01', '{}{}', '{"x":"\\q"}', '']) {
    assert.equal((await bundled(text, key)).status, 'not_checked');
  }
  assert.deepEqual(parseReceiptJson('{"a":[1,true,null,{"b":"a\\\"b"}]}'), { a: [1,true,null,{b:'a"b'}] });
});
test('CLI verifies both formats and rejects duplicate input before verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acta-browser-parity-'));
  try {
    for (const [receipt, pin] of [[current,key],[legacy,legacy.public_key]]) {
      const file=join(dir,'receipt.json');writeFileSync(file,JSON.stringify(receipt));
      const p=spawnSync(process.execPath,['cli.js',file,'--key',pin,'--json'],{encoding:'utf8'});
      assert.equal(p.status,0,p.stdout+p.stderr);
    }
    const file=join(dir,'duplicate.json');writeFileSync(file,'{"type":"x","type":"y"}');
    assert.equal(spawnSync(process.execPath,['cli.js',file],{encoding:'utf8'}).status,2);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
