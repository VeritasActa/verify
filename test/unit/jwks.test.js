import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';

import { classifyJwksSource, resolveFromJwks } from '../../src/util/jwks.js';

const publicKeyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const publicKeyX = Buffer.from(publicKeyHex, 'hex')
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');

async function writeJwks() {
  const dir = await mkdtemp(join(tmpdir(), 'va-jwks-'));
  const file = join(dir, 'keys.jwks');
  await writeFile(file, JSON.stringify({
    keys: [{
      kty: 'OKP',
      crv: 'Ed25519',
      kid: 'test-key',
      x: publicKeyX,
    }],
  }), 'utf8');
  return { dir, file };
}

test('resolveFromJwks reads absolute filesystem paths', async () => {
  const { file } = await writeJwks();
  const result = await resolveFromJwks(file, 'test-key');
  assert.equal(result.error, null);
  assert.equal(result.key, publicKeyHex);
  assert.equal(result.kid, 'test-key');
  assert.equal(result.source.type, 'file');
  assert.equal(result.source.resolved, file);
});

test('resolveFromJwks reads file:// URLs', async () => {
  const { file } = await writeJwks();
  const result = await resolveFromJwks(pathToFileURL(file).href, 'test-key');
  assert.equal(result.error, null);
  assert.equal(result.key, publicKeyHex);
  assert.equal(result.source.type, 'file');
  assert.equal(result.source.resolved, file);
});

test('resolveFromJwks reads bare relative filesystem paths from cwd', async () => {
  const { dir } = await writeJwks();
  const previous = process.cwd();
  process.chdir(dir);
  try {
    const result = await resolveFromJwks('keys.jwks', 'test-key');
    assert.equal(result.error, null);
    assert.equal(result.key, publicKeyHex);
    assert.equal(result.source.type, 'file');
    assert.match(result.source.resolved, /keys\.jwks$/);
  } finally {
    process.chdir(previous);
  }
});

test('resolveFromJwks reports unsupported URL schemes explicitly', async () => {
  const result = await resolveFromJwks('ftp://example.test/keys.jwks', 'test-key');
  assert.equal(result.key, null);
  assert.match(result.error, /Unsupported JWKS URL scheme: ftp:/);
});

test('classifyJwksSource reads a Windows drive-letter path as a file, not as a URL scheme', () => {
  // new URL('C:\\keys\\acta-keys.json') parses with protocol "c:", which earlier releases refused as a URL scheme.
  assert.equal(new URL('C:\\keys\\acta-keys.json').protocol, 'c:');
  for (const source of ['C:\\keys\\acta-keys.json', 'c:\\keys\\acta-keys.json', 'C:/keys/acta-keys.json', 'D:keys.json']) {
    assert.deepEqual(classifyJwksSource(source), { type: 'file', path: source }, source);
  }
  for (const source of ['/etc/acta/keys.jwks', 'keys.jwks', './keys.jwks', '\\\\server\\share\\keys.jwks']) {
    assert.deepEqual(classifyJwksSource(source), { type: 'file', path: source }, source);
  }
  assert.equal(classifyJwksSource(pathToFileURL('/tmp/keys.jwks').href).type, 'file');
});

test('classifyJwksSource reads http, https and other schemes as URLs, so loadJwks can refuse the others', () => {
  for (const [source, protocol] of [['https://issuer.example/.well-known/acta-keys.json', 'https:'], ['http://localhost:8080/jwks', 'http:'], ['ftp://example.test/keys.jwks', 'ftp:']]) {
    const c = classifyJwksSource(source);
    assert.equal(c.type, 'url', source);
    assert.equal(c.url.protocol, protocol, source);
  }
});

test('resolveFromJwks looks for a drive-letter path on disk rather than refusing its scheme', async () => {
  const result = await resolveFromJwks('C:\\veritasacta-missing\\acta-keys.json', 'test-key');
  assert.equal(result.key, null);
  assert.doesNotMatch(result.error, /Unsupported JWKS URL scheme/);
  assert.match(result.error, /ENOENT|no such file/i);
});
