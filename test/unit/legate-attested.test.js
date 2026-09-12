import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = (name) => join(here, '..', 'fixtures', 'legate', name);
const m = await import(pathToFileURL(join(here, '..', '..', 'src', 'engines', 'legate-core.mjs')).href);
const sampleQuote = readFileSync(fixturePath('tdx-quote-sample.hex'), 'utf8').trim();

test('a real Intel TDX quote verifies offline to the pinned Intel SGX Root CA', () => {
  const v = m.verifyTdxQuote(sampleQuote, new Date('2026-09-12T00:00:00Z'));
  assert.equal(v.valid, true, JSON.stringify(v.checks.filter((c) => !c.ok)));
  for (const id of ['quote', 'quote_signature', 'qe_binding', 'qe_signature', 'pck_chain']) assert.ok(v.checks.some((c) => c.id === id && c.ok), id);
  assert.ok(v.chain[v.chain.length - 1].includes('Intel SGX Root CA'));
  assert.ok(v.checks.some((c) => c.id === 'tcb' && c.informational));
});

test('a quote with one signed byte changed fails on its signature, and an expired view fails on the chain', () => {
  const bytes = Buffer.from(sampleQuote.replace(/^0x/, ''), 'hex'); bytes[48 + 520 + 3] ^= 1;
  const v = m.verifyTdxQuote(new Uint8Array(bytes), new Date('2026-09-12T00:00:00Z'));
  assert.equal(v.valid, false);
  assert.ok(v.checks.some((c) => c.id === 'quote_signature' && !c.ok));
  const late = m.verifyTdxQuote(sampleQuote, new Date('2049-06-01T00:00:00Z'));
  assert.ok(late.checks.some((c) => c.id === 'pck_chain' && !c.ok));
});

test('a model call signature recovers to the address the provider documents, and not after the response digest changes', () => {
  const call = { index: 0, model: 'Qwen/Qwen3.5-122B-A10B', kind: 'provider_tee', request_sha256: '2974f24b2a687856d2a0cf08d813902965c25e6552ba7062e4fa303432b6d2ad', response_sha256: '8cb30eef9d133bdc6bfe812772dc4a62336d2827caea843546cbeff3f004c42c', signature: '0xed381e84d059198d1826e44dbbbac9501caaa8f79f913f27578acafa5be852e6103fe34fabd6446d7fde3f5250c0a16e109fe088a562bae08ac13d081a66d0761b', signing_address: '0x6525e128afcffebf7eed05d485d7be983cdae934', signing_algo: 'ecdsa' };
  assert.equal(m.recoverSigner(call), call.signing_address);
  assert.notEqual(m.recoverSigner({ ...call, response_sha256: '0'.repeat(64) }), call.signing_address);
});

test('an attestation report whose quote does not bind the signing address is refused on the key binding, not on the quote', () => {
  const v = m.verifyModelAttestation({ signing_address: '0x6525e128afcffebf7eed05d485d7be983cdae934', signing_algo: 'ecdsa', intel_quote: sampleQuote, nonce: '00'.repeat(32) }, { model: 'Qwen/Qwen3.8-27B' }, new Date('2026-09-12T00:00:00Z'));
  assert.equal(v.valid, false);
  assert.ok(v.checks.some((c) => c.id === 'quote_pck_chain' && c.ok));
  assert.ok(v.checks.some((c) => c.id === 'report_data' && !c.ok));
});
