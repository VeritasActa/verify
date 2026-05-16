/**
 * Unit tests for prompt-verify engine (AIP supply-chain surface).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { verifyPrompt, hashPromptFile } from '../../src/engines/prompt.js';

function tmp(prefix = 'vp-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

test('hashPromptFile: returns sha256:<hex> prefix', () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'hello');
  const expected = `sha256:${createHash('sha256').update('hello').digest('hex')}`;
  assert.equal(hashPromptFile(p), expected);
});

test('verifyPrompt: expectedHash match → valid', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'expected match');
  const h = hashPromptFile(p);
  const r = await verifyPrompt({ promptPath: p, expectedHash: h });
  assert.equal(r.valid, true);
  assert.equal(r.source, 'expected-hash');
  assert.equal(r.prompt_hash, h);
});

test('verifyPrompt: expectedHash without sha256: prefix is normalised', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'prefix-normalise');
  const hex = hashPromptFile(p).replace(/^sha256:/, '');
  const r = await verifyPrompt({ promptPath: p, expectedHash: hex });
  assert.equal(r.valid, true);
  assert.equal(r.expected_hash.startsWith('sha256:'), true);
});

test('verifyPrompt: expectedHash mismatch → invalid with reason', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'mismatch');
  const r = await verifyPrompt({
    promptPath: p,
    expectedHash: '0000000000000000000000000000000000000000000000000000000000000000',
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'hash_mismatch');
});

test('verifyPrompt: missing source → error', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'missing source');
  const r = await verifyPrompt({ promptPath: p });
  assert.equal(r.valid, false);
  assert.match(r.error, /missing_source/);
});

test('verifyPrompt: via receipt.payload.prompt_hash → valid', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'receipt prompt hash');
  const h = hashPromptFile(p);

  const receipt = {
    payload: {
      type: 'prompt-attestation',
      prompt_hash: h,
      issuer_id: 'test-issuer',
      agent_id: 'test-agent',
      issued_at: '2026-04-20T00:00:00Z',
    },
    signature: { alg: 'ed25519', kid: 'test-kid', sig: 'dead' },
  };
  const rp = join(dir, 'receipt.json');
  writeFileSync(rp, JSON.stringify(receipt));

  const r = await verifyPrompt({ promptPath: p, receiptPath: rp });
  assert.equal(r.valid, true);
  assert.equal(r.source, 'receipt');
  assert.equal(r.receipt_summary.kid, 'test-kid');
});

test('verifyPrompt: via receipt.payload.instruction_hash alias → valid', async () => {
  const dir = tmp();
  const p = join(dir, 'CLAUDE.md');
  writeFileSync(p, 'instruction alias');
  const h = hashPromptFile(p);
  const receipt = {
    payload: { instruction_hash: h, type: 'x', issued_at: '2026' },
    signature: { kid: 'k' },
  };
  const rp = join(dir, 'receipt.json');
  writeFileSync(rp, JSON.stringify(receipt));
  const r = await verifyPrompt({ promptPath: p, receiptPath: rp });
  assert.equal(r.valid, true);
});

test('verifyPrompt: via receipt without prompt-hash fields → missing field error', async () => {
  const dir = tmp();
  const p = join(dir, 'skill.md');
  writeFileSync(p, 'empty receipt');
  const receipt = {
    payload: { type: 'decision', issued_at: '2026' },
    signature: { kid: 'k' },
  };
  const rp = join(dir, 'r.json');
  writeFileSync(rp, JSON.stringify(receipt));
  const r = await verifyPrompt({ promptPath: p, receiptPath: rp });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'receipt_missing_prompt_hash_field');
});

test('verifyPrompt: Sigstore DSSE bundle subject matches → valid', async () => {
  const dir = tmp();
  const p = join(dir, 'SKILLS.md');
  writeFileSync(p, 'sigstore-ok');
  const h = hashPromptFile(p).replace(/^sha256:/, '');

  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'SKILLS.md', digest: { sha256: h } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {},
  };
  const bundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
    dsseEnvelope: {
      payload: Buffer.from(JSON.stringify(statement), 'utf-8').toString('base64'),
      payloadType: 'application/vnd.in-toto+json',
      signatures: [],
    },
    verificationMaterial: { certificate: { rawBytes: '' } },
  };
  const bp = join(dir, 'bundle.json');
  writeFileSync(bp, JSON.stringify(bundle));

  const r = await verifyPrompt({ promptPath: p, sigstoreBundle: bp });
  assert.equal(r.valid, true);
  assert.equal(r.source, 'sigstore');
});

test('verifyPrompt: Sigstore bundle with wrong subject hash → invalid', async () => {
  const dir = tmp();
  const p = join(dir, 'SKILLS.md');
  writeFileSync(p, 'sigstore-wrong');
  const statement = {
    subject: [{ name: 'SKILLS.md', digest: { sha256: 'deadbeef'.repeat(8) } }],
  };
  const bundle = {
    dsseEnvelope: {
      payload: Buffer.from(JSON.stringify(statement), 'utf-8').toString('base64'),
    },
  };
  const bp = join(dir, 'bundle.json');
  writeFileSync(bp, JSON.stringify(bundle));
  const r = await verifyPrompt({ promptPath: p, sigstoreBundle: bp });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'sigstore_subject_hash_mismatch');
});

test('verifyPrompt: missing prompt file → cannot_read error', async () => {
  const r = await verifyPrompt({ promptPath: '/does/not/exist.md' });
  assert.equal(r.valid, false);
  assert.match(r.error, /cannot_read_prompt_file/);
});
