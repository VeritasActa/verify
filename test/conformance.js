#!/usr/bin/env node

/**
 * Conformance test for @veritasacta/verify
 *
 * Verifies all test vectors pass, sample artifacts verify, and bundles work.
 * Run: node test/conformance.js
 *
 * Exit 0 = all pass, Exit 1 = failure
 */

import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { verifyArtifact } from '@veritasacta/artifacts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(__dirname, '..');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.error(`  ✗ ${name}`);
    failed++;
  }
}

// ── Test Vectors ────────────────────────────────────────────────

console.log('\n⬢ Test vector verification\n');

const vectorsPath = join(pkgRoot, '..', '..', 'artifacts', 'test-vectors-v2.json');
let vectors;
try {
  vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));
} catch {
  console.error('  ⚠ test-vectors-v2.json not found, skipping vector tests');
  vectors = null;
}

if (vectors) {
  const publicKey = vectors._meta.keypair.public_key;

  for (const vector of vectors.vectors) {
    const result = verifyArtifact(vector.signed_artifact, publicKey);
    assert(result.valid === true, `Vector: ${vector.name}`);

    if (vector.verification?.hash) {
      assert(result.hash === vector.verification.hash, `  Hash match: ${vector.name}`);
    }
  }

  // Negative test: tampered artifact should fail
  const tampered = JSON.parse(JSON.stringify(vectors.vectors[0].signed_artifact));
  tampered.payload.decision = 'deny'; // tamper
  const tamperedResult = verifyArtifact(tampered, publicKey);
  assert(tamperedResult.valid === false, 'Tampered artifact correctly rejected');

  // Wrong key should fail
  const wrongKey = '0000000000000000000000000000000000000000000000000000000000000000';
  const wrongKeyResult = verifyArtifact(vectors.vectors[0].signed_artifact, wrongKey);
  assert(wrongKeyResult.valid === false, 'Wrong public key correctly rejected');
}

// ── Sample Artifacts ────────────────────────────────────────────

console.log('\n⬢ Sample artifact verification\n');

const sampleReceipt = JSON.parse(readFileSync(join(pkgRoot, 'samples', 'sample-receipt.json'), 'utf-8'));
// Use the test vector public key (the sample receipt was signed with the same keypair)
const sampleKey = vectors ? vectors._meta.keypair.public_key : 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const receiptResult = verifyArtifact(sampleReceipt, sampleKey);
assert(receiptResult.valid === true, 'Sample receipt verifies with test vector key');

// ── Sample Bundle ───────────────────────────────────────────────

console.log('\n⬢ Sample bundle verification\n');

const bundle = JSON.parse(readFileSync(join(pkgRoot, 'samples', 'sample-bundle.json'), 'utf-8'));

// Extract key from bundle
const jwk = bundle.verification.signing_keys[0];
assert(jwk.kty === 'OKP' && jwk.crv === 'Ed25519', 'Bundle contains Ed25519 JWK');

// Verify each receipt in bundle
for (let i = 0; i < bundle.receipts.length; i++) {
  const receipt = bundle.receipts[i];
  // We need the hex key — convert from JWK x
  const publicKey = vectors ? vectors._meta.keypair.public_key : sampleKey;
  const result = verifyArtifact(receipt, publicKey);
  assert(result.valid === true, `Bundle receipt ${i + 1}/${bundle.receipts.length}: ${receipt.type}`);
}

// ── Format Detection ────────────────────────────────────────────

console.log('\n⬢ Format detection\n');

assert(sampleReceipt.v === 2, 'v2 format detected');
assert(sampleReceipt.algorithm === 'ed25519', 'Ed25519 algorithm');
assert(typeof sampleReceipt.kid === 'string', 'kid present');
assert(typeof sampleReceipt.signature === 'string', 'Signature present');
assert(typeof sampleReceipt.payload === 'object', 'Payload is object');

// ── Exit Code Contract (3-way split) ────────────────────────────

console.log('\n⬢ Exit code contract (0=valid, 1=invalid, 2=error)\n');

const cliPath = join(pkgRoot, 'cli.js');

function runCli(args) {
  try {
    execFileSync('node', [cliPath, ...args], {
      stdio: 'pipe',
      timeout: 10000,
    });
    return 0;
  } catch (err) {
    return err.status;
  }
}

// Exit 0: valid receipt with correct key
assert(
  runCli([join(pkgRoot, 'samples', 'sample-receipt.json'), '--key', sampleKey]) === 0,
  'Exit 0 for valid receipt'
);

// Exit 1: tampered artifact (wrong key forces signature mismatch)
assert(
  runCli([join(pkgRoot, 'samples', 'sample-receipt.json'), '--key', '0000000000000000000000000000000000000000000000000000000000000000']) === 1,
  'Exit 1 for invalid signature (wrong key)'
);

// Exit 2: no input file specified
assert(
  runCli([]) === 2,
  'Exit 2 for missing input'
);

// Exit 2: non-existent file
assert(
  runCli(['/tmp/nonexistent_file_for_verify_test.json']) === 2,
  'Exit 2 for unreadable file'
);

// Exit 2: malformed JSON (test with a temp file containing invalid JSON)
const badJsonPath = join(pkgRoot, 'test', '_tmp_bad.json');
writeFileSync(badJsonPath, 'not-valid-json{{{');
assert(
  runCli([badJsonPath]) === 2,
  'Exit 2 for invalid JSON'
);

// Exit 2: valid JSON but missing required fields (no key)
const malformedPath = join(pkgRoot, 'test', '_tmp_malformed.json');
writeFileSync(malformedPath, '{"type": "protectmcp:decision", "tool_name": "something"}');
assert(
  runCli([malformedPath]) === 2,
  'Exit 2 for missing public key (undecidable)'
);

// Clean up temp files
try { unlinkSync(badJsonPath); } catch {}
try { unlinkSync(malformedPath); } catch {}

// ── Results ─────────────────────────────────────────────────────

console.log(`\n──────────────────────────────────────`);
console.log(`  ${passed} passed, ${failed} failed`);
console.log(`──────────────────────────────────────\n`);

process.exit(failed > 0 ? 1 : 0);
