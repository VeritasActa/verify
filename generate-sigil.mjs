#!/usr/bin/env node

/**
 * generate-sigil.mjs — Generate the Sigil commitment for this release.
 *
 * Run this ONCE per release, AFTER the source code is frozen.
 * It computes SHA-256 of cli.js, builds a policy, derives the Sigil,
 * and writes sigil.json.
 *
 * The stable Veritas Acta project public key is embedded in sigil.json
 * (published with the package). An optional sigil-key.json is used only by
 * --init to establish a new project identity; the current Sigil derivation is
 * a public integrity commitment, not a project-key signature.
 *
 * Usage:
 *   node generate-sigil.mjs [--init]   # --init creates a new keypair
 *   node generate-sigil.mjs            # derives Sigil from existing key
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  readSigilMonitoredSource,
  SIGIL_MONITORED_FILES,
} from './src/sigil-policy.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Ed25519 key generation (using Node.js built-in) ──────────────

async function generateKeypair() {
  const { generateKeyPairSync } = await import('node:crypto');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  // Ed25519 SPKI DER: last 32 bytes are the raw public key
  const pubHex = pubRaw.subarray(pubRaw.length - 32).toString('hex');
  const privHex = privRaw.toString('hex');
  return { pubHex, privHex };
}

// ── SHA-256 of file ──────────────────────────────────────────────

function sha256File(filepath) {
  const content = readFileSync(filepath);
  return createHash('sha256').update(content).digest('hex');
}

// ── Sigil derivation (matches web/src/lib/sigil/sigil.ts) ────────

function sigilDerive(pubKeyHex, policyHash, nonce = 0) {
  const domain = Buffer.from('scopeblind:sigil:v2');
  const pubKey = Buffer.from(pubKeyHex, 'hex');
  const policy = Buffer.from(policyHash, 'hex');
  const input = Buffer.concat([domain, pubKey, policy, Buffer.from([nonce & 0xff])]);
  return createHash('sha256').update(input).digest('hex');
}

// ── Human-readable name from fingerprint ─────────────────────────

const NAME_ADJ = [
  'Bright', 'Quiet', 'Deep', 'Bold', 'Pale', 'Warm', 'Still', 'Swift',
  'Clear', 'Dark', 'First', 'True', 'Slow', 'Fair', 'Old', 'New',
  'Gilded', 'Woven', 'Open', 'High', 'Lone', 'Kind', 'Keen', 'Wild',
];
const NAME_NOUN = [
  'Ember', 'Harbor', 'Field', 'Beacon', 'River', 'Grove', 'Arrow', 'Stone',
  'Ridge', 'Wind', 'Tide', 'Star', 'Vale', 'Peak', 'Lake', 'Dawn',
  'Reed', 'Cairn', 'Orchard', 'Meadow', 'Hearth', 'Anchor', 'Vessel', 'Thread',
];

function sigilName(fingerprint) {
  const n = parseInt(fingerprint.slice(0, 4), 16);
  const m = parseInt(fingerprint.slice(4, 8), 16);
  return `${NAME_ADJ[n % NAME_ADJ.length]} ${NAME_NOUN[m % NAME_NOUN.length]}`;
}

// ── Main ─────────────────────────────────────────────────────────

const keyPath = join(__dirname, 'sigil-key.json');
const sigilPath = join(__dirname, 'sigil.json');
const pkg = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8'));
const existingSigil = existsSync(sigilPath)
  ? JSON.parse(readFileSync(sigilPath, 'utf-8'))
  : null;

// Init mode: generate a new keypair
if (process.argv.includes('--init')) {
  if (existsSync(keyPath)) {
    console.error('sigil-key.json already exists. Delete it first if you want to regenerate.');
    process.exit(1);
  }
  const { pubHex, privHex } = await generateKeypair();
  writeFileSync(keyPath, JSON.stringify({ pubHex, privHex }, null, 2) + '\n');
  console.log(`✓ Generated Veritas Acta project keypair`);
  console.log(`  Public key: ${pubHex}`);
  console.log(`  Saved to: sigil-key.json (KEEP PRIVATE — do NOT publish to npm)`);
}

// Reuse the established public project identity. The derivation below never
// uses a private key, so a clean release checkout must not require one merely
// to refresh the monitored-source commitment.
let key;
if (existsSync(keyPath)) {
  key = JSON.parse(readFileSync(keyPath, 'utf-8'));
} else if (existingSigil) {
  if (typeof existingSigil.project_public_key !== 'string'
    || !/^[0-9a-f]{64}$/i.test(existingSigil.project_public_key)) {
    console.error('Existing sigil.json has no valid project public key. Run --init in the project custody environment.');
    process.exit(1);
  }
  key = { pubHex: existingSigil.project_public_key };
  console.log('  Reusing the published project public key from sigil.json.');
} else {
  console.error('No project public key found. Run --init in the project custody environment.');
  process.exit(1);
}

// Compute the source hash over the declared monitored surface. Release tests
// require this list to include cli.js and every shipped executable JavaScript
// module under src/, so changing any runtime module invalidates --self-check.
let combined;
try {
  combined = readSigilMonitoredSource(__dirname);
} catch (error) {
  console.error(`  ERROR: ${error.message}`);
  console.error('  Refusing to seal a reduced verifier surface.');
  process.exit(1);
}
const sourceHash = createHash('sha256').update(combined).digest('hex');

const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH;
const createdAt = sourceDateEpoch !== undefined
  ? Number(sourceDateEpoch) * 1000
  : existingSigil?.policy?.created_at ?? 0;
if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
  console.error('SOURCE_DATE_EPOCH or existing Sigil created_at must resolve to a non-negative integer.');
  process.exit(1);
}

// Build the deterministic policy. created_at is a stable policy epoch, not the
// wall-clock time of regeneration, so identical sources produce identical
// commitments.
const policy = {
  version: 3,
  package: pkg.name,
  package_version: pkg.version,
  source_hash: sourceHash,
  monitored_files: SIGIL_MONITORED_FILES,
  ietf_draft: 'draft-farley-acta-signed-receipts-03',
  conformance_tier: 'T4',
  supported_algorithms: ['ed25519', 'EdDSA', 'voprf-p256-sha256'],
  created_at: createdAt,
};

// Compute policy hash
const policyJson = JSON.stringify(policy);
const policyHash = createHash('sha256').update(policyJson).digest('hex');

// Derive Sigil
const sigilHash = sigilDerive(key.pubHex, policyHash);
const fingerprint = sigilHash.slice(0, 8);
const name = sigilName(fingerprint);

// Write sigil.json (this is published with the package)
const sigil = {
  sigil_version: 1,
  fingerprint,
  name,
  sigil_hash: sigilHash,
  project_public_key: key.pubHex,
  commitment_authentication: 'public_recomputable_integrity_only',
  policy,
  policy_hash: policyHash,
  derived_at: new Date(createdAt).toISOString(),
};

const serialized = JSON.stringify(sigil, null, 2) + '\n';
if (process.argv.includes('--check')) {
  const current = existsSync(sigilPath) ? readFileSync(sigilPath, 'utf8') : '';
  if (current !== serialized) {
    console.error('Sigil commitment is stale. Run npm run generate-sigil and review the change.');
    process.exit(1);
  }
  console.log('Sigil public integrity commitment is current and reproducible.');
  process.exit(0);
}

writeFileSync(sigilPath, serialized);

console.log(`\n✓ Sigil committed for ${pkg.name}@${pkg.version}`);
console.log(`  Name:        ${name}`);
console.log(`  Fingerprint: ${fingerprint}`);
console.log(`  Source hash:  ${sourceHash.slice(0, 16)}...`);
console.log(`  Policy hash:  ${policyHash.slice(0, 16)}...`);
console.log(`  Sigil hash:   ${sigilHash.slice(0, 16)}...`);
console.log(`  Written to:   sigil.json`);
console.log('  Authentication: public recomputation only (not a project signature)');
console.log(`\n  Anyone can check local integrity: npx @veritasacta/verify --self-check\n`);
