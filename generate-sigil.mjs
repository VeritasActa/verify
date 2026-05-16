#!/usr/bin/env node

/**
 * generate-sigil.mjs — Generate the Sigil commitment for this release.
 *
 * Run this ONCE per release, AFTER the source code is frozen.
 * It computes SHA-256 of cli.js, builds a policy, derives the Sigil,
 * and writes sigil.json.
 *
 * The Veritas Acta project keypair is stored in sigil-key.json (PRIVATE,
 * never published to npm). The public key is embedded in sigil.json
 * (published with the package).
 *
 * Usage:
 *   node generate-sigil.mjs [--init]   # --init creates a new keypair
 *   node generate-sigil.mjs            # derives Sigil from existing key
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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

// Load existing keypair
if (!existsSync(keyPath)) {
  console.error('No sigil-key.json found. Run: node generate-sigil.mjs --init');
  process.exit(1);
}

const key = JSON.parse(readFileSync(keyPath, 'utf-8'));

// Compute source hash over cli.js PLUS monitored engine/util files.
// v0.5.0 Sigil commits to the entire verification surface, not just cli.js,
// so that modification of any engine file invalidates --self-check.
const MONITORED_FILES = [
  'cli.js',
  'src/detect.js',
  'src/conformance.js',
  'src/errors.js',
  'src/engines/ed25519-receipt.js',
  'src/engines/voprf-token.js',
  'src/engines/knowledge-unit.js',
  'src/engines/selective-disclosure.js',
  'src/engines/sigil.js',
  'src/engines/attestation.js',
  'src/engines/bulk.js',
  'src/engines/diff.js',
  'src/engines/init.js',
  'src/engines/proxy.js',
  'src/engines/daemon.js',
  'src/engines/prompt.js',
  'src/engines/chain-explore.js',
  'src/engines/compliance-export.js',
  'src/engines/dsse.js',
  'src/engines/delegation.js',
  'src/engines/cosign.js',
  'src/engines/dashboard.js',
  'src/engines/rekor.js',
  'src/engines/attestation-quote.js',
  'src/engines/watch.js',
  'src/engines/sbom.js',
  'src/engines/transparency.js',
  'src/context/live-context.js',
  'src/output/terminal.js',
  'src/output/json.js',
  'src/output/html-report.js',
  'src/util/canonical.js',
  'src/util/hex.js',
  'src/util/jwks.js',
  'src/util/audit-log.js',
  'src/util/fips.js',
  'src/util/voprf-crypto.js',
  'src/util/voprf-crypto-v2.js',
];

import { readFileSync as _readFileSync } from 'node:fs';
const bufs = [];
for (const rel of MONITORED_FILES) {
  try { bufs.push(_readFileSync(join(__dirname, rel))); }
  catch (e) { console.error(`  WARNING: monitored file missing: ${rel}`); }
}
const combined = Buffer.concat(bufs);
const sourceHash = createHash('sha256').update(combined).digest('hex');

// Build the policy (v0.5.0 schema)
const policy = {
  version: 3,
  package: pkg.name,
  package_version: pkg.version,
  source_hash: sourceHash,
  monitored_files: MONITORED_FILES,
  ietf_draft: 'draft-farley-acta-signed-receipts-03',
  conformance_tier: 'T4',
  supported_algorithms: ['ed25519', 'EdDSA', 'voprf-p256-sha256'],
  created_at: Date.now(),
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
  policy,
  policy_hash: policyHash,
  derived_at: new Date().toISOString(),
};

writeFileSync(sigilPath, JSON.stringify(sigil, null, 2) + '\n');

console.log(`\n✓ Sigil committed for ${pkg.name}@${pkg.version}`);
console.log(`  Name:        ${name}`);
console.log(`  Fingerprint: ${fingerprint}`);
console.log(`  Source hash:  ${sourceHash.slice(0, 16)}...`);
console.log(`  Policy hash:  ${policyHash.slice(0, 16)}...`);
console.log(`  Sigil hash:   ${sigilHash.slice(0, 16)}...`);
console.log(`  Written to:   sigil.json`);
console.log(`\n  Anyone can verify: npx @veritasacta/verify --self-check\n`);
