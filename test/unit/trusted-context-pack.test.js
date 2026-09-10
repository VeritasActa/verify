/**
 * Unit tests for the Trusted Context Pack verifier (TCB v1).
 *
 * Builds and signs a pack EXACTLY as scopeblind-pm/src/trusted-context.ts does
 * (gate-tuple shape: digest = sha256(canonical(payload)), Ed25519 over the
 * digest), then re-verifies it via the open engine. Covers the detector, the
 * crypto, the relabel guard (gate_status must match the signed confidence and
 * freshness), tamper detection, and key pinning.
 *
 * @module test/unit/trusted-context-pack.test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { detectFormat } from '../../src/detect.js';
import { sortKeysDeep } from '../../src/util/canonical.js';
import {
  verifyTrustedContextPack, gateStatusFor, TCB_SCHEMA,
} from '../../src/engines/trusted-context-pack.js';

function mkSigner() {
  const priv = new Uint8Array(randomBytes(32));
  return { priv, vk: bytesToHex(ed25519.getPublicKey(priv)) };
}

function basePayload(over = {}) {
  return {
    schema: TCB_SCHEMA,
    workspace_id: 'meridian',
    source_id: 'tcb-abc123def456-0',
    source_type: 'book_positions',
    source_format: 'csv',
    source_lineage: 'upload',
    file_name: 'positions.csv',
    file_hash: 'a'.repeat(64),
    parser_version: 'tcb/1.0.0',
    parsed_artifacts: { positions: [{ symbol: 'ESH6', market_value: 12500000, sector: 'index', asset_class: 'futures' }] },
    freshness: { as_of: '2026-06-16T00:00:00.000Z', ingested_at: '2026-06-16T12:00:00Z', max_age_days: 3, stale: false },
    confidence: 0.9,
    warnings: [],
    gate_status: 'usable',
    summary: { positions: 1 },
    notice: 'attests the parse, not the provenance',
    ...over,
  };
}

/** Sign a payload as a gate-tuple, exactly as the engine does. */
function signPack(payload, signer = mkSigner()) {
  const hash = sha256(utf8ToBytes(JSON.stringify(sortKeysDeep(payload))));
  return {
    payload,
    digest: bytesToHex(hash),
    signature: bytesToHex(ed25519.sign(hash, signer.priv)),
    verification_key: signer.vk,
  };
}

test('detect classifies the TCB tuple as trusted-context-pack (before the generic gate tuple)', () => {
  const d = detectFormat(signPack(basePayload()));
  assert.equal(d.mode, 'trusted-context-pack');
  assert.ok(d.signals.includes('schema=scopeblind.trusted_context_pack.v1'));
});

test('a genuine pack verifies via the open engine', () => {
  const pack = signPack(basePayload());
  const out = verifyTrustedContextPack(pack);
  assert.equal(out.valid, true, JSON.stringify(out));
  assert.equal(out.format, 'trusted-context-pack');
  assert.equal(out.schemaRecognized, true);
  assert.equal(out.gateStatus, 'usable');
  assert.equal(out.confidence, 0.9);
  assert.equal(out.sourceType, 'book_positions');
  assert.equal(out.publicKey, pack.verification_key);
  assert.ok(Array.isArray(out.proves) && out.proves.length >= 3);
});

test('tampering with the payload breaks the digest', () => {
  const pack = signPack(basePayload());
  pack.payload.parsed_artifacts.positions[0].market_value = 999999999;
  const out = verifyTrustedContextPack(pack);
  assert.equal(out.valid, false);
  assert.equal(out.error, 'digest_mismatch');
});

test('a validly re-signed pack that lies about gate_status is rejected (relabel guard)', () => {
  // needs_approval confidence, but gate_status claims usable, re-signed with a real key.
  const lying = signPack(basePayload({ confidence: 0.5, gate_status: 'usable' }));
  const out = verifyTrustedContextPack(lying);
  assert.equal(out.valid, false);
  assert.equal(out.error, 'schema_invalid');
  assert.match(out.detail, /gate_status/);
});

test('a stale pack must be needs_approval, not usable', () => {
  const stale = signPack(basePayload({ freshness: { as_of: '2026-05-01T00:00:00Z', ingested_at: '2026-06-16T12:00:00Z', max_age_days: 3, stale: true }, gate_status: 'usable' }));
  const out = verifyTrustedContextPack(stale);
  assert.equal(out.valid, false);
  assert.equal(out.error, 'schema_invalid');
});

test('key pinning: a mismatched --key is refused', () => {
  const pack = signPack(basePayload());
  const out = verifyTrustedContextPack(pack, { publicKey: '0'.repeat(64) });
  assert.equal(out.valid, false);
  assert.equal(out.error, 'key_mismatch');
});

test('an invalid source_type fails schema validation', () => {
  const out = verifyTrustedContextPack(signPack(basePayload({ source_type: 'nonsense' })));
  assert.equal(out.valid, false);
  assert.equal(out.error, 'schema_invalid');
});

test('gateStatusFor mirrors the engine semantics', () => {
  const fresh = { stale: false };
  assert.equal(gateStatusFor(0.9, fresh), 'usable');
  assert.equal(gateStatusFor(0.5, fresh), 'needs_approval');
  assert.equal(gateStatusFor(0.9, { stale: true }), 'needs_approval');
  assert.equal(gateStatusFor(0, fresh), 'blocked');
});

test('a nav_account pack is a recognized source type', () => {
  const out = verifyTrustedContextPack(signPack(basePayload({
    source_type: 'nav_account',
    parsed_artifacts: { account: { nav: 500000000, cash: 42000000 } },
    summary: { nav: 500000000 },
  })));
  assert.equal(out.valid, true, JSON.stringify(out))
  assert.equal(out.sourceType, 'nav_account')
});

test('a non-TCB tuple is not claimed by this engine', () => {
  const out = verifyTrustedContextPack(signPack(basePayload({ schema: 'scopeblind.gate.decision/2' })));
  assert.equal(out.valid, false);
  assert.equal(out.error, 'unknown_format');
});
