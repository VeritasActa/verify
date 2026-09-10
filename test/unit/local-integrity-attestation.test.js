import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  buildCanonicalAttestation,
  verifyAttestation,
} from '../../src/engines/attestation.js';

const sigil = {
  fingerprint: '12345678',
  name: 'Test Commitment',
  sigil_hash: 'a'.repeat(64),
  policy: {
    package: '@veritasacta/verify',
    package_version: '0.9.3',
    ietf_draft: 'draft-farley-acta-signed-receipts-03',
    conformance_tier: 'T4',
  },
};

test('local-integrity attestation preserves legacy field without overclaiming provenance', () => {
  const root = mkdtempSync(join(tmpdir(), 'veritasacta-local-integrity-'));
  try {
    const artifact = buildCanonicalAttestation({
      sigil,
      canonical: true,
      keyPath: join(root, 'attester.json'),
    });
    assert.equal(artifact.payload.integrity_matches, true);
    assert.equal(artifact.payload.canonical, true);
    assert.equal(artifact.payload.publisher_authenticated, false);
    assert.equal(artifact.payload.assurance, 'self_signed_operator_statement');
    assert.equal(
      verifyAttestation(artifact, artifact.verification.attester_pubkey),
      true,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
