import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { verifyVoprfToken } from '../../src/engines/voprf-token.js';

// Synthetic frozen transcript, constructed separately by the fixture generator.
// No production issuer or private monorepo is needed; see fixtures/README.md.
const fixture = JSON.parse(readFileSync(new URL('../fixtures/standalone/brass-v2.json', import.meta.url), 'utf8'));
const options = { issuerPublicKey: fixture.issuer_public_key, expectedKid: fixture.token.kid };

test('synthetic BRASS v2 verifies only with the pinned issuer key', async () => {
  const ok = await verifyVoprfToken(fixture.token, options);
  assert.equal(ok.valid, true, ok.error);
  assert.equal(ok.dleq.issuer, true);
  assert.equal(ok.dleq.client, true);
  assert.equal(ok.nullifier, fixture.expected_nullifier);
  const unpinned = await verifyVoprfToken(fixture.token);
  assert.equal(unpinned.valid, false);
  assert.equal(unpinned.error, 'issuer_key_pin_required');
  const wrongKey = await verifyVoprfToken(fixture.token, { ...options, issuerPublicKey: 'other' });
  assert.equal(wrongKey.valid, false);
  assert.equal(wrongKey.error, 'issuer_key_mismatch');
  const wrongKid = await verifyVoprfToken(fixture.token, { ...options, expectedKid: 'other' });
  assert.equal(wrongKid.valid, false);
  assert.equal(wrongKid.error, 'kid_mismatch');
});

test('synthetic BRASS v2 rejects transcript tampering', async () => {
  for (const field of ['d', 'c_nonce', 'origin', 'policy']) {
    const proof = { ...fixture.token, [field]: 'changed' };
    const result = await verifyVoprfToken(proof, options);
    assert.equal(result.valid, false, field);
    assert.equal(result.error, 'invalid_piC', field);
  }
  const changedScope = await verifyVoprfToken({ ...fixture.token, scope: 'changed' }, options);
  assert.equal(changedScope.error, 'scope_point_mismatch');
  const changedIssuerProof = await verifyVoprfToken({ ...fixture.token, piI: { ...fixture.token.piI, z: 'AQ' } }, options);
  assert.equal(changedIssuerProof.error, 'invalid_piI');
  const missingProof = await verifyVoprfToken({ ...fixture.token, piC: null }, options);
  assert.equal(missingProof.error, 'missing_proofs');
});
