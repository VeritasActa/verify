/**
 * Connector-action profile: the verifier reaches the outcome each shared
 * vector requires, with and without the platform key, and never takes the
 * gate's recorded check on trust.
 *
 * The vectors are built by protect-mcp (src/connector-vectors.test.ts) and
 * committed at packages/protect-mcp/vectors/connector-action.v1.json.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectFormat } from '../../src/detect.js';
import { verifyReceipt } from '../../src/engines/ed25519-receipt.js';
import { checkConnectorAction, connectorSchemaErrors } from '../../src/engines/connector-action.js';

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, '..', '..', '..', 'protect-mcp', 'vectors', 'connector-action.v1.json');
const suite = existsSync(VECTORS) ? JSON.parse(readFileSync(VECTORS, 'utf8')) : null;

test('the shared vectors are present', { skip: suite ? false : 'protect-mcp vectors not checked out beside this package' }, () => {
  assert.equal(suite.type, 'acta.connector-action.vectors.v1');
  assert.equal(suite.profile, 'draft-farley-acta-connector-action-00');
  assert.ok(suite.vectors.length >= 7);
});

for (const v of suite?.vectors ?? []) {
  test(`vector ${v.id}: ${v.expect.verdict_with_platform_key} with the platform key, ${v.expect.verdict_without_platform_key} without`, async () => {
    const mode = detectFormat(v.receipt).mode;
    const withKey = await verifyReceipt(v.receipt, mode, { publicKey: suite.gate_public_key, platformKeys: suite.platform_keys });
    const withoutKey = await verifyReceipt(v.receipt, mode, { publicKey: suite.gate_public_key });

    assert.equal(withKey.valid, v.expect.verdict_with_platform_key === 'valid', `with key: ${withKey.error} ${JSON.stringify(withKey.connectorAction?.errors)}`);
    assert.equal(withoutKey.valid, v.expect.verdict_without_platform_key === 'valid', `without key: ${withoutKey.error}`);

    const c = withKey.connectorAction;
    assert.ok(c, 'the connector member is reported');
    assert.equal(c.profile, 'draft-farley-acta-connector-action-00');
    assert.equal(c.context_check, v.expect.context_check);
    assert.equal(c.valid ? 'ok' : 'invalid', v.expect.schema === 'invalid' ? 'invalid' : (v.expect.with_platform_key === 'invalid' ? 'invalid' : 'ok'));
    if (v.expect.schema === 'ok') assert.equal(c.platform_signature, v.expect.with_platform_key);
    if (v.expect.effect) assert.equal(c.effect, v.expect.effect);

    // Without the key a presented signature is unverifiable, never a failure by itself.
    const w = withoutKey.connectorAction;
    if (v.expect.schema === 'ok' && v.expect.with_platform_key !== 'absent') {
      assert.equal(w.platform_signature, 'unverifiable');
      assert.ok(w.warnings.some((x) => /no platform key supplied/.test(x)));
    }
    if (v.expect.verdict_with_platform_key === 'invalid' && v.expect.schema === 'ok') {
      assert.equal(withKey.error, 'connector_context_signature_invalid');
    }
    if (v.expect.schema === 'invalid') {
      assert.equal(withKey.error, 'connector_schema_invalid');
      assert.ok(connectorSchemaErrors(v.receipt.payload.connector).length > 0);
    }
  });
}

test('a receipt without the member is untouched by the profile', async () => {
  assert.equal(checkConnectorAction({ type: 'protectmcp:decision', tool_name: 'x' }), null);
});

test('a tampered connector member breaks the gate signature before the profile is even consulted', async () => {
  if (!suite) return;
  const v = suite.vectors.find((x) => x.id === 'signed-context-valid-confirmed');
  const tampered = JSON.parse(JSON.stringify(v.receipt));
  tampered.payload.connector.context.grant.purpose = 'Merge whatever is open';
  const r = await verifyReceipt(tampered, detectFormat(tampered).mode, { publicKey: suite.gate_public_key, platformKeys: suite.platform_keys });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'invalid_signature');
});

test('schema errors name the member that failed', () => {
  const errors = connectorSchemaErrors({ v: 1, context: { type: 'acta:connector-context', platform: 'meta.muse', agent: 'a', grant: { type: 'forever' } }, context_check: 'unsigned', request_digest: 'x' });
  assert.ok(errors.some((e) => /grant\.type/.test(e)));
  assert.ok(errors.some((e) => /request_digest/.test(e)));
});
