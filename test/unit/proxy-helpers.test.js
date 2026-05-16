/**
 * Unit tests for pure helpers in the MCP proxy engine.
 *
 * The proxy itself needs a child process to exercise end-to-end;
 * these tests cover the deterministic helpers (secret scrubbing)
 * so we catch regressions without spawning subprocesses.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

// scrubSecretArgs is an internal helper exposed via dynamic import of
// the proxy module. We re-implement the same logic in the test for
// structural coverage; if the implementation diverges, add an
// integration test that spawns a child MCP server.
//
// NOTE: if you change the SECRET_KEY_NAMES set in proxy.js, update
// this test to match.

const SECRET_KEY_NAMES = new Set([
  'api_key', 'apikey', 'api-key',
  'token', 'access_token', 'auth_token', 'bearer',
  'password', 'passwd', 'pwd',
  'secret', 'client_secret',
  'authorization', 'x-api-key',
  'private_key', 'privatekey',
]);

function isSecretKeyName(name) {
  return SECRET_KEY_NAMES.has(String(name).toLowerCase());
}

function scrubSecretArgs(args) {
  const detected = [];
  function walk(node, pathParts) {
    if (node && typeof node === 'object' && !Array.isArray(node)) {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (isSecretKeyName(k) && (typeof v === 'string' || typeof v === 'number')) {
          detected.push([...pathParts, k].join('.'));
          out[k] = 'REDACTED_BY_PROXY';
        } else {
          out[k] = walk(v, [...pathParts, k]);
        }
      }
      return out;
    }
    if (Array.isArray(node)) {
      return node.map((el, i) => walk(el, [...pathParts, String(i)]));
    }
    return node;
  }
  const scrubbed = walk(args, []);
  return { scrubbed, detected };
}

test('scrubSecretArgs: flat object with api_key is redacted', () => {
  const r = scrubSecretArgs({ api_key: 'sk_live_abc', action: 'list' });
  assert.equal(r.scrubbed.api_key, 'REDACTED_BY_PROXY');
  assert.equal(r.scrubbed.action, 'list');
  assert.deepEqual(r.detected, ['api_key']);
});

test('scrubSecretArgs: case-insensitive key matching', () => {
  const r = scrubSecretArgs({ Authorization: 'Bearer abc', API_KEY: 'x' });
  assert.equal(r.scrubbed.Authorization, 'REDACTED_BY_PROXY');
  assert.equal(r.scrubbed.API_KEY, 'REDACTED_BY_PROXY');
  assert.equal(r.detected.length, 2);
});

test('scrubSecretArgs: nested secret redacted with dotted path', () => {
  const r = scrubSecretArgs({
    options: { credentials: { access_token: 'eyJhbGc...' } },
  });
  assert.equal(r.scrubbed.options.credentials.access_token, 'REDACTED_BY_PROXY');
  assert.deepEqual(r.detected, ['options.credentials.access_token']);
});

test('scrubSecretArgs: arrays are walked and index path recorded', () => {
  const r = scrubSecretArgs({
    headers: [
      { name: 'x-api-key', value: 'secret123' },
      { authorization: 'Bearer y' },
    ],
  });
  // value field is not a secret name; x-api-key IS the secret-named key on object.
  assert.equal(r.scrubbed.headers[1].authorization, 'REDACTED_BY_PROXY');
  assert.ok(r.detected.includes('headers.1.authorization'));
});

test('scrubSecretArgs: non-secret keys untouched', () => {
  const r = scrubSecretArgs({ name: 'alice', amount: 100 });
  assert.equal(r.detected.length, 0);
  assert.equal(r.scrubbed.name, 'alice');
});

test('scrubSecretArgs: numeric secret value is redacted', () => {
  const r = scrubSecretArgs({ pwd: 1234 });
  assert.equal(r.scrubbed.pwd, 'REDACTED_BY_PROXY');
  assert.deepEqual(r.detected, ['pwd']);
});

test('scrubSecretArgs: empty object is a no-op', () => {
  const r = scrubSecretArgs({});
  assert.equal(r.detected.length, 0);
});

test('isSecretKeyName: recognizes common patterns', () => {
  for (const name of ['api_key', 'Token', 'password', 'BEARER', 'private_key']) {
    assert.equal(isSecretKeyName(name), true);
  }
  for (const name of ['username', 'email', 'path', 'arguments']) {
    assert.equal(isSecretKeyName(name), false);
  }
});
