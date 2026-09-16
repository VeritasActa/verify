/**
 * Unit tests for pure helpers in the MCP proxy engine.
 *
 * The proxy itself needs a child process to exercise end-to-end;
 * these tests cover the deterministic helpers (secret scrubbing)
 * so we catch regressions without spawning subprocesses.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {scrubSecretArgs,hashToolInput} from '../../src/engines/proxy.js';
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
    assert.equal(scrubSecretArgs({[name]:'s'}).detected.length,1);
  }
  for (const name of ['username', 'email', 'path', 'arguments']) {
    assert.equal(scrubSecretArgs({[name]:'s'}).detected.length,0);
  }
});

test('complete nested payment arguments affect the proxy hash',()=>{
 const x={payment:{amount:100,beneficiary:{id:'a'}},items:[{amount:2}]};
 for(const y of [{...x,payment:{...x.payment,amount:101}},{...x,payment:{...x.payment,beneficiary:{id:'b'}}},{...x,items:[{amount:3}]}]) assert.notEqual(hashToolInput(x),hashToolInput(y));
 assert.equal(hashToolInput(x),hashToolInput({items:[{amount:2}],payment:{beneficiary:{id:'a'},amount:100}}));
});
test('hashing and scrubbing retain prototype-named and Unicode members',()=>{
 const x=JSON.parse('{"2":2,"10":10,"__proto__":{"secret":1},"é":true}');
 assert.notEqual(hashToolInput(x),hashToolInput({'2':2,'10':10,'é':true}));
 const s=scrubSecretArgs(x).scrubbed;assert.ok(Object.hasOwn(s,'__proto__'));assert.equal(s.__proto__.secret,'REDACTED_BY_PROXY');
});
