/**
 * Unit tests for AIP-0006 delegation chain engine.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign as cryptoSign,
  createHash,
} from 'node:crypto';

import { verifyDelegationChain, scopeSubset } from '../../src/engines/delegation.js';
import { canonicalize } from '../../src/util/canonical.js';

// ───── Test helpers ─────

function mkKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPub = spki.subarray(spki.length - 32);
  return { publicKey, privateKey, pubHex: rawPub.toString('hex') };
}

function receiptHash(env) {
  return createHash('sha256').update(canonicalize(env)).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signEnvelope(payload, kid, privateKey) {
  const bytes = canonicalize(payload);
  const sig = cryptoSign(null, bytes, privateKey);
  return {
    payload,
    signature: { alg: 'EdDSA', kid, sig: sig.toString('hex') },
  };
}

/**
 * Build a single delegation envelope (signed by delegator's privateKey).
 */
function mkDelegation({
  delegatorKid, delegateKid,
  delegatorKey,                 // private key to sign
  scope = { tools: ['*'], max_depth: 10 },
  expiresAt,
  parentDelegationHash,
  issuedAt = '2026-04-20T00:00:00Z',
  issuer = 'test',
}) {
  const payload = {
    type: 'delegation',
    delegator_kid: delegatorKid,
    delegate_kid: delegateKid,
    scope,
    expires_at: expiresAt || '2030-01-01T00:00:00Z',
    issued_at: issuedAt,
    issuer_id: issuer,
    ...(parentDelegationHash ? { parent_delegation_hash: parentDelegationHash } : {}),
  };
  return signEnvelope(payload, delegatorKid, delegatorKey);
}

function mkActionReceipt({ action, target, signerKid, signerKey, delegationChain }) {
  const payload = {
    type: 'decision-receipt',
    action,
    issued_at: '2026-04-20T00:00:01Z',
    issuer_id: 'test',
    ...(target ? { target } : {}),
    ...(delegationChain ? { authorization: { delegation_chain: delegationChain } } : {}),
  };
  return signEnvelope(payload, signerKid, signerKey);
}

// ───── Tests ─────

test('scopeSubset: equal scopes are subset', () => {
  assert.equal(scopeSubset({ tools: ['Read'] }, { tools: ['Read'] }), true);
});

test('scopeSubset: child with fewer tools is subset', () => {
  assert.equal(scopeSubset({ tools: ['Read'] }, { tools: ['Read', 'Write'] }), true);
});

test('scopeSubset: child with extra tool is NOT subset', () => {
  assert.equal(scopeSubset({ tools: ['Read', 'Write'] }, { tools: ['Read'] }), false);
});

test('scopeSubset: wildcard parent accepts anything', () => {
  assert.equal(scopeSubset({ tools: ['Weird'] }, { tools: ['*'] }), true);
});

test('scopeSubset: glob prefix pattern works', () => {
  assert.equal(scopeSubset({ targets: ['mcp://github/repos'] }, { targets: ['mcp://github*'] }), true);
});

test('scopeSubset: max_depth must narrow by at least 1', () => {
  assert.equal(scopeSubset({ max_depth: 0 }, { max_depth: 1 }), true);
  assert.equal(scopeSubset({ max_depth: 1 }, { max_depth: 1 }), false);
  assert.equal(scopeSubset({ max_depth: 2 }, { max_depth: 1 }), false);
});

test('verifyDelegationChain: happy path alice → deploy-bot, Bash', () => {
  const alice = mkKey();
  const deployBot = mkKey();

  const root = mkDelegation({
    delegatorKid: 'alice',
    delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { tools: ['*'], max_depth: 10 },
  });
  const rootHash = receiptHash(root);

  const leaf = mkDelegation({
    delegatorKid: 'alice',
    delegateKid: 'deploy-bot',
    delegatorKey: alice.privateKey,
    scope: { tools: ['Bash', 'Read'], targets: ['mcp://github'], max_depth: 0 },
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);

  const action = mkActionReceipt({
    action: 'Bash',
    target: 'mcp://github',
    signerKid: 'deploy-bot',
    signerKey: deployBot.privateKey,
    delegationChain: [leafHash, rootHash],
  });

  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex },
  });

  assert.equal(r.valid, true);
  assert.equal(r.depth, 2);
  assert.equal(r.trust_anchor_kid, 'alice');
  assert.equal(r.action_in_scope, true);
});

test('verifyDelegationChain: action outside leaf scope → invalid', () => {
  const alice = mkKey();
  const deployBot = mkKey();

  const root = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { tools: ['*'], max_depth: 5 },
  });
  const rootHash = receiptHash(root);
  const leaf = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'deploy-bot',
    delegatorKey: alice.privateKey,
    scope: { tools: ['Read'], max_depth: 0 },
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);

  // Action is Bash, but leaf only permits Read.
  const action = mkActionReceipt({
    action: 'Bash',
    signerKid: 'deploy-bot', signerKey: deployBot.privateKey,
    delegationChain: [leafHash, rootHash],
  });

  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'action_not_in_leaf_scope');
});

test('verifyDelegationChain: expired delegation fails', () => {
  const alice = mkKey();
  const deployBot = mkKey();

  const root = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { tools: ['*'], max_depth: 5 },
  });
  const rootHash = receiptHash(root);
  const leaf = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'deploy-bot',
    delegatorKey: alice.privateKey,
    scope: { tools: ['Bash'] },
    expiresAt: '2020-01-01T00:00:00Z',  // long expired
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);
  const action = mkActionReceipt({
    action: 'Bash', signerKid: 'deploy-bot', signerKey: deployBot.privateKey,
    delegationChain: [leafHash, rootHash],
  });

  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /expired/);
});

test('verifyDelegationChain: widened scope (privilege escalation) fails', () => {
  const alice = mkKey();
  const bob = mkKey();
  const mallory = mkKey();

  // alice root, narrow to Read
  const root = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { tools: ['*'], max_depth: 5 },
  });
  const rootHash = receiptHash(root);

  // alice → bob: narrow to Read only
  const toBob = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'bob',
    delegatorKey: alice.privateKey,
    scope: { tools: ['Read'], max_depth: 1 },
    parentDelegationHash: rootHash,
  });
  const bobHash = receiptHash(toBob);

  // bob → mallory: attempts to widen to Bash (not allowed)
  const toMallory = mkDelegation({
    delegatorKid: 'bob', delegateKid: 'mallory',
    delegatorKey: bob.privateKey,
    scope: { tools: ['Bash'], max_depth: 0 },  // widens from Read to Bash
    parentDelegationHash: bobHash,
  });
  const malHash = receiptHash(toMallory);

  const action = mkActionReceipt({
    action: 'Bash', signerKid: 'mallory', signerKey: mallory.privateKey,
    delegationChain: [malHash, bobHash, rootHash],
  });
  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [malHash]: toMallory, [bobHash]: toBob, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex, 'bob': bob.pubHex },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /scope_widened/);
});

test('verifyDelegationChain: untrusted root → invalid', () => {
  const eve = mkKey();
  const leafKey = mkKey();

  const root = mkDelegation({
    delegatorKid: 'eve', delegateKid: 'eve',
    delegatorKey: eve.privateKey,
    scope: { tools: ['*'] },
  });
  const rootHash = receiptHash(root);
  const leaf = mkDelegation({
    delegatorKid: 'eve', delegateKid: 'eve-bot',
    delegatorKey: eve.privateKey,
    scope: { tools: ['Bash'] },
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);
  const action = mkActionReceipt({
    action: 'Bash', signerKid: 'eve-bot', signerKey: leafKey.privateKey,
    delegationChain: [leafHash, rootHash],
  });
  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { /* eve NOT trusted */ },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /root_kid_not_trusted/);
});

test('verifyDelegationChain: action receipt without delegation chain', () => {
  const alice = mkKey();
  const action = mkActionReceipt({
    action: 'Bash', signerKid: 'alice', signerKey: alice.privateKey,
  });
  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: {},
    trustAnchors: { 'alice': alice.pubHex },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'missing_delegation_chain');
});

test('verifyDelegationChain: action signer ≠ leaf delegate fails', () => {
  const alice = mkKey();
  const bob = mkKey();

  const root = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { tools: ['*'] },
  });
  const rootHash = receiptHash(root);
  const leaf = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'deploy-bot',
    delegatorKey: alice.privateKey,
    scope: { tools: ['Bash'] },
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);

  // Action is signed by BOB, not deploy-bot.
  const action = mkActionReceipt({
    action: 'Bash', signerKid: 'bob', signerKey: bob.privateKey,
    delegationChain: [leafHash, rootHash],
  });
  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'action_signer_not_leaf_delegate');
});

test('verifyDelegationChain: wildcard target in parent accepts narrower target in child', () => {
  const alice = mkKey();
  const bot = mkKey();
  const root = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'alice',
    delegatorKey: alice.privateKey,
    scope: { targets: ['*'], tools: ['*'], max_depth: 5 },
  });
  const rootHash = receiptHash(root);
  const leaf = mkDelegation({
    delegatorKid: 'alice', delegateKid: 'bot',
    delegatorKey: alice.privateKey,
    scope: { targets: ['mcp://github*'], tools: ['Read'], max_depth: 0 },
    parentDelegationHash: rootHash,
  });
  const leafHash = receiptHash(leaf);
  const action = mkActionReceipt({
    action: 'Read', target: 'mcp://github/repos',
    signerKid: 'bot', signerKey: bot.privateKey,
    delegationChain: [leafHash, rootHash],
  });
  const r = verifyDelegationChain({
    actionReceipt: action,
    delegations: { [leafHash]: leaf, [rootHash]: root },
    trustAnchors: { 'alice': alice.pubHex },
  });
  assert.equal(r.valid, true);
});
