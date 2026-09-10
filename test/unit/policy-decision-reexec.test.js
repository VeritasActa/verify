/**
 * Tests for the Re-executable Policy Decision Receipt verifier (AIP-0010).
 *
 * The point being demonstrated: the verifier does not trust the receipt's
 * `decision` field. It re-runs the policy engine over the policy and inputs and
 * catches any receipt whose recorded decision the policy would not actually
 * produce, including a self-consistent lie where the producer also updates the
 * input commitment.
 *
 * Run: node --test packages/verify-cli/test/unit/policy-decision-reexec.test.js
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  verifyPolicyDecisionReceipt, evaluateCedarSubset, commit,
} from "../../src/engines/policy-decision-reexec.js";

const POLICY = {
  policies: [
    {
      id: "policy-allow-alice-read",
      effect: "permit",
      principal: { op: "==", entity: 'User::"alice"' },
      action: { op: "==", entity: 'Action::"read"' },
      resource: { op: "==", entity: 'Document::"doc-42"' },
      conditions: [
        { kind: "when", expr: { op: "==", left: { attr: "context.mfa" }, right: { value: true } } },
      ],
    },
    {
      id: "policy-forbid-secret",
      effect: "forbid",
      principal: { op: "All" },
      action: { op: "All" },
      resource: { op: "All" },
      conditions: [
        { kind: "when", expr: { op: "==", left: { attr: "resource.classification" }, right: { value: "secret" } } },
      ],
    },
  ],
};

function baseInputs() {
  return {
    request: {
      principal: 'User::"alice"',
      action: 'Action::"read"',
      resource: 'Document::"doc-42"',
      context: { mfa: true },
    },
    entities: [
      { uid: 'Document::"doc-42"', attrs: { classification: "internal" }, parents: [] },
    ],
  };
}

function buildReceipt({ request, entities }, decision, overrides = {}) {
  return {
    type: "scopeblind.policy_decision.v1",
    v: 1,
    issued_at: "2026-05-30T00:00:00Z",
    engine: { name: "cedar", version: "4.2.0", semantics: "cedar-policy" },
    policy: { set_id: "sample", inline: POLICY, digest: commit(POLICY) },
    request,
    entities,
    input_commitment: commit({ request, entities }),
    disclosure: "full",
    decision,
    ...overrides,
  };
}

const clone = (x) => JSON.parse(JSON.stringify(x));

test("evaluator: permit when policy is satisfied", () => {
  const i = baseInputs();
  const d = evaluateCedarSubset(POLICY, i.request, i.entities);
  assert.equal(d.outcome, "permit");
  assert.deepEqual(d.determining_policies, ["policy-allow-alice-read"]);
});

test("evaluator: forbid overrides permit when resource is secret", () => {
  const i = baseInputs();
  i.entities[0].attrs.classification = "secret";
  const d = evaluateCedarSubset(POLICY, i.request, i.entities);
  assert.equal(d.outcome, "deny");
  assert.deepEqual(d.determining_policies, ["policy-forbid-secret"]);
});

test("evaluator: default deny when mfa missing", () => {
  const i = baseInputs();
  i.request.context.mfa = false;
  const d = evaluateCedarSubset(POLICY, i.request, i.entities);
  assert.equal(d.outcome, "deny");
  assert.deepEqual(d.determining_policies, []);
});

test("honest receipt verifies by re-execution", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, true, res.reason);
  assert.equal(res.checks.correctness, "verified_by_reexecution");
  assert.equal(res.claims.correctness, "re-execution");
});

test("tampered decision (permit faked) is caught by re-execution", () => {
  const i = baseInputs();
  i.request.context.mfa = false; // policy would deny
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, false);
  assert.equal(res.reason, "decision_mismatch");
  assert.equal(res.recomputed.outcome, "deny");
});

test("self-consistent lie (input + commitment updated) is still caught by re-execution", () => {
  // The producer flips mfa to false AND recomputes the commitment to match,
  // but keeps the decision as permit. Re-execution recomputes deny -> caught.
  const i = baseInputs();
  i.request.context.mfa = false;
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  // commitment already recomputed by buildReceipt over the tampered inputs
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, false);
  assert.equal(res.reason, "decision_mismatch");
});

test("tampered input without updating the commitment is caught by the commitment check", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  r.entities[0].attrs.classification = "secret"; // mutate after commitment fixed
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, false);
  assert.equal(res.reason, "input_commitment_mismatch");
});

test("policy substitution with stale digest is caught", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  // swap in an all-permit policy but keep the original digest
  r.policy.inline = { policies: [{ id: "p", effect: "permit", principal: { op: "All" }, action: { op: "All" }, resource: { op: "All" } }] };
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, false);
  assert.equal(res.reason, "policy_digest_mismatch");
});

test("policy substitution with updated digest is caught by catalog pin", () => {
  const i = baseInputs();
  const expected = commit(POLICY);
  const evil = { policies: [{ id: "p", effect: "permit", principal: { op: "All" }, action: { op: "All" }, resource: { op: "All" } }] };
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["p"], errors: [] });
  r.policy.inline = evil;
  r.policy.digest = commit(evil); // internally consistent now
  const res = verifyPolicyDecisionReceipt(r, { expectedPolicyDigest: expected });
  assert.equal(res.valid, false);
  assert.equal(res.reason, "policy_substitution");
});

test("engine version mismatch refuses to claim correctness", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  const res = verifyPolicyDecisionReceipt(r, { engineInfo: { name: "cedar", version: "3.0.0" } });
  assert.equal(res.valid, false);
  assert.equal(res.reason, "engine_unavailable");
});

test("committed mode verifies authenticity only, not correctness", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] });
  r.disclosure = "committed";
  delete r.request;
  delete r.entities;
  const res = verifyPolicyDecisionReceipt(r);
  assert.equal(res.valid, true);
  assert.equal(res.authenticityOnly, true);
  assert.equal(res.claims.correctness, "not_checked_inputs_hidden");
});

test("signature is optional and pluggable", () => {
  const i = baseInputs();
  const r = buildReceipt(i, { outcome: "permit", determining_policies: ["policy-allow-alice-read"], errors: [] }, { signature: "stub" });
  const bad = verifyPolicyDecisionReceipt(r, { verifySignature: () => false });
  assert.equal(bad.valid, false);
  assert.equal(bad.reason, "signature_invalid");
  const good = verifyPolicyDecisionReceipt(r, { verifySignature: () => true });
  assert.equal(good.valid, true, good.reason);
  assert.equal(good.claims.authenticity, "signature");
  assert.equal(good.claims.correctness, "re-execution");
});
