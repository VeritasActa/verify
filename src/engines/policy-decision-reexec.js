/**
 * @veritasacta/verify — Re-executable Policy Decision Receipt engine (AIP-0010).
 *
 * Verifies an authorization decision by RE-EXECUTING the policy engine over the
 * policy and inputs carried in the receipt and comparing the result to the
 * recorded decision. Correctness of the decision therefore rests on re-execution
 * of open, deterministic code, not on trusting the party that produced the
 * receipt. See specs/aip/AIP-0010-reexecutable-policy-decision-receipts.md.
 *
 * The bundled evaluator implements a faithful SUBSET of Cedar's evaluation
 * semantics (default-deny, forbid-overrides-permit, scope plus when/unless
 * conditions over context and entity attributes), sufficient to exercise and
 * demonstrate the re-execution mechanism. Production verifiers pass the official
 * Cedar engine identified by `receipt.engine` via the `engine` option.
 *
 * @module verify-cli/src/engines/policy-decision-reexec
 * @license Apache-2.0
 */

import { canonicalize, sha256Hex } from "../util/canonical.js";

const RECEIPT_TYPE = "scopeblind.policy_decision.v1";

/** Commitment helper: "sha256:" + hex(JCS(obj)). */
export function commit(obj) {
  return `sha256:${sha256Hex(canonicalize(obj))}`;
}

// ───────────────────────── faithful Cedar subset evaluator ─────────────────────────

/**
 * Evaluate a Cedar-subset policy set over a request and entity store.
 *
 * policySet: { policies: [ { id, effect: "permit"|"forbid",
 *   principal?: scope, action?: scope, resource?: scope,
 *   conditions?: [ { kind: "when"|"unless", expr } ] } ] }
 * scope: { op: "All" } | { op: "==", entity } | { op: "in", entity }
 * expr:  { op: "==|!=|<|<=|>|>=", left: ref, right: ref }
 *        | { op: "and"|"or", clauses: [expr...] } | { op: "not", clause: expr }
 * ref:   { attr: "context.x" | "resource.x" | "principal.x" } | { value: literal }
 *
 * Returns { outcome: "permit"|"deny", determining_policies: string[], errors: [] }.
 * Semantics: default deny; a request is permitted iff at least one permit policy
 * is satisfied and no forbid policy is satisfied (forbid overrides).
 */
export function evaluateCedarSubset(policySet, request, entities) {
  const errors = [];
  const entityMap = new Map((entities || []).map((e) => [e.uid, e]));
  const policies = (policySet && policySet.policies) || [];

  const satisfiedForbid = [];
  const satisfiedPermit = [];

  for (const p of policies) {
    let sat;
    try {
      sat = policySatisfied(p, request, entityMap);
    } catch (e) {
      errors.push({ policy: p.id, error: String(e.message || e) });
      sat = false; // a policy that errors is not satisfied (Cedar skips erroring policies)
    }
    if (!sat) continue;
    if (p.effect === "forbid") satisfiedForbid.push(p.id);
    else if (p.effect === "permit") satisfiedPermit.push(p.id);
  }

  if (satisfiedForbid.length > 0) {
    return { outcome: "deny", determining_policies: satisfiedForbid.sort(), errors };
  }
  if (satisfiedPermit.length > 0) {
    return { outcome: "permit", determining_policies: satisfiedPermit.sort(), errors };
  }
  return { outcome: "deny", determining_policies: [], errors };
}

function policySatisfied(policy, request, entityMap) {
  if (!scopeSatisfied(policy.principal, request.principal, entityMap)) return false;
  if (!scopeSatisfied(policy.action, request.action, entityMap)) return false;
  if (!scopeSatisfied(policy.resource, request.resource, entityMap)) return false;
  for (const cond of policy.conditions || []) {
    const value = Boolean(evalExpr(cond.expr, request, entityMap));
    if (cond.kind === "when" && !value) return false;
    if (cond.kind === "unless" && value) return false;
  }
  return true;
}

function scopeSatisfied(scope, uid, entityMap) {
  if (!scope || scope.op === "All") return true;
  if (scope.op === "==") return uid === scope.entity;
  if (scope.op === "in") return uid === scope.entity || isDescendantOf(uid, scope.entity, entityMap);
  throw new Error(`unsupported_scope_op:${scope.op}`);
}

function isDescendantOf(uid, ancestor, entityMap, seen = new Set()) {
  if (seen.has(uid)) return false;
  seen.add(uid);
  const ent = entityMap.get(uid);
  const parents = (ent && ent.parents) || [];
  if (parents.includes(ancestor)) return true;
  return parents.some((p) => isDescendantOf(p, ancestor, entityMap, seen));
}

function evalExpr(expr, request, entityMap) {
  if (!expr || typeof expr !== "object") throw new Error("bad_expr");
  switch (expr.op) {
    case "and": return (expr.clauses || []).every((c) => Boolean(evalExpr(c, request, entityMap)));
    case "or": return (expr.clauses || []).some((c) => Boolean(evalExpr(c, request, entityMap)));
    case "not": return !evalExpr(expr.clause, request, entityMap);
    case "==": case "!=": case "<": case "<=": case ">": case ">=": {
      const l = resolveRef(expr.left, request, entityMap);
      const r = resolveRef(expr.right, request, entityMap);
      return compare(expr.op, l, r);
    }
    default: throw new Error(`unsupported_op:${expr.op}`);
  }
}

function compare(op, l, r) {
  switch (op) {
    case "==": return l === r;
    case "!=": return l !== r;
    case "<": return l < r;
    case "<=": return l <= r;
    case ">": return l > r;
    case ">=": return l >= r;
    default: return false;
  }
}

function resolveRef(ref, request, entityMap) {
  if (ref == null || typeof ref !== "object") throw new Error("bad_ref");
  if ("value" in ref) return ref.value;
  if ("attr" in ref) {
    const [root, ...path] = String(ref.attr).split(".");
    let base;
    if (root === "context") base = request.context || {};
    else if (root === "principal") base = attrsOf(request.principal, entityMap);
    else if (root === "resource") base = attrsOf(request.resource, entityMap);
    else if (root === "action") base = attrsOf(request.action, entityMap);
    else throw new Error(`unknown_ref_root:${root}`);
    let cur = base;
    for (const key of path) {
      if (cur == null) return undefined;
      cur = cur[key];
    }
    return cur;
  }
  throw new Error("bad_ref");
}

function attrsOf(uid, entityMap) {
  const e = entityMap.get(uid);
  return (e && e.attrs) || {};
}

// ───────────────────────── the verifier ─────────────────────────

/**
 * Verify a Re-executable Policy Decision Receipt.
 *
 * @param {object} receipt
 * @param {object} [opts]
 * @param {function} [opts.engine] policy engine (default: bundled Cedar subset)
 * @param {function} [opts.verifySignature] (receipt) => boolean, authenticity check
 * @param {string}   [opts.expectedPolicyDigest] catalog/transparency-pinned digest
 * @param {{name:string,version:string,digest?:string}} [opts.engineInfo] local engine identity
 * @param {boolean}  [opts.allowCommitted=true] treat committed-mode as authenticity-only valid
 * @returns {{ valid:boolean, reason:string, checks:object, claims:object, recomputed?:object }}
 */
export function verifyPolicyDecisionReceipt(receipt, opts = {}) {
  const engine = opts.engine || evaluateCedarSubset;
  const checks = {};
  const claims = {};
  const done = (valid, reason, extra = {}) => ({ valid, reason, checks, claims, ...extra });

  if (!receipt || receipt.type !== RECEIPT_TYPE) return done(false, "wrong_type");
  if (!receipt.policy || !receipt.decision || !receipt.engine) return done(false, "missing_fields");

  // 1. Authenticity (optional, independent of correctness).
  if (opts.verifySignature && receipt.signature) {
    const ok = Boolean(opts.verifySignature(receipt));
    checks.authenticity = ok ? "verified" : "failed";
    if (!ok) return done(false, "signature_invalid");
    claims.authenticity = "signature";
  } else {
    checks.authenticity = "skipped";
  }

  // 2. Policy integrity (digest of inline policy, plus optional catalog pin).
  if (receipt.policy.inline !== undefined) {
    const digest = commit(receipt.policy.inline);
    if (receipt.policy.digest && digest !== receipt.policy.digest) {
      checks.policy_integrity = "mismatch";
      return done(false, "policy_digest_mismatch");
    }
    checks.policy_integrity = "verified";
  } else {
    checks.policy_integrity = "unresolved"; // policy carried by ref; caller must resolve+hash
  }
  if (opts.expectedPolicyDigest && receipt.policy.digest !== opts.expectedPolicyDigest) {
    checks.policy_identity = "substituted";
    return done(false, "policy_substitution");
  }

  // 3. Engine pin.
  if (opts.engineInfo) {
    const e = receipt.engine;
    const pinned = opts.engineInfo.name === e.name && opts.engineInfo.version === e.version
      && (!e.digest || !opts.engineInfo.digest || e.digest === opts.engineInfo.digest);
    if (!pinned) {
      checks.engine = "unavailable";
      claims.correctness = "engine_unavailable";
      return done(false, "engine_unavailable");
    }
    checks.engine = "pinned";
  }

  // 4. Committed mode: inputs withheld -> correctness CANNOT be checked here.
  if (receipt.disclosure === "committed") {
    checks.input_integrity = "committed";
    checks.correctness = "not_checked_inputs_hidden";
    claims.correctness = "not_checked_inputs_hidden";
    const valid = opts.allowCommitted !== false; // authenticity-only validity
    return done(valid, "inputs_committed_authenticity_only", { authenticityOnly: true });
  }

  // 5. Input integrity: the disclosed inputs must match the commitment.
  const recomputedCommit = commit({ request: receipt.request, entities: receipt.entities });
  if (receipt.input_commitment && recomputedCommit !== receipt.input_commitment) {
    checks.input_integrity = "mismatch";
    return done(false, "input_commitment_mismatch");
  }
  checks.input_integrity = "verified";

  // 6. RE-EXECUTION (the core): recompute the decision and compare.
  let recomputed;
  try {
    recomputed = engine(receipt.policy.inline, receipt.request, receipt.entities);
  } catch (e) {
    return done(false, `engine_error:${e.message || e}`);
  }
  const outcomeMatch = normOutcome(recomputed.outcome) === normOutcome(receipt.decision.outcome);
  const detMatch = sameSet(recomputed.determining_policies, receipt.decision.determining_policies);
  if (!outcomeMatch || !detMatch) {
    checks.correctness = "decision_mismatch";
    return done(false, "decision_mismatch", { recomputed });
  }
  checks.correctness = "verified_by_reexecution";
  claims.correctness = "re-execution";

  return done(true, "valid", { recomputed });
}

function normOutcome(o) {
  return o === "forbid" ? "deny" : o; // treat forbid/deny as the same negative outcome
}

function sameSet(a, b) {
  const sa = [...new Set(a || [])].sort();
  const sb = [...new Set(b || [])].sort();
  return sa.length === sb.length && sa.every((x, i) => x === sb[i]);
}
