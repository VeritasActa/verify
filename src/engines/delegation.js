/**
 * @veritasacta/verify — delegation chain engine (AIP-0006).
 *
 * Walks a chain of `delegation` receipts back to a trust-anchor root,
 * validating signatures, expiry, scope-subset, and max_depth at each
 * hop. An action receipt's `authorization.delegation_chain` references
 * delegations by their receipt_hash; this engine resolves the chain
 * from a caller-supplied map and returns a structured verdict.
 *
 * This engine does NOT verify the action receipt's own signature —
 * that is the caller's responsibility (typically via the Ed25519
 * receipt engine). Delegation verification adds the "who authorized
 * this" layer on top of "who signed this".
 *
 * @module verify-cli/src/engines/delegation
 * @license Apache-2.0
 */

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { canonicalize } from '../util/canonical.js';

/**
 * @typedef {Object} DelegationScope
 * @property {string[]} [tools]
 * @property {string[]} [targets]
 * @property {string[]} [resources]
 * @property {number} [max_depth]
 */

/**
 * @typedef {Object} DelegationVerifyOptions
 * @property {Object} actionReceipt                Signed action receipt with
 *   `payload.authorization.delegation_chain`.
 * @property {Object<string,Object>} delegations   Map: base64url receipt_hash → delegation envelope.
 * @property {Object<string,string>} trustAnchors  Map: kid → raw Ed25519 public-key hex (64 chars).
 * @property {Date} [now=new Date()]               Current time for expiry checks.
 * @property {number} [clockSkewSec=5]             Allowed clock skew in seconds.
 */

/**
 * @typedef {Object} DelegationVerifyResult
 * @property {boolean} valid
 * @property {string} [error]
 * @property {number} depth                        Number of delegations in the chain.
 * @property {Array<{hash: string, delegator_kid: string, delegate_kid: string, scope: DelegationScope, expires_at: string, ok: boolean, reason?: string}>} chain
 * @property {string} [trust_anchor_kid]           The root's delegator_kid that was validated.
 * @property {Object} [leaf_scope]                 The resolved scope at the leaf.
 * @property {boolean} [action_in_scope]
 */

/**
 * Verify a delegation chain backing an action receipt.
 *
 * @param {DelegationVerifyOptions} opts
 * @returns {DelegationVerifyResult}
 */
export function verifyDelegationChain(opts) {
  const {
    actionReceipt,
    delegations,
    trustAnchors,
    now = new Date(),
    clockSkewSec = 5,
  } = opts;

  const auth =
    actionReceipt && actionReceipt.payload && actionReceipt.payload.authorization;
  if (!auth || !Array.isArray(auth.delegation_chain) || auth.delegation_chain.length === 0) {
    return {
      valid: false,
      error: 'missing_delegation_chain',
      depth: 0,
      chain: [],
    };
  }

  const chainHashes = auth.delegation_chain;  // leaf-first
  const resolved = [];
  for (const h of chainHashes) {
    const d = delegations[h];
    if (!d) {
      return {
        valid: false,
        error: `unresolvable_delegation:${h.slice(0, 12)}`,
        depth: chainHashes.length,
        chain: [],
      };
    }
    resolved.push({ hash: h, envelope: d });
  }

  // Basic shape check: each resolved envelope must be a delegation.
  for (let i = 0; i < resolved.length; i++) {
    const p = resolved[i].envelope.payload || {};
    if (p.type !== 'delegation') {
      return {
        valid: false,
        error: `chain_entry_${i}_not_delegation`,
        depth: chainHashes.length,
        chain: [],
      };
    }
  }

  const report = resolved.map((e) => ({
    hash: e.hash,
    delegator_kid: e.envelope.payload.delegator_kid,
    delegate_kid: e.envelope.payload.delegate_kid,
    scope: e.envelope.payload.scope || {},
    expires_at: e.envelope.payload.expires_at,
    ok: true,
  }));

  const skewMs = clockSkewSec * 1000;
  const nowMs = now.getTime();

  // Pre-flight: the root's delegator_kid must be in trust anchors. This is
  // the most common failure mode; surfacing it first gives a clearer error
  // than cascading signature failures on intermediate hops.
  const rootPayload = resolved[resolved.length - 1].envelope.payload;
  if (rootPayload.delegator_kid !== rootPayload.delegate_kid) {
    report[report.length - 1].ok = false;
    report[report.length - 1].reason = 'root_not_self_signed';
    return { valid: false, error: 'root_must_be_self_signed', depth: chainHashes.length, chain: report };
  }
  if (rootPayload.parent_delegation_hash) {
    report[report.length - 1].ok = false;
    report[report.length - 1].reason = 'root_has_parent';
    return { valid: false, error: 'root_must_not_have_parent_hash', depth: chainHashes.length, chain: report };
  }
  if (!(trustAnchors && trustAnchors[rootPayload.delegator_kid])) {
    report[report.length - 1].ok = false;
    report[report.length - 1].reason = 'root_not_in_trust_anchors';
    return {
      valid: false,
      error: `root_kid_not_trusted:${rootPayload.delegator_kid}`,
      depth: chainHashes.length,
      chain: report,
    };
  }

  // 1. Action signer matches leaf delegate.
  const actionKid = (actionReceipt.signature && actionReceipt.signature.kid) || '';
  if (actionKid !== resolved[0].envelope.payload.delegate_kid) {
    report[0].ok = false;
    report[0].reason = 'action_signer_mismatch';
    return {
      valid: false,
      error: 'action_signer_not_leaf_delegate',
      depth: chainHashes.length,
      chain: report,
    };
  }

  // 2. Each delegation: signature, expiry, hash-link to parent, scope ⊆ parent,
  //    max_depth sufficient.
  for (let i = 0; i < resolved.length; i++) {
    const node = resolved[i];
    const p = node.envelope.payload;

    // Expiry
    const exp = Date.parse(p.expires_at);
    if (!Number.isFinite(exp)) {
      report[i].ok = false;
      report[i].reason = 'bad_expires_at';
      return { valid: false, error: `bad_expires_at_at_depth_${i}`, depth: chainHashes.length, chain: report };
    }
    if (nowMs + skewMs >= exp) {
      report[i].ok = false;
      report[i].reason = 'expired';
      return { valid: false, error: `delegation_expired_at_depth_${i}`, depth: chainHashes.length, chain: report };
    }

    // Signature: delegator signs the envelope. For non-root the delegator key
    // must match the parent's delegate. For root it must be in trust anchors.
    const isRoot = i === resolved.length - 1;
    let pubHex;
    if (isRoot) {
      if (p.delegator_kid !== p.delegate_kid) {
        report[i].ok = false;
        report[i].reason = 'root_not_self_signed';
        return { valid: false, error: 'root_must_be_self_signed', depth: chainHashes.length, chain: report };
      }
      if (p.parent_delegation_hash) {
        report[i].ok = false;
        report[i].reason = 'root_has_parent';
        return { valid: false, error: 'root_must_not_have_parent_hash', depth: chainHashes.length, chain: report };
      }
      pubHex = trustAnchors[p.delegator_kid];
      if (!pubHex) {
        report[i].ok = false;
        report[i].reason = 'root_not_in_trust_anchors';
        return {
          valid: false,
          error: `root_kid_not_trusted:${p.delegator_kid}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
    } else {
      const parent = resolved[i + 1].envelope.payload;
      // Hash-link integrity.
      const parentHashComputed = receiptHash(resolved[i + 1].envelope);
      if (parentHashComputed !== chainHashes[i + 1]) {
        report[i].ok = false;
        report[i].reason = 'parent_hash_mismatch';
        return {
          valid: false,
          error: `parent_hash_mismatch_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
      if (p.parent_delegation_hash !== chainHashes[i + 1]) {
        report[i].ok = false;
        report[i].reason = 'parent_delegation_hash_mismatch';
        return {
          valid: false,
          error: `parent_delegation_hash_mismatch_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
      if (p.delegator_kid !== parent.delegate_kid) {
        report[i].ok = false;
        report[i].reason = 'delegator_not_parent_delegate';
        return {
          valid: false,
          error: `delegator_mismatch_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
      // Scope subset.
      const parentScope = parent.scope || {};
      const scope = p.scope || {};
      if (!scopeSubset(scope, parentScope)) {
        report[i].ok = false;
        report[i].reason = 'scope_not_subset';
        return {
          valid: false,
          error: `scope_widened_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
      // max_depth: parent must have allowed at least this many further hops
      // remaining. Depth counted from root; leaf is depth 0 from its own POV.
      // We require: parentScope.max_depth >= (i). i=0 leaf: parent max_depth>=0.
      if (Number.isFinite(parentScope.max_depth) && parentScope.max_depth < i) {
        report[i].ok = false;
        report[i].reason = 'max_depth_exceeded';
        return {
          valid: false,
          error: `max_depth_exceeded_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
      // Non-root signer is the parent's delegate.
      pubHex = resolveKidPubkey(parent.delegate_kid, resolved, trustAnchors);
      if (!pubHex) {
        report[i].ok = false;
        report[i].reason = 'no_pubkey_for_delegator';
        return {
          valid: false,
          error: `no_pubkey_for_delegator_at_depth_${i}`,
          depth: chainHashes.length,
          chain: report,
        };
      }
    }

    // Signature check.
    const sigOk = verifyReceiptSignature(node.envelope, pubHex);
    if (!sigOk) {
      report[i].ok = false;
      report[i].reason = 'signature_invalid';
      return {
        valid: false,
        error: `signature_invalid_at_depth_${i}`,
        depth: chainHashes.length,
        chain: report,
      };
    }
  }

  // 3. Action is within leaf scope.
  const leafScope = resolved[0].envelope.payload.scope || {};
  const actionInScope = actionWithinScope(actionReceipt.payload || {}, leafScope);
  if (!actionInScope) {
    return {
      valid: false,
      error: 'action_not_in_leaf_scope',
      depth: chainHashes.length,
      chain: report,
      leaf_scope: leafScope,
      action_in_scope: false,
    };
  }

  return {
    valid: true,
    depth: chainHashes.length,
    chain: report,
    trust_anchor_kid: resolved[resolved.length - 1].envelope.payload.delegator_kid,
    leaf_scope: leafScope,
    action_in_scope: true,
  };
}

// ───── Scope ⊆ ─────

/**
 * Return true iff `child ⊆ parent`. Semantics:
 *   - Each pattern in `child.tools` must be matched by some pattern in
 *     `parent.tools` (or parent.tools absent / contains "*").
 *   - Likewise `targets`, `resources`.
 *   - `child.max_depth` MUST be ≤ `parent.max_depth - 1`.
 */
export function scopeSubset(child, parent) {
  const checkList = (cs, ps) => {
    if (cs == null) return true;               // inherits
    if (!Array.isArray(cs)) return false;
    if (ps == null || ps.includes('*')) return true;
    if (!Array.isArray(ps)) return false;
    for (const cEntry of cs) {
      const matched = ps.some((p) => patternMatches(p, cEntry));
      if (!matched) return false;
    }
    return true;
  };
  if (!checkList(child.tools, parent.tools)) return false;
  if (!checkList(child.targets, parent.targets)) return false;
  if (!checkList(child.resources, parent.resources)) return false;

  if (
    Number.isFinite(child.max_depth) &&
    Number.isFinite(parent.max_depth) &&
    child.max_depth > parent.max_depth - 1
  ) {
    return false;
  }
  return true;
}

function patternMatches(parentPattern, candidate) {
  if (parentPattern === '*') return true;
  if (parentPattern === candidate) return true;
  if (parentPattern.endsWith('*')) {
    const pre = parentPattern.slice(0, -1);
    return typeof candidate === 'string' && candidate.startsWith(pre);
  }
  return false;
}

function actionWithinScope(actionPayload, scope) {
  // Tool check
  if (scope.tools) {
    const a = actionPayload.action || actionPayload.tool_name || '';
    const ok = scope.tools.includes('*') || scope.tools.some((p) => patternMatches(p, a));
    if (!ok) return false;
  }
  // Target check (optional in action payload)
  if (scope.targets) {
    const t = actionPayload.target || '';
    if (t) {
      const ok = scope.targets.includes('*') || scope.targets.some((p) => patternMatches(p, t));
      if (!ok) return false;
    }
  }
  return true;
}

// ───── Crypto helpers ─────

function receiptHash(envelope) {
  const bytes = canonicalize(envelope);
  return createHash('sha256').update(bytes).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function verifyReceiptSignature(envelope, pubHex) {
  if (!envelope || !envelope.signature || !envelope.signature.sig) return false;
  if (typeof pubHex !== 'string' || pubHex.length !== 64) return false;

  // The signed bytes are the JCS canonicalization of the payload.
  const payloadBytes = canonicalize(envelope.payload);

  const pubDer = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(pubHex, 'hex'),
  ]);
  const pub = createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
  const sigBuf = decodeSignature(envelope.signature.sig);
  if (!sigBuf) return false;
  try {
    return cryptoVerify(null, payloadBytes, pub, sigBuf);
  } catch {
    return false;
  }
}

function decodeSignature(str) {
  if (typeof str !== 'string') return null;
  if (/^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0) {
    return Buffer.from(str, 'hex');
  }
  try {
    return Buffer.from(str, 'base64');
  } catch {
    return null;
  }
}

/**
 * Resolve a kid's public key. Order:
 *   1. Verifier's trust anchors (caller-supplied map).
 *   2. A delegation whose `delegate_kid == kid` AND whose payload
 *      carries a `delegate_public_key` — this binds the kid to a
 *      key inside the chain itself, so operators don't need a full
 *      trust-anchor map of every intermediate kid.
 */
function resolveKidPubkey(kid, resolvedChain, trustAnchors) {
  if (trustAnchors && trustAnchors[kid]) return trustAnchors[kid];
  for (const entry of resolvedChain) {
    if (entry.envelope.payload.delegate_kid === kid &&
        entry.envelope.payload.delegate_public_key) {
      return entry.envelope.payload.delegate_public_key;
    }
  }
  return null;
}
