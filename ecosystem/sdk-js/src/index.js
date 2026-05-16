/**
 * @veritasacta/sdk — tiny signing SDK
 *
 * Usage (Node.js):
 *
 *   import { Signer } from '@veritasacta/sdk';
 *   const signer = Signer.fromKeyFile('.veritasacta/attester.json');
 *   const receipt = signer.signDecision({
 *     tool: 'web_search',
 *     args: { query: '...' },
 *     decision: 'allow',
 *     policy_id: 'research-only',
 *   });
 *
 * The SDK does one thing: produce valid draft-farley-acta-signed-receipts
 * envelopes. Framework adapters use this SDK; the SDK itself has no
 * framework-specific code.
 *
 * @license Apache-2.0
 */

import { readFileSync } from 'node:fs';
import { sign, createPrivateKey, createHash } from 'node:crypto';

function canonicalize(obj) {
  // Minimal JCS-like canonicalization (AIP-0001 restrictions).
  const sortDeep = (o) => {
    if (o === null || typeof o !== 'object') return o;
    if (Array.isArray(o)) return o.map(sortDeep);
    const out = {};
    for (const k of Object.keys(o).sort()) out[k] = sortDeep(o[k]);
    return out;
  };
  return JSON.stringify(sortDeep(obj));
}

export class Signer {
  constructor({ kid, privateKey, pubHex, issuerId = null }) {
    this.kid = kid;
    this.privateKey = privateKey;
    this.pubHex = pubHex;
    this.issuerId = issuerId || kid;
    this.sequence = 0;
    this.previousReceiptHash = null;
  }

  /**
   * Load a signer from a key file written by `veritasacta init`
   * (matches the { kid, pubHex, privateDer } shape).
   *
   * @param {string} path
   * @returns {Signer}
   */
  static fromKeyFile(path) {
    const data = JSON.parse(readFileSync(path, 'utf-8'));
    const privateKey = createPrivateKey({
      key: Buffer.from(data.privateDer, 'hex'),
      format: 'der',
      type: 'pkcs8',
    });
    return new Signer({ kid: data.kid, privateKey, pubHex: data.pubHex });
  }

  /**
   * Sign a single tool-call decision and return the receipt envelope.
   *
   * @param {Object} args
   * @param {string} args.tool              tool name
   * @param {Object} [args.args]            tool arguments (hashed, not stored raw)
   * @param {string} [args.decision='allow']
   * @param {string} [args.policy_id]
   * @param {string} [args.policy_hash]
   * @param {string} [args.skill_version_hash]
   * @param {string} [args.delegation_chain_root]
   * @param {Object} [args.metadata]
   * @returns {Object} receipt envelope { payload, signature }
   */
  signDecision(args) {
    this.sequence += 1;
    const argStr = JSON.stringify(args.args || {}, Object.keys(args.args || {}).sort());
    const tool_input_hash = 'sha256:' + createHash('sha256').update(argStr, 'utf-8').digest('hex');

    const payload = {
      type: 'veritasacta:decision',
      spec: 'draft-farley-acta-signed-receipts-03',
      tool_name: args.tool,
      tool_input_hash,
      decision: args.decision || 'allow',
      issued_at: new Date().toISOString(),
      issuer_id: this.issuerId,
      sequence: this.sequence,
      previousReceiptHash: this.previousReceiptHash,
    };
    if (args.policy_id) payload.policy_id = args.policy_id;
    if (args.policy_hash) payload.policy_hash = args.policy_hash;
    if (args.skill_version_hash) payload.skill_version_hash = args.skill_version_hash;
    if (args.delegation_chain_root) payload.delegation_chain_root = args.delegation_chain_root;
    if (args.metadata) payload.metadata = args.metadata;

    const canonical = canonicalize(payload);
    const sig = sign(null, Buffer.from(canonical, 'utf-8'), this.privateKey);

    // Chain linkage
    this.previousReceiptHash = 'sha256:' + createHash('sha256').update(canonical, 'utf-8').digest('hex');

    return {
      payload,
      signature: { alg: 'EdDSA', kid: this.kid, sig: sig.toString('hex') },
    };
  }
}
