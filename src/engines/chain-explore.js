/**
 * @veritasacta/verify — chain explorer
 *
 * Given a starting receipt (the chain tip) and a directory of receipts,
 * walk the ancestry via previousReceiptHash and produce a structured
 * description of the chain plus any integrity breaks encountered.
 *
 * This surfaces what "cryptographic causal integrity" actually means:
 * if receipt B claims A caused it, we can verify that claim by hashing
 * A and comparing to B.previousReceiptHash. The walker validates every
 * link on the way up.
 *
 * @module verify-cli/src/engines/chain-explore
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

import { canonicalize } from '../util/canonical.js';

/**
 * @typedef {Object} ChainExploreOptions
 * @property {string} receiptPath         Path to the starting receipt (usually
 *                                        the chain tip).
 * @property {string} [searchDir]         Directory to scan for ancestor
 *                                        receipts. Defaults to the dirname of
 *                                        receiptPath.
 * @property {number} [maxDepth=100]      Stop walking after this many ancestors.
 * @property {boolean} [verify=true]      Verify each hash link.
 */

/**
 * @typedef {Object} ChainNode
 * @property {string} path                Path the receipt was loaded from.
 * @property {string} hash                SHA-256 of the canonicalized envelope.
 * @property {string|null} previousHash   payload.previousReceiptHash, or null.
 * @property {string} action              payload.action, for display.
 * @property {string} issued_at
 * @property {string} kid
 * @property {boolean} link_valid         Whether this node's previousHash
 *                                        correctly matches the next ancestor's
 *                                        hash.
 */

/**
 * @typedef {Object} ChainExploreResult
 * @property {boolean} valid              Every link in the chain verified.
 * @property {number} depth               Number of receipts walked.
 * @property {number} links_broken        Number of broken previousReceiptHash
 *                                        links encountered.
 * @property {ChainNode[]} nodes          Tip first, root last.
 * @property {string[]} warnings
 * @property {string} [error]
 */

/**
 * Walk the receipt chain from a starting receipt back to the root.
 */
export async function exploreChain(opts) {
  const {
    receiptPath,
    searchDir,
    maxDepth = 100,
    verify = true,
  } = opts;

  const startPath = resolve(receiptPath);
  let startReceipt;
  try {
    startReceipt = JSON.parse(readFileSync(startPath, 'utf-8'));
  } catch (err) {
    return {
      valid: false,
      depth: 0,
      links_broken: 0,
      nodes: [],
      warnings: [],
      error: `cannot_read_starting_receipt:${err.code || err.message}`,
    };
  }

  const dir = searchDir ? resolve(searchDir) : resolve(startPath, '..');
  const hashToPath = buildReceiptIndex(dir);

  const nodes = [];
  const warnings = [];
  let linksBroken = 0;

  let current = startReceipt;
  let currentPath = startPath;
  let depth = 0;

  while (current && depth < maxDepth) {
    const nodeHash = receiptHash(current);
    const node = {
      path: currentPath,
      hash: nodeHash,
      previousHash:
        (current.payload && current.payload.previousReceiptHash) || null,
      action:
        (current.payload && (current.payload.action || current.payload.tool_name)) ||
        '(unknown)',
      issued_at:
        (current.payload && current.payload.issued_at) || '(unknown)',
      kid:
        (current.signature && current.signature.kid) || '(unknown)',
      // Optional trace / causal-DAG fields (AIP-0001 extension).
      trace_id:
        (current.payload && current.payload.trace_id) || null,
      parent_receipt_id:
        (current.payload && current.payload.parent_receipt_id) || null,
      link_valid: true,
    };
    nodes.push(node);
    depth++;

    if (!node.previousHash) {
      // We've reached the root.
      break;
    }

    const ancestorPath = hashToPath.get(node.previousHash);
    if (!ancestorPath) {
      node.link_valid = false;
      linksBroken++;
      warnings.push(
        `Chain ends at receipt[${depth - 1}]: previousReceiptHash ${node.previousHash.slice(0, 16)}... ` +
          `not found in searchDir ${dir}`
      );
      break;
    }

    let ancestor;
    try {
      ancestor = JSON.parse(readFileSync(ancestorPath, 'utf-8'));
    } catch (err) {
      node.link_valid = false;
      linksBroken++;
      warnings.push(
        `Cannot read ancestor at ${ancestorPath}: ${err.code || err.message}`
      );
      break;
    }

    if (verify) {
      const computed = receiptHash(ancestor);
      if (computed !== node.previousHash) {
        // Shouldn't happen because we keyed hashToPath by computed hash, but
        // retain as a defensive check.
        node.link_valid = false;
        linksBroken++;
        warnings.push(
          `Hash mismatch at ancestor of receipt[${depth - 1}]: ` +
            `expected ${node.previousHash.slice(0, 16)}... got ${computed.slice(0, 16)}...`
        );
        break;
      }
    }

    current = ancestor;
    currentPath = ancestorPath;
  }

  if (depth >= maxDepth) {
    warnings.push(`Reached maxDepth=${maxDepth}; chain may extend further.`);
  }

  return {
    valid: linksBroken === 0,
    depth,
    links_broken: linksBroken,
    nodes,
    warnings,
  };
}

/**
 * Compute SHA-256 of the canonical envelope, base64url-encoded.
 * Matches receipt_hash() in receipts.py across the ecosystem.
 */
function receiptHash(envelope) {
  const bytes = canonicalize(envelope);
  const digest = createHash('sha256').update(bytes).digest();
  return digest.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Scan a directory for receipt files and build a hash→path index.
 */
function buildReceiptIndex(dir) {
  const index = new Map();
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return index;
  }

  for (const entry of entries) {
    const p = join(dir, entry);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (!st.isFile() || !entry.endsWith('.json')) continue;
    try {
      const receipt = JSON.parse(readFileSync(p, 'utf-8'));
      if (!receipt.payload || !receipt.signature) continue;
      const hash = receiptHash(receipt);
      index.set(hash, p);
    } catch {
      continue;
    }
  }

  return index;
}

/**
 * Group nodes by trace_id. Returns a map trace_id → ChainNode[].
 * Nodes with no trace_id go under the key "(no-trace)".
 *
 * Within each trace, nodes are ordered tip-first (as produced by the
 * walker). Callers that want causal ordering by parent_receipt_id can
 * post-process.
 *
 * @param {ChainExploreResult} result
 * @returns {Object<string, ChainNode[]>}
 */
export function groupByTrace(result) {
  const out = {};
  for (const n of result.nodes || []) {
    const key = n.trace_id || '(no-trace)';
    if (!out[key]) out[key] = [];
    out[key].push(n);
  }
  return out;
}

/**
 * Render a result as a human-readable ASCII tree for terminal output.
 */
export function renderChainTree(result, opts = {}) {
  const { maxLineWidth = 80 } = opts;
  const lines = [];

  if (!result.valid && result.nodes.length === 0) {
    return `Chain explore failed: ${result.error || '(unknown)'}`;
  }

  lines.push('');
  lines.push(`Chain: depth=${result.depth}  links_broken=${result.links_broken}  valid=${result.valid}`);
  lines.push('');

  for (let i = 0; i < result.nodes.length; i++) {
    const n = result.nodes[i];
    const prefix = i === 0 ? '▶' : '↑';
    const statusMark = n.link_valid ? ' ' : '✗';
    const line = `${prefix} ${statusMark} ${n.hash.slice(0, 12)}...  ${n.action}  (${n.issued_at})`;
    lines.push(line.length > maxLineWidth ? line.slice(0, maxLineWidth - 1) + '…' : line);
    if (i < result.nodes.length - 1) lines.push('  │');
  }

  if (result.warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of result.warnings) {
      lines.push(`  • ${w}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}
