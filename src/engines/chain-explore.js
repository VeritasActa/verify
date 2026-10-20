/**
 * @veritasacta/verify: chain explorer
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
 * A link is the draft-farley-acta-signed-receipts-03 §6.7 value: "sha256:"
 * and the lowercase hex SHA-256 of the JCS of the whole previous receipt,
 * signature included. Each link is read by the rules the receipt verifier
 * applies (checkChainLinkSyntax) and resolved the way --replay-chain
 * resolves it, so the two agree about every chain. A link over the
 * ancestor's payload alone, which no revision of the draft defines, is
 * refused with chain_break unless allowPayloadOnlyLinks reads it as a
 * legacy link.
 *
 * @module verify-cli/src/engines/chain-explore
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

import { canonicalize } from '../util/canonical.js';
import { checkChainLinkSyntax } from './ed25519-receipt.js';
import { COMPATIBILITY_NOTE } from './bulk.js';

/**
 * @typedef {Object} ChainExploreOptions
 * @property {string} receiptPath         Path to the starting receipt (usually
 *                                        the chain tip).
 * @property {string} [searchDir]         Directory to scan for ancestor
 *                                        receipts. Defaults to the dirname of
 *                                        receiptPath.
 * @property {number} [maxDepth=100]      Stop walking after this many ancestors.
 * @property {boolean} [verify=true]      Verify each hash link.
 * @property {boolean} [allowPayloadOnlyLinks=false]  Read a link over the
 *                                        ancestor's payload alone as a legacy
 *                                        link, counted and warned, instead of
 *                                        refusing it with chain_break.
 */

/**
 * @typedef {Object} ChainNode
 * @property {string} path                Path the receipt was loaded from.
 * @property {string} hash                The receipt's §6.7 chain value, the one a
 *                                        successor's previousReceiptHash holds.
 * @property {*} previousHash             payload.previousReceiptHash as written, or
 *                                        null at the root.
 * @property {string|null} link_form      How previousHash named the ancestor:
 *                                        'sha256' (§6.7), 'legacy-bare-hex', or
 *                                        'legacy-payload' (a link over the
 *                                        ancestor's payload alone, read only with
 *                                        allowPayloadOnlyLinks); null at the root
 *                                        or when refused for its form.
 * @property {string} [link_error]        malformed_chain_link,
 *                                        unsupported_chain_hash_algorithm, or
 *                                        chain_break for a payload-only link.
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
 * @property {number} legacy_links        Payload-only links read as legacy
 *                                        links, only with allowPayloadOnlyLinks.
 * @property {false} [conformant]         Present, and false, when a legacy
 *                                        link was read: that reading is a
 *                                        compatibility mode, not conformant to
 *                                        draft §6.7.
 * @property {ChainNode[]} nodes          Tip first, root last.
 * @property {string[]} warnings
 * @property {string} [code]              The verifier's error code when a link
 *                                        was refused: for its form, or as a
 *                                        payload-only link (chain_break).
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
    allowPayloadOnlyLinks = false,
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
      legacy_links: 0,
      nodes: [],
      warnings: [],
      error: `cannot_read_starting_receipt:${err.code || err.message}`,
    };
  }

  const dir = searchDir ? resolve(searchDir) : resolve(startPath, '..');
  const index = buildReceiptIndex(dir);

  const nodes = [];
  const warnings = [];
  let linksBroken = 0;
  let legacyLinks = 0;
  let code;

  let current = startReceipt;
  let currentPath = startPath;
  let depth = 0;

  while (current && depth < maxDepth) {
    const payload = current.payload && typeof current.payload === 'object' ? current.payload : {};
    const hasLink = Object.hasOwn(payload, 'previousReceiptHash');
    const link = hasLink ? payload.previousReceiptHash : null;
    const node = {
      path: currentPath,
      hash: chainLinkOf(current),
      previousHash: link,
      link_form: null,
      action: payload.action || payload.tool_name || '(unknown)',
      issued_at: payload.issued_at || '(unknown)',
      kid:
        (current.signature && current.signature.kid) || '(unknown)',
      // Optional trace / causal-DAG fields (AIP-0001 extension).
      trace_id: payload.trace_id || null,
      parent_receipt_id: payload.parent_receipt_id || null,
      link_valid: true,
    };
    nodes.push(node);
    depth++;
    const at = `receipt[${depth - 1}]`;

    if (link === null) {
      // We've reached the root. Draft §2.2 has the first receipt omit the member; earlier tools wrote null instead.
      if (hasLink) warnings.push(`${at}: previousReceiptHash is null; draft §2.2 says the first receipt in a chain omits the member.`);
      break;
    }

    const syntax = checkChainLinkSyntax({ previousReceiptHash: link });
    if (syntax.error) {
      node.link_valid = false;
      node.link_error = syntax.error;
      linksBroken++;
      code = code || syntax.error;
      warnings.push(
        syntax.error === 'unsupported_chain_hash_algorithm'
          ? `${at}: unsupported_chain_hash_algorithm: previousReceiptHash ${preview(link)} names a hash algorithm other than sha256 (draft §6.7)`
          : `${at}: malformed_chain_link: previousReceiptHash ${preview(link)} is not "sha256:" and 64 lowercase hex characters, nor the bare digest of earlier revisions (draft §6.7)`
      );
      break;
    }
    node.link_form = syntax.form;

    const digest = link.startsWith('sha256:') ? link.slice(7) : link;
    let ancestorPath = index.byReceipt.get(digest);
    if (!ancestorPath && index.byPayload.has(digest)) {
      // A link over the ancestor's payload alone. No revision of the draft defines one, and §6.7 hashes the whole
      // receipt so that a re-signed copy cannot keep the original's link. Refused whatever the ancestor's spec says,
      // as --replay-chain refuses it, unless the caller reads it as a legacy link.
      const named = index.byPayload.get(digest);
      if (!allowPayloadOnlyLinks) {
        node.link_valid = false;
        node.link_error = 'chain_break';
        linksBroken++;
        code = code || 'chain_break';
        warnings.push(
          `${at}: chain_break: previousReceiptHash ${preview(link)} is the SHA-256 of the payload alone of ${named}. ` +
            'Draft-03 §6.7 links the whole receipt, signature included, and no revision defines a payload-only link. ' +
            `--allow-payload-only-links reads it as a legacy link, ${COMPATIBILITY_NOTE}.`
        );
        break;
      }
      ancestorPath = named;
      node.link_form = 'legacy-payload';
      legacyLinks++;
      warnings.push(
        `${at}: previousReceiptHash hashes the payload alone of ${named}, read as a legacy link because ` +
          `--allow-payload-only-links was given: ${COMPATIBILITY_NOTE}. A re-signed copy of that receipt would carry the same link; draft-03 §6.7 links the whole receipt.`
      );
    }
    if (!ancestorPath) {
      node.link_valid = false;
      linksBroken++;
      warnings.push(
        `Chain ends at ${at}: previousReceiptHash ${preview(link)} ` +
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
      const computed = node.link_form === 'legacy-payload' ? payloadDigest(ancestor) : receiptDigest(ancestor);
      if (computed !== digest) {
        // Shouldn't happen because the index is keyed by the computed hash, but
        // retain as a defensive check.
        node.link_valid = false;
        linksBroken++;
        warnings.push(
          `Hash mismatch at ancestor of ${at}: ` +
            `expected ${digest.slice(0, 16)}... got ${computed.slice(0, 16)}...`
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
    legacy_links: legacyLinks,
    ...(legacyLinks ? { conformant: false } : {}),
    nodes,
    warnings,
    ...(code ? { code } : {}),
  };
}

/**
 * The value a successor's previousReceiptHash holds for this receipt: "sha256:" and the lowercase hex SHA-256 of the
 * JCS of the whole envelope, signature included (draft-03 §6.7).
 *
 * @param {Object} envelope
 * @returns {string}
 */
export function chainLinkOf(envelope) {
  return `sha256:${receiptDigest(envelope)}`;
}

function receiptDigest(envelope) {
  return createHash('sha256').update(canonicalize(envelope), 'utf-8').digest('hex');
}

/** A link over the payload alone, as the proxy and daemon of @veritasacta/verify 0.9.3 and earlier wrote it. */
function payloadDigest(envelope) {
  return createHash('sha256').update(canonicalize(envelope.payload), 'utf-8').digest('hex');
}

function preview(link) {
  const text = typeof link === 'string' ? link : JSON.stringify(link);
  return text.length > 23 ? `${text.slice(0, 23)}...` : text;
}

/**
 * Scan a directory for receipt files and index each by the digests a successor's link may carry: the SHA-256 of the
 * whole receipt (§6.7), and the SHA-256 of its payload, so that a payload-only link is named when it is refused and
 * found when the caller reads it as a legacy link.
 */
function buildReceiptIndex(dir) {
  const byReceipt = new Map();
  const byPayload = new Map();
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return { byReceipt, byPayload };
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
      byReceipt.set(receiptDigest(receipt), p);
      if (typeof receipt.payload === 'object') byPayload.set(payloadDigest(receipt), p);
    } catch {
      continue;
    }
  }

  return { byReceipt, byPayload };
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
  lines.push(`Chain: depth=${result.depth}  links_broken=${result.links_broken}${result.legacy_links ? `  legacy_links=${result.legacy_links} (${COMPATIBILITY_NOTE})` : ''}  valid=${result.valid}`);
  lines.push('');

  for (let i = 0; i < result.nodes.length; i++) {
    const n = result.nodes[i];
    const prefix = i === 0 ? '▶' : '↑';
    const statusMark = n.link_valid ? ' ' : '✗';
    const shortHash = String(n.hash).replace(/^sha256:/, '').slice(0, 12);
    const line = `${prefix} ${statusMark} ${shortHash}...  ${n.action}  (${n.issued_at})`;
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
