#!/usr/bin/env node
/**
 * AIP-0004 reference implementation — content-addressed snapshot +
 * rollback receipt Merkle helper.
 *
 * Produces `snapshot_root` given a list of (relative_path, file_bytes)
 * entries. Also includes a lightweight example signer that composes
 * with the AIP-0001 envelope so operators can see end-to-end how the
 * pieces compose.
 *
 * This is a reference implementation of the spec at
 * specs/aip/AIP-0004-snapshot-receipts.md. The production path is for
 * sb-runtime (or any rollback engine) to adopt this Merkle construction
 * and the receipt schema; the verify-cli will validate those receipts
 * once the v0.6.0 --verify-snapshot path lands.
 *
 * Usage as a library:
 *   import { buildSnapshotRoot, makeSnapshotPayload } from './snapshot.mjs';
 *   const root = buildSnapshotRoot([['src/app.js', fileBytes], ...]);
 *
 * Usage as a CLI (experimental):
 *   node snapshot.mjs --root ./project --out snapshot.json --session <uuid>
 *
 * License: Apache-2.0.
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { createHash } from 'node:crypto';

// ───── Core Merkle construction (AIP-0004 §1.2) ─────

/**
 * Compute the AIP-0004 snapshot Merkle root.
 *
 * @param {Array<[string, Buffer|Uint8Array]>} entries
 *        [relativePath, fileBytes] pairs. Paths MUST be POSIX and
 *        relative to the snapshot root.
 * @returns {string} base64url-encoded SHA-256 Merkle root (no padding).
 */
export function buildSnapshotRoot(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return sha256b64url(Buffer.alloc(0));
  }

  // Sort lexicographically by path.
  const sorted = [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  // Leaves: SHA-256(path_utf8 || 0x00 || SHA-256(file_bytes))
  let layer = sorted.map(([path, bytes]) => {
    const pathBuf = Buffer.from(path, 'utf-8');
    const fileHash = sha256(bytes);
    return sha256(Buffer.concat([pathBuf, Buffer.from([0x00]), fileHash]));
  });

  // Pairwise hash; duplicate last if odd.
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(sha256(Buffer.concat([left, right])));
    }
    layer = next;
  }

  return base64url(layer[0]);
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

function sha256b64url(buf) {
  return base64url(sha256(buf));
}

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ───── Snapshot payload builder (AIP-0004 §1) ─────

/**
 * Build an unsigned AIP-0004 snapshot payload.
 *
 * @param {Object} opts
 * @param {string} opts.session_id
 * @param {string} opts.snapshot_root
 * @param {'zfs'|'btrfs'|'git'|'cow'|'copy'|'nono'|'custom'} opts.backend
 * @param {number} opts.file_count
 * @param {Object} opts.scope  { allowed_read[], allowed_write[], deny[]? }
 * @param {string} opts.issuer_id
 * @param {string} opts.agent_id
 * @param {string} [opts.snapshot_uri]
 * @param {string} [opts.policy_hash]
 * @param {string} [opts.previousReceiptHash]
 * @returns {Object}
 */
export function makeSnapshotPayload(opts) {
  const payload = {
    type: 'snapshot',
    session_id: opts.session_id,
    snapshot_root: opts.snapshot_root,
    snapshot_backend: opts.backend,
    file_count: opts.file_count,
    snapshot_scope: {
      allowed_read:  opts.scope.allowed_read  || [],
      allowed_write: opts.scope.allowed_write || [],
      ...(opts.scope.deny ? { deny: opts.scope.deny } : {}),
    },
    issuer_id: opts.issuer_id,
    agent_id:  opts.agent_id,
    issued_at: new Date().toISOString(),
  };
  if (opts.snapshot_uri)         payload.snapshot_uri = opts.snapshot_uri;
  if (opts.policy_hash)          payload.policy_hash  = opts.policy_hash;
  if (opts.previousReceiptHash)  payload.previousReceiptHash = opts.previousReceiptHash;
  return payload;
}

/**
 * Build an unsigned AIP-0004 rollback payload.
 *
 * @param {Object} opts
 * @param {string} opts.session_id
 * @param {string} opts.snapshot_receipt_hash
 * @param {string} opts.rollback_reason               MAX 256 bytes
 * @param {'human'|'policy'|'anomaly-detector'} opts.rollback_initiator
 * @param {'success'|'partial'|'failed'} opts.rollback_outcome
 * @param {string} opts.post_rollback_root
 * @param {string} opts.issuer_id
 * @param {string} opts.agent_id
 * @param {Array<{receipt_hash:string, action:string, compensable:boolean}>} [opts.external_side_effects]
 * @param {string} [opts.previousReceiptHash]
 * @returns {Object}
 */
export function makeRollbackPayload(opts) {
  if (opts.rollback_reason && Buffer.byteLength(opts.rollback_reason, 'utf-8') > 256) {
    throw new Error('rollback_reason exceeds 256 bytes');
  }
  const payload = {
    type: 'rollback',
    session_id: opts.session_id,
    snapshot_receipt_hash: opts.snapshot_receipt_hash,
    rollback_reason: opts.rollback_reason,
    rollback_initiator: opts.rollback_initiator,
    rollback_outcome: opts.rollback_outcome,
    post_rollback_root: opts.post_rollback_root,
    issuer_id: opts.issuer_id,
    agent_id:  opts.agent_id,
    issued_at: new Date().toISOString(),
  };
  if (opts.external_side_effects)  payload.external_side_effects = opts.external_side_effects;
  if (opts.previousReceiptHash)    payload.previousReceiptHash   = opts.previousReceiptHash;
  return payload;
}

// ───── Directory walker (convenience — not part of the spec) ─────

/**
 * Walk a directory tree and return [relPath, Buffer] entries suitable
 * for buildSnapshotRoot. Applies an optional include/exclude filter.
 *
 * @param {string} root
 * @param {Object} [filter]
 * @param {(relPath: string) => boolean} [filter.include]
 * @returns {Array<[string, Buffer]>}
 */
export function walkDirectory(root, filter = {}) {
  const absRoot = resolve(root);
  const entries = [];

  function recurse(dir) {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.isDirectory()) {
        recurse(full);
      } else if (st.isFile()) {
        const rel = relative(absRoot, full).split('\\').join('/');
        if (filter.include && !filter.include(rel)) continue;
        try { entries.push([rel, readFileSync(full)]); } catch { continue; }
      }
    }
  }

  recurse(absRoot);
  return entries;
}

// ───── CLI (example wiring) ─────

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const args = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--root')       opts.root       = args[++i];
    else if (a === '--out')   opts.out        = args[++i];
    else if (a === '--session') opts.session  = args[++i];
    else if (a === '--backend') opts.backend  = args[++i];
    else if (a === '--issuer')  opts.issuer   = args[++i];
    else if (a === '--agent')   opts.agent    = args[++i];
    else if (a === '-h' || a === '--help') {
      console.log('snapshot.mjs --root <dir> --session <id> [--out <file>]');
      console.log('             [--backend zfs|btrfs|git|cow|copy|nono|custom]');
      console.log('             [--issuer <id>] [--agent <id>]');
      console.log('Builds an unsigned AIP-0004 snapshot payload. Hand to your signer.');
      process.exit(0);
    }
  }
  if (!opts.root) {
    console.error('--root required');
    process.exit(2);
  }

  const entries = walkDirectory(opts.root, {
    include: (p) => !p.startsWith('.git/') && !p.startsWith('node_modules/'),
  });
  const root = buildSnapshotRoot(entries);
  const payload = makeSnapshotPayload({
    session_id: opts.session || 'anon-session',
    snapshot_root: root,
    backend: opts.backend || 'copy',
    file_count: entries.length,
    scope: { allowed_read: [opts.root], allowed_write: [opts.root] },
    issuer_id: opts.issuer || 'reference-issuer',
    agent_id: opts.agent || 'reference-agent',
  });
  const out = JSON.stringify(payload, null, 2);
  if (opts.out) writeFileSync(opts.out, out + '\n');
  else process.stdout.write(out + '\n');
}
