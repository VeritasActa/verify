/**
 * @veritasacta/verify — SBOM integration for audit bundles.
 *
 * Given a directory of receipts + (optionally) a software bill of
 * materials in SPDX or CycloneDX JSON, produce an audit bundle that:
 *
 *   1. References the SBOM by digest.
 *   2. Embeds a compact per-receipt summary.
 *   3. Signs the bundle manifest with a supplied key.
 *
 * This gives regulated customers the artifact they actually want:
 * a single tamper-evident JSON that says "this session ran on this
 * software (by SBOM), produced these receipts (by hash), signed by
 * this identity (by pubkey)."
 *
 * SBOM format detection is structural:
 *   - SPDX:      has `spdxVersion` field.
 *   - CycloneDX: has `bomFormat: "CycloneDX"` field.
 *   - Unknown:   accepted but reported as `sbom_format: "unknown"`.
 *
 * @module verify-cli/src/engines/sbom
 * @license Apache-2.0
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';

/**
 * @typedef {Object} SbomBundleOptions
 * @property {string} receiptsDir
 * @property {string} [sbomPath]
 * @property {string} [organizationName]
 * @property {string} [sessionId]
 * @property {(payload: Buffer) => {alg: string, kid: string, sig: string}} [sign]
 *    Optional signer callback. Takes canonical manifest bytes, returns a
 *    signature object to attach.
 */

/**
 * Produce the bundle without signing. Signing happens in a caller-
 * supplied callback so key management stays in the operator's
 * control.
 *
 * @param {SbomBundleOptions} opts
 */
export function buildSbomBundle(opts) {
  const {
    receiptsDir,
    sbomPath,
    organizationName = '(unspecified)',
    sessionId = null,
    sign,
  } = opts;

  const dir = resolve(receiptsDir);
  const receipts = loadReceipts(dir);

  let sbom = null;
  if (sbomPath) {
    sbom = loadSbom(sbomPath);
  }

  const manifest = {
    format: 'veritasacta:sbom-audit-bundle/v1',
    generated_at: new Date().toISOString(),
    organization: organizationName,
    session_id: sessionId,
    sbom: sbom ? summariseSbom(sbom) : null,
    receipts: receipts.map(summariseReceipt),
    receipt_count: receipts.length,
    receipts_fingerprint: receiptsFingerprint(receipts),
  };

  const manifestBytes = canonicalBytes(manifest);
  const manifest_hash = 'sha256:' + createHash('sha256').update(manifestBytes).digest('hex');

  const bundle = {
    manifest,
    manifest_hash,
    ...(sign ? { signature: sign(manifestBytes) } : {}),
  };
  return bundle;
}

// ───── Helpers ─────

function loadReceipts(dir) {
  let entries;
  try { entries = readdirSync(dir); }
  catch (err) { throw new Error(`cannot_read_receipts_dir:${err.code || err.message}:${dir}`); }

  const list = [];
  for (const entry of entries) {
    if (!entry.endsWith('.json')) continue;
    const p = join(dir, entry);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (!st.isFile()) continue;
    try {
      const parsed = JSON.parse(readFileSync(p, 'utf-8'));
      if (parsed && parsed.payload && parsed.signature) list.push({ path: p, ...parsed });
    } catch { /* skip */ }
  }
  // Sort by issued_at if present; fallback to filename.
  list.sort((a, b) => {
    const aa = (a.payload && a.payload.issued_at) || '';
    const bb = (b.payload && b.payload.issued_at) || '';
    return aa < bb ? -1 : aa > bb ? 1 : 0;
  });
  return list;
}

function loadSbom(sbomPath) {
  const bytes = readFileSync(sbomPath);
  const parsed = JSON.parse(bytes.toString('utf-8'));
  return {
    raw: parsed,
    bytes,
    path: sbomPath,
  };
}

function detectSbomFormat(parsed) {
  if (parsed.spdxVersion) return 'spdx';
  if (parsed.bomFormat === 'CycloneDX') return 'cyclonedx';
  return 'unknown';
}

function summariseSbom({ raw, bytes, path }) {
  const format = detectSbomFormat(raw);
  const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');

  const base = {
    sbom_format: format,
    sbom_digest: digest,
    sbom_path: path,
  };

  if (format === 'spdx') {
    return {
      ...base,
      spdx_version: raw.spdxVersion,
      data_license: raw.dataLicense,
      creator: (raw.creationInfo && raw.creationInfo.creators) || null,
      package_count: Array.isArray(raw.packages) ? raw.packages.length : null,
      sbom_name: raw.name || null,
    };
  }
  if (format === 'cyclonedx') {
    return {
      ...base,
      spec_version: raw.specVersion,
      serial_number: raw.serialNumber,
      component_count: Array.isArray(raw.components) ? raw.components.length : null,
    };
  }
  return base;
}

function summariseReceipt(r) {
  const p = r.payload || {};
  const sig = r.signature || {};
  return {
    file: r.path,
    issued_at: p.issued_at || null,
    action: p.action || p.tool_name || null,
    decision: p.decision || null,
    kid: sig.kid || null,
    cost_tier: p.cost_tier ?? null,
    trace_id: p.trace_id || null,
  };
}

function receiptsFingerprint(receipts) {
  // Deterministic SHA-256 over the ordered canonical bytes of each
  // receipt. If any receipt changes, the fingerprint changes.
  const h = createHash('sha256');
  for (const r of receipts) {
    const { path, ...rest } = r;
    h.update(canonicalBytes(rest));
  }
  return 'sha256:' + h.digest('hex');
}

function canonicalBytes(value) {
  function jcs(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  }
  return Buffer.from(jcs(value), 'utf-8');
}
