/**
 * Unit tests for SBOM audit bundle builder.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { buildSbomBundle } from '../../src/engines/sbom.js';

function mkReceipt(dir, name, action, issuedAt) {
  const r = {
    payload: {
      type: 'decision-receipt',
      action,
      issued_at: issuedAt,
      issuer_id: 'test',
      cost_tier: 2,
    },
    signature: { alg: 'EdDSA', kid: 'agent-1', sig: '00' },
  };
  writeFileSync(join(dir, name), JSON.stringify(r));
  return r;
}

function mkSbomSpdx(dir) {
  const sbom = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    name: 'scopeblind-verify-cli-spdx',
    creationInfo: {
      created: '2026-04-20T00:00:00Z',
      creators: ['Tool: syft-1.0'],
    },
    packages: [
      { name: 'node', versionInfo: '20.11.0' },
      { name: '@veritasacta/verify', versionInfo: '0.5.3' },
    ],
  };
  const path = join(dir, 'sbom.spdx.json');
  writeFileSync(path, JSON.stringify(sbom));
  return path;
}

function mkSbomCycloneDX(dir) {
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:deadbeef',
    components: [
      { type: 'library', name: 'ed25519' },
    ],
  };
  const path = join(dir, 'sbom.cdx.json');
  writeFileSync(path, JSON.stringify(sbom));
  return path;
}

test('buildSbomBundle: empty receipts dir produces empty manifest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  const bundle = buildSbomBundle({ receiptsDir: dir });
  assert.equal(bundle.manifest.receipt_count, 0);
  assert.equal(bundle.manifest.sbom, null);
  assert.ok(bundle.manifest_hash.startsWith('sha256:'));
});

test('buildSbomBundle: summarises receipts with cost_tier and trace_id', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  mkReceipt(dir, '02.json', 'Read', '2026-04-20T00:01:00Z');
  const bundle = buildSbomBundle({ receiptsDir: dir, organizationName: 'Acme' });
  assert.equal(bundle.manifest.receipt_count, 2);
  assert.equal(bundle.manifest.receipts[0].cost_tier, 2);
  assert.equal(bundle.manifest.organization, 'Acme');
});

test('buildSbomBundle: ingests SPDX and attaches digest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  const sbomPath = mkSbomSpdx(dir);
  const bundle = buildSbomBundle({ receiptsDir: dir, sbomPath });
  assert.equal(bundle.manifest.sbom.sbom_format, 'spdx');
  assert.match(bundle.manifest.sbom.sbom_digest, /^sha256:/);
  assert.equal(bundle.manifest.sbom.spdx_version, 'SPDX-2.3');
  assert.equal(bundle.manifest.sbom.package_count, 2);
});

test('buildSbomBundle: ingests CycloneDX', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  const sbomPath = mkSbomCycloneDX(dir);
  const bundle = buildSbomBundle({ receiptsDir: dir, sbomPath });
  assert.equal(bundle.manifest.sbom.sbom_format, 'cyclonedx');
  assert.equal(bundle.manifest.sbom.component_count, 1);
});

test('buildSbomBundle: unknown SBOM format still digested', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  writeFileSync(join(dir, 'sbom-unknown.json'), JSON.stringify({ hello: 'world' }));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  const bundle = buildSbomBundle({ receiptsDir: dir, sbomPath: join(dir, 'sbom-unknown.json') });
  assert.equal(bundle.manifest.sbom.sbom_format, 'unknown');
  assert.match(bundle.manifest.sbom.sbom_digest, /^sha256:/);
});

test('buildSbomBundle: deterministic receipts_fingerprint across runs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  mkReceipt(dir, '02.json', 'Read', '2026-04-20T00:01:00Z');
  const a = buildSbomBundle({ receiptsDir: dir });
  const b = buildSbomBundle({ receiptsDir: dir });
  assert.equal(a.manifest.receipts_fingerprint, b.manifest.receipts_fingerprint);
});

test('buildSbomBundle: sign callback receives canonical bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-'));
  mkReceipt(dir, '01.json', 'Bash', '2026-04-20T00:00:00Z');
  let seenBytes = null;
  const sign = (buf) => {
    seenBytes = buf;
    return { alg: 'EdDSA', kid: 'signer', sig: 'cafef00d' };
  };
  const bundle = buildSbomBundle({ receiptsDir: dir, sign });
  assert.ok(Buffer.isBuffer(seenBytes));
  assert.equal(bundle.signature.kid, 'signer');
});
