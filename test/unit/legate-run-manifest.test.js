import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { detectFormat } from '../../src/detect.js';
import { verifyLegateStandard } from '../../src/engines/legate-standard.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = (name) => join(here, '..', 'fixtures', 'legate', name);
const fixture = (name) => JSON.parse(readFileSync(fixturePath(name), 'utf8'));
const NOW = new Date('2026-09-12T00:00:00Z');

test('a run manifest is detected and verifies alone as intact but unbound', async () => {
  const manifest = fixture('run-manifest.json');
  assert.equal(detectFormat(manifest).mode, 'legate-standard');
  const r = await verifyLegateStandard(manifest, { now: NOW });
  assert.equal(r.valid, true, JSON.stringify(r.checks));
  assert.equal(r.artifact_type, 'scopeblind.run_manifest.v1');
  assert.equal(r.binding, 'manifest_only');
  assert.equal(r.summary.passed, manifest.summary.passed);
  assert.equal(r.signer.demo, true);
  assert.match(r.in_plain_words, new RegExp(`Result: ${manifest.summary.passed} of ${manifest.summary.tasks} passed; ${manifest.summary.calls} governed calls, ${manifest.summary.refused} refused`));
  assert.ok(r.not_established.some((s) => /supply the signed standard/.test(s)));
});

const callsFixture = () => readFileSync(fixturePath('run-calls.jsonl'), 'utf8').trim().split('\n').map((l) => { const c = JSON.parse(l); return { tool: c.tool, input: c.input }; });

test('with the standard, the receipts, the calls, and the second grading beside it, the run manifest is bound and every check passes', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: fixture('run-regrade.json') });
  assert.equal(r.valid, true);
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.ok(r.checks.some((c) => c.id === 'calls_bind' && c.ok));
  assert.ok(r.checks.some((c) => c.id === 'regrade' && c.ok));
  const manifest = fixture('run-manifest.json');
  assert.equal(r.chain.count, manifest.gateway.receipt_count);
  assert.equal(r.chain.deny, manifest.summary.refused);
  assert.ok(r.checks.some((c) => c.id === 'tools' && c.ok));
  assert.ok(r.checks.some((c) => c.id === 'chain_head' && c.ok));
  assert.ok(r.establishes.some((s) => /every allowed call on the tool list/.test(s)));
});

test('a manifest whose score was raised fails on its digest', async () => {
  const manifest = fixture('run-manifest.json');
  manifest.summary.passed += 1;
  const r = await verifyLegateStandard(manifest, { now: NOW });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'digest_mismatch');
});

test('without the second grading, a standard that asks for independent reconciliation holds the verdicts as the harness\'s word', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json') });
  assert.equal(r.valid, true);
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'verdict_evidence' && !c.ok));
  assert.ok(r.not_established.some((s) => /harness's word/.test(s)));
});

test('a rewritten call in the calls log does not bind to its receipt', async () => {
  const calls = callsFixture(); const i = calls.findIndex((c) => c.tool === 'Bash'); calls[i >= 0 ? i : 0] = { tool: 'Bash', input: { command: 'ls -la' } };
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls, regrade: fixture('run-regrade.json') });
  assert.ok(r.checks.some((c) => c.id === 'calls_bind' && !c.ok));
});

test('a receipt log with a receipt removed does not bind to the manifest', async () => {
  const receipts = fixture('run-receipts.json').slice(0, -1);
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts });
  assert.equal(r.valid, true);
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'chain_head' && !c.ok));
});

const provenanceFixture = () => ({ bundles: readFileSync(fixturePath('run-provenance.sigstore.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)), bytes: { manifest: readFileSync(fixturePath('run-manifest.json')), receipts: readFileSync(fixturePath('run-receipts.jsonl')), standard: readFileSync(fixturePath('run-standard.json')) } });
const attestedFixture = () => ({ modelCalls: readFileSync(fixturePath('run-model-calls.jsonl'), 'utf8'), modelAttestations: JSON.parse(readFileSync(fixturePath('run-model-attestation.json'), 'utf8')) });

test('with the signed model calls and the attestation report beside it, the model route is observed, not declared', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: fixture('run-regrade.json'), provenance: provenanceFixture(), ...attestedFixture() });
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  for (const id of ['model_attestation', 'model_attestation_pin', 'model_calls_digest', 'model_calls_bind', 'model_attestation_1_quote_pck_chain', 'model_attestation_1_report_data', 'model_attestation_1_compose']) assert.ok(r.checks.some((c) => c.id === id && c.ok && !c.informational), id);
  assert.match(r.checks.find((c) => c.id === 'model_route').detail, /observed, not declared/);
  assert.equal(r.model_attestation.verified, true);
  assert.ok(r.establishes.some((s) => /inside a TDX confidential machine/.test(s)));
});

test('a model call whose signature no longer recovers unbinds the run', async () => {
  const a = attestedFixture(); const lines = a.modelCalls.split('\n').filter(Boolean); const first = JSON.parse(lines[0]); first.response_sha256 = 'a'.repeat(64); lines[0] = JSON.stringify(first); a.modelCalls = lines.join('\n') + '\n';
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), ...a });
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'model_calls_digest' && !c.ok));
});

test('with the provenance bundle beside it, the workflow, the commit, and the log entry are verified against the pinned Sigstore trust root', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: fixture('run-regrade.json'), provenance: provenanceFixture() });
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.equal(r.provenance.verified, true);
  for (const id of ['provenance_1_certificate', 'provenance_1_identity', 'provenance_1_signature', 'provenance_1_log', 'provenance_1_inclusion', 'provenance_1_sct', 'provenance_manifest', 'provenance_receipts', 'provenance_standard']) assert.ok(r.checks.some((c) => c.id === id && c.ok), id);
  assert.match(r.provenance.identity.workflow, /\/\.github\/workflows\/verified-run\.yml@/);
  assert.ok(r.establishes.some((s) => /Provenance verified here against the pinned Sigstore trust root/.test(s)));
});

test('a valid bundle from another run beside this run\'s counts for nothing and unbinds nothing', async () => {
  const p = provenanceFixture(); p.bundles.push(JSON.parse(readFileSync(fixturePath('run-provenance-other.sigstore.jsonl'), 'utf8').trim().split('\n')[0]));
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: fixture('run-regrade.json'), provenance: p });
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.equal(r.provenance.verified, true);
  assert.ok(r.checks.some((c) => c.id === 'provenance_2_identity' && c.ok && c.informational && /another run/.test(c.detail)));
});

test('a provenance bundle whose signature was altered does not verify, and the run no longer binds', async () => {
  const p = provenanceFixture(); const sig = Buffer.from(p.bundles[0].dsseEnvelope.signatures[0].sig, 'base64'); sig[5] ^= 1; p.bundles[0].dsseEnvelope.signatures[0].sig = sig.toString('base64');
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), provenance: p });
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'provenance_1_signature' && !c.ok));
});

test('a manifest edited after attestation is not the bytes the provenance names', async () => {
  const p = provenanceFixture(); p.bytes.manifest = Buffer.concat([p.bytes.manifest, Buffer.from('\n')]);
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, provenance: p });
  assert.ok(r.checks.some((c) => c.id === 'provenance_manifest' && !c.ok));
  assert.equal(r.provenance.verified, false);
});

test('the CLI takes --standard, --receipts, and --provenance and reports the binding', () => {
  const cli = join(here, '..', '..', 'cli.js');
  const r = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--standard', fixturePath('run-standard.json'), '--receipts', fixturePath('run-receipts.jsonl'), '--calls', fixturePath('run-calls.jsonl'), '--regrade', fixturePath('run-regrade.json'), '--provenance', fixturePath('run-provenance.sigstore.jsonl'), '--model-calls', fixturePath('run-model-calls.jsonl'), '--model-attestation', fixturePath('run-model-attestation.json'), '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.valid, true);
  assert.equal(out.binding, 'bound', JSON.stringify(out.checks.filter((c) => !c.ok)));
  assert.equal(out.provenance.verified, true);
  assert.equal(out.model_attestation.verified, true);
  const alone = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json')], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  assert.equal(alone.status, 0, alone.stderr);
  assert.match(alone.stdout, /Run manifest verifies: \d+ of \d+ passed, unbound/);
  assert.match(alone.stdout, /manifest only \(add --standard, --receipts, --calls, --regrade to bind\)/);
});

const regradeBytes = () => readFileSync(fixturePath('run-regrade.json'));

test('a grading made elsewhere, given as a further regrade, is checked like the first and reconciles when it agrees', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: fixture('run-regrade.json'), regrades: [{ regrade: fixture('run-regrade.json'), bytes: regradeBytes() }] });
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  const second = r.checks.find((c) => c.id === 'regrade_2');
  assert.ok(second && second.ok, JSON.stringify(second));
  assert.equal(second.label, 'Grading 3');
  assert.ok(r.checks.some((c) => c.id === 'regrade' && c.ok));
});

test('a grading made elsewhere whose verdict was changed after signing fails its own check and unbinds the run, while the run\'s own grading still holds', async () => {
  const manifest = fixture('run-manifest.json');
  const own = fixture('run-regrade.json');
  const other = fixture('run-regrade.json');
  other.results[0].verdict = other.results[0].verdict === 'pass' ? 'fail' : 'pass';
  const r = await verifyLegateStandard(manifest, { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), calls: callsFixture(), regrade: own, regrades: [{ regrade: other, bytes: JSON.stringify(other) }] });
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'regrade' && c.ok));
  const second = r.checks.find((c) => c.id === 'regrade_2');
  assert.ok(second && !second.ok && /altered after signing/.test(second.detail), JSON.stringify(second));
});

test('--regrade may be given more than once: the first is the run\'s own, the rest gradings made elsewhere', () => {
  const cli = join(here, '..', '..', 'cli.js');
  const r = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--standard', fixturePath('run-standard.json'), '--receipts', fixturePath('run-receipts.jsonl'), '--calls', fixturePath('run-calls.jsonl'), '--regrade', fixturePath('run-regrade.json'), '--regrade', fixturePath('run-regrade.json'), '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.match(r.stdout, /"id":\s*"regrade_2",\s*"label":\s*"Grading 3",\s*"ok":\s*true/);
});

test('the receipt log is checked as bytes: a log that parses to the same records but differs in bytes fails log_bytes and unbinds', async () => {
  const text = readFileSync(fixturePath('run-receipts.jsonl'), 'utf8');
  const exact = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), bytes: { receipts: text } });
  assert.ok(exact.checks.some((c) => c.id === 'log_bytes' && c.ok), JSON.stringify(exact.checks.find((c) => c.id === 'log_bytes')));
  const padded = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json'), bytes: { receipts: text.replace('\n', ' \n') } });
  assert.ok(padded.checks.some((c) => c.id === 'log_bytes' && !c.ok));
  assert.notEqual(padded.binding, 'bound');
});

test('a pinned maintainer key is a trust root from outside the files: the right key establishes the signer, a wrong one unbinds', async () => {
  const standard = fixture('run-standard.json');
  const right = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard, receipts: fixture('run-receipts.json'), pins: { maintainer_key: standard.recipient.verification_key } });
  assert.ok(right.checks.some((c) => c.id === 'maintainer_pin' && c.ok));
  assert.ok(right.establishes.some((s) => /maintainer key you pinned/.test(s)));
  const wrong = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard, receipts: fixture('run-receipts.json'), pins: { maintainer_key: 'ab'.repeat(32) } });
  assert.ok(wrong.checks.some((c) => c.id === 'maintainer_pin' && !c.ok));
  assert.notEqual(wrong.binding, 'bound');
});

test('the gate policy digest is recomputed from the policy text the standard carries', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json') });
  const policy = r.checks.find((c) => c.id === 'policy');
  assert.ok(policy && policy.ok && /recomputed here/.test(policy.detail), JSON.stringify(policy));
});

test('the exit status is 1 when a run manifest fails to bind to a companion file, and 0 alone or when bound', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const cli = join(here, '..', '..', 'cli.js');
  const dir = mkdtempSync(join(tmpdir(), 'verify-exit-'));
  const lines = readFileSync(fixturePath('run-receipts.jsonl'), 'utf8').trim().split('\n');
  const truncated = join(dir, 'receipts-truncated.jsonl'); writeFileSync(truncated, lines.slice(0, -1).join('\n') + '\n');
  const bad = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--standard', fixturePath('run-standard.json'), '--receipts', truncated, '--json'], { encoding: 'utf8' });
  assert.equal(bad.status, 1, bad.stdout.slice(0, 300));
  assert.match(bad.stdout, /"binding":\s*"partial"/);
  // The fixture standard asks for verdict evidence, so the bound case carries the second grading and the calls log too.
  const good = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--standard', fixturePath('run-standard.json'), '--receipts', fixturePath('run-receipts.jsonl'), '--calls', fixturePath('run-calls.jsonl'), '--regrade', fixturePath('run-regrade.json'), '--maintainer-key', fixture('run-standard.json').recipient.verification_key, '--json'], { encoding: 'utf8' });
  assert.equal(good.status, 0, good.stdout.slice(0, 300));
  assert.match(good.stdout, /"id":\s*"maintainer_pin",\s*"label":\s*"Maintainer key pinned",\s*"ok":\s*true/);
  const alone = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--json'], { encoding: 'utf8' });
  assert.equal(alone.status, 0);
});
