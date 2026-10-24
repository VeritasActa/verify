#!/usr/bin/env node
/** Synthetic public test data, Apache-2.0. Never use these deterministic test keys.
 * No verifier/production producer imports: expected outcomes are explicit below.
 * Node's crypto signs envelopes; noble supplies P-256 group operations only.
 * This script regenerates fixtures for review, never during the test run.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { p256, hashToCurve } from '@noble/curves/p256';
const root = new URL('../test/fixtures/standalone/', import.meta.url);
const checking = process.argv.includes('--check');
const put = (name, value) => {
  const file = new URL(name, root), expected = JSON.stringify(value, null, 2) + '\n';
  if (checking) {
    if (readFileSync(file, 'utf8') !== expected) throw new Error(`Fixture drift: ${name}`);
  } else writeFileSync(file, expected);
};
mkdirSync(new URL('claims/', root), { recursive: true });
const jcs = value => value === null || typeof value !== 'object' ? JSON.stringify(value)
  : Array.isArray(value) ? '[' + value.map(jcs).join(',') + ']'
  : '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + jcs(value[key])).join(',') + '}';
const hash = value => createHash('sha256').update(value).digest('hex');
const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'); // RFC 8032 test #1
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), type: 'pkcs8', format: 'der' });
const publicJwk = createPublicKey(key).export({ format: 'jwk' });
const keyFingerprint = createHash('sha256').update(jcs(publicJwk)).digest('base64url');
const meta = { provenance: 'synthetic public test data; not a normative corpus or production-issuer assertion', generator: 'scripts/generate-standalone-fixtures.mjs', test_key: 'RFC 8032 test vector 1; never use in production' };

// BRASS v2: independent deterministic prover for the published transcript.
// Tiny scalars and fixed nonces are intentionally insecure TEST DATA only.
const G = p256.ProjectivePoint.BASE, N = p256.CURVE.n;
const mod = x => (x % N + N) % N;
const bytes = x => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
const b64 = x => Buffer.from(x).toString('base64url');
const point = x => b64(x.toRawBytes(true));
const H = (...parts) => createHash('sha256').update(Buffer.concat(parts.flatMap(part => {
  const buf = typeof part === 'string' ? Buffer.from(part) : Buffer.from(part);
  const len = Buffer.alloc(4); len.writeUInt32BE(buf.length); return [len, buf];
}))).digest();
const prove = (g1, h1, g2, h2, secret, nonce, bind) => {
  const a1 = g1.multiply(nonce), a2 = g2.multiply(nonce);
  const c = mod(BigInt('0x' + H('BRASS:OPRF_METERING_DLEQ_v1:', ...[g1,h1,g2,h2,a1,a2].map(p => p.toRawBytes(true)), bind).toString('hex')));
  return { c: b64(bytes(c)), z: b64(bytes(mod(nonce - c * secret))) };
};
const issuerSecret = 7n, blind = 11n;
const P = p256.ProjectivePoint.fromHex(hashToCurve(Buffer.from('synthetic-scope'), { DST: 'BRASS-P256_XMD:SHA-256_SSWU_RO_SCOPE-v1' }).toRawBytes(true));
const Y = G.multiply(issuerSecret), M = P.multiply(blind), Z = M.multiply(issuerSecret), Zprime = P.multiply(issuerSecret);
const token = { type: 'scopeblind.brass.redemption.v2', protocol: 'BRASS', version: '2.0', algorithm: 'voprf-p256-sha256', scope: 'synthetic-scope', kid: 'synthetic-brass-v2', issuer_public_key: point(Y), origin: 'https://example.test', epoch: 1, policy: 'test-policy', window: 1, P: point(P), M: point(M), Z: point(Z), Zprime: point(Zprime), c_nonce: point(G.multiply(13n)), d: 'synthetic-run-digest', aadr: 'run:synthetic' };
const eta = H('BRASS_SALT_v1', token.issuer_public_key, token.origin, String(token.epoch), token.policy, String(token.window));
token.piI = prove(G, Y, M, Z, issuerSecret, 17n, Buffer.alloc(0));
token.piC = prove(P, M, Zprime, Z, blind, 19n, H('BRASS:BIND:', token.c_nonce, token.d, eta, H('no_exporter')));
put('brass-v2.json', { _meta: { ...meta, test_key: 'fixed P-256 test scalars and nonces; never use in production' }, issuer_public_key: point(Y), expected_nullifier: b64(H('BRASS_NULLIFIER_v1', token.Zprime, token.kid, token.aadr, eta)), token });

const receipt = { id: 'synthetic-001', tool: 'gate.approve', decision: 'allow', input_sha256: 'a'.repeat(64), result_sha256: 'b'.repeat(64), at: '2026-01-01T00:00:00Z' };
put('governed-receipt-vectors.json', { _meta: meta,
  legate_receipt_payload: [ { name: 'approval', input: receipt, expected: 'scopeblind.receipt.v1|synthetic-001|gate.approve|allow|' + 'a'.repeat(64) + '|' + 'b'.repeat(64) + '|2026-01-01T00:00:00Z' }, { name: 'deny-with-unbound-extra', input: { ...receipt, decision: 'deny', note: 'not in this wire payload' }, expected: 'scopeblind.receipt.v1|synthetic-001|gate.approve|deny|' + 'a'.repeat(64) + '|' + 'b'.repeat(64) + '|2026-01-01T00:00:00Z' } ],
  canonical_json: [ { name: 'nested-objects-arrays', input: { z: [{ b: 2, a: 1 }], a: false }, expected: '{"a":false,"z":[{"a":1,"b":2}]}' }, { name: 'null-and-escaped-string', input: { z: null, a: 'line\nquoted"' }, expected: '{"a":"line\\nquoted\\\"","z":null}' } ],
  gate_tuple_digest: [ { name: 'nested-context', payload: { decision: 'allow', context: { z: 3, a: 1 } }, expected_canonical: '{"context":{"a":1,"z":3},"decision":"allow"}', expected_sha256: hash('{"context":{"a":1,"z":3},"decision":"allow"}') } ],
});

// All five projections, precedence and unresolved cases; expected results are authored, not read from the engine.
const projectionBase = { structural_valid: true, assessment_supported: true, material_conflict: false, indication: 'SUPPORTS', contradiction_final: false, blocking_gap: false, establishment: 'ESTABLISHED' };
const projections = [
 ['satisfied', {}, 'satisfied'], ['invalid', { structural_valid: false }, null],
 ['unsupported-precedes-conflict', { assessment_supported: false, material_conflict: true }, 'not_assessable'],
 ['conflict-precedes-violation', { material_conflict: true, indication: 'CONTRADICTS', contradiction_final: true }, 'conflict'],
 ['violation-precedes-gap', { indication: 'CONTRADICTS', contradiction_final: true, blocking_gap: true }, 'violated'],
 ['gap-precedes-supported', { blocking_gap: true }, 'incomplete'],
 ['nonfinal-contradiction', { indication: 'CONTRADICTS' }, 'not_assessable'],
 ['unestablished-support', { establishment: 'UNESTABLISHED' }, 'not_assessable'],
 ['indeterminate', { indication: 'INDETERMINATE' }, 'not_assessable'],
];
put('claims/08-claims-v2.1.1-projection.json', { _meta: meta, vectors: projections.map(([id,patch,projection]) => ({ id, input: { ...projectionBase, ...patch }, expected: { verification_status: projection === null ? 'rejected' : 'accepted_for_projection', projection } })) });

const opBase = { population_closed: true, period_closed: true, empty_population_semantics: 'not_assessable', allow_vacuous_truth: false };
const opResult = (indication = 'INDETERMINATE', options = {}) => ({ indication, support_final: indication === 'SUPPORTS', contradiction_final: indication === 'CONTRADICTS', material_conflict: false, assessment_supported: true, ...options });
const operators = [];
const op = (id, operator, values, expected, outcome, patch = {}) => operators.push({ id, input: { ...opBase, operator, values, expected, ...patch }, expected: outcome });
op('all-closed', 'for_all', ['ok','ok'], 'ok', opResult('SUPPORTS'));
op('all-open', 'for_all', ['ok'], 'ok', opResult(), { population_closed: false });
op('all-counterexample-open', 'for_all', ['bad'], 'ok', opResult('CONTRADICTS'), { period_closed: false });
op('none-closed', 'none', ['ok'], 'bad', opResult('SUPPORTS'));
op('none-counterexample', 'none', ['bad'], 'bad', opResult('CONTRADICTS'), { population_closed: false });
op('exists-witness-open', 'exists', ['ok'], 'ok', opResult('SUPPORTS'), { population_closed: false });
op('exists-absent-closed', 'exists', ['bad'], 'ok', opResult('CONTRADICTS'));
op('exists-absent-open', 'exists', [], 'ok', opResult(), { period_closed: false });
op('count-equal-closed', 'count_eq', [1,2], 2, opResult('SUPPORTS'));
op('count-equal-open', 'count_eq', [1,2], 2, opResult(), { period_closed: false });
op('count-over-open', 'count_eq', [1,2,3], 2, opResult('CONTRADICTS'), { population_closed: false });
op('count-short-closed', 'count_eq', [1], 2, opResult('CONTRADICTS'));
op('count-invalid', 'count_eq', [1], -1, opResult('INDETERMINATE', { assessment_supported: false }));
op('count-cap-closed', 'count_lte', [1,2], 2, opResult('SUPPORTS'));
op('count-cap-open', 'count_lte', [1], 2, opResult(), { population_closed: false });
op('count-cap-over', 'count_lte', [1,2,3], 2, opResult('CONTRADICTS'));
op('sum-cap', 'sum_lte', [2,3], 5, opResult('SUPPORTS'));
op('sum-open', 'sum_lte', [2], 5, opResult(), { period_closed: false });
op('sum-over', 'sum_lte', [2,4], 5, opResult('CONTRADICTS'), { population_closed: false });
op('negative-sum-unsupported', 'sum_lte', [-1,4], 5, opResult('INDETERMINATE', { assessment_supported: false }));
op('equals', 'equals', [{ b: 2, a: 1 }, { a: 1, b: 2 }], { a: 1, b: 2 }, opResult('SUPPORTS'));
op('unequal', 'equals', ['x'], 'y', opResult('CONTRADICTS'));
op('conflicting-values', 'equals', ['x','y'], 'x', opResult('INDETERMINATE', { material_conflict: true }));
op('member', 'in_set', ['x'], ['x','y'], opResult('SUPPORTS'));
op('nonmember', 'in_set', ['z'], ['x','y'], opResult('CONTRADICTS'));
op('unknown-operator', 'average', [1,2], 2, opResult('INDETERMINATE', { assessment_supported: false }));
op('empty-no-opt-in', 'for_all', [], 'x', opResult());
op('empty-vacuous-opt-in', 'for_all', [], 'x', opResult('SUPPORTS'), { empty_population_semantics: 'vacuous_truth_recipient_opt_in', allow_vacuous_truth: true });
op('empty-vacuous-without-opt-in', 'none', [], 'x', opResult(), { empty_population_semantics: 'vacuous_truth_recipient_opt_in' });
op('empty-violated', 'for_all', [], 'x', opResult('CONTRADICTS'), { empty_population_semantics: 'violated' });
put('claims/09-claims-v2.1.1-operator-finality.json', { _meta: meta, vectors: operators });

const modules = [
 ['base', ['C0@2.1.1'], ['C0@2.1.1'], []],
 ['closure', ['C0@2.1.1','C1@2.1.1','C2a@2.1.1'], ['C0@2.1.1','C1@2.1.1','C2a@2.1.1'], []],
 ['missing-supported', ['C0@2.1.1'], [], ['UNSUPPORTED_REQUIRED_MODULE']],
 ['missing-dependency', ['C1@2.1.1'], ['C0@2.1.1','C1@2.1.1'], ['DOWNGRADE_ATTEMPT']],
 ['old-version', ['C0@2.0.0'], ['C0@2.1.1'], ['DOWNGRADE_ATTEMPT']],
 ['unknown-module', ['X@1'], [], ['UNSUPPORTED_REQUIRED_MODULE']],
];
const report = { digest: 'report', claim_contract_digest: 'contract', trust_policy_digest: 'policy', trust_snapshot_digest: 'snapshot', conformance_manifest_digest: 'manifest', indication: 'SUPPORTS', establishment: 'ESTABLISHED', projection: 'satisfied' };
const decision = { report_digest: 'report', claim_contract_digest: 'contract', trust_policy_digest: 'policy', trust_snapshot_digest: 'snapshot', conformance_manifest_digest: 'manifest', acknowledged_result: { indication: 'SUPPORTS', establishment: 'ESTABLISHED', projection: 'satisfied' }, decision: 'accept', reason_code: 'requirements_met', exceptions: [] };
const decisionVectors = [{ id: 'accepted-satisfied', decision, report, expected: { bindings_match: true, acknowledged: true, exception_required: false, exception_valid: true, semantically_valid: true } }];
for (const field of ['report_digest','claim_contract_digest','trust_policy_digest','trust_snapshot_digest','conformance_manifest_digest']) decisionVectors.push({ id: 'wrong-' + field, decision: { ...decision, [field]: 'other' }, report, expected: { bindings_match: false, acknowledged: true, exception_required: false, exception_valid: true, semantically_valid: false } });
for (const [id, dpatch, rpatch, expected] of [
 ['unacknowledged', { acknowledged_result: { ...decision.acknowledged_result, projection: 'incomplete' } }, {}, { bindings_match: true, acknowledged: false, exception_required: false, exception_valid: true, semantically_valid: false }],
 ['incomplete-without-exception', { acknowledged_result: { ...decision.acknowledged_result, projection: 'incomplete' } }, { projection: 'incomplete' }, { bindings_match: true, acknowledged: true, exception_required: true, exception_valid: false, semantically_valid: false }],
 ['incomplete-with-exception', { acknowledged_result: { ...decision.acknowledged_result, projection: 'incomplete' }, reason_code: 'exception_accepted', exceptions: ['synthetic explicit exception'] }, { projection: 'incomplete' }, { bindings_match: true, acknowledged: true, exception_required: true, exception_valid: true, semantically_valid: true }],
 ['reject-incomplete', { decision: 'reject', acknowledged_result: { ...decision.acknowledged_result, projection: 'incomplete' } }, { projection: 'incomplete' }, { bindings_match: true, acknowledged: true, exception_required: false, exception_valid: true, semantically_valid: true }],
]) decisionVectors.push({ id, decision: { ...decision, ...dpatch }, report: { ...report, ...rpatch }, expected });
put('claims/10-claims-v2.1.1-modules-and-decisions.json', { _meta: meta, module_vectors: modules.map(([id,required,supported,issues]) => ({ id,required,supported,expected: { supported: issues.length === 0, issues } })), decision_vectors: decisionVectors });

const candidate = { schema_valid: true, signature_valid: true, issued_at: '2026-01-02T12:00:00Z', expires_at: '2026-01-02T13:00:00Z', as_of: '2026-01-02T11:00:00Z', issuer_key_fingerprint: 'synthetic-key', issuer_role: 'observer', fact_class: 'test-result', source_id: 'ci', population_id: 'run-001', population_digest: 'population-digest', source_assurance: 'source_signed', state_domain_digest: 'domain-digest', state: 'passed', subject_digest: 'revision-digest', purpose: 'acceptance', period_starts_at: '2026-01-02T00:00:00Z', period_ends_at: '2026-01-03T00:00:00Z', required_modules: ['C0@2.1.1'], artifact_type: 'synthetic:test', artifact_digest: 'artifact-digest', replay_scope: 'claim-and-source' };
candidate.replay_identity = hash(jcs({ type: 'scopeblind.claims_evidence_replay_identity.v1', artifact_type: candidate.artifact_type, artifact_digest: candidate.artifact_digest, issuer_key_fingerprint: candidate.issuer_key_fingerprint, source_id: candidate.source_id, subject_digest: candidate.subject_digest, population_digest: candidate.population_digest, as_of: candidate.as_of }));
const context = { evaluated_at: '2026-01-02T12:30:00Z', authorized_issuers: [{ key_fingerprint: 'synthetic-key', roles: ['observer'], fact_classes: ['test-result'], source_ids: ['ci'], valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-01-04T00:00:00Z' }], key_observations: [{ key_fingerprint: 'synthetic-key', status: 'active', observed_at: '2026-01-02T12:00:00Z' }], revoked_keys: [], contract: { max_lifetime_seconds: 3600, max_age_seconds: 3600, minimum_source_assurance: 'authenticated_pull', source_ids: ['ci'], population_id: candidate.population_id, population_digest: candidate.population_digest, state_domain_digest: candidate.state_domain_digest, state_values: ['passed','failed'], subject_digest: candidate.subject_digest, purpose: candidate.purpose, period_starts_at: candidate.period_starts_at, period_ends_at: candidate.period_ends_at }, policy: { max_lifetime_seconds: 3600, max_age_seconds: 3600 }, accepted_sources: [{ source_id: 'ci', population_id: 'run-001', minimum_assurance: 'source_signed' }], source_observations: [{ source_id: 'ci', status: 'trusted', assurance: 'source_signed', observed_at: '2026-01-02T12:00:00Z' }], supported_modules: ['C0@2.1.1'], replay_observations: [] };
const admission = [
 ['admitted', {}, {}, []], ['schema-invalid', { schema_valid: false }, {}, ['SCHEMA_INVALID']],
 ['bad-signature', { signature_valid: false }, {}, ['SIGNATURE_INVALID']],
 ['no-authority', {}, { authorized_issuers: [] }, ['UNAUTHORIZED_ISSUER']],
 ['revoked-key', {}, { revoked_keys: [{ key_fingerprint: 'synthetic-key', revoked_at: '2026-01-02T12:00:00Z' }] }, ['KEY_REVOKED']],
 ['unobserved-key', {}, { key_observations: [] }, ['UNAUTHORIZED_ISSUER']],
 ['expired', {}, { evaluated_at: '2026-01-02T14:00:00Z' }, ['STALE_EVIDENCE']],
 ['long-lived', { expires_at: '2026-01-03T12:00:00Z' }, {}, ['STALE_EVIDENCE']],
 ['future-issued', { issued_at: '2026-01-02T12:45:00Z' }, {}, ['FUTURE_DATED_EVIDENCE']],
 ['wrong-population', {}, { contract: { population_digest: 'other' } }, ['SOURCE_OUTSIDE_POPULATION']],
 ['low-assurance', { source_assurance: 'self_attested' }, {}, ['SOURCE_OUTSIDE_POPULATION']],
 ['inflated-assurance', { source_assurance: 'independent_witness' }, {}, ['SOURCE_OUTSIDE_POPULATION']],
 ['missing-source', {}, { source_observations: [] }, ['SOURCE_OUTSIDE_POPULATION']],
 ['wrong-state', { state: 'unknown' }, {}, ['STATE_DOMAIN_MISMATCH']],
 ['wrong-domain', { state_domain_digest: 'other' }, {}, ['STATE_DOMAIN_MISMATCH']],
 ['wrong-purpose', { purpose: 'other' }, {}, ['UNAUTHORIZED_ISSUER']],
 ['wrong-period', { period_ends_at: '2026-01-04T00:00:00Z' }, {}, ['SOURCE_OUTSIDE_POPULATION']],
 ['unsupported-module', { required_modules: ['X@1'] }, {}, ['UNSUPPORTED_REQUIRED_MODULE']],
 ['wrong-replay-id', { replay_identity: 'other' }, {}, ['ARTIFACT_TYPE_REPLAY']],
 ['wrong-replay-scope', { replay_scope: 'global' }, {}, ['ARTIFACT_TYPE_REPLAY']],
 ['replayed', {}, { replay_observations: [{ artifact_type: candidate.artifact_type, replay_scope: candidate.replay_scope, identity: candidate.replay_identity, seen_before: true }] }, ['REPLAY_DETECTED']],
];
put('claims/11-claims-v2.1.1-evidence-admission.json', { _meta: meta, base: { candidate, context }, vectors: admission.map(([id,candidate_patch,context_patch,expected_issue_codes]) => ({ id,candidate_patch,context_patch,expected_issue_codes })) });
put('claims/12-claims-v2.1.1-parser.json', { _meta: meta, vectors: [
 { id: 'numeric-key-order', json: '{"2":2,"10":10}', expected_valid: true, expected_canonical: '{"10":10,"2":2}' },
 { id: 'nested-sort', json: '{"z":[{"b":2,"a":1}],"a":null}', expected_valid: true, expected_canonical: '{"a":null,"z":[{"a":1,"b":2}]}' },
 { id: 'negative-zero', json: '{"a":-0}', expected_valid: true, expected_canonical: '{"a":0}' },
 { id: 'duplicate', json: '{"a":1,"a":2}', expected_valid: false, error_contains: 'duplicate' },
 { id: 'escaped-duplicate', json: '{"a":1,"\\u0061":2}', expected_valid: false, error_contains: 'duplicate' },
 { id: 'nested-duplicate', json: '{"a":{"b":1,"b":2}}', expected_valid: false, error_contains: 'duplicate' },
 { id: 'unsafe-integer', json: '9007199254740992', expected_valid: false, error_contains: 'safe range' },
 { id: 'infinity', json: '1e999', expected_valid: false, error_contains: 'non-finite' },
 { id: 'surrogate', json: '"\\ud800"', expected_valid: false, error_contains: 'surrogate' },
 { id: 'bom', json: '\ufeff{}', expected_valid: false, error_contains: 'bom' },
 { id: 'too-deep', deep_array_depth: 66, expected_valid: false, error_contains: 'depth' },
 { id: 'trailing-input', json: '{}true', expected_valid: false, error_contains: 'trailing' },
] });
const d = 'a'.repeat(64);
const manifest = { type: 'scopeblind.claims_conformance_manifest.v1', version: 1, manifest_id: 'synthetic-manifest-001', protocol_release: '2.1.1', modules: [{ id: 'C0', version: '2.1.1', specification_digest: d, schema_set_digest: d, vector_set_digest: d, implementation_digest: d }], required_modules: ['C0@2.1.1'], canonicalization: { suite: 'RFC8785-JCS', number_profile: 'I-JSON-safe', duplicate_key_policy: 'reject', unicode_policy: 'preserve-scalars-no-compat-normalization' }, implementation: { name: 'Synthetic fixture producer', version: '1', language: 'JavaScript', build_digest: d }, supported_artifact_types: ['scopeblind.claims_conformance_manifest.v1'], issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z' };
const payload = Buffer.from(jcs(manifest));
const artifact = { ...manifest, digest: hash(payload), signature: { algorithm: 'Ed25519', key_fingerprint: keyFingerprint, signed_at: manifest.issued_at, value: sign(null, payload, key).toString('base64url') } };
put('claims/13-claims-v2.1.1-envelope.json', { _meta: meta, public_jwk: publicJwk, key_fingerprint: keyFingerprint, signed_payload: payload.toString(), artifact,
 invalid_cases: [
  { id: 'changed-payload', artifact_patch: { implementation: { version: '2' } }, expected_verified: false },
  { id: 'changed-digest', artifact_patch: { digest: 'b'.repeat(64) }, expected_verified: false },
  { id: 'changed-signature', artifact_patch: { signature: { value: 'A'.repeat(86) } }, expected_verified: false },
  { id: 'changed-fingerprint', artifact_patch: { signature: { key_fingerprint: 'B'.repeat(43) } }, expected_verified: false },
  { id: 'changed-signed-time', artifact_patch: { signature: { signed_at: '2026-01-02T00:00:00Z' } }, expected_verified: false },
 ], invalid_keys: [ { id: 'wrong-ed25519-key', public_jwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.alloc(32, 1).toString('base64url') }, expected_verified: false }, { id: 'wrong-curve', public_jwk: { ...publicJwk, crv: 'X25519' }, expected_verified: false } ] });
// Conformance v2 envelopes use the same public demonstration key as existing samples.
const artifacts = ['allow','deny'].map(decision => {
 const envelope = { v: 2, type: 'decision_receipt', algorithm: 'ed25519', kid: 'rfc8032-test-key', issuer: 'https://example.test', issued_at: '2026-01-01T00:00:00Z', payload: { decision, tool: 'synthetic_tool', context: { account: 'demo', amount: 50 } } };
 const message = Buffer.from(jcs(envelope));
 return { name: 'synthetic-v2-' + decision, signed_artifact: { ...envelope, signature: sign(null, message, key).toString('hex') }, verification: { hash: hash(message) } };
});
put('test-vectors-v2.json', { _meta: { ...meta, keypair: { public_key: Buffer.from(publicJwk.x, 'base64url').toString('hex') } }, vectors: artifacts });
console.log(checking ? 'Synthetic fixture regeneration is byte-identical.' : 'Wrote explicitly synthetic standalone fixtures. Review changes before accepting new expected results.');
