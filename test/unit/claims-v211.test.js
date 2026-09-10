import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  admissionIssueCodesV211Independent,
  canonicalizeClaimsV211Independent,
  evaluateOperatorV211Independent,
  fingerprintEd25519JwkIndependent,
  negotiateClaimsModulesV211Independent,
  parseClaimsJsonV211Independent,
  projectClaimsV211Independent,
  validateRecipientDecisionV211Independent,
  verifyClaimsArtifactV211,
  verifyClaimsEnvelopeV211Independent,
} from '../../src/engines/claims-v211.js';

const packageRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const vectorRoot = resolve(packageRoot, '../../specs/conformance/test-vectors');
const MONOREPO = existsSync(vectorRoot);
const needsMonorepo = { skip: !MONOREPO && 'needs fixtures from the monorepo root; not present in a standalone checkout' };

function vector(name) {
  return JSON.parse(readFileSync(resolve(vectorRoot, name), 'utf8'));
}

function deepMerge(base, patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return patch;
  const output = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    output[key] = value && typeof value === 'object' && !Array.isArray(value)
      ? deepMerge(output[key] ?? {}, value)
      : value;
  }
  return output;
}

test('independent verifier matches every five-state projection vector', needsMonorepo, () => {
  for (const item of vector('08-claims-v2.1.1-projection.json').vectors) {
    assert.deepEqual(projectClaimsV211Independent(item.input), item.expected, item.id);
  }
});

test('independent verifier matches every operator-finality vector', needsMonorepo, () => {
  for (const item of vector('09-claims-v2.1.1-operator-finality.json').vectors) {
    assert.deepEqual(evaluateOperatorV211Independent(item.input), item.expected, item.id);
  }
});

test('independent module and recipient-decision logic matches normative vectors', needsMonorepo, () => {
  const document = vector('10-claims-v2.1.1-modules-and-decisions.json');
  for (const item of document.module_vectors) {
    const result = negotiateClaimsModulesV211Independent(item.required, item.supported);
    assert.equal(result.supported, item.expected.supported, item.id);
    assert.deepEqual([...new Set(result.issues)], item.expected.issues, item.id);
  }
  for (const item of document.decision_vectors) {
    assert.deepEqual(
      validateRecipientDecisionV211Independent({ decision: item.decision, report: item.report }),
      item.expected,
      item.id,
    );
  }
});

test('independent evidence admission matches normative vectors', needsMonorepo, () => {
  const document = vector('11-claims-v2.1.1-evidence-admission.json');
  for (const item of document.vectors) {
    const candidate = deepMerge(document.base.candidate, item.candidate_patch);
    const context = deepMerge(document.base.context, item.context_patch);
    assert.deepEqual(
      admissionIssueCodesV211Independent({ candidate, context }).sort(),
      [...item.expected_issue_codes].sort(),
      item.id,
    );
  }
});

test('independent strict parser and canonicalizer match normative vectors', needsMonorepo, () => {
  for (const item of vector('12-claims-v2.1.1-parser.json').vectors) {
    const source = item.deep_array_depth
      ? `${'['.repeat(item.deep_array_depth)}0${']'.repeat(item.deep_array_depth)}`
      : item.json;
    if (item.expected_valid) {
      assert.equal(
        canonicalizeClaimsV211Independent(parseClaimsJsonV211Independent(source)),
        item.expected_canonical,
        item.id,
      );
    } else {
      assert.throws(
        () => parseClaimsJsonV211Independent(source),
        (error) => error instanceof Error && error.message.toLowerCase().includes(item.error_contains),
        item.id,
      );
    }
  }
});

test('independent verifier validates the production-generated raw-JCS envelope vector', needsMonorepo, () => {
  const document = vector('13-claims-v2.1.1-envelope.json');
  assert.equal(fingerprintEd25519JwkIndependent(document.public_jwk), document.key_fingerprint);
  assert.equal(
    verifyClaimsEnvelopeV211Independent(document.artifact, document.public_jwk).verified,
    true,
  );
  assert.equal(
    verifyClaimsArtifactV211(document.artifact, { publicJwk: document.public_jwk }).valid,
    true,
  );
  for (const item of document.invalid_cases) {
    assert.equal(
      verifyClaimsEnvelopeV211Independent(
        deepMerge(document.artifact, item.artifact_patch),
        document.public_jwk,
      ).verified,
      item.expected_verified,
      item.id,
    );
  }
  for (const item of document.invalid_keys) {
    assert.equal(
      verifyClaimsEnvelopeV211Independent(document.artifact, item.public_jwk).verified,
      item.expected_verified,
      item.id,
    );
  }
});

test('independent verifier rejects a signed artifact with malformed nested schema', needsMonorepo, () => {
  const document = vector('13-claims-v2.1.1-envelope.json');
  const malformed = deepMerge(document.artifact, {
    modules: [{ ...document.artifact.modules[0], id: 42 }],
  });
  const result = verifyClaimsEnvelopeV211Independent(malformed, document.public_jwk);
  assert.equal(result.structural_valid, false);
  assert.equal(result.verified, false);
});

test('independent verifier never upgrades signature validity into trust or acceptance', needsMonorepo, () => {
  const document = vector('13-claims-v2.1.1-envelope.json');
  const result = verifyClaimsArtifactV211(document.artifact, { publicJwk: document.public_jwk });
  assert.equal(result.valid, true);
  assert.equal(result.cryptographically_valid, true);
  assert.equal(result.trusted, false);
  assert.equal(result.accepted, false);
  assert.match(result.limitations.join(' '), /not recipient trust or acceptance/i);
  const noKey = verifyClaimsArtifactV211(document.artifact);
  assert.equal(noKey.valid, false);
  assert.equal(noKey.error, 'public_key_required');
});
