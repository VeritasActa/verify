/**
 * Independent ScopeBlind Verifiable Claims v2.1.1 verifier.
 *
 * This implementation intentionally does not import the production TypeScript
 * kernel. Both implementations consume the same normative vectors.
 */

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { claimsV211Schemas } from '../generated/claims-v211-schemas.js';

export const CLAIMS_V211_TYPES = new Set([
  'scopeblind.claim_contract.v2',
  'scopeblind.claims_conformance_manifest.v1',
  'scopeblind.trust_policy.v2',
  'scopeblind.trust_snapshot.v1',
  'scopeblind.claim_verification_report.v2',
  'scopeblind.recipient_reliance_decision.v3',
]);

const ROOT_FIELDS = {
  'scopeblind.claim_contract.v2': [
    'type', 'version', 'contract_id', 'revision', 'issued_at', 'expires_at',
    'issuer', 'purpose', 'audience', 'subject', 'boundary', 'predicate',
    'evidence_requirements', 'required_modules', 'disclosure',
    'migration_provenance', 'digest', 'signature',
  ],
  'scopeblind.claims_conformance_manifest.v1': [
    'type', 'version', 'manifest_id', 'protocol_release', 'modules',
    'required_modules', 'canonicalization', 'implementation',
    'supported_artifact_types', 'issued_at', 'expires_at', 'digest', 'signature',
  ],
  'scopeblind.trust_policy.v2': [
    'type', 'version', 'policy_id', 'revision', 'owner', 'purpose', 'audience',
    'authorized_issuers', 'accepted_sources', 'revoked_keys', 'acceptance',
    'issued_at', 'expires_at', 'digest', 'signature',
  ],
  'scopeblind.trust_snapshot.v1': [
    'type', 'version', 'snapshot_id', 'nonce', 'policy_digest',
    'evaluation_subject_digest', 'collected_at', 'effective_at', 'expires_at',
    'collector', 'implementation_digest', 'key_observations',
    'source_observations', 'module_observations', 'replay_observations',
    'registry_commitments', 'digest', 'signature',
  ],
  'scopeblind.claim_verification_report.v2': [
    'type', 'version', 'report_id', 'nonce', 'claim_contract_digest',
    'evidence_root_digest', 'trust_policy_digest', 'trust_snapshot_digest',
    'conformance_manifest_digest', 'evaluated_at', 'expires_at',
    'verification_status', 'structural_valid', 'cryptographically_valid',
    'indication', 'establishment', 'projection', 'dimensions', 'issues',
    'admissible_witnesses', 'signals', 'limitations', 'verifier', 'digest',
    'signature',
  ],
  'scopeblind.recipient_reliance_decision.v3': [
    'type', 'version', 'decision_id', 'nonce', 'report_digest',
    'claim_contract_digest', 'trust_policy_digest', 'trust_snapshot_digest',
    'conformance_manifest_digest', 'acknowledged_result', 'decision',
    'reliance_purpose', 'reliance_scope', 'reason_code', 'reason', 'exceptions',
    'requested_document_classes', 'recipient', 'decided_at', 'expires_at',
    'digest', 'signature',
  ],
};

const REQUIRED_FIELDS = Object.fromEntries(
  Object.entries(ROOT_FIELDS).map(([type, fields]) => [
    type,
    fields.filter((field) => field !== 'migration_provenance'),
  ]),
);
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const schemaValidators = new Map(
  Object.entries(claimsV211Schemas).map(([type, schema]) => [type, ajv.compile(schema)]),
);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function parseClaimsJsonV211Independent(source, limits = {}) {
  const maxBytes = limits.max_bytes ?? 1_048_576;
  const maxDepth = limits.max_depth ?? 64;
  if (Buffer.byteLength(source, 'utf8') > maxBytes) throw new Error('maximum JSON byte length exceeded');
  if (source.charCodeAt(0) === 0xfeff) throw new Error('UTF-8 BOM is not permitted');
  let index = 0;
  const whitespace = () => {
    while (/[\u0009\u000a\u000d\u0020]/.test(source[index] ?? '')) index += 1;
  };
  const scanString = () => {
    const start = index;
    if (source[index] !== '"') throw new Error(`expected string at ${index}`);
    index += 1;
    let escaped = false;
    while (index < source.length) {
      const code = source.charCodeAt(index);
      if (!escaped && source[index] === '"') {
        index += 1;
        const decoded = JSON.parse(source.slice(start, index));
        assertScalarString(decoded);
        return decoded;
      }
      if (!escaped && code < 0x20) throw new Error('unescaped control character');
      if (!escaped && source[index] === '\\') escaped = true;
      else escaped = false;
      index += 1;
    }
    throw new Error('unterminated string');
  };
  const scanValue = (depth) => {
    if (depth > maxDepth) throw new Error('maximum JSON depth exceeded');
    whitespace();
    const token = source[index];
    if (token === '{') {
      index += 1;
      whitespace();
      const keys = new Set();
      if (source[index] === '}') {
        index += 1;
        return;
      }
      while (true) {
        const key = scanString();
        if (keys.has(key)) throw new Error(`duplicate object key: ${key}`);
        keys.add(key);
        whitespace();
        if (source[index] !== ':') throw new Error(`expected colon at ${index}`);
        index += 1;
        scanValue(depth + 1);
        whitespace();
        if (source[index] === '}') {
          index += 1;
          return;
        }
        if (source[index] !== ',') throw new Error(`expected comma at ${index}`);
        index += 1;
        whitespace();
      }
    }
    if (token === '[') {
      index += 1;
      whitespace();
      if (source[index] === ']') {
        index += 1;
        return;
      }
      while (true) {
        scanValue(depth + 1);
        whitespace();
        if (source[index] === ']') {
          index += 1;
          return;
        }
        if (source[index] !== ',') throw new Error(`expected comma at ${index}`);
        index += 1;
      }
    }
    if (token === '"') {
      scanString();
      return;
    }
    const literal = /^(?:true|false|null)/.exec(source.slice(index));
    if (literal) {
      index += literal[0].length;
      return;
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(index));
    if (!number) throw new Error(`unexpected token at ${index}`);
    index += number[0].length;
    const value = Number(number[0]);
    if (!Number.isFinite(value)) throw new Error('non-finite number outside I-JSON profile');
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error('integer outside the I-JSON safe range');
    }
  };
  whitespace();
  scanValue(0);
  whitespace();
  if (index !== source.length) throw new Error(`unexpected trailing data at ${index}`);
  return JSON.parse(source);
}

function assertScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
        throw new Error('unpaired high surrogate');
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('unpaired low surrogate');
    }
  }
}

function canonical(value, depth = 0, seen = new Set()) {
  if (depth > 64) throw new Error('maximum depth exceeded');
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number outside I-JSON profile');
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error('integer outside the I-JSON safe range');
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value === 'string') {
    assertScalarString(value);
    return JSON.stringify(value);
  }
  if (!isObject(value) && !Array.isArray(value)) throw new Error('unsupported JSON value');
  if (seen.has(value)) throw new Error('cyclic JSON');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonical(entry, depth + 1, seen)).join(',')}]`;
    }
    return `{${Object.keys(value).sort().map((key) => {
      assertScalarString(key);
      return `${JSON.stringify(key)}:${canonical(value[key], depth + 1, seen)}`;
    }).join(',')}}`;
  } finally {
    seen.delete(value);
  }
}

export function canonicalizeClaimsV211Independent(value) {
  return canonical(value);
}

function digestHex(value) {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

function base64UrlDecode(value) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error('non-canonical base64url');
  return decoded;
}

export function fingerprintEd25519JwkIndependent(jwk) {
  if (!isObject(jwk) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('unsupported public JWK');
  }
  if (base64UrlDecode(jwk.x).length !== 32) throw new Error('invalid Ed25519 public key length');
  return createHash('sha256')
    .update(canonical({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }))
    .digest('base64url');
}

function envelopePayload(artifact) {
  const payload = { ...artifact };
  delete payload.digest;
  delete payload.signature;
  return payload;
}

function rootShapeValid(artifact) {
  if (!isObject(artifact) || !CLAIMS_V211_TYPES.has(artifact.type)) return false;
  const validator = schemaValidators.get(artifact.type);
  return Boolean(validator?.(artifact))
    && isObject(artifact.signature)
    && Object.keys(artifact.signature).sort().join(',') === 'algorithm,key_fingerprint,signed_at,value'
    && artifact.signature.algorithm === 'Ed25519'
    && artifact.signature.signed_at === artifact[{
      'scopeblind.claim_contract.v2': 'issued_at',
      'scopeblind.claims_conformance_manifest.v1': 'issued_at',
      'scopeblind.trust_policy.v2': 'issued_at',
      'scopeblind.trust_snapshot.v1': 'collected_at',
      'scopeblind.claim_verification_report.v2': 'evaluated_at',
      'scopeblind.recipient_reliance_decision.v3': 'decided_at',
    }[artifact.type]];
}

export function projectClaimsV211Independent(input) {
  if (!input.structural_valid) return { verification_status: 'rejected', projection: null };
  if (!input.assessment_supported) return { verification_status: 'accepted_for_projection', projection: 'not_assessable' };
  if (input.material_conflict) return { verification_status: 'accepted_for_projection', projection: 'conflict' };
  if (input.indication === 'CONTRADICTS' && input.contradiction_final) {
    return { verification_status: 'accepted_for_projection', projection: 'violated' };
  }
  if (input.blocking_gap) return { verification_status: 'accepted_for_projection', projection: 'incomplete' };
  if (input.indication === 'SUPPORTS' && input.establishment === 'ESTABLISHED') {
    return { verification_status: 'accepted_for_projection', projection: 'satisfied' };
  }
  return { verification_status: 'accepted_for_projection', projection: 'not_assessable' };
}

export function negotiateClaimsModulesV211Independent(required, supported) {
  const known = new Set(['C0@2.1.1', 'C1@2.1.1', 'C2a@2.1.1']);
  const dependencies = {
    'C0@2.1.1': [],
    'C1@2.1.1': ['C0@2.1.1'],
    'C2a@2.1.1': ['C0@2.1.1', 'C1@2.1.1'],
  };
  const requiredSet = new Set(required);
  const supportedSet = new Set(supported);
  const issues = [];
  for (const module of required) {
    if (!known.has(module)) {
      issues.push(module.startsWith('C0@') || module.startsWith('C1@') || module.startsWith('C2a@')
        ? 'DOWNGRADE_ATTEMPT'
        : 'UNSUPPORTED_REQUIRED_MODULE');
      continue;
    }
    if (!supportedSet.has(module)) issues.push('UNSUPPORTED_REQUIRED_MODULE');
    for (const dependency of dependencies[module]) {
      if (!requiredSet.has(dependency)) issues.push('DOWNGRADE_ATTEMPT');
      if (!supportedSet.has(dependency)) issues.push('UNSUPPORTED_REQUIRED_MODULE');
    }
  }
  return { supported: issues.length === 0, issues };
}

const ASSURANCE_RANK = {
  self_attested: 0,
  authenticated_pull: 1,
  source_signed: 2,
  independent_witness: 3,
};

export function admissionIssueCodesV211Independent(input) {
  const { candidate, context } = input;
  const issues = [];
  const add = (code) => {
    if (!issues.includes(code)) issues.push(code);
  };
  if (!candidate.schema_valid) add('SCHEMA_INVALID');
  if (!candidate.signature_valid) add('SIGNATURE_INVALID');
  if (issues.length) return issues;

  const evaluated = Date.parse(context.evaluated_at);
  const issued = Date.parse(candidate.issued_at);
  const expires = Date.parse(candidate.expires_at);
  const asOf = Date.parse(candidate.as_of);
  const authorization = context.authorized_issuers.find((entry) =>
    entry.key_fingerprint === candidate.issuer_key_fingerprint
    && entry.roles.includes(candidate.issuer_role)
    && entry.fact_classes.includes(candidate.fact_class)
    && entry.source_ids.includes(candidate.source_id)
    && issued >= Date.parse(entry.valid_from)
    && issued <= Date.parse(entry.valid_until));
  if (!authorization) add('UNAUTHORIZED_ISSUER');
  const observedKey = context.key_observations.find((entry) =>
    entry.key_fingerprint === candidate.issuer_key_fingerprint);
  if (context.revoked_keys.some((entry) =>
    entry.key_fingerprint === candidate.issuer_key_fingerprint
    && Date.parse(entry.revoked_at) <= evaluated)
    || observedKey?.status === 'revoked') {
    add('KEY_REVOKED');
  } else if (!observedKey || observedKey.status !== 'active') {
    add('UNAUTHORIZED_ISSUER');
  } else if (Date.parse(observedKey.observed_at) > evaluated + 300_000) {
    add('FUTURE_DATED_EVIDENCE');
  }
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) add('SCHEMA_INVALID');
  else {
    const maxLifetime = Math.min(context.contract.max_lifetime_seconds, context.policy.max_lifetime_seconds);
    const maxAge = Math.min(context.contract.max_age_seconds, context.policy.max_age_seconds);
    if (expires - issued > maxLifetime * 1000 || evaluated > expires || evaluated - issued > maxAge * 1000) {
      add('STALE_EVIDENCE');
    }
    if (issued > evaluated + 300_000 || asOf > evaluated + 300_000) add('FUTURE_DATED_EVIDENCE');
  }
  const acceptedSource = context.accepted_sources.find((entry) =>
    entry.source_id === candidate.source_id && entry.population_id === candidate.population_id);
  const observedSource = context.source_observations.find((entry) => entry.source_id === candidate.source_id);
  const minimumAssurance = acceptedSource
    ? Math.max(ASSURANCE_RANK[context.contract.minimum_source_assurance], ASSURANCE_RANK[acceptedSource.minimum_assurance])
    : Number.POSITIVE_INFINITY;
  if (!acceptedSource
    || !context.contract.source_ids.includes(candidate.source_id)
    || observedSource?.status !== 'trusted'
    || ASSURANCE_RANK[candidate.source_assurance] < minimumAssurance
    || (observedSource
      && ASSURANCE_RANK[candidate.source_assurance] > ASSURANCE_RANK[observedSource.assurance])
    || candidate.population_id !== context.contract.population_id
    || candidate.population_digest !== context.contract.population_digest) {
    add('SOURCE_OUTSIDE_POPULATION');
  }
  if (observedSource && Date.parse(observedSource.observed_at) > evaluated + 300_000) {
    add('FUTURE_DATED_EVIDENCE');
  }
  if (candidate.state_domain_digest !== context.contract.state_domain_digest
    || !context.contract.state_values.includes(candidate.state)) {
    add('STATE_DOMAIN_MISMATCH');
  }
  if (candidate.subject_digest !== context.contract.subject_digest || candidate.purpose !== context.contract.purpose) {
    add('UNAUTHORIZED_ISSUER');
  }
  if (candidate.period_starts_at !== context.contract.period_starts_at
    || candidate.period_ends_at !== context.contract.period_ends_at
    || asOf < Date.parse(context.contract.period_starts_at)
    || asOf > Date.parse(context.contract.period_ends_at)) {
    add('SOURCE_OUTSIDE_POPULATION');
  }
  for (const code of negotiateClaimsModulesV211Independent(candidate.required_modules, context.supported_modules).issues) add(code);
  const replayIdentity = digestHex({
    type: 'scopeblind.claims_evidence_replay_identity.v1',
    artifact_type: candidate.artifact_type,
    artifact_digest: candidate.artifact_digest,
    issuer_key_fingerprint: candidate.issuer_key_fingerprint,
    source_id: candidate.source_id,
    subject_digest: candidate.subject_digest,
    population_digest: candidate.population_digest,
    as_of: candidate.as_of,
  });
  if (candidate.replay_scope !== 'claim-and-source' || candidate.replay_identity !== replayIdentity) {
    add('ARTIFACT_TYPE_REPLAY');
  }
  if (context.replay_observations.some((entry) =>
    entry.artifact_type === candidate.artifact_type
    && entry.replay_scope === candidate.replay_scope
    && entry.identity === candidate.replay_identity
    && entry.seen_before)) {
    add('REPLAY_DETECTED');
  }
  return issues;
}

export function evaluateOperatorV211Independent(input) {
  const values = input.values;
  const closed = input.population_closed && input.period_closed;
  const empty = values.length === 0;
  const vacuous = empty
    && input.empty_population_semantics === 'vacuous_truth_recipient_opt_in'
    && input.allow_vacuous_truth;
  let indication = 'INDETERMINATE';
  let support_final = false;
  let contradiction_final = false;
  let material_conflict = false;
  let assessment_supported = true;
  const equal = (left, right) => digestHex(left) === digestHex(right);

  if (empty && closed && input.empty_population_semantics === 'violated') {
    indication = 'CONTRADICTS';
    contradiction_final = true;
  } else if (input.operator === 'for_all') {
    if (values.some((value) => !equal(value, input.expected))) {
      indication = 'CONTRADICTS';
      contradiction_final = true;
    } else if ((!empty && closed) || vacuous) {
      indication = 'SUPPORTS';
      support_final = true;
    }
  } else if (input.operator === 'none') {
    if (values.some((value) => equal(value, input.expected))) {
      indication = 'CONTRADICTS';
      contradiction_final = true;
    } else if ((!empty && closed) || vacuous) {
      indication = 'SUPPORTS';
      support_final = true;
    }
  } else if (input.operator === 'exists') {
    if (values.some((value) => equal(value, input.expected))) {
      indication = 'SUPPORTS';
      support_final = true;
    } else if (closed) {
      indication = 'CONTRADICTS';
      contradiction_final = true;
    }
  } else if (input.operator === 'count_eq' || input.operator === 'count_lte') {
    if (!Number.isInteger(input.expected) || input.expected < 0) assessment_supported = false;
    else if (input.operator === 'count_eq') {
      if (values.length > input.expected || (closed && values.length !== input.expected)) {
        indication = 'CONTRADICTS';
        contradiction_final = true;
      } else if (closed && values.length === input.expected) {
        indication = 'SUPPORTS';
        support_final = true;
      }
    } else if (values.length > input.expected) {
      indication = 'CONTRADICTS';
      contradiction_final = true;
    } else if (closed) {
      indication = 'SUPPORTS';
      support_final = true;
    }
  } else if (input.operator === 'sum_lte') {
    if (typeof input.expected !== 'number' || values.some((value) => typeof value !== 'number' || value < 0)) {
      assessment_supported = false;
    } else if (values.reduce((sum, value) => sum + value, 0) > input.expected) {
      indication = 'CONTRADICTS';
      contradiction_final = true;
    } else if (closed) {
      indication = 'SUPPORTS';
      support_final = true;
    }
  } else if (input.operator === 'equals' || input.operator === 'in_set') {
    const unique = new Map(values.map((value) => [digestHex(value), value]));
    if (unique.size > 1) material_conflict = true;
    else if (unique.size === 1) {
      const value = [...unique.values()][0];
      const matches = input.operator === 'equals'
        ? equal(value, input.expected)
        : Array.isArray(input.expected) && input.expected.some((entry) => equal(entry, value));
      indication = matches ? 'SUPPORTS' : 'CONTRADICTS';
      support_final = matches;
      contradiction_final = !matches;
    }
  } else {
    assessment_supported = false;
  }
  return {
    indication,
    support_final,
    contradiction_final,
    material_conflict,
    assessment_supported,
  };
}

export function validateRecipientDecisionV211Independent(input) {
  const bindings_match = input.decision.report_digest === input.report.digest
    && input.decision.claim_contract_digest === input.report.claim_contract_digest
    && input.decision.trust_policy_digest === input.report.trust_policy_digest
    && input.decision.trust_snapshot_digest === input.report.trust_snapshot_digest
    && input.decision.conformance_manifest_digest === input.report.conformance_manifest_digest;
  const acknowledged = input.report.projection !== null
    && input.decision.acknowledged_result.indication === input.report.indication
    && input.decision.acknowledged_result.establishment === input.report.establishment
    && input.decision.acknowledged_result.projection === input.report.projection;
  const exception_required = input.decision.decision === 'accept' && input.report.projection !== 'satisfied';
  const exception_valid = !exception_required
    || (input.decision.reason_code === 'exception_accepted' && input.decision.exceptions.length > 0);
  return {
    bindings_match,
    acknowledged,
    exception_required,
    exception_valid,
    semantically_valid: bindings_match && acknowledged && exception_valid,
  };
}

export function verifyClaimsEnvelopeV211Independent(artifact, jwk) {
  if (!rootShapeValid(artifact)) {
    return { verified: false, structural_valid: false, digest_valid: false, signature_valid: false, reason: 'schema_invalid' };
  }
  try {
    const fingerprint = fingerprintEd25519JwkIndependent(jwk);
    const payload = Buffer.from(canonical(envelopePayload(artifact)));
    const digest = createHash('sha256').update(payload).digest('hex');
    const digest_valid = artifact.digest === digest;
    const fingerprint_valid = artifact.signature.key_fingerprint === fingerprint;
    const signature_valid = verifySignature(
      null,
      payload,
      createPublicKey({ key: jwk, format: 'jwk' }),
      base64UrlDecode(artifact.signature.value),
    );
    return {
      verified: digest_valid && fingerprint_valid && signature_valid,
      structural_valid: true,
      digest_valid,
      signature_valid,
      fingerprint_valid,
      reason: digest_valid && fingerprint_valid && signature_valid ? null : 'signature_invalid',
    };
  } catch (error) {
    return {
      verified: false,
      structural_valid: true,
      digest_valid: false,
      signature_valid: false,
      reason: error instanceof Error ? error.message : 'signature_invalid',
    };
  }
}

function publicJwkFromHex(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('Claims v2.1.1 requires a 32-byte Ed25519 public key');
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(hex, 'hex').toString('base64url') };
}

export function verifyClaimsArtifactV211(artifact, options = {}) {
  let jwk = options.publicJwk;
  if (!jwk && options.publicKey) jwk = publicJwkFromHex(options.publicKey);
  if (!jwk) {
    return {
      valid: false,
      error: 'public_key_required',
      format: 'scopeblind-claims-v2.1.1',
      type: artifact?.type,
      cryptographically_valid: false,
      trusted: false,
      accepted: false,
      limitations: ['A signing key must be pinned by the verifier; the artifact cannot install its own trust anchor.'],
    };
  }
  const envelope = verifyClaimsEnvelopeV211Independent(artifact, jwk);
  let semantic_valid = true;
  let semantic = null;
  if (artifact?.type === 'scopeblind.claim_verification_report.v2' && envelope.structural_valid) {
    semantic = projectClaimsV211Independent({
      structural_valid: artifact.structural_valid,
      assessment_supported: !artifact.issues.some((entry) => entry.code === 'ASSESSMENT_UNSUPPORTED'),
      indication: artifact.indication ?? 'INDETERMINATE',
      contradiction_final: artifact.issues.some((entry) => entry.code === 'DECISIVE_CONTRADICTION'),
      material_conflict: artifact.issues.some((entry) => entry.code === 'MATERIAL_CONFLICT'),
      blocking_gap: artifact.establishment === 'BLOCKED'
        && !artifact.issues.some((entry) => entry.code === 'MATERIAL_CONFLICT'),
      establishment: artifact.establishment ?? 'BLOCKED',
    });
    semantic_valid = semantic.verification_status === artifact.verification_status
      && semantic.projection === artifact.projection;
  }
  if (artifact?.type === 'scopeblind.recipient_reliance_decision.v3'
    && artifact.decision === 'accept'
    && artifact.acknowledged_result?.projection !== 'satisfied') {
    semantic_valid = artifact.reason_code === 'exception_accepted' && artifact.exceptions?.length > 0;
  }
  return {
    valid: envelope.verified && semantic_valid,
    error: envelope.verified ? semantic_valid ? null : 'semantic_mismatch' : envelope.reason,
    format: 'scopeblind-claims-v2.1.1',
    modeLabel: 'ScopeBlind Verifiable Claims v2.1.1 point-in-time artifact',
    type: artifact?.type,
    algorithm: 'Ed25519',
    publicKey: Buffer.from(base64UrlDecode(jwk.x)).toString('hex'),
    keySource: options.publicKey ? 'provided' : 'pinned-jwk',
    cryptographically_valid: envelope.verified,
    trusted: false,
    accepted: false,
    projection: artifact?.projection ?? artifact?.acknowledged_result?.projection ?? null,
    semantic,
    limitations: [
      'Signature validity is not recipient trust or acceptance.',
      'This verifier checks one point-in-time artifact; an Assurance Case must also bind its exact companion artifacts.',
      'This release does not provide standing assurance.',
    ],
  };
}
