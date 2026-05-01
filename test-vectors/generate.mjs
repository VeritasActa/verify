/**
 * Generator for VeritasActa/verify test-vectors.
 *
 * Produces three deterministic JSON files:
 *   1. jcs-test-vectors.json       - JCS canonicalization conformance
 *   2. cross-verify-bundle.json    - 10-receipt Knowledge Unit bundle
 *   3. selective-disclosure-salted-commit.json - AIP-0002 reference
 *
 * Determinism:
 *   Ed25519 keys derive from SHA-256(SEED || role).
 *   Salts and timestamps are fixed constants.
 *   Running this script should always produce byte-identical output.
 */

import {
  canonicalize,
  canonicalHash,
  createSignedArtifact,
  getPublicKey,
  publicKeyToJWK,
  computeKid,
  bytesToHex,
  hexToBytes,
  sha256,
} from '@veritasacta/artifacts';
import { ed25519 } from '@noble/curves/ed25519';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// ─── Deterministic seed ──────────────────────────────────────────
const SEED = 'veritasacta:verify:test-vectors:2026-04-17';

function deriveKey(role) {
  const seed = sha256(new TextEncoder().encode(`${SEED}:${role}`));
  return bytesToHex(seed);
}

function sha256hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

// ═══════════════════════════════════════════════════════════════════
// 1. jcs-test-vectors.json
// ═══════════════════════════════════════════════════════════════════

const JCS_CASES = [
  {
    name: 'empty_object',
    description: 'Empty object serializes as {} with no whitespace.',
    input: {},
  },
  {
    name: 'single_key_value',
    description: 'Single key-value pair, no sorting needed.',
    input: { message: 'hello' },
  },
  {
    name: 'nested_key_sorting',
    description: 'Nested objects are sorted recursively by key name.',
    input: {
      b: { z: 1, a: 2 },
      a: 1,
    },
  },
  {
    name: 'array_order_preserved',
    description: 'Array element order is preserved (not sorted).',
    input: { list: [3, 1, 2, 'c', 'a', 'b'] },
  },
  {
    name: 'number_serialization',
    description: 'Numbers serialize with JSON.stringify defaults. No trailing zeros, no +e notation for integers in this range.',
    input: { int: 42, neg: -17, zero: 0, frac: 0.5 },
  },
  {
    name: 'mixed_primitives',
    description: 'null, true, false, string, empty array, empty object all serialize correctly.',
    input: {
      nul: null,
      t: true,
      f: false,
      s: 'hi',
      empty_arr: [],
      empty_obj: {},
    },
  },
  {
    name: 'unicode_in_values_ok',
    description: 'Non-ASCII characters in values are permitted. Only keys are restricted to ASCII (AIP-0001 §JCS Canonicalization).',
    input: { greeting: 'héllo wörld', emoji: '✓' },
  },
  {
    name: 'receipt_shaped_payload',
    description: 'Realistic receipt-shaped payload: decision, policy digest, scope, nested metadata. The shape a real KU receipt payload takes.',
    input: {
      type: 'veritasacta:knowledge_unit:receipt',
      ku_id: 'ku_4b3f7c2a',
      sequence: 1,
      model: { name: 'claude-opus-4.6', vendor: 'anthropic' },
      response_digest: 'sha256:f7e2d4c1b8a9',
      policy_digest: 'sha256:abcdef0123456789',
      decision: 'allow',
    },
  },
  {
    name: 'ascii_only_key_rejected',
    description: 'Non-ASCII characters in keys are rejected at ingest per AIP-0001 §JCS Canonicalization. This sidesteps the Unicode normalization surface (NFC vs NFD, combining marks, bidi). Matches APS v1.41.0 canonicalizer behavior.',
    input: { 'héllo': 'world' },
    expected_error: 'non-ASCII key',
  },
];

function buildJcsVectors() {
  const vectors = [];
  for (const c of JCS_CASES) {
    if (c.expected_error) {
      let error = null;
      try {
        canonicalize(c.input);
      } catch (e) {
        error = e.message;
      }
      vectors.push({
        name: c.name,
        description: c.description,
        input: c.input,
        expected: { error: error || 'ERROR_NOT_THROWN' },
      });
    } else {
      const canonical = canonicalize(c.input);
      vectors.push({
        name: c.name,
        description: c.description,
        input: c.input,
        canonical,
        sha256: sha256hex(canonical),
      });
    }
  }
  return {
    format: 'veritasacta:jcs-test-vectors:v1',
    spec: 'AIP-0001 §JCS Canonicalization',
    normative_reference: 'RFC 8785 (with ASCII-only key restriction)',
    generated_at: '2026-04-17T00:00:00Z',
    generator: '@veritasacta/artifacts canonicalize() v0.2.2',
    how_to_use: [
      'For each vector, feed `input` to your JCS canonicalizer.',
      'Compare your output string byte-for-byte to `canonical`.',
      'Compute SHA-256 of your output and compare to `sha256` (lowercase hex).',
      'For `ascii_only_key_rejected`, your canonicalizer MUST throw when a key contains non-ASCII.',
    ],
    vectors,
  };
}

// ═══════════════════════════════════════════════════════════════════
// 2. cross-verify-bundle.json
// ═══════════════════════════════════════════════════════════════════

const MODELS = [
  { id: 'claude-opus-4.6', vendor: 'anthropic', role: 'model-claude' },
  { id: 'gpt-5', vendor: 'openai', role: 'model-gpt' },
  { id: 'gemini-2.5-pro', vendor: 'google', role: 'model-gemini' },
  { id: 'grok-4.20', vendor: 'xai', role: 'model-grok' },
];

// Fixed deliberation content (stand-in for real model outputs).
// Each response is summarized as a digest; full content is out-of-band.
const ROUND_CONTENT = {
  topic: 'Given fixed FLOPs budget, does quadratic attention or linear attention yield better sample efficiency at 70B scale?',
  round1: {
    'claude-opus-4.6':  { position: 'quadratic', confidence: 0.72 },
    'gpt-5':            { position: 'quadratic', confidence: 0.65 },
    'gemini-2.5-pro':   { position: 'depends_on_sequence_length', confidence: 0.80 },
    'grok-4.20':        { position: 'linear', confidence: 0.58 },
  },
  round2: {
    'claude-opus-4.6':  { position: 'quadratic', confidence: 0.74, dissent_from: ['grok-4.20'] },
    'gpt-5':            { position: 'depends_on_sequence_length', confidence: 0.70, updated_from_round1: true },
    'gemini-2.5-pro':   { position: 'depends_on_sequence_length', confidence: 0.85 },
    'grok-4.20':        { position: 'linear', confidence: 0.55, dissent_from: ['claude-opus-4.6', 'gpt-5', 'gemini-2.5-pro'] },
  },
};

const KU_ID = 'ku_4b3f7c2a9d8e1f05';
const BUNDLE_ISSUED = '2026-04-17T12:00:00Z';

function buildReceipt({ type, payload, signerKey, kid, issuer, issuedAt }) {
  const { artifact } = createSignedArtifact(type, payload, signerKey, {
    kid,
    issuer,
    issued_at: issuedAt,
  });
  return artifact;
}

function buildBundle() {
  // Keys: one per model + one arbiter for synthesis/aggregate
  const keys = {};
  for (const m of MODELS) {
    const priv = deriveKey(m.role);
    const pub = getPublicKey(priv);
    keys[m.id] = { priv, pub, kid: computeKid(pub), issuer: `ku:model:${m.id}` };
  }
  const arbiterPriv = deriveKey('arbiter');
  const arbiterPub = getPublicKey(arbiterPriv);
  keys['__arbiter__'] = {
    priv: arbiterPriv,
    pub: arbiterPub,
    kid: computeKid(arbiterPub),
    issuer: 'ku:arbiter:scopeblind-reference',
  };

  const receipts = [];
  let sequence = 0;
  let prevHash = null;

  function nextReceipt(modelKey, payload, type) {
    sequence += 1;
    const k = keys[modelKey];
    const fullPayload = {
      ku_id: KU_ID,
      sequence,
      ...payload,
      ...(prevHash ? { previousReceiptHash: `sha256:${prevHash}` } : {}),
    };
    const issuedAt = `2026-04-17T12:00:${String(sequence).padStart(2, '0')}Z`;
    const artifact = buildReceipt({
      type,
      payload: fullPayload,
      signerKey: k.priv,
      kid: k.kid,
      issuer: k.issuer,
      issuedAt,
    });
    prevHash = canonicalHash(artifact);
    receipts.push(artifact);
    return artifact;
  }

  // Round 1: four independent responses
  for (const m of MODELS) {
    nextReceipt(
      m.id,
      {
        round: 1,
        model: { id: m.id, vendor: m.vendor },
        topic_digest: sha256hex(ROUND_CONTENT.topic),
        response: ROUND_CONTENT.round1[m.id],
      },
      'veritasacta:knowledge_unit:round_response',
    );
  }

  // Round 2: four cross-critiques
  for (const m of MODELS) {
    nextReceipt(
      m.id,
      {
        round: 2,
        model: { id: m.id, vendor: m.vendor },
        topic_digest: sha256hex(ROUND_CONTENT.topic),
        response: ROUND_CONTENT.round2[m.id],
      },
      'veritasacta:knowledge_unit:round_response',
    );
  }

  // Round 3: synthesis (arbiter)
  nextReceipt(
    '__arbiter__',
    {
      round: 3,
      synthesis: {
        consensus: 'depends_on_sequence_length',
        consensus_models: ['gpt-5', 'gemini-2.5-pro'],
        dissenting_positions: [
          { position: 'quadratic', models: ['claude-opus-4.6'], mean_confidence: 0.74 },
          { position: 'linear', models: ['grok-4.20'], mean_confidence: 0.55 },
        ],
        synthesis_confidence: 0.68,
      },
      topic_digest: sha256hex(ROUND_CONTENT.topic),
    },
    'veritasacta:knowledge_unit:synthesis',
  );

  // Aggregate: binds all 9 prior receipts by hash
  const priorHashes = receipts.map((r) => `sha256:${canonicalHash(r)}`);
  nextReceipt(
    '__arbiter__',
    {
      aggregate: {
        binds_receipts: priorHashes,
        round_count: 3,
        model_count: MODELS.length,
        deliberation_outcome: 'synthesis_with_recorded_dissent',
      },
    },
    'veritasacta:knowledge_unit:aggregate',
  );

  // Verification keys (JWK set)
  const signingKeys = [];
  for (const m of MODELS) {
    const k = keys[m.id];
    signingKeys.push({ ...publicKeyToJWK(k.pub, k.kid), issuer: k.issuer });
  }
  signingKeys.push({
    ...publicKeyToJWK(keys.__arbiter__.pub, keys.__arbiter__.kid),
    issuer: keys.__arbiter__.issuer,
  });

  return {
    format: 'veritasacta:knowledge-unit-bundle:v1',
    spec: 'draft-farley-acta-knowledge-units-00',
    ku_id: KU_ID,
    generated_at: BUNDLE_ISSUED,
    description:
      'Complete Knowledge Unit deliberation: 4 models × 2 rounds + 1 synthesis + 1 aggregate = 10 Ed25519-signed receipts. Hash-chained via payload.previousReceiptHash over JCS-canonical bytes. Every receipt is individually verifiable with @veritasacta/verify; the bundle is verifiable with --bundle.',
    verification: {
      signing_keys: signingKeys,
    },
    external_receipts: {
      aps: {
        description:
          'Drop-in slot for an APS DecisionLineageReceipt that references ku_id=' +
          KU_ID +
          '. When populated, both @veritasacta/verify and agent-passport-system verifiers should exit 0 over the same bundle.',
        ku_id: KU_ID,
        expected_fields: ['subject', 'scope', 'ku_id', 'receipt_hash', 'signature'],
        receipt_uri: null,
        receipt: null,
      },
    },
    receipts,
  };
}

function buildApsCrossVerifyArtifacts(bundle) {
  const seed = sha256(new TextEncoder().encode('aps:veritasacta:ku-cross-verify:v1'));
  const priv = bytesToHex(seed);
  const pub = ed25519.getPublicKey(seed);
  const publicKeyHex = bytesToHex(pub);
  const kid = 'aps-ku-cross-verify-v1';
  const seedNote = 'derived from sha256("aps:veritasacta:ku-cross-verify:v1") — test key, NOT a production issuer';
  const issuer = 'aps:test:ku-cross-verify';

  const receipt = {
    receiptId: `dlr_va_${KU_ID}`,
    timestamp: '2026-04-18T00:00:00Z',
    decisionArtifactId: `veritasacta:ku:${KU_ID}`,
    decisionType: 'knowledge_unit_deliberation',
    contributingSources: bundle.receipts.map((r, i) => ({
      sourceId: r.issuer,
      accessReceiptId: `sha256:${canonicalHash(r)}`,
      derivationDepth: i + 1,
      transformPath: ['aggregation'],
      termsVersionAtAccess: 'veritasacta:knowledge-unit-bundle:v1',
      lineageConfidence: 'complete',
      compensationStatus: 'settled',
    })),
    lineageCompleteness: 'complete',
    externalHopsPresent: true,
    transformChain: ['aggregation'],
    governingPurpose: 'research:academic',
    jurisdictionContext: 'veritasacta:knowledge-unit-bundle:v1',
    explanation:
      `APS DecisionLineageReceipt attesting to VeritasActa Knowledge Unit ${KU_ID}. Bundle terminal aggregate sha256: ${canonicalHash(bundle.receipts.at(-1))}. Each entry in contributingSources commits to the JCS-canonical sha256 of one KU receipt; tampering any byte of any KU receipt invalidates the recorded accessReceiptId, breaking cross-layer integrity even though APS's Ed25519 signature over this DecisionLineageReceipt remains cryptographically valid.`,
  };
  receipt.signature = bytesToHex(ed25519.sign(new TextEncoder().encode(canonicalize(receipt)), hexToBytes(priv)));

  const signingKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    use: 'sig',
    issuer,
    public_key_hex: publicKeyHex,
    seed_note: seedNote,
  };

  const jwks = {
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        use: 'sig',
        kid,
        x: Buffer.from(pub).toString('base64url'),
        issuer,
        seed_note: seedNote,
      },
    ],
  };

  const positive = JSON.parse(JSON.stringify(bundle));
  positive.external_receipts.aps.receipt = receipt;
  positive.external_receipts.aps.verification_key_ref = `test-vectors/keys/aps-ku-cross-verify.jwks#${kid}`;
  positive.external_receipts.aps.verifier_hint =
    'Verify APS DecisionLineageReceipt using the independently anchored key referenced by external_receipts.aps.verification_key_ref. Cross-layer integrity: each contributingSources[].accessReceiptId is the JCS-canonical sha256 of the corresponding entry in bundle.receipts.';

  const negative = JSON.parse(JSON.stringify(bundle));
  negative.external_receipts.aps.receipt = receipt;
  negative.external_receipts.aps.signing_key = signingKey;
  negative.external_receipts.aps.verifier_hint =
    'Negative conformance fixture. A verifier MUST reject this bundle because the APS verification key is transported inside external_receipts.aps.signing_key without an independent anchor.';
  negative.external_receipts.aps.expected_result = {
    verifier: '@veritasacta/verify',
    result: 'MUST_REJECT',
    error: 'verification key transported inside receipt without independent anchor',
  };
  negative.expected_verification = {
    result: 'MUST_REJECT',
    error: 'verification key transported inside receipt without independent anchor',
    normative_reference: 'draft-farley-acta-signed-receipts-02 Security Considerations',
  };

  return { positive, negative, jwks };
}

// ═══════════════════════════════════════════════════════════════════
// 3. selective-disclosure-salted-commit.json
// ═══════════════════════════════════════════════════════════════════

function buildSelectiveDisclosure() {
  // Take grok-4.20's Round 1 dissenting response.
  // Redact the response.position and response.confidence under AIP-0002 salted commits.
  const priv = deriveKey('model-grok');
  const pub = getPublicKey(priv);
  const kid = computeKid(pub);
  const issuer = 'ku:model:grok-4.20';

  // Fixed salts for determinism.
  const saltPosition = 'sdc_salt_8f3b2a1c9d6e4702';
  const saltConfidence = 'sdc_salt_11ea5f0c7b4dc893';

  const positionPlain = 'linear';
  const confidencePlain = 0.58;

  // Commitment algorithm: sha256(salt + ":" + JSON.stringify(plaintext)).
  // JSON.stringify gives a canonical encoding for both string and number values:
  //   "linear" → "\"linear\""   0.58 → "0.58"
  const commitPosition = sha256hex(`${saltPosition}:${JSON.stringify(positionPlain)}`);
  const commitConfidence = sha256hex(`${saltConfidence}:${JSON.stringify(confidencePlain)}`);

  // Redacted receipt: published publicly (consensus-visible, dissent-hidden).
  const redactedPayload = {
    ku_id: KU_ID,
    sequence: 4,
    round: 1,
    model: { id: 'grok-4.20', vendor: 'xai' },
    topic_digest: sha256hex(ROUND_CONTENT.topic),
    response: {
      _redacted: {
        scheme: 'veritasacta:aip-0002:salted-sha256-commit',
        fields: {
          position: {
            commitment: `sha256:${commitPosition}`,
            commit_algorithm: 'sha256(salt || ":" || json(value))',
          },
          confidence: {
            commitment: `sha256:${commitConfidence}`,
            commit_algorithm: 'sha256(salt || ":" || json(value))',
          },
        },
      },
    },
  };

  const redactedArtifact = buildReceipt({
    type: 'veritasacta:knowledge_unit:round_response',
    payload: redactedPayload,
    signerKey: priv,
    kid,
    issuer,
    issuedAt: '2026-04-17T12:00:04Z',
  });

  // Disclosure witness: salts + plaintext values that unlock the commitments.
  // Shipped separately (e.g. to an auditor with need-to-know).
  const witness = {
    ku_id: KU_ID,
    sequence: 4,
    disclosures: {
      'response.position': {
        salt: saltPosition,
        plaintext: positionPlain,
        expected_commitment: `sha256:${commitPosition}`,
        verify: 'sha256(salt || ":" || json(plaintext)) === expected_commitment',
      },
      'response.confidence': {
        salt: saltConfidence,
        plaintext: confidencePlain,
        expected_commitment: `sha256:${commitConfidence}`,
        verify: 'sha256(salt || ":" || json(plaintext)) === expected_commitment',
      },
    },
  };

  return {
    format: 'veritasacta:selective-disclosure-salted-commit:v1',
    spec: 'AIP-0002 §Salted SHA-256 Commitments',
    generated_at: BUNDLE_ISSUED,
    description:
      'Demonstrates AIP-0002 redaction: a dissenting round-1 response is published with position and confidence fields replaced by salted SHA-256 commitments. The unsigned `witness` block carries the salts + plaintext values that reveal the commitments to a need-to-know recipient. Complementary to Merkle-tree selective disclosure (APS-style): simpler and zero-dependency, but subset boundary must be fixed at commit time.',
    how_to_use: [
      'Verify `redacted_receipt` with @veritasacta/verify — the Ed25519 signature is over the redacted payload, so verification succeeds without access to the witness.',
      'For each entry in `witness.disclosures`, compute sha256(salt + ":" + JSON.stringify(plaintext)) and compare to `expected_commitment`. If bytes match, the disclosure is authentic.',
      'The receipt is publishable; the witness stays with parties authorized to see the dissenting response.',
    ],
    verification: {
      signing_keys: [{ ...publicKeyToJWK(pub, kid), issuer }],
    },
    redacted_receipt: redactedArtifact,
    witness,
  };
}

// ═══════════════════════════════════════════════════════════════════
// Emit files
// ═══════════════════════════════════════════════════════════════════

const jcsVecs = buildJcsVectors();
const bundle = buildBundle();
const aps = buildApsCrossVerifyArtifacts(bundle);
const sdc = buildSelectiveDisclosure();

const outDir = process.argv[2] || '.';
mkdirSync(`${outDir}/keys`, { recursive: true });
writeFileSync(`${outDir}/jcs-test-vectors.json`, JSON.stringify(jcsVecs, null, 2) + '\n');
writeFileSync(`${outDir}/cross-verify-bundle.json`, JSON.stringify(aps.positive, null, 2) + '\n');
writeFileSync(`${outDir}/cross-verify-embedded-key-bundle.json`, JSON.stringify(aps.negative, null, 2) + '\n');
writeFileSync(`${outDir}/keys/aps-ku-cross-verify.jwks`, JSON.stringify(aps.jwks, null, 2) + '\n');
writeFileSync(
  `${outDir}/selective-disclosure-salted-commit.json`,
  JSON.stringify(sdc, null, 2) + '\n',
);

console.log('Wrote:');
console.log(`  ${outDir}/jcs-test-vectors.json (${jcsVecs.vectors.length} cases)`);
console.log(`  ${outDir}/cross-verify-bundle.json (${bundle.receipts.length} receipts, ${bundle.verification.signing_keys.length} keys, APS sidecar key)`);
console.log(`  ${outDir}/cross-verify-embedded-key-bundle.json (MUST reject embedded-key fixture)`);
console.log(`  ${outDir}/keys/aps-ku-cross-verify.jwks (APS sidecar key)`);
console.log(`  ${outDir}/selective-disclosure-salted-commit.json (${Object.keys(sdc.witness.disclosures).length} redacted fields)`);
