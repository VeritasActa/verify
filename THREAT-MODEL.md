# Threat Model

`@veritasacta/verify` is a local, offline verifier for signed
machine-decision artifacts. This document specifies what it protects
against, what it does not, and the trust boundaries a caller must
understand.

## 1. Goals (in scope)

The verifier provides, for any artifact it reports as VALID:

- **Signature integrity**: the signed payload has not been modified since
  the signer produced it. An adversary with access to the artifact but
  not the signing key cannot produce a VALID result by tampering.
- **Policy binding** (for receipts that include `policy_hash` /
  `policy_id`): the decision was made under the identified policy
  version, not a later-substituted policy.
- **Chain integrity** (for chained receipts): no receipt in the chain
  has been inserted, removed, or reordered; every `previousReceiptHash`
  matches the canonical hash of the preceding receipt.
- **Algorithm conformance**: the signature algorithm is explicitly
  supported; unrecognized algorithms are reported as `undecidable`
  rather than silently accepted.
- **Canonicalization determinism**: input that re-encodes into the same
  canonical bytes produces the same verification result byte-for-byte.
  Canonicalization follows RFC 8785 with AIP-0001 ASCII-only keys.
- **Selective-disclosure validity** (for receipts with `_commitments`):
  a revealed `{field, salt, value}` triple matches the committed hash
  if and only if the field content is authentic.
- **VOPRF DLEQ proof verification** (when full extraction lands):
  tokens are proven issued by the claimed issuer key.
- **Local byte-integrity comparison** (`--self-check`): the installed
  verifier binary + engine files match the commitment bundled in that
  installation. This is not publisher authentication unless the caller
  independently pins the expected commitment.
- **Offline operation**: verification uses no network calls unless the
  caller explicitly passes `--jwks`.

## 2. Non-Goals (out of scope)

The verifier does NOT protect against:

- **Compromised signing keys**: if the signer's private key leaks, an
  adversary with the key can produce VALID receipts. The verifier
  cannot distinguish these from legitimate receipts.
- **Issuer collusion**: if an issuer signs receipts for actions that
  never occurred, those receipts are cryptographically valid. Detecting
  such fraud requires separate mechanisms (transparency logs, independent
  attestation, external audit).
- **Policy semantics**: the verifier confirms a receipt references a
  `policy_id` / `policy_hash`, but does NOT interpret the policy or
  evaluate whether the decision was correct given the inputs. Policy
  interpretation is the caller's responsibility.
- **Replay across contexts**: a receipt valid in one context (e.g., a
  specific session) may be replayed in another. Preventing replay is
  the application layer's responsibility; the verifier surfaces
  `nullifier`, `scope`, and timestamp fields that enable the caller to
  implement replay guards.
- **Time authority**: `issued_at` is self-asserted by the signer. The
  verifier does not independently time-stamp. Applications requiring a
  trusted timestamp must combine signed receipts with transparency-log
  inclusion proofs or an external timestamping authority.
- **Holder possession**: when `holder_binding` is present in a receipt,
  the verifier surfaces the binding but does NOT prove the presenting
  party is the committed holder. Possession proof requires an additional
  mechanism (DPoP header at presentation, signed nonce, etc.) at the
  caller layer.
- **Receipt availability / censorship**: the verifier only evaluates
  artifacts it is given. It cannot detect missing receipts, gaps in a
  chain held elsewhere, or receipts that were never surfaced.
- **Input size / resource exhaustion**: the verifier imposes reasonable
  defaults on input size, but callers accepting untrusted input at scale
  should apply their own limits before invoking the verifier.

## 3. Trust Boundaries

For a verification to be trustworthy, the following must hold:

### 3.1 The caller must authentically obtain the verification key

The verifier takes a public key as input (via `--key`, `--jwks`, or
`--trust-anchor`). The authenticity of that key is the caller's
responsibility. The verifier does NOT accept keys embedded in the
receipt payload itself (this was the `embedded_key_rejected` issue
fixed in 0.4.0).

Recommended key distribution mechanisms:

- **JWKS at a well-known URL** with TLS-authenticated domain ownership
- **DID Document** with method-specific authentication
- **Configured trust anchor** (locally pinned public key)
- **Transparency log entry** with inclusion proof

### 3.2 The caller must provide an authentic runtime environment

The verifier executes in Node.js. A compromised Node.js runtime or a
compromised installation of the verifier can produce arbitrary output.
The `--self-check` command compares the declared monitored source with the
commitment bundled beside it. The monitored runtime includes `cli.js` and
every shipped executable JavaScript module under `src/`; a release test fails
if that runtime tree and the declaration diverge. A compromised environment
can alter both source and commitment, so a passing self-check does not
authenticate the publisher or prove an independently canonical release.
Callers operating in high-assurance environments should pin the expected
commitment through an authenticated channel and reproduce the verification in
a separate trust domain.

### 3.3 The caller must authentically obtain the verifier

The npm package ships with a Sigil commitment over specific file hashes.
`--self-check` confirms the declared monitored source matches that bundled
commitment only.
An npm provenance attestation is a separate supply-chain artifact; callers
must verify it independently and must not infer it from a passing self-check.
Callers verifying an installation should:

1. Install via `npm install @veritasacta/verify` (Sigstore-attested)
2. Verify the npm provenance attestation using the registry's supported
   mechanism
3. Obtain the expected Sigil fingerprint through an authenticated,
   independently trusted channel
4. Run `npx @veritasacta/verify --pin-sigil <fingerprint>` and
   `--self-check` to confirm local files match that pinned commitment

## 4. Explicit Attack Classes

### 4.1 Signature forgery

Forgery of an Ed25519 signature without possession of the private key
requires breaking Ed25519 (equivalent to ~128-bit security against
classical attackers; reduced under post-quantum attack but still
requires significant work).

### 4.2 Hash collision

Forgery via SHA-256 collision requires ~2^128 work; outside practical
threat model. The verifier treats `sha256:` prefixes consistently and
rejects malformed hash strings.

### 4.3 Canonicalization confusion

Canonicalization divergence between signer and verifier can allow an
attacker to produce a receipt that verifies under one canonicalization
but fails under another. The verifier uses RFC 8785 JCS with AIP-0001
ASCII-only keys, consistently. Test vectors in
`specs/conformance/test-vectors/` exercise edge cases.

Non-ASCII keys are rejected at ingest per AIP-0001, preventing the
most common Unicode-normalization attacks.

### 4.4 Timing attacks

Signature byte comparison uses constant-time equality
(`constantTimeEqual` in `src/util/hex.js`). Cache-timing and
side-channel attacks against the @noble/curves Ed25519 implementation
are outside this project's scope; we rely on the auditability of that
library (audited by Trail of Bits, etc.).

### 4.5 Input-parsing attacks

The verifier parses JSON via Node.js's built-in parser. Deeply nested
or oversized inputs can exhaust memory. Callers accepting untrusted
input at scale should apply size limits (e.g., 10 MB) before invoking
the verifier. A future release will impose a built-in default limit.

### 4.6 Algorithm downgrade

The verifier requires an explicit algorithm identifier in the signature
envelope. Unknown algorithms trigger `unsupported_algorithm`, not
silent fallback to a weaker algorithm. Hybrid post-quantum algorithms
(`ed25519+ml-dsa-65`) are recognized structurally but fully verified
only when full PQ support lands (v0.6+).

### 4.7 JWKS endpoint compromise

If a caller uses `--jwks <url>` and the URL endpoint serves malicious
keys, those keys will be used for verification. The caller is
responsible for ensuring JWKS endpoints are authenticated (TLS with
pinned certificates or trusted PKI) and are controlled by the expected
issuer.

### 4.8 Process-level interference

A malicious process running in the same user context can replace the
verifier binary, modify its output, or intercept its inputs. The
verifier does not mitigate this; it is a correct-implementation of
verification in a correct-environment model. OS-level isolation (e.g.,
Linux Landlock, macOS sandboxing) or process-level attestation is the
caller's responsibility.

## 5. Cryptographic Assumptions

1. **Ed25519 is unforgeable** under known-message attacks (standard
   EUF-CMA assumption per RFC 8032).
2. **SHA-256 is collision-resistant** at ~128 bits of work.
3. **JCS canonicalization** produces deterministic output for
   semantically equivalent JSON.
4. **The @noble/curves and @noble/hashes libraries** correctly
   implement the claimed primitives, verified by third-party audit.

Any future quantum computer sufficient to break Ed25519 invalidates
signatures created under Ed25519. The verifier's hybrid PQ support
path (`ed25519+ml-dsa-65`) provides forward compatibility.

## 6. Supply Chain

The v0.5.0 package is published with:

- `npm publish --provenance`: Sigstore-attested supply chain
- Sigil commitment in `sigil.json` covering `cli.js`, every shipped
  executable JavaScript module under `src/`, and the other explicitly
  declared monitored sources
- `@veritasacta/artifacts` as the single declared dependency
- Transitive dependencies limited to `@noble/curves` and
  `@noble/hashes`

Callers verifying the supply chain should:

1. Install from npm: `npm install @veritasacta/verify@0.9.6`
2. Verify the npm provenance attestation via `npm audit signatures`
   or Sigstore's cosign
3. Obtain and pin the expected Sigil fingerprint through an independently
   authenticated channel
4. Run `--self-check` to confirm the installed files match that pinned
   commitment

## 7. Reporting Issues

See `SECURITY.md` for the coordinated disclosure policy and contact
address.
