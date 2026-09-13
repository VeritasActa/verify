# Changelog

## 0.10.11 (2026-09-12)

- Exit status means what a CI gate needs it to mean. A run manifest given companion files exits 1 unless it binds to all of them; alone it still exits 0 and says unbound. Before this, a mutated receipt log could fail a check, report `binding: partial`, and exit 0 (found by aeoess).
- The receipt log and the calls log are checked as bytes: `receipts.jsonl` and `calls.jsonl` as given must hash to the digests the manifest records, not merely parse to the same records (found by aeoess).
- The gate policy digest is recomputed from the policy text the standard carries, instead of two declared digests being compared (found by aeoess).
- `--maintainer-key <hex|file>` pins the maintainer key that must have signed the standard, a trust root from outside the files; the report then establishes who signed the standard instead of asking you to pin it.

## 0.10.10 (2026-09-12)

- Readable names. Certificate subjects and issuers print as `CN=..., O=...` instead of raw attribute OIDs, in the Sigstore and Intel TDX chains alike.
- The mode line names the artifact: a run manifest reads `Legate verified run (run manifest), checked offline`, a standard, a decision, and an action bundle each their own, instead of one line listing all four.
- What a run establishes reads in the order a reader asks: the signed account, the standard, the receipts, the gradings, the provenance, the model route, then the keys; each line shorter, repositories and workflows by name.

## 0.10.9 (2026-09-12)

- `--regrade` is repeatable. The first is the run's own second grading; each further one is a grading made elsewhere (`regrade_2`, `regrade_3`, ...), verified the same way: under its grader key, for this manifest, accepted by the standard (a listed key, or the provenance identity of a bundle given with `--provenance` that names the grading's exact bytes), distinct from the harness key, and agreeing with every verdict and workspace. One accepted, agreeing grading reconciles the verdicts; every grading supplied must hold for the run to bind. The first such grader is VeritasActa/verified-runs-grader.
- A second grading is accepted by the key the standard names, or by the provenance identity the standard names (`trust.accepted_grader_provenance`) when the regrade's own bytes carry a verified bundle from that identity: a grader elsewhere needs no key listed in advance. The report says which repository made the regrade and whether it is the run's own or another.
- Keys by provenance. When a run's manifest and receipts carry verified provenance and its gateway and harness keys are not the demonstration keys, the verifier reports them as generated inside the attested workflow run; otherwise it says which keys are demonstration keys, and always says the maintainer key must be pinned through a channel of the reader's own.

## 0.10.8 (2026-09-12)

- A run manifest's `model_calls` pin (the digest and count of the signed model-calls log) is part of the signed body. 0.10.7 computed the manifest digest without it and refused every attested manifest as altered; this release verifies them. A manifest without the field is unchanged.
- Attestation reports from a gateway (`model_attestations[]`, one per model node) are expanded to their entries.

## 0.10.7 (2026-09-12)

- Attested model route. `--model-calls model-calls.jsonl` and `--model-attestation model-attestation.json` verify, offline, that every model call of a run was signed inside the inference provider's TEE (NEAR AI Cloud's shape: a secp256k1 signature over `{model}:{sha256(request)}:{sha256(response)}`), that each signing key is bound in an attestation report whose Intel TDX quote chains to the pinned Intel SGX Root CA (quote signature, quoting-enclave binding and signature, PCK chain, validity), and that the attested model is the one the standard names. The report's GPU evidence and the platform's TCB status are carried and named, not verified here. Adds `verifyTdxQuote` to the engine.

## 0.10.6 (2026-09-12)

- `--provenance`: a bundle made in another run verifies on its own terms but does not count for this manifest, and unbinds nothing; it contradicts the manifest only when it names the manifest's own bytes. A deterministic standard is attested by every run that used it, so `gh attestation download standard.json` returns every run's bundle, and a reader may well hold bundles from other runs.

## 0.10.5 (2026-09-12)

- `--provenance <path>` for Legate run manifests: the Sigstore provenance bundles beside a run (`provenance/*.sigstore.jsonl`, a file or a directory, repeatable) are verified here, offline, against the pinned Sigstore public-good trust root: the certificate chain to Fulcio, the workflow identity in the certificate (issuer, workflow, repository, commit, run) against what the manifest names, the DSSE signature, the Rekor entry (log key, entry body, signed entry timestamp, integration time inside the certificate's validity), the inclusion proof and signed checkpoint, and the certificate-transparency SCT. Each file given on the command line must be a subject of a verified bundle, by its exact bytes. `gh attestation verify` remains an independent path.
- Run manifests may name the commit and the workflow the run was made at (`environment.attestation.commit`, `.workflow`); when present, the certificate must agree.

## 0.10.4 (2026-09-11)

### Added
- Run manifests bind two more things. `--calls <file>` takes the calls log (one call per receipt: tool and input) and checks that every receipt's input digest opens to the call recorded, so an allowed shell receipt is no longer a digest a reader cannot look behind. `--regrade <file>` takes a second grading (`scopeblind.run_regrade.v1`): the pinned tests re-run on the archived workspace, signed under a grader key the standard accepts and distinct from the harness key; the verifier reconciles it with the manifest, and a standard that asks for independent reconciliation is held until a second grading agrees. Manifests may pin each attempt's workspace and the calls log by digest. These answer the first outside review of a verified run (arian-gogani, nobulex): the verdicts were the harness's word, and an input digest could not tell a listing from an egress.

## 0.10.3 (2026-09-11)

### Added
- Consumed authority. An effect readback may carry a signed `authorization` block: the destination consumed the gate's receipt as a single-use authorization for exactly these terms before it committed (kind, receipt digest, request id, consumed at, spend index). A standard that sets `requirements.receiver_consumes_authorization` is evaluated with a `consumption` check: a readback without a cited authorization is held, not accepted. Readbacks made before the block existed verify byte for byte; a readback that carries the block needs this version or later, because the block is under the signature.
- `requirements.credentials_held_by_gate`: the credentials the gateway holds and injects. The gateway receipt report checks that every allowed call to the tool records the label (`credential_ref`), never the value.

## 0.10.2 (2026-09-11)

### Changed
- Run manifests: the harness key that signed the manifest must be one the standard accepts as a readback source (`trust.accepted_readback_sources`), checked as `harness_key`. Without it a manifest re-signed under a fresh key verified as intact with nothing tying it to the maintainer. Manifests made before this cut fail the check against their standards until the standard names the harness key, which is the point.

## 0.10.1 (2026-09-11)

### Added
- Run manifests (`scopeblind.run_manifest.v1`): a harness's signed account of a governed run, such as a benchmark submission made with every tool call through the gateway. Alone, the file verifies as intact and prints its result. With `--standard <standard.json>` and `--receipts <receipts.jsonl>` beside it, the verifier checks that the manifest names that standard by digest, that the receipts are the ones the manifest names (count and chain head), that every receipt cites the policy compiled from the standard, that every allowed call names a tool on the standard's list, that no task exceeds the allowed attempts or time, that the task-set and harness pins match, and that the gateway key is one the standard accepts. What it does not establish is printed with it: who holds the keys, whether the sandbox enforced its network rule (that is the environment attestation's job), and anything the agent said.

## 0.10.0 (2026-09-11)

### Added
- Legate standard files verify with the one command: a signed standard (`scopeblind.proof_request.v1`), a recipient decision (`scopeblind.admission_decision.v1`), and an action assurance bundle (`scopeblind.action_assurance_bundle.v1`) are detected and verified by the same core the Legate site runs, bundled as `src/engines/legate-core.mjs` and synced from the web package. Force it with `--mode legate`. A green result names what it does not establish: who holds the key, and for a bundle without `--key`, that any signer is pinned.

### Changed
- `chain replay` accepts the pre-03 payload-only link only when the predecessor cites draft -02 or earlier, or no spec. Under -03 a payload-only link is a chain break, because accepting it would let a re-signed receipt keep the original's link, which is what section 6.7 closes. Legacy links taken are counted in `legacyLinks`.

## 0.9.7 (2026-09-10)

### Documentation says what exists

No code change. The README advertised an SDK that is not on npm or PyPI,
seven adapter packages that were never published, two hostnames that do not
resolve, Sigstore provenance the releases do not carry, and a Homebrew install
path that is not the tap. It now names the four published packages
(protect-mcp, protect-mcp-adk, @scopeblind/langchain, scopeblind-swarms),
points at the source adapters and SDK helpers as source, says which ecosystem
workers are deployed (none), and describes the supply chain as it is.

ROADMAP is rewritten from this changelog: shipped since 0.5.4, what is next,
and the two deprecated flags that are still parsed. SECURITY's supported
versions start at 0.9.x. THREAT-MODEL pins this release. No em dashes remain
in the shipped documentation.

The README is part of the monitored verifier surface, so the bundled
integrity commitment (`sigil.json`) is regenerated and this release has a new
Sigil name. `--self-check` on 0.9.6 and on 0.9.7 each match their own bytes.

## 0.9.6 (2026-09-10)

### Fix: extra positionals are an error, not a silent drop

`verify a.json b.json` verified only `b.json` and exited on that, printing
one verdict for the whole set. The parser assigned every positional to the
same `opts.file`, so the last one won and the rest were discarded without a
word. A conformance suite that handed the verifier a glob was therefore
checking one receipt in four (reported as finding 7 in
ScopeBlind/agent-governance-testvectors#13).

Every subcommand takes at most one file; `--diff` carries a second one as a
flag. So a second positional is never legitimate, and it now exits 2 with a
message naming every file given. Nothing is verified in that case. A verifier
that silently discards inputs is not correct, it is quiet.

Chain-link fixes from 0.9.5 are unchanged.

## 0.9.5 (2026-08-31)

### Fix: 0.9.4 shipped with a stale Sigil commitment

0.9.4 carried the correct chain-hash code but the `sigil.json` commitment from
0.9.3. Every install of 0.9.4 therefore failed its own integrity check:

    npx @veritasacta/verify --self-check
    x Monitored verifier source does not match the bundled commitment
      It may be a fork, a development build, or a tampered copy.

The source was never wrong. `src/engines/{proxy,daemon,bulk}.js` and
`src/errors.js` are all in MONITORED_FILES, so editing them for the 0.9.4 fix
invalidated the commitment, and `generate-sigil.mjs` was not re-run before
publishing. This release regenerates it.

`--self-check` and `--self-test` both pass on 0.9.5. Verified against a real
install rather than the source tree.

Use 0.9.5, not 0.9.4. The chain-hash fix below is present and correct in both;
only 0.9.4's integrity commitment is wrong.

## 0.9.4 (2026-08-30)

### Fix: the chain link was computed over the wrong bytes

`proxy` and `daemon` emitted `previousReceiptHash` as `"sha256:"` followed by
the hash of the receipt's **payload**. The settled rule
(draft-farley-acta-signed-receipts-03 section 6.7) is the hash of the **entire
signed receipt including its signature member**. Both engines now do that.

This was invisible because the read path in `bulk` accepts either form, so
chains this tool wrote verified against this tool and would have failed any
verifier implementing 6.7 strictly. Reported by an outside reviewer building
an independent verifier.

Hashing the payload alone gives a re-signed receipt the same chain link as the
original, so a key rotation or re-issue is invisible in the chain. Verified:
two receipts with identical payloads signed by different keys now produce
different links, and the emitted links match what protect-mcp independently
computes for the same receipt.

### Fix: genesis receipts carried `previousReceiptHash: null`

Section 2.2 requires the first receipt in a chain to omit the member entirely
rather than carry `null`, because the two produce different JCS output and
therefore different signed bytes. Both engines now omit it.

### Spec citations corrected

Error metadata and chain comments cited section 5.4 and draft-02 section 5.7,
both superseded numbering. They now cite 6.6 (Signature Scope) and 6.7 (Chain
Hash Scope). The stale citations are why the rule appeared to be missing from
a release that partly implemented it.

### Upgrading

Chains written by 0.9.3 or earlier still verify: the read path accepts the
payload-only form for chains predating the rule. Chains written by 0.9.4
will not verify against 0.9.3 or earlier.

## 0.9.3 (2026-07-08)

### Tree reconciliation: the 0.9.1/0.9.2 line and this line are one again

npm 0.9.1/0.9.2 were published from a tree that had diverged from this one.
This release unifies them: everything published there now lives here
(restraint-receipt openable detail with re-hashed bindings and the
`Prevented:` terminal block, `verifyRestraintBindings` export, the RFC 9711
EAT output modes `--emit-eat` / `--emit-eat-cbor`, the `verify` bin alias,
`samples/sample-restraint-receipt.json`), and everything that had only
lived here ships to npm for the first time (Legate proof-pack, macro
snapshot and track-record, and trusted-context-pack engines).

### draft-02 receipts and s5.7 chain links

protect-mcp 0.10.0 emits draft-farley-acta-signed-receipts-02 envelopes;
these verified here already via the passport path. `--replay-chain` now
recomputes chain links under both conventions: the draft-02 section 5.7
hash (SHA-256 over the JCS bytes of the entire previous envelope, signature
included) and the older payload-only hash, so a mixed pre/post-migration
receipt log replays cleanly including the link that spans the boundary.

### s5.7 chain links in --replay-chain

`--replay-chain` now recomputes chain links under both conventions: the
draft-farley-acta-signed-receipts-02 section 5.7 hash (SHA-256 over the JCS
bytes of the entire previous envelope, signature included), which is what
protect-mcp 0.10.0+ writes, and the older payload-only hash for chains
written before the migration. A mixed pre/post-migration receipt log
replays cleanly, including the link that spans the boundary.

Tree reconciliation blocker: RESOLVED in this release (see above).


## 0.9.0 (2026-06-22)

### Legate adherence / restraint proof packs

Recognizes and verifies `scopeblind.legate.proof-pack.v1`: the allocator-facing,
position-blind record a Legate desk produces of what the gate prevented over a
session (held / blocked, attributed to the committed-mandate rules) plus order-path
shadow evidence (what it would have blocked on a FIX feed), bound to the mandate
digest, the signed book provenance, and a receipt Merkle root. The signature is
Ed25519 over the canonical (deep-sorted, no-whitespace) bytes of the pack minus its
`signature`, `sha256`, and `hybrid_signature` fields, against the embedded runtime
`verification_key` (pin it with `--key`). Cross-implementation tested against a real
desktop-runtime-signed fixture (`samples/legate-proof-pack.json`); tampering with any
field, and a wrong pinned key, fail. An optional `hybrid_signature` (Ed25519 +
ML-DSA-65) is recognized and reported; classical Ed25519 is verified here, with PQ
verification documented as an optional add-on in the restraint-receipts draft.

## 0.8.0 (2026-06-13)

### RFC 6962 transparency log for macro track records

Recognizes `scopeblind.macro.transparency-head/1` and
`scopeblind.macro.transparency-witness/1`, and verifies the `transparency`
evidence carried in a macro track-record bundle: every record's Merkle
inclusion proof against the signed head (RFC 6962 hashing: leaf =
sha256(0x00||digest), node = sha256(0x01||l||r)), plus an independent witness
co-signature. The bundle result reports `Transparency: witness-anchored /
self-signed / not anchored`; a tampered head or a missing inclusion fails the
chain check. No new signing crypto: inclusion is recomputed from the path and
checked against the head root. This is what makes a dropped or rewritten record
detectable to anyone who retained a head, not merely a single un-trimmed export.

### ScopeBlind macro-engine snapshots and track-record bundles

New engine `src/engines/macro-snapshot.js` recognizes the macro-engine
schemas (`scopeblind.macro.market-state/1`, `regime-snapshot/1`,
`tape-snapshot/1`, `vulnerability/1`, `alert/1`, `journal-entry/1`) and the
signed track-record bundle (`scopeblind.macro.track-record-bundle/1`). Macro
snapshots already verified cryptographically as generic Gate tuples; this adds
schema recognition, a per-schema semantic-contract check, and a schema-aware
summary in the output (no more "unrecognized schema" for macro records). No
new cryptography: crypto is delegated to `verifyGateTuple` and canonicalization
to `canonicalGateJSON`.

The track-record bundle verifier mirrors the Gate evidence-bundle: it checks
every record's signature, single-signer custody (every record including the
manifest shares one model key), exact manifest completeness (entries enumerate
the snapshots then journal entries in order), the snapshot/journal counts, and
the `history_head_digest` over the ordered record digests. Dropping or
tampering any record breaks the bundle. `--mode macro` forces the bundle path.

Anchored exports additionally carry a monotonic manifest sequence, previous
manifest/history-head links, retained prior manifests, and a signed checkpoint
chain. Verification rejects deletion of any previously manifested record.
`--key` is now reported explicitly as the operator-identity trust boundary;
without it the result proves embedded-key integrity only. `--history-head` and
`--anchor-head` pin independently retained anti-rollback checkpoints.

## 0.7.0 (2026-06-12)

### Release rule for execution evidence

Bundles whose entries carry fills under an unreleased decision fail the
chain check: fills require an ALLOW parent, or an APPROVAL_REQUIRED
parent with a present approval whose decision is approved. A DENY or
REVIEW parent with fills always fails. Without this rule a bundle could
present individually valid signatures as evidence of an unauthorized
execution.

### Restraint receipts: prove what was prevented, offline and position-blind

A restraint receipt (`tool: gate.restrain`) is already verified as a Legate
governed receipt. This release re-verifies and surfaces its openable detail, so
the receipt proves not merely that a deny was signed but exactly WHAT was
prevented and WHY:

- The disclosed denial outcome (the determining rules, risk band, mandate
  digest) is re-hashed and confirmed to bind to the signed `result_sha256`, and
  the proposed blocked order is re-hashed under its salt and confirmed to bind to
  `input_sha256`. Re-hashing uses the same JCS canonicalization the runtime used,
  so altering the disclosed detail flips the binding to a failure while the
  signature stays valid over the original hashes (you cannot lie about what was
  blocked).
- Position-blind by construction: the blocked order can be withheld, and the
  outcome still verifies because the order is salt-committed into the signed input
  hash and openable to a regulator on demand.
- Terminal output gains a `Prevented:` block (risk band, determining rules, the
  blocked order or a position-blind note, and the two binding checks). New
  `verifyRestraintBindings` export. A sample lives at
  `samples/sample-restraint-receipt.json`; see `RESTRAINT-DEMO.md`.
- Added a `verify` bin alias (alongside `verify-artifact`) so
  `npx @veritasacta/verify <receipt>` reads naturally.

### ScopeBlind Gate receipt tuples and evidence bundles

New detected format and engine: `src/engines/gate-receipt.js` verifies
ScopeBlind Gate receipt tuples (`{ payload, digest, signature,
verification_key }`) and signed-manifest
`scopeblind.gate.evidence-bundle/2` exports, including their semantic
and exact chain links.

- Crypto contract: canonical form is deep-key-sorted JSON
  (`JSON.stringify(deepSort(payload))`, arrays keep order); `digest` is
  SHA-256 of the canonical UTF-8 bytes (lowercase hex); `signature` is
  Ed25519 over the 32 hex-decoded digest bytes, verified with the
  carried `verification_key`. Note this differs from the Acta receipt
  contract (JCS canonical bytes signed directly).
- Current bundle schema: `scopeblind.gate.evidence-bundle/2`. Its
  gate-signed manifest exactly enumerates every exported receipt digest
  and declares the retained-history scope. Legacy `/1` bundles are
  detected but fail closed because they cannot prove export
  completeness.
- Recognized payload schemas: `scopeblind.gate.decision/2`,
  `scopeblind.gate.batch/1`, `scopeblind.gate.batch-leg/1`,
  `scopeblind.gate.approval/1`, `scopeblind.gate.fill/1`,
  `scopeblind.gate.fill/2`, `scopeblind.gate.order-state/1`,
  `scopeblind.gate.evidence-manifest/1`, and
  `scopeblind.mandate.delegation/1`. Recognized schemas are validated
  semantically after cryptographic verification. Tuples with
  unknown `payload.schema` still crypto-verify as generic tuples and
  are reported as unrecognized (no hard fail).
- Bundle chain checks compare complete signed leg summaries, approval
  scope/state/determining rules, fill quantities and signed-leg
  digests, held-remainder authority, delegation holder/issuer/parent/
  child lineage, and the signed manifest's exact inventory. Crypto
  failures (`[crypto]`)
  and chain failures (`[chain]`) are counted and reported separately:
  a record can be individually authentic while its cross-record link
  is inconsistent.
- Signer report: distinct signing keys seen with their roles and whether
  all gate-authored receipts match the bundle's
  `gate_verification_key`. `--key` pins that trust anchor.
- Honest output: the report states what a VALID result proves
  (authenticity, integrity, schema validity, exact chain consistency,
  and manifest coverage) and what it does not (risk-input correctness,
  independent production corroboration for explicitly labeled demo
  fills, or records beyond the manifest's declared history scope).
- New error codes: `digest_mismatch`, `chain_link_mismatch`, and
  `schema_invalid` (tampered, exit 1), plus `key_mismatch` when a
  carried key differs from the `--key` pin.
- New modes `gate-receipt-tuple` and `gate-evidence-bundle` in
  detection, `--capabilities`, and forced dispatch (`--mode gate`,
  `--mode gate-bundle`).
- New samples signed with published deterministic demo keys:
  `samples/sample-gate-tuple.json`, `samples/sample-gate-bundle.json`.
- Focused unit tests in `test/unit/gate-receipt.test.js`; the signing
  side is implemented independently in the tests per the contract.

## 0.6.1 (2026-05-20)

Description-only release. No on-the-wire format change. No code change.

The npm description is updated to surface the broader deployment picture: this CLI is now the offline verification engine for protect-mcp (AI agent decision receipts), the ScopeBlind cold-chain evidence tag (NSW ETCF 2026 application #197, hardware programme in development), and Microsoft AI Agents for Beginners Lesson 18 (64K+ ★ curriculum): same primitive, three deployment contexts.

See [scopeblind.com/cold-chain](https://www.scopeblind.com/cold-chain) for the hardware programme and [github.com/microsoft/ai-agents-for-beginners/blob/main/18-securing-ai-agents/](https://github.com/microsoft/ai-agents-for-beginners/blob/main/18-securing-ai-agents/) for Lesson 18.

## 0.5.4 (2026-04-20): Rekor anchoring + hardware attestation + transparency profiles + watcher + SBOM bundles + AIP-0007

Ships the "differentiation roadmap" responding to the Signet / nono
feature-parity analysis. Thirteen new primitives across four strategic
tiers; none of them imitate Signet or nono: they extend the shipping
product to ground that only Veritas Acta holds.

### New AIP

- **AIP-0007** (Draft): Zero-Knowledge Compliance Proofs. Portable
  receipt-chain-level proof that every receipt adhered to a declared
  policy without revealing receipts. Target release: v0.7.0; the spec
  is committed now for public review.

### New engines

- **`src/engines/rekor.js`**: Transparency-log anchoring (AIP-0005 T4).
  Offline verification of Rekor / Sigstore inclusion proofs.
  RFC 6962 Merkle-path recomputation + Signed-Note signature
  verification. ISO 8601 duration parsing for `anchored_within`.
- **`src/engines/attestation-quote.js`**: Hardware-attestation quote
  validator (AIP-0005 T2). Dispatches to per-platform validators:
  ATECC608B (full crypto validator), Apple Secure Enclave (full),
  TPM2 / SGX / SEV-SNP / TDX (structural in v0.5.4; full crypto in v0.7).
  Enforces that `measured_kid` matches `signature.kid`.
- **`src/engines/watch.js`**: Live receipt watcher + webhook
  dispatcher. Rule kinds: `cost_tier_below`, `delegation_expiring_within`,
  `chain_break`, `deny_decision`, `scrub_triggered`. Slack / Discord /
  generic JSON payloads.
- **`src/engines/sbom.js`**: SBOM-audit bundle builder. Ingests SPDX /
  CycloneDX / unknown-format SBOMs; builds a deterministic
  `receipts_fingerprint` + canonical manifest; optional signing via
  caller-supplied callback.
- **`src/engines/transparency.js`**: Four profiles (private, auditable,
  transparent, high-assurance), profile-based anchor decisions, and a
  public-facing badge JSON format.

### New packages

- **`@veritasacta/cross-verify`**: Arbitrator tool for multi-format
  sessions. Extracts canonical `(tool, input_hash, issued_at)` tuples
  from Signet / Sigstore / Acta receipts and confirms agreement.
  Emits a SHA-256 agreement fingerprint. 19 unit tests.

### Ecosystem artifacts

- **`docs/voprf-issuance-for-implementers.md`**: Public pitch for
  competitors to route their T1 cost-tier through our commercial API.
- **`docs/framework-author-guide.md`**: Adoption onboarding for
  CrewAI / LangChain / Vercel AI / etc.
- **`docs/posts/infrastructure-not-competitor.md`**: Public letter to
  peer receipt-format projects articulating the infrastructure stance.
- **`docs/case-study-three-ecosystems.md`**: Microsoft + AWS +
  Anthropic contribution ledger.
- **`ecosystem/certify/`**: Weekly cross-implementation conformance
  certification program (workflow + runner skeleton).
- **`ecosystem/dashboard/`**: Upgraded with a DAG view for trace_id
  grouping.

### Tests

- 54 new unit tests: 12 Rekor, 11 attestation-quote, 12 watch, 7 sbom,
  14 transparency, 19 cross-verify (cross-verify is a separate package).
- verify-cli suite: **219 unit+integration + 26 conformance = 245 total**,
  all green.

### Sigil

- Historical bundled commitment: **Open Wind** (`677a8a81`).
- 36 source files monitored (up from 31 in v0.5.3).

## 0.5.3 (2026-04-20): delegation chains + bilateral cosign + trace_id + proxy hardening + dashboard

Responds to the Signet / nono comparison: adds the four receipt-shape
primitives that peer implementations have ("who authorized this
agent", "agent + server co-signed", "these receipts all belong to one
workflow", "receipts are visualisable") and the two proxy-layer
security primitives ("scrub secrets from captured args", "cosign the
same decision from two independent keys"). None of this requires new
cryptography. All composes with existing AIPs.

### New AIP

- **AIP-0006** (Draft): Delegation Chains. Defines a `delegation`
  receipt type conveying scoped, time-bounded, narrowing-only
  authority from a delegator to a delegate. Defines an
  `authorization.delegation_chain` payload field on action receipts
  referencing delegations by receipt_hash. Verifier walks to a trust
  anchor, checks signatures, expiry, scope subset, and max_depth at
  each hop.

### New engines

- **`src/engines/delegation.js`**: `verifyDelegationChain()` walks the
  chain from leaf to root, validating Ed25519 signatures against trust
  anchors, scope subset at each hop (narrowing-only), and the action's
  tool/target against the leaf's scope. 14 unit tests.
- **`src/engines/cosign.js`**: `verifyCosignatures()` + `attachCosignature()`.
  Envelope-level additive signatures. Each cosignature signs the SAME
  canonical payload bytes as the primary `signature`. Default semantic:
  all cosignatures must be resolved + valid; `requireAllValid: false`
  opt-in for M-of-N. 11 unit tests.
- **`src/engines/dashboard.js`**: `startDashboard()` spins up a
  loopback-only HTTP server serving `ecosystem/dashboard/` static + a
  `/api/receipts` JSON feed for a configured directory. DNS-rebinding
  defense (rejects non-loopback Host headers) and path-traversal
  defense. 6 smoke tests.

### New subcommand + CLI surface

- **`verify dashboard [--port 3847] [--bind 127.0.0.1] [--receipts-dir <dir>]`** : 
  Start the local dashboard. Opens immediately; no build step.
- **`verify proxy ... --bilateral --server-key <file>`**: Proxy now
  attaches a second independent signature (via `cosignatures[]`) to
  every receipt. Enables agent + server bilateral evidence without
  touching the primary signing path.
- **`verify proxy ... --scrub-secrets`**: Walks incoming tool args for
  probable-secret key names (`api_key`, `token`, `password`,
  `authorization`, etc.), redacts VALUES in the outgoing call, and
  flags the redacted paths on the receipt via `scrub_detected`. Secrets
  no longer enter the receipt even as a hash of the real value.
- **`verify proxy ... --trace-id <id>`**: Stamps every receipt with a
  workflow `trace_id` so multi-step flows group cleanly.

### Receipt-format extensions (non-breaking)

- **`trace_id`** + **`parent_receipt_id`** as optional AIP-0001 payload
  fields. `previousReceiptHash` remains the chain pointer; trace_id
  groups by workflow; parent_receipt_id expresses non-chain causal
  links. `chain explore` surfaces both; `groupByTrace(result)` buckets
  nodes by workflow.
- **`cosignatures: [{alg, kid, sig}, ...]`** as an optional
  envelope-level array. Old verifiers ignore it; v0.5.3+ verifiers
  check each one against caller-supplied trust anchors.
- **`authorization.delegation_chain: [<hash>...]`** as an optional
  AIP-0001 payload field. AIP-0006 verifiers walk it; others treat as
  opaque.

### Tests

- 41 new unit tests across this release: 14 delegation, 11 cosign,
  2 chain-explore trace, 8 proxy helpers, 6 dashboard.
- Full suite: **163 unit+integration + 26 conformance = 189 total**,
  all green.

### Sigil

- 31 source files monitored (up from 28 in v0.5.2). Historical bundled commitment:
  **Bright Lake** (`ea78b16e`).

## 0.5.2 (2026-04-20): compliance export + DSSE + BRASS v2 scaffold + AIP-0004/0005

Ships alongside v0.5.1 as the "governance surface fill" release. Adds
the compliance export subcommand, Sigstore DSSE envelope engine,
BRASS v2 hardening scaffold, and reference implementations for two new
AIPs.

### New subcommand

- **`verify compliance --receipts-dir <dir>`**: bucket a directory of
  receipts into SOC 2 / ISO 42001 / EU AI Act controls and emit an
  auditor-ready JSON bundle or self-contained HTML report. Supports
  `--framework soc2|iso42001|eu-ai-act|all`, `--start-date`, `--end-date`,
  `--org`, `--output`. Zero-evidence controls are surfaced explicitly
  so the auditor sees gaps rather than hidden silences.

### New engines

- **`src/engines/dsse.js`**: Dead Simple Signing Envelope (DSSE) wrap /
  unwrap / verify. Produces and consumes Sigstore-compatible envelopes
  with payload types `application/vnd.acta.receipt+json`,
  `application/vnd.acta.knowledge-unit+json`, or the standard in-toto
  statement type. Signatures bind to the DSSE pre-authentication
  encoding (PAE), not the raw payload.
- **`src/util/voprf-crypto-v2.js`**: BRASS v2 scaffold: length-prefixed
  hashing (`H_LP`), nullifier derivation bound to issuer public key Y
  (`deriveNullifier_v2`), single-variable πC restatement
  (`piCVerify_v2`). Not wired into the default path; accessible to
  implementers and exercised by unit tests.

### New AIPs

- **AIP-0004** (Draft): Content-Addressed Snapshot and Rollback
  Receipts. Defines `snapshot` and `rollback` receipt types with a
  Merkle root over file-content hashes. Reference implementation at
  `ecosystem/rollback/snapshot.mjs`; schema at
  `ecosystem/rollback/snapshot-receipt.schema.json`.
- **AIP-0005** (Draft): Attestation Weight Profile. Defines a
  portable `cost_tier` (T0–T4) over receipts, substantiated by VOPRF
  tokens (T1), hardware quotes (T2), multi-party signatures (T3), or
  transparency-log anchoring (T4). Reference implementation notes at
  `ecosystem/physical-attestation/DESIGN.md` + attestation-quote
  schema.

### Ecosystem additions

- **`ecosystem/wshobson-plugin/protect-mcp/`**: PR-ready Claude Code
  plugin tree for `wshobson/agents` marketplace. Closes issue #471.
  Ships agents (`policy-enforcer`, `receipt-verifier`), skill
  (`protect-mcp-setup`), slash commands (`/verify-receipt`,
  `/audit-chain`), and hooks.json.
- **`ecosystem/dashboard/index.html` + `dashboard.js`**: local-first
  in-browser audit dashboard scaffold. JCS + chain-integrity check
  over dropped receipts; renders `verify --json` output. No server,
  no telemetry.
- **`ecosystem/physical-attestation/DESIGN.md`**: physical-digital
  causal chain design for Seal hardware cost_tier T2 receipts.

### Sigil + tests

- Sigil commitment expanded to **28 source files** (adds compliance
  export, DSSE engine, v2 crypto util). Historical bundled commitment: **New Ember**
  (`b28f8d60`).
- 41 new unit tests across prompt, chain-explore, snapshot, compliance,
  DSSE, and BRASS v2 (11 of 41 new in this release).
- Full suite: **122 unit+integration + 26 conformance**: 148 total,
  all green.

## 0.5.1 (2026-04-20): prompt provenance + chain explorer + 5 sandbox profiles

### New subcommands

- **`verify prompt <file>`**: verify the provenance of a prompt/skill/system-instruction file against a Veritas Acta receipt asserting its SHA-256, a Sigstore DSSE bundle with an in-toto subject, or an `--expected-hash`. Closes the supply-chain attack vector where an attacker modifies `CLAUDE.md`, `SKILLS.md`, `AGENTS.md`, or a system prompt between authoring and agent runtime.
- **`verify chain explore <receipt>`**: walk the `previousReceiptHash` chain back to its root, validating every hash link. Emits a depth-annotated ASCII tree in terminal mode, structured JSON in `--json` mode. `--search-dir <dir>` overrides the ancestor search directory; `--max-depth N` caps the walk.

### Sigil commitment expansion

- Sigil v0.5.1 covered **25 source files** (up from 24 in v0.5.0): added `src/engines/prompt.js` + `src/engines/chain-explore.js`. Historical bundled commitment: **Bright Star** (`1cc829ab`).

### Ecosystem profiles

- **`ecosystem/profiles/`** ships pre-built sandboxing profiles for five common agent runtimes: Claude Code, Cursor, Codex, Gemini CLI, OpenClaw. Each ships `profile.yaml` + `policy.cedar` + `nono-capabilities.yaml` + `README.md` with threat-model notes. Composes with `sb-runtime --ring N --policy ./policy.cedar` and `nono run --caps ./nono-capabilities.yaml` for defense-in-depth.

### Tests

- 20 new unit tests: 10 for `verifyPrompt` (expected-hash / receipt / Sigstore / missing-source / error paths), 10 for `exploreChain` / `renderChainTree` (3-receipt chain, tamper detection, missing ancestor, maxDepth, searchDir override).
- Full suite now: **81 unit+integration + 26 conformance**: 107 total.

## 0.5.0 (2026-04-19): unified verifier + network-effect mechanics

### Network-effect mechanics

- **`--attest`** produces a self-signed local-integrity attestation: a signed
  JSON artifact the user can publish anywhere to demonstrate they ran
  local bytes matching the bundled public commitment. Fully offline,
  user-signed, opt-in; it does not authenticate the publisher.
  `--attest-org <name>` attaches an attributable identifier.
  `--attest-key <file>` overrides the default key location
  (`~/.veritasacta-verify/attester.json`).
- **`--emit-verification-receipt`** produces a signed receipt of a
  specific verification event: "this attester reported that this verifier
  returned valid at time T." Composable with Sigstore Rekor.

### Enterprise features

- **`--pin-sigil <fingerprint>`** enforces that the installed verifier
  matches a specific Sigil. Fails fast with exit code 2 and a clear
  message on mismatch. Supply-chain pinning for regulated deployments.
- **`--audit-log <file>`** appends every verification event to a local
  JSONL file with chain-linked hashes. Tamper-evident local audit trail
  for SIEM integration. Fully offline; nothing phoned home.
- **`--fips`** enforces FIPS 140-3 approved algorithms only. Currently
  rejects Ed25519 (pending NIST approval) with a clear migration
  message pointing at hybrid `ed25519+ml-dsa-65` (v0.6+).
- **`--replay-chain <file>`** bulk-verifies every receipt in a JSONL
  chain. Reports total / verified / failed / chain-breaks. Chain
  linkage (`previousReceiptHash`) is explicitly validated.
- **`--diff <other-file>`** structural diff between two receipts.
  Surfaces added/removed/changed fields, canonical hash comparison,
  and signature equality. Debugging aid for implementers.
- **`--audit-report`** renders a self-contained HTML audit report
  suitable for delivery to auditors / compliance teams / counterparties.
  Embeds the self-signed local-integrity attestation if `--attest` is also set.
  Includes verification summary, per-receipt breakdown, verifier
  provenance, and raw JSON result.
- **`--output <file>`** writes HTML reports or attestation JSON to a
  file instead of stdout.

### Sigil commitment expansion

- Sigil v0.5.0 commits to **21 source files** (up from v0.3.0's single
  cli.js): cli.js + 20 engines/outputs/utils/context files. Any
  modification invalidates `--self-check`.

### New subcommands (bootstrap + integration)

- **`verify init`**: zero-config onboarding wizard. Auto-detects framework across 13 supported agents (Claude Code, Claude Agent SDK, Google ADK, CrewAI, Pydantic AI, AutoGen, Smolagents, LangChain JS/Py, LangGraph JS/Py, OpenAI Agents, Vercel AI). Generates keys, writes `.veritasacta/config.json`, emits next-steps. `--framework <name>` override, `--force` overwrite.
- **`verify proxy --target "<cmd>"`**: universal MCP proxy. Wraps any MCP server with signing. No code changes in server or agent; each `tools/call` emits a chain-linked receipt. Signet-parity.
- **`verify daemon`**: sidecar daemon on Unix socket. Language-agnostic signing API (`POST /sign`). One daemon handles receipts for any number of agents in any language.

### Ecosystem artifacts (`ecosystem/`)

Shipped (working code):

- `ecosystem/github-action/`: drop-in CI step (`VeritasActa/verify-action@v1`)
- `ecosystem/claude-code-plugin/`: one-click Claude Code plugin + SKILL.md
- `ecosystem/homebrew-tap/Formula/veritasacta-verify.rb`: `brew install veritasacta-verify`
- `ecosystem/sdk-js/`: `@veritasacta/sdk` tiny signing helper (JS)
- `ecosystem/sdk-py/`: `veritasacta-sdk` tiny signing helper (Python)
- `ecosystem/adapters/langchain/`: LangChain adapter with full `withReceipts()` implementation
- `ecosystem/adapters/{langgraph,crewai,openai-agents,vercel-ai,smolagents,pydantic-ai,autogen}/`: seven additional framework adapter scaffolds
- `ecosystem/registry-worker/`: `registry.veritasacta.com` Cloudflare Worker
- `ecosystem/badge-worker/`: `verify.veritasacta.com/badge/*` shields.io-compatible SVG badges
- `ecosystem/interop-leaderboard/workflow.yml`: weekly cross-implementation interop CI

Scaffolds (design docs, implementation pending):

- `ecosystem/cosign-compat/DESIGN.md`: v0.6.0 Sigstore compatibility
- `ecosystem/rollback/DESIGN.md`: filesystem snapshots + undo (nono-style)
- `ecosystem/supervisor/DESIGN.md`: runtime approval flows
- `ecosystem/reputation/DESIGN.md`: issuer reputation (complement to aeoess agent reputation)
- `ecosystem/dashboard/DESIGN.md`: web audit dashboard (Signet-style)
- `ecosystem/browser-extension/DESIGN.md`: Claude.ai / ChatGPT consumer reach
- `ecosystem/ebpf-observer/DESIGN.md`: kernel-level auto-instrumentation (highest novelty)
- `ecosystem/vscode-extension/`: editor integration (v0.5.1)
- `ecosystem/CONFORMANCE-CERTIFICATION.md`: commercial certification service design
- `ecosystem/SIGIL-NAMING.md` + `ecosystem/RELEASE-NAMING.md`: public brand convention + historical Sigil registry

## 0.5.0 core: 2026-04-19 (unified verifier)

### Major

- **Unified verifier.** Single Apache-2.0 binary now handles Ed25519
  signed receipts, VOPRF anonymous-credential tokens (full dual-DLEQ
  verification), Knowledge Unit bundles, and selective-disclosure
  receipts. Auto-detects input format; `--mode receipt|voprf|ku|
  bundle|auto` forces a specific engine.
- **Full VOPRF DLEQ verification.** Both the issuer proof (πI:
  log_G(Y) = log_M(Z)) and the client proof (πC: knowledge of the
  blinding scalar b such that M = b·P) are verified with Schnorr
  DLEQ reconstruction (`A1 = r·g1 + c·h1`, `A2 = r·g2 + c·h2`; check
  that the recomputed challenge equals c). The engine is byte-
  compatible with the production BRASS issuer at `api.scopeblind.com`
  and the production client SDK: tokens issued in production verify
  against this engine, and the engine rejects any tampered scalar,
  wrong issuer key, scope mismatch, or AAD-bound πC tampering.
- **`--allow-partial-voprf` flag** retained as a no-op for
  compatibility with the `_partial` flag that existed during the
  port. All VOPRF results in 0.5.0 are full verifications; the flag
  is documented as deprecated and scheduled for removal in v0.6.0.
- **Modular architecture.** cli.js is a thin dispatcher; verification
  logic lives in `src/engines/*.js`. Each engine is independently
  auditable and testable.
- **Conformance tiers (T1-T5).** The verifier reports which tier of
  conformance a receipt exercised: T1 basic (Ed25519 + JCS + chain),
  T2 disclosure (AIP-0002), T3 attestation (hardware / anchor_uri),
  T4 privacy (VOPRF + holder_binding), T5 full (ZK compliance, v1.0+).
  Each verification surfaces the tier achieved.
- **Knowledge Unit bundles.** First-class support for
  draft-farley-acta-knowledge-units-00 multi-model deliberation
  bundles. Reports topic, models, rounds, consensus level, dissent,
  and verifies each embedded receipt.
- **AIP-0002 selective disclosure.** `--disclose field:salt:value`
  verifies salted SHA-256 commitments on redacted fields without
  needing the issuer. Redacted fields are counted and surfaced.
- **Sigil claim 2: live-context verification (patent #5).**
  `--require-context clock:±5s` / `geofence:...` / `sensor:temp<18`
  evaluates predicates at verification time. The verifier aggregates
  results and fails verification when any required predicate fails.
- **Sigil commits to entire codebase.** Previously Sigil only
  committed to cli.js. v0.5.0 extends commitment to all 15 source
  files (cli.js + src/engines/* + src/output/* + src/util/* +
  src/context/*). Modification of any file invalidates `--self-check`.
- **JSON output.** `--json` emits structured results including
  `tier`, `mode`, `algorithm`, `kid`, `key_source`, and
  `sigil_fingerprint` for machine consumption.
- **`--capabilities` command.** Lists supported modes, algorithms,
  tiers, specs, and wayfinding. For CI integration and compatibility
  discovery.
- **Error code registry.** Every emitted error code is stable,
  documented in ERRORS.md, and includes a spec section reference
  where applicable.

### Field recognition (surfaced in output, no verification required)

- `disclosure_mode` enum
- `holder_binding` object (modes: jwk_thumbprint, dpop,
  attested_credential; per AIP-0003)
- `annex_hash` (private annex commitment)
- `attestation_mode` (software, hardware:secure_element, hardware:tee,
  hardware:hsm)
- `anchor_uri` (transparency log anchor URI)
- Extended decision enum (challenge, payment_required, escalate,
  override)
- `nullifier` (VOPRF mode)
- `scope` structure (origin, epoch, sub)
- `compliance_credit_ref` (reserved for v1.0 ZK compliance proofs)
- `transport_hint` (direct, ohttp, tor, custom)
- `verifier_salt_kid` (VOPRF mode)

### Hybrid post-quantum

- Verifier detects `algorithm` values of the form `ed25519+ml-dsa-65`,
  `ed25519+dilithium3`, etc., and emits a clear `unsupported_algorithm`
  error. Full hybrid PQ verification is planned for v0.6+.

### Security

- Embedded-key rejection (from 0.4.0) retained. The deprecated
  `--allow-embedded-key` escape hatch is still present in 0.5.0 but
  will be removed in 0.6.0.
- `--strict` mode disables all deprecated fallbacks.
- Constant-time signature comparison preserved.

### Spec alignment

- Targets draft-farley-acta-signed-receipts-03 (Sigil self-check
  output now references -03 explicitly).
- References draft-farley-acta-knowledge-units-00 as the KU format.
- References AIP-0001 (receipt format), AIP-0002 (selective
  disclosure), AIP-0003 (holder binding).

### Supply chain

- Published with `npm publish --provenance` (Sigstore-anchored
  supply chain attestation).
- Dependency tree: `@veritasacta/artifacts` only. Transitive surface:
  `@noble/curves`, `@noble/hashes`.

### Documentation

- THREAT-MODEL.md: formal threat model covering tamper detection,
  replay, forgery, canonicalization, and the explicit non-goals.
- SECURITY.md: disclosure policy and supported-version matrix.
- ERRORS.md: complete error-code registry with spec references.
- Expanded README with conformance tiers and usage examples for
  every mode.

## 0.4.0 (2026-04-19): embedded-key rejection

### Security

- **Breaking change: embedded keys in receipt payloads are now
  rejected by default.** A verification key transported inside the
  signed payload does not provide authenticity against tampering
  (see draft-farley-acta-signed-receipts-03 Security Considerations).
- **New flag: `--allow-embedded-key`** (deprecated; removed in 0.5
  or 0.6). Restores pre-0.4.0 behaviour for one release cycle.
- Issue surfaced publicly by @desiorac on GetBindu PR #459.

## 0.3.0 (2026-04-05): previous release

Offline receipt verification via `@veritasacta/verify` CLI.
