# Changelog


## 0.6.1 - 2026-05-16

- Support `--jwks` resolution from `file://` URLs, absolute paths, and bare relative filesystem paths for offline test-vector and CI workflows.
- Preserve HTTP(S) JWKS behavior unchanged.
- Surface the resolved local JWKS path in verifier output.
- Add unit coverage for local JWKS path handling.

## 0.5.4 — 2026-04-20 (Rekor anchoring + hardware attestation + transparency profiles + watcher + SBOM bundles + AIP-0007)

Ships the "differentiation roadmap" responding to the Signet / nono
feature-parity analysis. Thirteen new primitives across four strategic
tiers; none of them imitate Signet or nono — they extend the shipping
product to ground that only Veritas Acta holds.

### New AIP

- **AIP-0007** (Draft) — Zero-Knowledge Compliance Proofs. Portable
  receipt-chain-level proof that every receipt adhered to a declared
  policy without revealing receipts. Target release: v0.7.0; the spec
  is committed now for public review.

### New engines

- **`src/engines/rekor.js`** — Transparency-log anchoring (AIP-0005 T4).
  Offline verification of Rekor / Sigstore inclusion proofs.
  RFC 6962 Merkle-path recomputation + Signed-Note signature
  verification. ISO 8601 duration parsing for `anchored_within`.
- **`src/engines/attestation-quote.js`** — Hardware-attestation quote
  validator (AIP-0005 T2). Dispatches to per-platform validators:
  ATECC608B (full crypto validator), Apple Secure Enclave (full),
  TPM2 / SGX / SEV-SNP / TDX (structural in v0.5.4; full crypto in v0.7).
  Enforces that `measured_kid` matches `signature.kid`.
- **`src/engines/watch.js`** — Live receipt watcher + webhook
  dispatcher. Rule kinds: `cost_tier_below`, `delegation_expiring_within`,
  `chain_break`, `deny_decision`, `scrub_triggered`. Slack / Discord /
  generic JSON payloads.
- **`src/engines/sbom.js`** — SBOM-audit bundle builder. Ingests SPDX /
  CycloneDX / unknown-format SBOMs; builds a deterministic
  `receipts_fingerprint` + canonical manifest; optional signing via
  caller-supplied callback.
- **`src/engines/transparency.js`** — Four profiles (private, auditable,
  transparent, high-assurance), profile-based anchor decisions, and a
  public-facing badge JSON format.

### New packages

- **`@veritasacta/cross-verify`** — Arbitrator tool for multi-format
  sessions. Extracts canonical `(tool, input_hash, issued_at)` tuples
  from Signet / Sigstore / Acta receipts and confirms agreement.
  Emits a SHA-256 agreement fingerprint. 19 unit tests.

### Ecosystem artifacts

- **`docs/voprf-issuance-for-implementers.md`** — Public pitch for
  competitors to route their T1 cost-tier through our commercial API.
- **`docs/framework-author-guide.md`** — Adoption onboarding for
  CrewAI / LangChain / Vercel AI / etc.
- **`docs/posts/infrastructure-not-competitor.md`** — Public letter to
  peer receipt-format projects articulating the infrastructure stance.
- **`docs/case-study-three-ecosystems.md`** — Microsoft + AWS +
  Anthropic contribution ledger.
- **`ecosystem/certify/`** — Weekly cross-implementation conformance
  certification program (workflow + runner skeleton).
- **`ecosystem/dashboard/`** — Upgraded with a DAG view for trace_id
  grouping.

### Tests

- 54 new unit tests: 12 Rekor, 11 attestation-quote, 12 watch, 7 sbom,
  14 transparency, 19 cross-verify (cross-verify is a separate package).
- verify-cli suite: **219 unit+integration + 26 conformance = 245 total**,
  all green.

### Sigil

- Canonical release: **Open Wind** (`677a8a81`).
- 36 source files monitored (up from 31 in v0.5.3).

## 0.5.3 — 2026-04-20 (delegation chains + bilateral cosign + trace_id + proxy hardening + dashboard)

Responds to the Signet / nono comparison: adds the four receipt-shape
primitives that peer implementations have ("who authorized this
agent", "agent + server co-signed", "these receipts all belong to one
workflow", "receipts are visualisable") and the two proxy-layer
security primitives ("scrub secrets from captured args", "cosign the
same decision from two independent keys"). None of this requires new
cryptography. All composes with existing AIPs.

### New AIP

- **AIP-0006** (Draft) — Delegation Chains. Defines a `delegation`
  receipt type conveying scoped, time-bounded, narrowing-only
  authority from a delegator to a delegate. Defines an
  `authorization.delegation_chain` payload field on action receipts
  referencing delegations by receipt_hash. Verifier walks to a trust
  anchor, checks signatures, expiry, scope subset, and max_depth at
  each hop.

### New engines

- **`src/engines/delegation.js`** — `verifyDelegationChain()` walks the
  chain from leaf to root, validating Ed25519 signatures against trust
  anchors, scope subset at each hop (narrowing-only), and the action's
  tool/target against the leaf's scope. 14 unit tests.
- **`src/engines/cosign.js`** — `verifyCosignatures()` + `attachCosignature()`.
  Envelope-level additive signatures. Each cosignature signs the SAME
  canonical payload bytes as the primary `signature`. Default semantic:
  all cosignatures must be resolved + valid; `requireAllValid: false`
  opt-in for M-of-N. 11 unit tests.
- **`src/engines/dashboard.js`** — `startDashboard()` spins up a
  loopback-only HTTP server serving `ecosystem/dashboard/` static + a
  `/api/receipts` JSON feed for a configured directory. DNS-rebinding
  defense (rejects non-loopback Host headers) and path-traversal
  defense. 6 smoke tests.

### New subcommand + CLI surface

- **`verify dashboard [--port 3847] [--bind 127.0.0.1] [--receipts-dir <dir>]`** —
  Start the local dashboard. Opens immediately; no build step.
- **`verify proxy ... --bilateral --server-key <file>`** — Proxy now
  attaches a second independent signature (via `cosignatures[]`) to
  every receipt. Enables agent + server bilateral evidence without
  touching the primary signing path.
- **`verify proxy ... --scrub-secrets`** — Walks incoming tool args for
  probable-secret key names (`api_key`, `token`, `password`,
  `authorization`, etc.), redacts VALUES in the outgoing call, and
  flags the redacted paths on the receipt via `scrub_detected`. Secrets
  no longer enter the receipt even as a hash of the real value.
- **`verify proxy ... --trace-id <id>`** — Stamps every receipt with a
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

- 31 source files monitored (up from 28 in v0.5.2). Canonical release:
  **Bright Lake** (`ea78b16e`).

## 0.5.2 — 2026-04-20 (compliance export + DSSE + BRASS v2 scaffold + AIP-0004/0005)

Ships alongside v0.5.1 as the "governance surface fill" release. Adds
the compliance export subcommand, Sigstore DSSE envelope engine,
BRASS v2 hardening scaffold, and reference implementations for two new
AIPs.

### New subcommand

- **`verify compliance --receipts-dir <dir>`** — bucket a directory of
  receipts into SOC 2 / ISO 42001 / EU AI Act controls and emit an
  auditor-ready JSON bundle or self-contained HTML report. Supports
  `--framework soc2|iso42001|eu-ai-act|all`, `--start-date`, `--end-date`,
  `--org`, `--output`. Zero-evidence controls are surfaced explicitly
  so the auditor sees gaps rather than hidden silences.

### New engines

- **`src/engines/dsse.js`** — Dead Simple Signing Envelope (DSSE) wrap /
  unwrap / verify. Produces and consumes Sigstore-compatible envelopes
  with payload types `application/vnd.acta.receipt+json`,
  `application/vnd.acta.knowledge-unit+json`, or the standard in-toto
  statement type. Signatures bind to the DSSE pre-authentication
  encoding (PAE), not the raw payload.
- **`src/util/voprf-crypto-v2.js`** — BRASS v2 scaffold: length-prefixed
  hashing (`H_LP`), nullifier derivation bound to issuer public key Y
  (`deriveNullifier_v2`), single-variable πC restatement
  (`piCVerify_v2`). Not wired into the default path; accessible to
  implementers and exercised by unit tests.

### New AIPs

- **AIP-0004** (Draft) — Content-Addressed Snapshot and Rollback
  Receipts. Defines `snapshot` and `rollback` receipt types with a
  Merkle root over file-content hashes. Reference implementation at
  `ecosystem/rollback/snapshot.mjs`; schema at
  `ecosystem/rollback/snapshot-receipt.schema.json`.
- **AIP-0005** (Draft) — Attestation Weight Profile. Defines a
  portable `cost_tier` (T0–T4) over receipts, substantiated by VOPRF
  tokens (T1), hardware quotes (T2), multi-party signatures (T3), or
  transparency-log anchoring (T4). Reference implementation notes at
  `ecosystem/physical-attestation/DESIGN.md` + attestation-quote
  schema.

### Ecosystem additions

- **`ecosystem/wshobson-plugin/protect-mcp/`** — PR-ready Claude Code
  plugin tree for `wshobson/agents` marketplace. Closes issue #471.
  Ships agents (`policy-enforcer`, `receipt-verifier`), skill
  (`protect-mcp-setup`), slash commands (`/verify-receipt`,
  `/audit-chain`), and hooks.json.
- **`ecosystem/dashboard/index.html` + `dashboard.js`** — local-first
  in-browser audit dashboard scaffold. JCS + chain-integrity check
  over dropped receipts; renders `verify --json` output. No server,
  no telemetry.
- **`ecosystem/physical-attestation/DESIGN.md`** — physical-digital
  causal chain design for Seal hardware cost_tier T2 receipts.

### Sigil + tests

- Sigil commitment expanded to **28 source files** (adds compliance
  export, DSSE engine, v2 crypto util). Canonical release: **New Ember**
  (`b28f8d60`).
- 41 new unit tests across prompt, chain-explore, snapshot, compliance,
  DSSE, and BRASS v2 (11 of 41 new in this release).
- Full suite: **122 unit+integration + 26 conformance** — 148 total,
  all green.

## 0.5.1 — 2026-04-20 (prompt provenance + chain explorer + 5 sandbox profiles)

### New subcommands

- **`verify prompt <file>`** — verify the provenance of a prompt/skill/system-instruction file against a Veritas Acta receipt asserting its SHA-256, a Sigstore DSSE bundle with an in-toto subject, or an `--expected-hash`. Closes the supply-chain attack vector where an attacker modifies `CLAUDE.md`, `SKILLS.md`, `AGENTS.md`, or a system prompt between authoring and agent runtime.
- **`verify chain explore <receipt>`** — walk the `previousReceiptHash` chain back to its root, validating every hash link. Emits a depth-annotated ASCII tree in terminal mode, structured JSON in `--json` mode. `--search-dir <dir>` overrides the ancestor search directory; `--max-depth N` caps the walk.

### Sigil commitment expansion

- Sigil v0.5.1 now covers **25 source files** (up from 24 in v0.5.0): adds `src/engines/prompt.js` + `src/engines/chain-explore.js`. Canonical release: **Bright Star** (`1cc829ab`).

### Ecosystem profiles

- **`ecosystem/profiles/`** ships pre-built sandboxing profiles for five common agent runtimes: Claude Code, Cursor, Codex, Gemini CLI, OpenClaw. Each ships `profile.yaml` + `policy.cedar` + `nono-capabilities.yaml` + `README.md` with threat-model notes. Composes with `sb-runtime --ring N --policy ./policy.cedar` and `nono run --caps ./nono-capabilities.yaml` for defense-in-depth.

### Tests

- 20 new unit tests: 10 for `verifyPrompt` (expected-hash / receipt / Sigstore / missing-source / error paths), 10 for `exploreChain` / `renderChainTree` (3-receipt chain, tamper detection, missing ancestor, maxDepth, searchDir override).
- Full suite now: **81 unit+integration + 26 conformance** — 107 total.

## 0.5.0 — 2026-04-19 (unified verifier + network-effect mechanics)

### Network-effect mechanics

- **`--attest`** produces a canonical verifier attestation: a signed
  JSON artifact the user can publish anywhere to demonstrate they ran
  the canonical unmodified verifier. Fully offline, user-signed, opt-in.
  `--attest-org <name>` attaches an attributable identifier.
  `--attest-key <file>` overrides the default key location
  (`~/.veritasacta-verify/attester.json`).
- **`--emit-verification-receipt`** produces a signed receipt of a
  specific verification event — "this receipt verified valid by the
  canonical verifier at time T." Composable with Sigstore Rekor.

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
  Embeds the canonical attestation if `--attest` is also set.
  Includes verification summary, per-receipt breakdown, verifier
  provenance, and raw JSON result.
- **`--output <file>`** writes HTML reports or attestation JSON to a
  file instead of stdout.

### Sigil commitment expansion

- Sigil v0.5.0 commits to **21 source files** (up from v0.3.0's single
  cli.js): cli.js + 20 engines/outputs/utils/context files. Any
  modification invalidates `--self-check`.

### New subcommands (bootstrap + integration)

- **`verify init`** — zero-config onboarding wizard. Auto-detects framework across 13 supported agents (Claude Code, Claude Agent SDK, Google ADK, CrewAI, Pydantic AI, AutoGen, Smolagents, LangChain JS/Py, LangGraph JS/Py, OpenAI Agents, Vercel AI). Generates keys, writes `.veritasacta/config.json`, emits next-steps. `--framework <name>` override, `--force` overwrite.
- **`verify proxy --target "<cmd>"`** — universal MCP proxy. Wraps any MCP server with signing. No code changes in server or agent; each `tools/call` emits a chain-linked receipt. Signet-parity.
- **`verify daemon`** — sidecar daemon on Unix socket. Language-agnostic signing API (`POST /sign`). One daemon handles receipts for any number of agents in any language.

### Ecosystem artifacts (`ecosystem/`)

Shipped (working code):

- `ecosystem/github-action/` — drop-in CI step (`VeritasActa/verify-action@v1`)
- `ecosystem/claude-code-plugin/` — one-click Claude Code plugin + SKILL.md
- `ecosystem/homebrew-tap/Formula/veritasacta-verify.rb` — `brew install veritasacta-verify`
- `ecosystem/sdk-js/` — `@veritasacta/sdk` tiny signing helper (JS)
- `ecosystem/sdk-py/` — `veritasacta-sdk` tiny signing helper (Python)
- `ecosystem/adapters/langchain/` — LangChain adapter with full `withReceipts()` implementation
- `ecosystem/adapters/{langgraph,crewai,openai-agents,vercel-ai,smolagents,pydantic-ai,autogen}/` — seven additional framework adapter scaffolds
- `ecosystem/registry-worker/` — `registry.veritasacta.com` Cloudflare Worker
- `ecosystem/badge-worker/` — `verify.veritasacta.com/badge/*` shields.io-compatible SVG badges
- `ecosystem/interop-leaderboard/workflow.yml` — weekly cross-implementation interop CI

Scaffolds (design docs, implementation pending):

- `ecosystem/cosign-compat/DESIGN.md` — v0.6.0 Sigstore compatibility
- `ecosystem/rollback/DESIGN.md` — filesystem snapshots + undo (nono-style)
- `ecosystem/supervisor/DESIGN.md` — runtime approval flows
- `ecosystem/reputation/DESIGN.md` — issuer reputation (complement to aeoess agent reputation)
- `ecosystem/dashboard/DESIGN.md` — web audit dashboard (Signet-style)
- `ecosystem/browser-extension/DESIGN.md` — Claude.ai / ChatGPT consumer reach
- `ecosystem/ebpf-observer/DESIGN.md` — kernel-level auto-instrumentation (highest novelty)
- `ecosystem/vscode-extension/` — editor integration (v0.5.1)
- `ecosystem/CONFORMANCE-CERTIFICATION.md` — commercial certification service design
- `ecosystem/SIGIL-NAMING.md` + `ecosystem/RELEASE-NAMING.md` — public brand convention + historical Sigil registry

## 0.5.0 core — 2026-04-19 (unified verifier)

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
- **Sigil claim 2 — live-context verification (patent #5).**
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

## 0.4.0 — 2026-04-19 (embedded-key rejection)

### Security

- **Breaking change: embedded keys in receipt payloads are now
  rejected by default.** A verification key transported inside the
  signed payload does not provide authenticity against tampering
  (see draft-farley-acta-signed-receipts-03 Security Considerations).
- **New flag: `--allow-embedded-key`** (deprecated; removed in 0.5
  or 0.6). Restores pre-0.4.0 behaviour for one release cycle.
- Issue surfaced publicly by @desiorac on GetBindu PR #459.

## 0.3.0 — 2026-04-05 (previous release)

Offline receipt verification via `@veritasacta/verify` CLI.
