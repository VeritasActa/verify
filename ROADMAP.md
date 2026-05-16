# Roadmap

## v0.5.4 (shipping — 2026-04-20)

- AIP-0007 ZK compliance proofs (spec draft).
- Rekor / transparency-log anchoring engine (AIP-0005 T4).
- Hardware-attestation quote validator (ATECC608B + Apple SE full crypto; TPM2/SGX/SEV structural).
- Receipt watcher with Slack / Discord / generic webhooks.
- SBOM audit bundle builder (SPDX + CycloneDX).
- Four-profile transparency switch (private / auditable / transparent / high-assurance).
- `@veritasacta/cross-verify` arbitrator package.
- Conformance certification program workflow.
- Canonical release: Open Wind (677a8a81). Sigil covers 36 source files.

## v0.5.3 (shipping — 2026-04-20)

- **AIP-0006**: delegation chains with narrowing-only scope, TTL, max_depth, cryptographic chain to trust anchor.
- **Bilateral cosign**: envelope-level `cosignatures[]` field. Proxy supports `--bilateral --server-key`.
- **trace_id + parent_receipt_id**: optional AIP-0001 fields for workflow-level grouping.
- **Proxy --scrub-secrets**: redacts probable-secret values from outgoing tool-call args + flags on receipt.
- **`verify dashboard`**: loopback-only local audit server; DNS-rebinding + path-traversal defenses.
- 41 new unit tests. Sigil covers 31 source files.

## v0.5.2 (shipping — 2026-04-20)

- **Compliance export subcommand**: SOC 2 / ISO 42001 / EU AI Act control mapping with HTML auditor report.
- **DSSE envelope engine**: Sigstore-compatible wrap/unwrap/verify for receipts, KUs, and in-toto statements.
- **BRASS v2 crypto scaffold**: length-prefixed hashing, nullifier-bound-to-Y, single-variable πC restatement.
- **AIP-0004** (Draft): content-addressed snapshot and rollback receipts, with reference Merkle helper.
- **AIP-0005** (Draft): attestation weight profile (cost_tier T0–T4) with evidence schemas.
- **Claude Code plugin staging** for wshobson/agents marketplace (`protect-mcp` tree, closes #471).
- **Audit dashboard scaffold**: local-first, in-browser receipt visualiser.
- **Physical attestation design**: Seal cost_tier T2 integration spec.
- Sigil covers 28 source files. Canonical release: **New Ember** (`b28f8d60`).

## v0.5.1 (shipped — 2026-04-20)

- **Prompt provenance**: `verify prompt <file>` verifies a CLAUDE.md / SKILL.md / AGENTS.md / system prompt against a Veritas Acta receipt, a Sigstore DSSE bundle, or an expected SHA-256.
- **Chain explorer**: `verify chain explore <receipt>` walks `previousReceiptHash` to root with link-by-link hash validation; ASCII tree and `--json` output.
- **Sandbox profiles**: `ecosystem/profiles/` — Cedar policy + nono capabilities + README for Claude Code, Cursor, Codex, Gemini CLI, OpenClaw.
- Sigil commitment grows to **25 source files** (adds prompt.js + chain-explore.js). Canonical release: **Bright Star** (`1cc829ab`).

## v0.5.0 (shipped — 2026-04-19)

- Unified verifier: Ed25519 receipts, VOPRF tokens (full dual-DLEQ), Knowledge Unit bundles, selective-disclosure receipts
- Sigil visual commitment covering 23 source files (since expanded in 0.5.1)
- `--attest` canonical attestations, `--emit-verification-receipt`
- `--pin-sigil`, `--audit-log`, `--audit-report`, `--replay-chain`, `--diff`
- `--fips` enforcement; `--allow-embedded-key` deprecated
- Subcommands: `init`, `proxy`, `daemon`, `--self-check`, `--capabilities`
- Network-effect mechanics (attestations, pinning, receipts-of-receipts)

## v0.6.0 (planned)

Scheduled items, each tracked as a separate implementation task.

### Cryptographic hardening (BRASS protocol)

| Item | Motivation | Breaking? |
|---|---|---|
| Switch BRASS hashing to length-prefixed (RFC 8785 JCS-aligned) | Eliminates variable-length concat collision surface in `piC` bind (AADr and KID are variable-length inputs). | Yes. Dual-mode verifier accepts both v1 and v2 wire formats during the deprecation window. |
| Bind nullifier derivation to issuer public key `Y` | Prevents cross-issuer nullifier collisions if two issuers ever share a KID string. | Yes, but the dual-mode derivation supports both and migration is operator-paced. |
| Restate πC as a standard single-variable Schnorr proof (wire unchanged) | The production BRASS scheme uses a DLEQ structure with `A2 = G` hardcoded. This is cryptographically equivalent to a single-variable Schnorr but reads as degenerate to external auditors. Restating clarifies without changing the wire. | No. |
| Formal verification of the BRASS scheme via Tamarin or ProVerif | Procurement-audit credibility; catches subtle issues the paper analysis misses. | No. |
| Apache-2.0 reference issuer | Patent conversion often benefits from a complete open specification of the invention, even when the commercial operation is proprietary. | No. Commercial differentiation via managed operations, SLAs, rate limits, key rotation, etc. Algorithm goes public. |

### Post-quantum hybrid

- Optional `ed25519+ml-dsa-65` hybrid signature mode on Ed25519 receipts. v0.5.0 recognizes the algorithm identifier and emits a clean `unsupported_algorithm` error. v0.6.0 ships the verifier side via a library like `@noble/post-quantum`.
- Expected scope: ~200 lines of code + spec additions + conformance vectors.

### VOPRF enhancements

- Drop the `--allow-partial-voprf` flag (no-op since 0.5.0 shipped full DLEQ).
- `scope` parameter refinement: support richer scope matching than `origin` equality (e.g., origin wildcards, epoch bounds).
- Per-issuer policy cache: avoid re-verifying πI for tokens known to be from a trusted-fingerprint issuer.

### Reporting and audit

- `--audit-report` template extensibility: custom CSS, operator logo embedding, export to PDF via headless Chrome.
- SBOM attachment: embed SPDX or CycloneDX alongside the verified receipt chain.

### Spec tracking

- Align with draft-farley-acta-signed-receipts-03 as that draft progresses through the IETF.
- Publish BRASS v2 as a separate draft (`draft-farley-brass-anonymous-tokens`).

## v0.7.0 / v1.0 (exploratory)

| Item | Notes |
|---|---|
| Sigstore / DSSE wrapping | `ecosystem/cosign-compat/DESIGN.md` outlines the wrap. Rekor anchoring for temporal proof. |
| Filesystem rollback helper | `ecosystem/rollback/DESIGN.md`. Content-addressed snapshots for post-incident recovery. |
| Runtime supervisor | `ecosystem/supervisor/DESIGN.md`. Dynamic permission expansion with approval gates. |
| Issuer reputation | `ecosystem/reputation/DESIGN.md`. Bayesian reputation over receipt issuers, complement to agent reputation. |
| Audit dashboard GUI | `ecosystem/dashboard/DESIGN.md`. Web dashboard for operator audits. |
| Browser extension | `ecosystem/browser-extension/DESIGN.md`. Consumer reach via Claude.ai / ChatGPT injection. |
| eBPF OS observer | `ecosystem/ebpf-observer/DESIGN.md`. Kernel-level auto-instrumentation. |

## Deprecations

| Item | Deprecated in | Removed in |
|---|---|---|
| `--allow-embedded-key` | 0.4.0 | 0.6.0 |
| `--allow-partial-voprf` | 0.5.0 | 0.6.0 |
| `voprf-p256-sha256` v1 wire format (plain-concat hash) | 0.6.0 (dual-mode) | 0.7.0 or later |

## Commitments

- v0.6.0 targets Q3 2026.
- All breaking changes ship with a dual-mode transition window of at least one minor release.
- Every new wire-format change is accompanied by conformance vectors in [ScopeBlind/agent-governance-testvectors](https://github.com/ScopeBlind/agent-governance-testvectors).
- `--self-check` continues to prove source integrity across releases; Sigils rotate per release with the registry maintained at `ecosystem/RELEASE-NAMING.md`.
