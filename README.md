# @veritasacta/verify

**Unified offline verifier for signed machine-decision artifacts. Network-effect mechanics built in.**

Apache-2.0 · Ed25519 + VOPRF · Offline · Sigil-verified canonical release · Auto-onboarding · MCP proxy · Sidecar daemon

> **Receipt format:** ScopeBlind emits Veritas Acta receipts. Legacy ScopeBlind
> receipts remain verifiable, but Acta v0.1 is the canonical format going
> forward. Spec: [`@veritasacta/protocol`](https://www.npmjs.com/package/@veritasacta/protocol)
> · IETF: [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

```bash
# Install
npm install -g @veritasacta/verify
# Or
brew install veritasacta/verify/veritasacta-verify

# Prove canonical release
npx @veritasacta/verify --self-check

# Zero-config onboarding (auto-detects framework)
npx @veritasacta/verify init

# Verify any receipt format
npx @veritasacta/verify receipt.json --key <pubkey>
```

Part of the [Veritas Acta](https://veritasacta.com) protocol for machine-decision evidence.

## What it verifies

| Mode | Input | Conformance tier |
|---|---|---|
| Ed25519 receipt | Signed decision receipts (v1, v2, Passport envelope) | T1 |
| Ed25519 + AIP-0002 | Selective-disclosure receipts with `_commitments` | T2 |
| Ed25519 + attestation | Receipts with `attestation_mode` or `anchor_uri` | T3 |
| VOPRF token | Anonymous credential tokens (RFC 9497, BRASS wire format). Full Schnorr DLEQ verification for both πI (issuer) and πC (client). | T4 |
| Knowledge Unit | Multi-model deliberation bundles (draft-farley-acta-knowledge-units-00) | varies |
| Audit bundle | Multiple receipts with embedded signing keys | varies |

## Subcommands

The CLI is a dispatcher: one binary, eight modes.

```bash
verify                          # verify a single file (default)
verify init                     # zero-config onboarding, auto-detects framework
verify proxy --target "..."     # transparent MCP proxy, signs every tool call
verify daemon                   # unix-socket sidecar, language-agnostic signing API
verify prompt <file>            # verify provenance of a CLAUDE.md / SKILL.md / system prompt
verify chain explore <r.json>   # walk a receipt chain to its root, validate every hash link
verify --replay-chain ...       # bulk verification with chain-linkage check
verify --self-check             # prove this binary is the canonical release
verify --attest                 # emit a shareable canonical attestation
```

### Prompt provenance

Closes the supply-chain vector where an attacker modifies `CLAUDE.md`, `SKILLS.md`, or a system prompt between authoring time and agent runtime.

```bash
# Against a Veritas Acta receipt asserting the prompt hash
verify prompt SKILL.md --prompt-receipt prompt-receipt.json

# Against a Sigstore bundle (DSSE + in-toto statement)
verify prompt CLAUDE.md --sigstore-bundle bundle.json

# Fast path: caller knows the expected hash
verify prompt SKILL.md --expected-hash <sha256-hex>
```

### Chain exploration

Walks the `previousReceiptHash` chain from a chain tip back to its root, validating every link's SHA-256.

```bash
verify chain explore ./receipts/tip.json
# → ASCII tree, depth, links_broken, warnings

verify chain explore ./receipts/tip.json --search-dir ./audit/ --max-depth 200 --json
```

### Pre-built sandbox profiles

`ecosystem/profiles/` ships sandboxing profiles (Cedar policy + nono capabilities + README) for common agent runtimes — Claude Code, Cursor, Codex, Gemini CLI, OpenClaw. Compose with `sb-runtime --ring 3 --policy ./policy.cedar` + `nono run --caps ./nono-capabilities.yaml`.

## Verification properties

- **Offline.** No network contacted unless `--jwks <url>` is explicitly passed.
- **Tamper-evident.** Exit 1 is proven tampering; exit 2 is undecidable (malformed, missing key, unsupported algorithm).
- **No vendor trust.** Only Ed25519 (RFC 8032) and JCS (RFC 8785) in the verification path.
- **Self-verifying.** `--self-check` cryptographically proves the installed verifier (24 source files) matches the canonical release.
- **Algorithm-agile.** Hybrid PQ (`ed25519+ml-dsa-65`) recognized; full PQ in v0.6+.
- **Zero telemetry.** The verifier never phones home.

## Quick start: frictionless onboarding

```bash
$ cd my-agent-project
$ npx @veritasacta/verify init

[Sigil ASCII art]
  sigil: 956f2e88

✓ Veritas Acta initialized
  Directory: ./.veritasacta
  Kid:       project:956f2e8895fd
  Framework: crewai (python)

Next steps:
  Install: pip install veritasacta-crewai
  Wrap your agent with the adapter as shown in the adapter README.

Verify:
  npx @veritasacta/verify .veritasacta/receipts/*.json --key 956f2e88...
```

Init auto-detects your framework from `package.json` / `pyproject.toml` / `requirements.txt` across 13 supported frameworks (Claude Code, Claude Agent SDK, Google ADK, CrewAI, Pydantic AI, AutoGen, Smolagents, LangChain JS/Python, LangGraph JS/Python, OpenAI Agents SDK, Vercel AI SDK).

## Universal MCP proxy — zero code changes

```bash
$ verify proxy --target "node my-mcp-server.js"
[veritasacta proxy] rcpt_1 signed (web_search) kid=project:956f2e8895fd
[veritasacta proxy] rcpt_2 signed (read_file) kid=project:956f2e8895fd
...
```

Wraps any MCP server with signing. No changes in the server. No changes in the agent. Every `tools/call` gets a chain-linked Ed25519 receipt.

## Sidecar daemon — language-agnostic signing

Run once; any process in the same user context signs receipts by POST.

```bash
$ verify daemon &

# Any language, any process:
$ curl --unix-socket /tmp/veritasacta-$UID.sock -X POST http://_/sign \
    -d '{"tool":"web_search","args":{"q":"..."},"decision":"allow"}'

{ "payload": {...}, "signature": {"alg":"EdDSA","kid":"...","sig":"..."} }
```

One daemon, N agents, zero SDK embedding.

## Canonical attestation — network-effect mechanics

Every user who runs `--self-check` can emit a **canonical attestation** — a signed JSON artifact proving they ran the canonical unmodified verifier. Publish wherever (GitHub README, status page, SBOM, Rekor).

```bash
$ verify --attest --attest-org "Acme Corp" --output attestation.json
```

Output:

```json
{
  "payload": {
    "type": "veritasacta:verifier-attestation",
    "sigil_fingerprint": "6391ae72",
    "sigil_name": "Quiet Orchard",
    "canonical": true,
    "attester_org": "Acme Corp",
    "issued_at": "2026-04-19T...",
    "expires_at": "2026-04-26T...",
    "attester_kid": "attester:..."
  },
  "signature": { "alg": "EdDSA", ... },
  "verification": { "attester_pubkey": "..." }
}
```

Offline. User-signed. Counterfeit forks produce attestations marked `canonical: false` — detectable across the network.

## Verification receipts

```bash
$ verify receipt.json --key <pubkey> --emit-verification-receipt
```

Produces a signed "the canonical verifier checked this receipt and it was valid" artifact. Anchor in Sigstore Rekor, publish in SBOMs, attach to compliance reports.

## Enterprise features

| Flag | Purpose |
|---|---|
| `--pin-sigil <hex>` | Require the installed Sigil fingerprint to match (supply-chain enforcement) |
| `--audit-log <file>` | Append every verification event to a chain-hashed JSONL log |
| `--audit-report` | Render an HTML audit report (self-contained, auditor-ready) |
| `--fips` | Enforce FIPS-approved algorithms only |
| `--strict` | Disable all deprecated fallbacks |
| `--tier N` | Require minimum conformance tier (1-5) |
| `--replay-chain <file>` | Bulk-verify a JSONL chain with parallel workers |
| `--diff <other>` | Structural diff between two receipts |

## Live-context verification (Sigil claim 2)

```bash
$ verify receipt.json \
    --require-context clock:±5s \
    --require-context sensor:temp<18
```

Gates verification on live context (NTP, sensors, feeds). Predicate fails → verification fails. Operationalizes patent #5 claim 2.

## Algorithms supported

- `Ed25519` / `EdDSA` (RFC 8032)
- `voprf-p256-sha256` (RFC 9497, structural; full DLEQ extraction in progress)
- Hybrid PQ recognized: `ed25519+ml-dsa-65`, `ed25519+dilithium3` (v0.6+)

## Conformance tiers

| Tier | Requirements |
|---|---|
| T1 Basic | Ed25519 + JCS + chain linkage |
| T2 Disclosure | T1 + AIP-0002 selective disclosure |
| T3 Attestation | T2 + `attestation_mode` + `anchor_uri` |
| T4 Privacy | T3 + VOPRF + `holder_binding` |
| T5 Full | T4 + ZK compliance proofs (v1.0+) |

Each verification surfaces the tier achieved. Implementations earn tier badges for their READMEs.

## Framework adapters

| Framework | Package | Language |
|---|---|---|
| Claude Code (MCP hooks) | `protect-mcp` | JS |
| Google ADK | `protect-mcp-adk` | Python |
| LangChain | `@veritasacta/langchain` / `veritasacta-langchain` | JS / Python |
| LangGraph | `@veritasacta/langgraph` / `veritasacta-langgraph` | JS / Python |
| CrewAI | `veritasacta-crewai` | Python |
| Pydantic AI | `veritasacta-pydantic-ai` | Python |
| AutoGen | `veritasacta-autogen` | Python |
| Smolagents | `veritasacta-smolagents` | Python |
| OpenAI Agents SDK | `@veritasacta/openai-agents` | JS / Python |
| Vercel AI SDK | `@veritasacta/vercel-ai` | JS |
| Any MCP server | `verify proxy --target "<cmd>"` | language-agnostic |
| Anything else | `verify daemon` + HTTP POST | language-agnostic |

## SDK

Tiny language-agnostic signing helpers for custom integrations:

```bash
npm install @veritasacta/sdk
pip install veritasacta-sdk
```

```js
import { Signer } from '@veritasacta/sdk';
const signer = Signer.fromKeyFile('.veritasacta/attester.json');
const receipt = signer.signDecision({ tool: 'x', args: {}, decision: 'allow' });
```

## Release names (Sigil brand convention)

Every release gets a unique deterministic name from its cryptographic fingerprint. Current release: **Quiet Orchard** (`6391ae72`). Full registry at [veritasacta.com/sigils](https://veritasacta.com/sigils). See [ecosystem/RELEASE-NAMING.md](./ecosystem/RELEASE-NAMING.md) for the derivation.

## Ecosystem artifacts

The `ecosystem/` directory ships:

- **GitHub Action** (`ecosystem/github-action/`) — drop-in CI step
- **Claude Code plugin** (`ecosystem/claude-code-plugin/`) — one-click Claude Code install
- **Homebrew tap** (`ecosystem/homebrew-tap/`) — `brew install veritasacta-verify`
- **Registry worker** (`ecosystem/registry-worker/`) — public implementations registry (`registry.veritasacta.com`)
- **Badge worker** (`ecosystem/badge-worker/`) — shields.io-compatible badges (`verify.veritasacta.com/badge/*`)
- **Interop leaderboard** (`ecosystem/interop-leaderboard/`) — weekly cross-implementation CI
- **Language SDKs** (`ecosystem/sdk-js/`, `ecosystem/sdk-py/`) — tiny signing helpers
- **Framework adapters** (`ecosystem/adapters/*`) — LangChain, CrewAI, OpenAI Agents, Vercel AI, Smolagents, Pydantic AI, AutoGen, LangGraph
- **Design docs** (`ecosystem/rollback/`, `ecosystem/supervisor/`, `ecosystem/reputation/`, `ecosystem/dashboard/`, `ecosystem/browser-extension/`, `ecosystem/ebpf-observer/`, `ecosystem/cosign-compat/`, `ecosystem/CONFORMANCE-CERTIFICATION.md`)

See [`ecosystem/README.md`](./ecosystem/README.md) for the full map.

## Relationship to the Veritas Acta stack

- **Protocol:** [veritasacta.com](https://veritasacta.com) — open IETF drafts, AIP specs, Apache-2.0.
- **Verifier:** this package. Open, offline, fully user-controlled.
- **Managed issuance (commercial):** [scopeblind.com](https://scopeblind.com) — managed receipt infrastructure + VOPRF issuance API.

Open verifier + closed issuer. The verifier is always free. The commercial product is the managed service.

## Supply chain

v0.5.0 is published with:

- `npm publish --provenance` — Sigstore-attested supply chain
- Sigil commitment covering 24 source files
- Minimum dependency tree: only `@veritasacta/artifacts` (+ transitively `@noble/curves`, `@noble/hashes`)

Verify your installation:

```bash
npm audit signatures             # Sigstore attestation
verify --self-check              # matches canonical Sigil
verify --pin-sigil <fingerprint> # enforce a specific release
```

## Specifications

- [draft-farley-acta-signed-receipts-03](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- [draft-farley-acta-knowledge-units-00](https://datatracker.ietf.org/doc/draft-farley-acta-knowledge-units/)
- AIP-0001 (receipt format + ASCII-only JCS)
- AIP-0002 (selective disclosure)
- AIP-0003 (holder binding)
- RFC 8032, 8785, 9497, 9380, 7517, 7638

## Documentation

- [CHANGELOG.md](./CHANGELOG.md) — release history
- [THREAT-MODEL.md](./THREAT-MODEL.md) — what the verifier protects against and what it doesn't
- [SECURITY.md](./SECURITY.md) — disclosure policy + supported versions
- [ERRORS.md](./ERRORS.md) — complete error-code registry
- [ecosystem/RELEASE-NAMING.md](./ecosystem/RELEASE-NAMING.md) — Sigil naming convention

## License

Apache-2.0.

Patent-adjacent; covered by the Apache-2.0 patent grant (§3). See [PATENTS.md](./PATENTS.md).
