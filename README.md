# @veritasacta/verify

**Offline verifier for signed machine-decision receipts and artifacts.**

Apache-2.0 · Ed25519 + VOPRF · Offline · Locally recomputable integrity commitment · Auto-onboarding · MCP proxy · Sidecar daemon

> **Receipt format:** ScopeBlind emits Veritas Acta receipts. Legacy ScopeBlind
> receipts remain verifiable; Acta receipts (draft-farley-acta-signed-receipts-03)
> are the canonical format. Spec: [`@veritasacta/protocol`](https://www.npmjs.com/package/@veritasacta/protocol)
> · IETF: [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

```bash
# Install
npm install -g @veritasacta/verify
# Or
brew install veritasacta/tap/veritasacta-verify

# Compare installed bytes with the bundled integrity commitment
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
| Gate receipt / bundle | ScopeBlind Gate receipt tuples (`scopeblind.gate.*`) and signed-manifest `scopeblind.gate.evidence-bundle/2` exports with semantic and exact chain checks | T1 |
| Macro track record | Signed macro snapshots, append-only manifest sequence, and signed history checkpoints | T1 |
| Legate standard files | A signed standard (`scopeblind.proof_request.v1`), a recipient decision (`scopeblind.admission_decision.v1`), or an action assurance bundle (`scopeblind.action_assurance_bundle.v1`), verified by the same core the Legate site runs, bundled here | T1 |

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
verify --self-check             # compare monitored source with bundled commitment
verify --attest                 # emit a signed local-verifier attestation
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

### ScopeBlind Gate receipts

Verifies the receipt tuples emitted by the ScopeBlind Gate (the pre-trade mandate gate): single decisions, batch decisions and their exact signed legs, PM co-sign approvals, execution fills, held-remainder states, and issuer-signed mandate delegations. Version 2 evidence bundles add a gate-signed completeness manifest that enumerates every exported digest. Tuples sign the SHA-256 of the deep-key-sorted payload; the Ed25519 signature covers the digest bytes and verifies against the `verification_key` carried in the tuple.

```bash
verify gate-receipt.json                      # auto-detected tuple
verify gate-bundle.json                       # schemas, exact links, and signed manifest checked
verify gate-receipt.json --key <gate-pubkey>  # pin the expected signer
verify gate-bundle.json --key <gate-pubkey>   # pin the bundle trust anchor
verify samples/sample-gate-bundle.json        # try it (deterministic demo keys)
```

A VALID result proves cryptographic authenticity, payload integrity, recognized-schema validity, exact parent-child consistency, fail-closed partial-fill handling, and that the signed manifest exactly covers the records in the export. It does NOT prove the risk inputs were correct, that a demo fill came from an independent production custodian, or that records outside the manifest's declared history scope do not exist. Verification keys travel inside the records, so pin the expected gate signer with `--key` for identity assurance. Crypto and chain failures are reported separately (`[crypto]` vs `[chain]`): a record can be individually authentic while its semantic or cross-record relationship is invalid.

Legacy `scopeblind.gate.evidence-bundle/1` files are detected but fail closed because they do not contain a signed completeness manifest. Re-export them as `/2`.

### ScopeBlind macro track records

Macro exports verify offline. An embedded key proves internal signature
integrity, not who controls that key. Pin the operator key and an independently
retained anti-rollback head for identity and historical assurance:

```bash
npx @veritasacta/verify@0.10.0 legate-macro-track-record.json \
  --key <operator-ed25519-public-key> \
  --history-head <expected-history-head> \
  --anchor-head <expected-anchor-digest>
```

The verifier checks every record, the exact current manifest inventory, prior
manifest links, retention of previously manifested records, and the signed
checkpoint chain. Publication at a mutable URL is not itself a transparency
log; retain or independently timestamp checkpoint heads.

### Pre-built sandbox profiles

`ecosystem/profiles/` ships sandboxing profiles (Cedar policy + nono capabilities + README) for common agent runtimes: Claude Code, Cursor, Codex, Gemini CLI, OpenClaw. Compose with `sb-runtime --ring 3 --policy ./policy.cedar` + `nono run --caps ./nono-capabilities.yaml`.

## Verification properties

- **Offline.** No network contacted unless `--jwks <url>` is explicitly passed.
- **Tamper-evident.** Exit 1 is proven tampering; exit 2 is undecidable (malformed, missing key, unsupported algorithm).
- **No vendor trust.** Only Ed25519 (RFC 8032) and JCS (RFC 8785) in the verification path.
- **Locally integrity-checkable.** `--self-check` recomputes the bundled
  commitment over the verifier surface. This detects byte drift relative to
  that copy; it is not a publisher signature or independent supply-chain
  attestation unless the fingerprint is separately pinned.
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

## Universal MCP proxy: zero code changes

```bash
$ verify proxy --target "node my-mcp-server.js"
[veritasacta proxy] rcpt_1 signed (web_search) kid=project:956f2e8895fd
[veritasacta proxy] rcpt_2 signed (read_file) kid=project:956f2e8895fd
...
```

Wraps any MCP server with signing. No changes in the server. No changes in the agent. Every `tools/call` gets a chain-linked Ed25519 receipt.

## Sidecar daemon: language-agnostic signing

Run once; any process in the same user context signs receipts by POST.

```bash
$ verify daemon &

# Any language, any process:
$ curl --unix-socket /tmp/veritasacta-$UID.sock -X POST http://_/sign \
    -d '{"tool":"web_search","args":{"q":"..."},"decision":"allow"}'

{ "payload": {...}, "signature": {"alg":"EdDSA","kid":"...","sig":"..."} }
```

One daemon, N agents, zero SDK embedding.

## Local-integrity attestation

Every user who runs `--self-check` can emit a **local-integrity attestation**:
a self-signed statement that the declared monitored source on that machine
matched the bundled public commitment. The monitored runtime includes
`cli.js` and every shipped executable JavaScript module under `src/`; a release
test fails if a module is omitted. This does not authenticate the package
publisher, prove an independently canonical release, or establish trust in
the attester unless the recipient separately pins the commitment and attester
key.

```bash
$ verify --attest --attest-org "Acme Corp" --output attestation.json
```

Output:

```json
{
  "payload": {
    "type": "veritasacta:verifier-attestation",
    "sigil_fingerprint": "<from sigil.json>",
    "sigil_name": "<from sigil.json>",
    "integrity_matches": true,
    "publisher_authenticated": false,
    "assurance": "self_signed_operator_statement",
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

Offline and user-signed. The legacy `canonical` field is retained for wire
compatibility and aliases `integrity_matches`. Neither field authenticates the
publisher. Missing monitored files fail closed rather than sealing a reduced
verification surface.

## Verification receipts

```bash
$ verify receipt.json --key <pubkey> --emit-verification-receipt
```

Produces a signed "this local verifier checked this receipt and reported it
valid" artifact. The attester key and any independently pinned verifier
fingerprint determine whether a recipient should trust it.

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

Pass `--tier N` to require a minimum tier.

## Framework adapters

Published packages:

| Framework | Package | Language |
|---|---|---|
| Claude Code, Codex, Cursor, Gemini, Hermes (hooks) and any MCP server (gateway) | [`protect-mcp`](https://www.npmjs.com/package/protect-mcp) | JS |
| Google ADK | [`protect-mcp-adk`](https://pypi.org/project/protect-mcp-adk/) | Python |
| LangChain | [`@scopeblind/langchain`](https://www.npmjs.com/package/@scopeblind/langchain) | JS |
| Swarms | [`scopeblind-swarms`](https://pypi.org/project/scopeblind-swarms/) | Python |
| Any MCP server | `verify proxy --target "<cmd>"` | language-agnostic |
| Anything else | `verify daemon` + HTTP POST | language-agnostic |

Source adapters for LangGraph, CrewAI, Pydantic AI, AutoGen, Smolagents, the
OpenAI Agents SDK and the Vercel AI SDK live under
[`ecosystem/adapters/`](./ecosystem/adapters/) and are not published as
packages.

## SDK

Tiny signing helpers for custom integrations ship as source in
[`ecosystem/sdk-js/`](./ecosystem/sdk-js/) and [`ecosystem/sdk-py/`](./ecosystem/sdk-py/).
They are not published as packages; copy the file you need. Receipts they
produce verify with this CLI.

## Release names (Sigil brand convention)

Every committed verifier surface gets a unique deterministic name from its
cryptographic fingerprint. The bundled `sigil.json` is the authoritative name
and fingerprint for the installed copy; `verify --self-check` recomputes it.
See
[ecosystem/RELEASE-NAMING.md](./ecosystem/RELEASE-NAMING.md) for the derivation.

## Ecosystem artifacts

The `ecosystem/` directory ships source, not deployed services:

- **GitHub Action** (`ecosystem/github-action/`): a CI step that verifies receipts
- **Claude Code plugin** (`ecosystem/claude-code-plugin/`)
- **Homebrew tap** (`ecosystem/homebrew-tap/`): the formula behind `brew install veritasacta/tap/veritasacta-verify`
- **Registry and badge workers** (`ecosystem/registry-worker/`, `ecosystem/badge-worker/`): Cloudflare Worker source; no public instance is running
- **Interop leaderboard** (`ecosystem/interop-leaderboard/`): cross-implementation CI design
- **Language SDKs** (`ecosystem/sdk-js/`, `ecosystem/sdk-py/`): signing helpers, unpublished
- **Framework adapters** (`ecosystem/adapters/*`): see the table above
- **Design docs** (`ecosystem/rollback/`, `ecosystem/supervisor/`, `ecosystem/dashboard/`)

See [`ecosystem/README.md`](./ecosystem/README.md) for the full map.

## Relationship to the Veritas Acta stack

- **Protocol:** [veritasacta.com](https://veritasacta.com): open IETF drafts, AIP specs, Apache-2.0.
- **Verifier:** this package. Open, offline, fully user-controlled.
- **Managed issuance (commercial):** [scopeblind.com](https://scopeblind.com): managed receipt infrastructure + VOPRF issuance API.

Open verifier + closed issuer. The verifier is always free. The commercial product is the managed service.

## Supply chain

Releases are published from the source of record after the bundled integrity
commitment is regenerated and `--self-check` passes on the exact bytes
shipped. The dependency tree is small: `@veritasacta/artifacts`, `@noble/curves`,
`@noble/hashes`, `ajv` and `ajv-formats`. npm registry signatures apply to every
version; Sigstore provenance attestations are not currently published.

Verify your installation:

```bash
npm audit signatures             # registry signatures
verify --self-check              # matches the bundled integrity commitment
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

- [CHANGELOG.md](./CHANGELOG.md): release history
- [THREAT-MODEL.md](./THREAT-MODEL.md): what the verifier protects against and what it doesn't
- [SECURITY.md](./SECURITY.md): disclosure policy + supported versions
- [ERRORS.md](./ERRORS.md): complete error-code registry
- [ecosystem/RELEASE-NAMING.md](./ecosystem/RELEASE-NAMING.md): Sigil naming convention

## License

Apache-2.0.

Patent-adjacent; covered by the Apache-2.0 patent grant (§3). See [PATENTS.md](./PATENTS.md).
