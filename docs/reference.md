# Advanced verifier reference

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
| VOPRF token | Anonymous credential tokens (RFC 9497, BRASS wire format, and BRASS 2.0 redemptions). Full Schnorr DLEQ verification for both πI (issuer) and πC (client), against the issuer key given with `--key` (base64url compressed P-256 point); a token is never verified against the `issuer_public_key` it carries, and one that carries another key is invalid (`issuer_key_mismatch`). | T4 |
| Knowledge Unit | Multi-model deliberation bundles (draft-farley-acta-knowledge-units-00), checked through the receipts they carry: one that fails makes the KU invalid (exit 1). The aggregate `receipt_sig` and `receipt_hash` are not checked, since §8 does not define their preimage unambiguously, so otherwise the KU is undecidable (exit 2, `receipt_binding_not_checked`, or the receipts' own reason), never valid; `notChecked` says so | varies |
| Audit bundle | Multiple receipts and a `verification.signing_keys` block. Checked with `--key` or `--jwks`; the bundle's own keys are used only with `--trust-bundle-keys` (0.10.27) | varies |
| Gate receipt / bundle | ScopeBlind Gate receipt tuples (`scopeblind.gate.*`) and signed-manifest `scopeblind.gate.evidence-bundle/2` exports with semantic and exact chain checks | T1 |
| Macro track record | Signed macro snapshots, append-only manifest sequence, and signed history checkpoints | T1 |
| ScopeBlind standard files | A signed standard (`scopeblind.proof_request.v1`), a recipient decision (`scopeblind.admission_decision.v1`), or an action assurance bundle (`scopeblind.action_assurance_bundle.v1`), verified by the same core the ScopeBlind website runs, bundled here. `--key` pins the key that signed it (the recipient key of a standard or a decision, the gate key of a bundle); a file signed with another key is invalid (`key_mismatch`, exit 1) | T1 |
| ScopeBlind run manifest | A harness's signed account of a governed run (`scopeblind.run_manifest.v1`): a benchmark submission made with every tool call through the gateway. Alone it verifies as intact but unbound. Add the files beside it to bind it: `--standard` (the pins, the policy, the tool list, the attempts, the time limit), `--receipts` (the chain head and every receipt), `--calls` (each call behind its receipt), `--regrade` (a second grading; repeat it for gradings made elsewhere), `--provenance` (the run's Sigstore bundles, verified offline against the pinned trust root and tied to the exact bytes given), `--model-calls` with `--model-attestation` (every model call signed inside the provider's TEE, each key bound in an Intel TDX quote chained to the pinned Intel root), and `--maintainer-key` (with `--standard`: pin the key that must have signed the standard; refused without it). `--key` pins the harness key that signed the manifest. With companion files the exit status is 0 only when the run binds to all of them. Example: `npx @veritasacta/verify manifest.json --standard standard.json --receipts receipts.jsonl --calls calls.jsonl --regrade regrade.json --provenance provenance` | T1 |

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

`verify prompt` does not check the signature of a receipt or a Sigstore bundle. A receipt or bundle that names the prompt's hash is undecidable (`signature_not_checked`, exit 2), never verified provenance: verify the receipt itself with `verify prompt-receipt.json --key <hex>`, or the bundle with a Sigstore verifier. One that names another hash fails (exit 1). Only `--expected-hash`, a hash you supply, gives a valid result (exit 0).

### Chain exploration

Walks the `previousReceiptHash` chain from a chain tip back to its root, validating every link's SHA-256.

```bash
verify chain explore ./receipts/tip.json
# → ASCII tree, depth, links_broken, warnings

verify chain explore ./receipts/tip.json --search-dir ./audit/ --max-depth 200 --json
```

Links are read by the rules of draft §6.7 that the receipt verifier applies: `sha256:` and the lowercase hex SHA-256 of the JCS of the whole previous receipt, or the bare digest of earlier revisions. A malformed link stops the walk with `malformed_chain_link` (exit 1), and one naming another algorithm with `unsupported_chain_hash_algorithm` (exit 2). A link over the ancestor's payload alone stops it with `chain_break` (exit 1), whatever the ancestor's `spec` says; `--allow-payload-only-links` reads one as a legacy link instead, a compatibility mode that is not conformant to draft §6.7 (see [0.10.25](#chain-links-over-the-whole-receipt-01025)). Before 0.10.23 the explorer looked ancestors up by an unprefixed base64url hash, so it did not walk §6.7 chains.

### ScopeBlind Gate receipts

Verifies the receipt tuples emitted by the ScopeBlind Gate (the pre-trade mandate gate): single decisions, batch decisions and their exact signed legs, PM co-sign approvals, execution fills, held-remainder states, and issuer-signed mandate delegations. Version 2 evidence bundles add a gate-signed completeness manifest that enumerates every exported digest. Tuples sign the SHA-256 of the deep-key-sorted payload; the Ed25519 signature covers the digest bytes. The tuple carries its `verification_key`, which is never a trust anchor: without `--key` the result is undecidable (`embedded_key_rejected`, exit 2), and `--allow-carried-key` accepts it with a notice that the signature proves nothing about who signed.

```bash
verify gate-receipt.json --key <gate-pubkey>  # pin the expected signer
verify gate-bundle.json --key <gate-pubkey>   # schemas, exact links, and signed manifest checked
verify gate-receipt.json --allow-carried-key  # integrity only, against the key the tuple carries
verify samples/sample-gate-bundle.json --key 0f37d844c1934a03851a48d7927e5109be76d8cbed6eac1dc8684ed89d977790  # try it (deterministic demo key)
```

A VALID result proves cryptographic authenticity, payload integrity, recognized-schema validity, exact parent-child consistency, fail-closed partial-fill handling, and that the signed manifest exactly covers the records in the export. It does NOT prove the risk inputs were correct, that a demo fill came from an independent production custodian, or that records outside the manifest's declared history scope do not exist. Verification keys travel inside the records, so pin the expected gate signer with `--key`; without it the result is undecidable. Crypto and chain failures are reported separately (`[crypto]` vs `[chain]`): a record can be individually authentic while its semantic or cross-record relationship is invalid.

Legacy `scopeblind.gate.evidence-bundle/1` files are detected but fail closed because they do not contain a signed completeness manifest. Re-export them as `/2`.

### Repository reviews

```bash
npx @veritasacta/verify@0.10.18 review.json --key <service-ed25519-public-key> --json
```

Repository review exports bind the owner’s brief and acceptance criteria to an exact receiver-signed pull-request proposal, preview observation, and each human’s matching approval or rejection. Scoped agent findings include their signed preparation authority and service-recorded use. A review prepared from earlier feedback carries its exact frozen source and a signed registration commitment; approvals remain specific to the new task.

The verifier checks these records offline. It does not fetch or execute preview pages, prove that a mutable preview URL still serves the observed content, or prove that an agent’s assessment is correct. An artifact digest, when present, identifies the recorded artifact bytes separately from the preview URL. Pin the service key through an independent channel; the receiver’s signed GitHub observations remain assertions by that receiver. Existing repository and collaboration v1 exports remain supported.

### ScopeBlind macro track records

Macro exports verify offline. An embedded key proves internal signature
integrity, not who controls that key, so without `--key` the result is
undecidable (exit 2) unless `--allow-carried-key` accepts it. Pin the operator
key and an independently retained anti-rollback head for identity and historical
assurance:

```bash
npx @veritasacta/verify@0.10.4 legate-macro-track-record.json \
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
- **Tamper-evident.** Exit 1 means a verification check failed, including a wrong expected key, signature mismatch or invalid structure. It does not by itself prove tampering. Exit 2 means the result is undecidable (for example missing key or unsupported format).
- **No vendor trust.** Only Ed25519 (RFC 8032) and JCS (RFC 8785) in the verification path.
- **Locally integrity-checkable.** `--self-check` recomputes the bundled
  commitment over the verifier surface. This detects byte drift relative to
  that copy; it is not a publisher signature or independent supply-chain
  attestation unless the fingerprint is separately pinned.
- **Algorithm-agile.** An algorithm the verifier does not implement is reported undecidable (`unsupported_algorithm`, exit 2), never as a bad signature. ML-DSA-65, alone or in the hybrid `ed25519+ml-dsa-65`, is recognized and not implemented.
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

One daemon, N agents, zero SDK embedding. Each receipt's `tool_input_hash` is the SHA-256 of the RFC 8785 canonical form of the full `args`, recorded as `tool_input_hash_method: jcs-sha256-v1`, as the proxy writes it.

## Local-integrity attestation

Every user who runs `--self-check` can emit a **local-integrity attestation**:
a self-signed statement that the declared monitored source on that machine
matched the bundled public commitment. The monitored runtime includes
`cli.js` and every shipped executable JavaScript module under `src/`, the
bundled verifier core `src/engines/legate-core.mjs` included from 0.10.26; a
release test fails if a module is omitted. This does not authenticate the package
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
| `--audit-log <file>` | Append every verification event to a chain-hashed JSONL log: each entry's `_chain_hash` is the SHA-256 of the previous entry's `_chain_hash` followed by the entry, and an entry is not appended to a log whose last line carries none |
| `--audit-report` | Render an HTML audit report (self-contained, auditor-ready) |
| `--fips` | Enforce FIPS-approved algorithms only: a valid result stands only when every algorithm the engine verified is approved (Ed25519 is, under FIPS 186-5). The algorithm is the one the engine reports it verified, never a label in the file; a format that reports none is refused (exit 2) |
| `--strict` | Disable all deprecated fallbacks, `--allow-carried-key` included |
| `--allow-carried-key` | Accept a result that rests only on a key the file carries: a Gate tuple or bundle, a macro snapshot or track record, a governed receipt, a proof or context pack, repository evidence, a standard file or a run manifest checked without `--key`. Without it such a result is undecidable (`embedded_key_rejected`, exit 2); with it, exit 0, `carriedKeyOnly: true`, and a notice that the signature proves nothing about who signed. `--strict` refuses it |
| `--tier N` | Require minimum conformance tier (1-5) |
| `--replay-chain <file>` | Verify every receipt in a JSONL file in turn, and each §6.7 link to the receipt before it; reports the chains the file holds. Keys come from `--key`, or from `--jwks` by each receipt's `kid`. Exits 1 if a line is invalid or a link breaks, else 2 if a line could not be checked, else 0 |
| `--allow-payload-only-links` | Read a chain link over the previous receipt's payload alone as a legacy link, counted and warned: a compatibility mode for 0.9.3-era chains, not conformant to draft §6.7, marked `conformant: false` (disabled by `--strict`) |
| `--previous <file>` | Check one receipt against the receipt it follows: its link must be that receipt's §6.7 hash, and an absent or `null` link fails too (`chain_break`, exit 1) |
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
- Recognized, not implemented: `ML-DSA-65`, `ed25519+ml-dsa-65`, `ed25519+dilithium3`. A receipt that declares one is undecidable (`unsupported_algorithm`, exit 2).

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
[`ecosystem/adapters/`](.././ecosystem/adapters/) and are not published as
packages.

## SDK

Tiny signing helpers for custom integrations ship as source in
[`ecosystem/sdk-js/`](.././ecosystem/sdk-js/) and [`ecosystem/sdk-py/`](.././ecosystem/sdk-py/).
They are not published as packages; copy the file you need. Receipts they
produce verify with this CLI.

## Release names (Sigil brand convention)

Every committed verifier surface gets a unique deterministic name from its
cryptographic fingerprint. The bundled `sigil.json` is the authoritative name
and fingerprint for the installed copy; `verify --self-check` recomputes it.
See
[ecosystem/RELEASE-NAMING.md](.././ecosystem/RELEASE-NAMING.md) for the derivation.

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

See [`ecosystem/README.md`](.././ecosystem/README.md) for the full map.

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

- [CHANGELOG.md](.././CHANGELOG.md): release history
- [THREAT-MODEL.md](.././THREAT-MODEL.md): what the verifier protects against and what it doesn't
- [SECURITY.md](.././SECURITY.md): disclosure policy + supported versions
- [ERRORS.md](.././ERRORS.md): complete error-code registry
- [ecosystem/RELEASE-NAMING.md](.././ecosystem/RELEASE-NAMING.md): Sigil naming convention

## License

Apache-2.0.

Patent-adjacent; covered by the Apache-2.0 patent grant (§3). See [PATENTS.md](.././PATENTS.md).

### Keys from outside the file (0.10.27)

An Acta receipt or audit bundle is never checked with a key taken from the file being checked. An audit bundle's `verification.signing_keys` arrive in that file, so they are not a trust anchor: without `--key` or `--jwks` its receipts are undecidable (`no_public_key`, exit 2), and the result's `detail` says why. To check them against the keys the bundle carries anyway, pass `--trust-bundle-keys`; each receipt, and the bundle, then reports `keySource: bundle`, and the `warning` says that a valid result shows only that the receipts match keys in the same file. `--strict` disables the flag, and it is refused (exit 2) for a file that is not an audit bundle. With `--jwks`, the key set is read once and each receipt gets the key its own `kid` names, with that key's window applied to its signed `issued_at`; a receipt whose `kid` the set lacks is undecidable (`jwks_fetch_failed`). Earlier releases gave every receipt the set's first key. `--key` takes precedence over `--jwks`, and either over `--trust-bundle-keys`.

Gate receipt tuples and evidence bundles, macro track records, governed receipts, proof packs and trusted context packs are not changed: given no key, they verify against the key they carry, and label the result `embedded-tuple`, `embedded-receipt` or `embedded-pack` (`identityStatus: embedded_key_only` for a macro track record), which shows integrity, not who holds the key. Pin the key with `--key`. From 0.11.0 such a result is undecidable (`embedded_key_rejected`, exit 2), for these formats and for repository evidence, standard files and run manifests, unless `--allow-carried-key` accepts it, which marks it `carriedKeyOnly` and says the signature proves nothing about who signed.

```bash
verify bundle.json --key ISSUER_PUBLIC_KEY --json
verify bundle.json --trust-bundle-keys --json      # the bundle's own keys, labelled as such
```

A bundle's outcome combines its receipts': invalid (exit 1) if any receipt is invalid, else undecidable (exit 2) if any could not be checked, else valid. The result carries `outcome`, `error`, `keySource` and `undecidable`, and `failed` counts invalid receipts only.

A key carried in a receipt's signed bytes, the value of a `public_key`, `verification_key` or `verification_jwk` member (in an envelope's payload; at the top level of a flat receipt, or in a v2 receipt's payload), is never used to verify it. When the key comes from `--key`, `--jwks` or a trusted bundle, a carried key that is not that key makes the receipt invalid (`key_mismatch`, exit 1), as §5.3 of the -04 editor's copy (VeritasActa/drafts) has it, even when the signature verifies. Keys are compared as 32 bytes: 64 hex characters in either case, base64 or base64url, or an OKP Ed25519 JWK. The JSON reports the check as `checks.carried_key` (`pass` or `fail`) when there is a carried key and a key to compare it with. A key from `--jwks` is reported as `keySource: jwks`.

An envelope whose payload names an `issuer_id` must name its signature's `kid`, as §2.2 says. One that names another, or names one while the signature object has no `kid`, is invalid (`issuer_kid_mismatch`, exit 1), whatever key was used, or none; the JSON reports the check as `checks.issuer_kid`. A payload with no `issuer_id` is not checked, and `payloadNotes` names the gap. The flat shapes are not checked.

### The signed issued_at, and disclosures against the signed root (0.10.27)

A key's `valid_from` / `valid_until` window is applied to the `issued_at` the signature covers and nothing else: `payload.issued_at` in the envelope shape, the top-level `issued_at` in the flat shapes, read only as an RFC 3339 date-time string. An `issued_at` or `timestamp` beside an envelope's payload is outside the signature, a `timestamp` is not an `issued_at`, and a number is not a date-time, so with any of those in its place the window is undecidable (`key_window_unverifiable`, exit 2). Without a window nothing changes.

`--disclosure-file` is checked against the `committed_fields_root` the signature covers: in an envelope's payload, where draft §2.2 puts it, or at the top level of a flat receipt (or in a v2 receipt's payload). `--disclose` (AIP-0002) is checked against the `_commitments` map the signature covers, read the same way. A root or map beside an envelope's payload is not signed and is not used. A disclosure that cannot be applied, because the file cannot be read, is not JSON or holds no disclosure, because a `--disclose` value is not `field:salt:value`, or because the signed bytes carry nothing to check it against, is undecidable (`disclosure_not_applied`, exit 2); a failure another check found stays the outcome. Both flags apply to one receipt, and are refused (exit 2) with an audit bundle, `--replay-chain`, `--diff` or a subcommand. Each proof gives its leaf count as `tree_size`, as draft §6.5 names it; `treeSize`, which earlier releases read and protect-mcp writes, is accepted too, and a proof that gives both with different values does not verify.

```bash
verify committed.json --key ISSUER_PUBLIC_KEY --disclosure-file disclosure.json --json
```

### Payload notes (0.10.27)

For an envelope, `payloadNotes` lists what the payload lacks against §2.2 of the -04 editor's copy (VeritasActa/drafts): a `type`, `issued_at` or `issuer_id`, or a signature object with no `kid` when no `issuer_id` names one (an `issuer_id` that does not match the `kid` is `issuer_kid_mismatch`, above); and against its declared type, for `protectmcp:decision` (§3.1.1: `tool_name` and `decision` are REQUIRED, and `decision` is one of `allow`, `deny`, `rate_limit`, `require_approval`) and `protectmcp:restraint` (§3.2.1). The terminal prints them under "Payload notes". They are reported only and never change the outcome or the exit status. The flat shapes get none.

### A receipt and the one before it (0.10.26)

`--previous <file>` checks one receipt against the receipt the caller says it follows. Its `previousReceiptHash` must be the draft §6.7 link of that receipt: `sha256:` and the lowercase hex SHA-256 of the JCS of the whole receipt, signature included, or the bare hex of earlier revisions. Anything else is a `chain_break` (exit 1), and the result's `previous` member says which: `absent` (the receipt has no `previousReceiptHash`), `null`, `mismatch` (it names another receipt) or `payload-only` (it hashes that receipt's payload alone). Supplying the predecessor asserts the succession, so a receipt that names no predecessor does not follow the one supplied. `--replay-chain` reads the order from the file instead and asserts none, so there a receipt with no link still starts a new chain (§2.2).

```bash
verify receipt.json --jwks acta-keys.json --previous before.json --json
```

One run checks the signature, the key window and the link, each whatever the others found; the first failure in that order is the one reported, so a tampered receipt still reports `invalid_signature`. A payload-only link is refused unless `--allow-payload-only-links` is given, and `--strict` disables that flag. A link in no §6.7 form is `malformed_chain_link` (exit 1), and one naming another algorithm is `unsupported_chain_hash_algorithm` (exit 2), as without `--previous`. The receipt given with `--previous` is hashed, not verified: verify it with its own invocation. The flag applies to a single receipt, and is refused (exit 2) with `--replay-chain`, `--bundle`, `--diff`, a subcommand, or a file that is not an Ed25519 receipt.

In the JSON result, `previous` carries `file`, `expected` (the §6.7 link of the receipt supplied), `link` (as written), `result` (`linked`, `legacy-payload`, `absent`, `null`, `mismatch`, `payload-only`, `malformed` or `unsupported`), `form` (`sha256` or `legacy-bare-hex`, when the link has one of those forms) and `detail`. A link `--previous` matched is reported as a verified feature (`chain-linkage`) rather than a declared one. A link naming another hash algorithm is undecidable (exit 2), as §6.7.1 of the -04 editor's copy (VeritasActa/drafts) has it, and a payload-only link read under `--allow-payload-only-links` sets `conformant: false`.

### Three outcomes (0.10.26)

A verification has one of three outcomes, as §5.3 of the -04 editor's copy (VeritasActa/drafts) has them, and the exit status tells them apart: valid (exit 0), invalid (exit 1), undecidable (exit 2). A single receipt goes through several checks: the signing input (§6.6), the signature, the link's syntax (§6.7), the key window (§5.5 of the -04 editor's copy, §9.2 of -03) and, with `--previous`, the link against the receipt supplied. Each runs whatever the others found, except that a signature is not checked over a signing input that carries a signature member, and they combine this way: invalid if any check ran and failed, even when another could not run; undecidable if none failed and at least one could not run (no key, an unsupported algorithm, a link naming another hash algorithm, a window that cannot be applied); valid only when every check that applies passed. The code reported is the first failure in that order, or the first check that could not run when none failed. So a receipt whose link names another algorithm and whose `issued_at` falls outside its key's window is invalid with `key_outside_validity_window`, where 0.10.25 reported it undecidable; and a receipt with a malformed link is invalid with `malformed_chain_link` even when no key was supplied, where 0.10.25 reported `no_public_key`. The JSON result carries `outcome` and `checks`, each check's `result` (`pass`, `fail`, `undecidable`, or one that moves nothing: `absent`, `not_established`, `not_run`) and its `code`. The connector-action profile is checked once the receipt's own checks pass.

`--replay-chain` applies the same rule to each line, with the link to the line before it as one of the checks, and to the file: it exits 1 if any line is invalid or any link breaks, else 2 if any line could not be checked, else 0. A link naming another hash algorithm is undecided, not a break. A line that is not well-formed JSON is undecidable. The summary carries `outcome`, and `verified`, `failed` and `undecidable` count lines by outcome; `failed` used to count a line once for its link and again for its signature, and to include lines that could not be checked. The terminal names the outcome and the exit status.

`--replay-chain` takes keys from `--jwks` as well as `--key`. The key set, a URL or a file, is read once; each receipt's key is the one its `kid` names, and that key's `valid_from` / `valid_until` window is applied to the receipt's `issued_at`, as for a single file. A receipt whose `kid` the key set does not have is undecidable (`jwks_fetch_failed`, naming the `kid`), and a key set that cannot be read stops the replay before anything is verified (exit 2). `--key` takes precedence over `--jwks`. Before 0.10.26 replay ignored `--jwks` and failed every line with `no_public_key`. Each line's result carries `keyStatus` and `checks`.

Key windows read only RFC 3339 date-times that write their UTC offset out: `Z`, or `+hh:mm` / `-hh:mm`. Earlier releases read a time with `Date.parse`, which takes a time with no offset in the machine's own time zone, so `issued_at` `2026-05-31T23:30:00` against a window ending `2026-06-01T00:00:00Z` was inside it on a machine set to UTC and outside it on one set to New York. A time without an offset, a date alone, prose, or a day that does not exist (30 February) now makes the window undecidable (`key_window_unverifiable`, exit 2), and the detail names the value and the cause. A bound the key set writes as `null` is not a timestamp and cannot be applied; only a bound the key set leaves out leaves the window open on that side, and `keyStatus.window` now leaves such a bound out rather than writing it as `null`.

A key given with `--key` comes from no key source, so nothing gives it a window: `keyStatus.result` is `not_established` (it was `not_applicable`), and the terminal says the key's validity at issuance is not established. That is not a failure, and the exit status does not change. When no key is resolved at all, the result is `not_run`.

`--allow-payload-only-links` stays, for the chains the proxy and daemon of 0.9.3 and earlier wrote, but §6.7.1 of the -04 editor's copy (VeritasActa/drafts) says a verifier must not accept a payload-only link, so reading one is a compatibility mode, not conformance. Wherever a link was read that way (`--replay-chain`, `chain explore`, `--previous`), the JSON carries `conformant: false`, and the terminal summary and the warnings say the link was read under a compatibility mode, not conformant to draft §6.7. The exit status is as before.

### Chain links over the whole receipt (0.10.25)

Draft §6.7 defines `previousReceiptHash` as the SHA-256 of the JCS of the whole previous receipt, signature included, and -02 §5.7 defined the same preimage. No revision defines a link over the payload alone, which would give a re-signed receipt the same link as the original. `--replay-chain` and `verify chain explore` refuse such a link with `chain_break` (exit 1), whatever the previous receipt's `spec` says. The proxy and daemon of 0.9.3 and earlier wrote payload-only links. To read one of their chains, add `--allow-payload-only-links`:

```bash
verify --replay-chain receipts.jsonl --key PUBLIC_KEY --allow-payload-only-links
verify chain explore tip.json --allow-payload-only-links
```

Each link read that way is counted (`legacyLinks` in replay, `legacy_links` in explore) and named in the warnings. The flag changes nothing else: a link over the whole receipt is read as before, and any other mismatch is still a `chain_break`. `--strict` disables it, and since this release `--strict` applies to `--replay-chain` and `chain explore` as well as to a single file.

`--replay-chain` reads a file as one or more chains. A receipt after the first with no `previousReceiptHash`, or with a `null` one as 0.9.3 wrote on a first receipt, starts a new chain: draft §2.2 says such a receipt is a chain genesis or an unchained receipt, so it is neither checked against the receipt before it nor a break. The result counts the chains in `chains` and names each new start in `warnings`, beside the receipt verifier's own warnings. A `receipts.jsonl` the proxy appended to over several sessions holds one chain per session.

`--trust-anchor` was listed as a key source but never implemented: no key was read from the file, so a bundle or Gate record verified against the keys it carried. It is now refused (exit 2). Pin the key with `--key`, or with `--jwks` and a URL or a local JWKS file.

### Chain link syntax (0.10.22)

Draft §6.7 says `previousReceiptHash` is `sha256:` followed by 64 lowercase hex characters. Once a receipt's signature holds, a malformed link fails with `malformed_chain_link` (exit 1) and a prefix naming another algorithm with `unsupported_chain_hash_algorithm` (exit 2), whether or not the predecessor is supplied. The bare digest of earlier revisions is accepted on read, and a `null` link, which earlier tools wrote on a chain's first receipt, verifies with a warning. The result's `chainLink` names the form accepted.

### No signature member in the signing input (0.10.21)

Draft §6.6 says the object canonicalized for the signature never contains a `signature` member, not even as `null` or the empty string. An envelope receipt whose payload carries one fails with `signature_in_signing_input` (exit 1), even when the signature over those bytes verifies.

### Key validity windows (0.10.20)

When the JWKS gives the signing key a `valid_from` / `valid_until` window (draft §9.2), the verifier applies it to the receipt's `issued_at`. The window is `[valid_from, valid_until)`, so a receipt issued exactly at `valid_until` is outside it. A receipt outside the window fails with `key_outside_validity_window`. Every receipt result carries `keyStatus`: `inside`, `outside`, `no_window` (validity at issuance not established), `unverifiable`, or, from 0.10.26, `not_established` for a key pinned with `--key` (it was `not_applicable`) and `not_run` when no key was resolved. Add `--require-key-window` to fail when the key source gives no window:

```bash
npx @veritasacta/verify receipt.json --jwks ./jwks.json --require-key-window --json
```

`issued_at` is asserted by the signer, so a window catches a key still in use after an honest rotation, not a compromised key backdated into the window.

### Canonical JSON compatibility (0.10.15)

Receipt verification uses RFC 8785 key ordering, including numeric-looking keys. Historical receipts signed using JavaScript's numeric-key insertion order fail with `legacy_non_jcs_signature`. To inspect one intentionally, use `verify receipt.json --allow-legacy-canonicalization --key PUBLIC_KEY`. The result is labeled as a historical encoding; it does not claim JCS conformance. `--strict` always disables this compatibility mode. Metadata such as `holder_binding` is reported as declared until its underlying property is actually verified.


Code-work exports (`scopeblind.repository.coding-evidence.v1`) use the same command:

```sh
npx @veritasacta/verify@0.10.18 coding-work.json --key <service-ed25519-public-key> --json
```

The report checks the separate coding mandate, exact source feedback, recorded limits and worker's publication statement. A published PR is not a merge approval or recipient acceptance. Tests, build results and GitHub readbacks are attributed attestations; offline verification does not rerun code or fetch the preview. Project-device records additionally carry the principal's scoped grant and a service-signed authority check at recording time; this proves recorded history, not current device access.
