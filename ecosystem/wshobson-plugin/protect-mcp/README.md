# protect-mcp — Cedar policy + signed receipts for Claude Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Every Claude Code tool call is evaluated against a Cedar policy, then signed as an Ed25519 receipt.** Offline-verifiable. Tamper-evident. No vendor lock-in.

This is the first Claude Code plugin that enforces policies *cryptographically* — not just via hooks. An attacker who bypasses the hook surface still cannot forge the receipt, because forgery requires the Ed25519 signing key.

Closes [wshobson/agents#471](https://github.com/wshobson/agents/issues/471).

## Install

```
/plugin install protect-mcp
```

Then:

```bash
npx protect-mcp init
```

That single command:
- Generates an Ed25519 signing key at `.protect-mcp/signer.json`
- Writes a default Cedar policy at `.protect-mcp/policy.cedar`
- Wires `PreToolUse` + `PostToolUse` hooks via `hooks/hooks.json`
- Stores receipts at `.protect-mcp/receipts/NNNN-*.json`

## What it does

| Hook | Action |
|---|---|
| `PreToolUse` | Evaluate Cedar policy against `(tool, args, context)`. Allow or deny. |
| `PostToolUse` | Sign an Ed25519 receipt for the decision. Chain-link via `previousReceiptHash`. |

Receipts are written as they're signed. Every one verifies offline with `@veritasacta/verify`.

## Verify

Inside Claude Code:

```
/verify-receipt .protect-mcp/receipts/0042.json
/audit-chain
```

Or from your terminal:

```bash
npx @veritasacta/verify .protect-mcp/receipts/*.json --key $(cat .protect-mcp/signer.json | jq -r .public_key)
```

Tampering with any receipt fails the chain. Guaranteed by SHA-256 + JCS + Ed25519.

## Policy: default behavior

The default Cedar policy allows non-destructive tools (Read, Grep, Glob, WebFetch, WebSearch) and gates writes behind path scoping:

```cedar
permit(
    principal == Agent::"claude-code",
    action in [Action::"Read", Action::"Grep", Action::"Glob"],
    resource
);

permit(
    principal == Agent::"claude-code",
    action == Action::"Write",
    resource
) when {
    resource.path like "./src/*" || resource.path like "./tests/*"
};

forbid(
    principal,
    action == Action::"Bash",
    resource
) when {
    resource.command like "rm -rf *" ||
    resource.command like "sudo *"  ||
    resource.command like "*curl * | sh"
};
```

Customize `.protect-mcp/policy.cedar` to your environment. The `policy-enforcer` agent (included) can translate natural-language rules into Cedar.

## Cryptographic governance

Every tool call produces a signed artifact in this shape:

```json
{
  "payload": {
    "type": "decision-receipt",
    "action": "Write",
    "tool_name": "Write",
    "agent_id": "claude-code",
    "issuer_id": "protect-mcp:v0.1",
    "issued_at": "2026-04-20T...",
    "previousReceiptHash": "...",
    "decision": "allow",
    "args_commitment": "sha256:..."
  },
  "signature": { "alg": "EdDSA", "kid": "protect-mcp:local", "sig": "..." }
}
```

- **Ed25519** (RFC 8032) — tamper-evident.
- **JCS** (RFC 8785) — canonical JSON, reproducible hashes.
- **Chain linkage** — each receipt references the previous, forming an append-only DAG.
- **Offline verify** — no phone-home, no server, no API key.

## Relationship to the broader ecosystem

This plugin is the Claude Code surface for a broader governance stack:

- **Protocol:** [veritasacta.com](https://veritasacta.com) — IETF drafts, open AIP specs (Apache-2.0).
- **Verifier:** [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify) — offline CLI (Apache-2.0).
- **Managed issuance (optional):** [scopeblind.com](https://scopeblind.com) — VOPRF anonymous credentials, chain pinning, SIEM export.

The plugin works standalone. Adding managed issuance is optional.

## Agents & commands included

| Kind | Name | Purpose |
|---|---|---|
| Agent | `policy-enforcer` | Translates natural-language rules into Cedar policies for Claude Code tools |
| Agent | `receipt-verifier` | Walks receipt chains, detects tampering, explains Ed25519 + JCS |
| Skill | `protect-mcp-setup` | Step-by-step setup and verification guide |
| Command | `/verify-receipt <path>` | Runs `@veritasacta/verify` on a receipt |
| Command | `/audit-chain` | Walks the receipt chain from the most recent tip |

## Dependencies

Runtime: Node.js ≥ 18. `protect-mcp` and `@veritasacta/verify` install automatically as npm packages.

No network access required at runtime. Receipts verify fully offline.

## License

MIT. See [LICENSE](https://github.com/wshobson/agents/blob/main/LICENSE).

Parts of this plugin's verifier dependency (`@veritasacta/verify`) are Apache-2.0; patent-adjacent packages carry the Apache-2.0 patent grant.
