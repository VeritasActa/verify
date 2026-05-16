---
name: protect-mcp-setup
description: Set up Cedar policy enforcement and Ed25519 signed receipts for every Claude Code tool call. Use when adopting protect-mcp for the first time, when configuring a new policy, or when auditing a session.
---

# protect-mcp setup

Sign every Claude Code tool call with an offline-verifiable Ed25519 receipt, gated by a Cedar policy.

## When to use this skill

- First-time setup of cryptographic governance in a Claude Code project
- Configuring a Cedar policy for specific tool/path combinations
- Verifying the receipts produced during a session
- Auditing a session's receipt chain for tampering

## Step 1: Install and initialize

```bash
npm install -g protect-mcp @veritasacta/verify
npx protect-mcp init
```

What `init` does:

1. Generates an Ed25519 keypair at `.protect-mcp/signer.json`
2. Writes a default policy at `.protect-mcp/policy.cedar`
3. Creates `.protect-mcp/receipts/` for receipt storage
4. Installs `hooks/hooks.json` — PreToolUse + PostToolUse triggers

## Step 2: Review the default policy

Open `.protect-mcp/policy.cedar`. The default allows reads + grep/glob, permits writes under `./src/` and `./tests/`, and forbids destructive bash. Edit to suit.

The `policy-enforcer` agent (shipped with the plugin) can translate rules from plain English — "never allow curl piped to sh" — into Cedar.

## Step 3: Run a session

Any Claude Code session that uses tools will now:

- Evaluate the Cedar policy at `PreToolUse` — deny decisions surface in the transcript
- Sign a receipt at `PostToolUse` — written to `.protect-mcp/receipts/NNNN-tool.json`

Receipts chain via `previousReceiptHash`. The chain is append-only. Any tamper breaks the chain under offline verification.

## Step 4: Verify

Use the plugin's built-in commands:

- `/verify-receipt <path>` — verify a single receipt
- `/audit-chain` — walk the chain from the most recent tip

Or from the shell:

```bash
npx @veritasacta/verify .protect-mcp/receipts/*.json \
    --key $(cat .protect-mcp/signer.json | jq -r .public_key)
```

Exit 0 means every receipt verified. Exit 1 means tampering. Exit 2 means malformed or undecidable.

For a compliance-grade report:

```bash
npx @veritasacta/verify --replay-chain .protect-mcp/receipts.jsonl \
    --audit-report --output audit.html
```

## Step 5: (optional) Pin the verifier

Supply chain: make sure the verifier you run is the canonical one.

```bash
npx @veritasacta/verify --self-check
```

Every verify invocation accepts `--pin-sigil <fingerprint>` to refuse to run unless the installed verifier matches a specific Sigil.

## Troubleshooting

**Receipts aren't appearing.** Check that `hooks/hooks.json` was registered — `claude config list | grep hooks` should show PreToolUse and PostToolUse entries for protect-mcp.

**"cedar_policy_denied" on unexpected tools.** Run `/policy-enforcer` to propose a narrower Cedar rule, or edit `.protect-mcp/policy.cedar` directly.

**Verification fails with `hash_mismatch`.** Someone modified a receipt. The chain is tamper-evident — this is working as designed.

**Verification fails with `unknown_algorithm`.** You're using a verifier older than v0.5.0. Upgrade: `npm i -g @veritasacta/verify@latest`.

## Related

- Cedar docs: https://www.cedarpolicy.com/
- `@veritasacta/verify`: https://www.npmjs.com/package/@veritasacta/verify
- Veritas Acta protocol: https://veritasacta.com
- IETF drafts: draft-farley-acta-signed-receipts
