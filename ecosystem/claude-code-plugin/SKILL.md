---
name: Veritas Acta Verify
description: Signs every Claude Code tool call with an offline-verifiable Ed25519 receipt. Lets you audit exactly what Claude did and when, without trusting any server.
---

# Veritas Acta Verify

This plugin attaches to Claude Code's PreToolUse and PostToolUse hooks
and signs a Veritas Acta decision receipt for every tool call.

## When to use this

- You're building an agent that needs a cryptographic audit trail.
- You need compliance evidence (SOC 2, EU AI Act, ISO 27001).
- You want to prove what Claude did without trusting Anthropic's logs.
- You're deploying Claude Code in a regulated industry.

## Configure

After installing the plugin, run:

```
npx @veritasacta/verify init
```

This creates `.veritasacta/` with signing keys and a config. The
plugin then automatically signs every tool call.

## Verify

```
/verify-receipt path-to-receipt.json
```

Or via the CLI:

```
npx @veritasacta/verify .veritasacta/receipts/*.json --key <pubkey>
```

## Commands

- `/verify-receipt <path>` — verify a specific receipt file
- `/verify-chain` — verify the entire session chain
- `/veritasacta-sigil` — show the Sigil of the installed verifier
