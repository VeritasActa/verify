# Veritas Acta Verify — Claude Code Plugin

One-click installation of the Veritas Acta receipt-signing pipeline for Claude Code. Every tool call produces a cryptographic receipt you can verify offline.

## Install

From the Claude Code plugin marketplace:

```
/plugin install veritasacta-verify
```

Or manually:

```bash
npx @veritasacta/verify init
```

Both paths do the same thing: generate a signing key, wire up PreToolUse / PostToolUse hooks, and configure receipt storage.

## What you get

1. **Every tool call signs a receipt.** Stored at `.veritasacta/receipts/`.
2. **PreToolUse policy check.** Cedar policy gates run before the tool fires.
3. **Chain linkage.** Receipts form a tamper-evident chain via `previousReceiptHash`.
4. **Self-check.** `verify --self-check` proves the installed verifier is canonical.
5. **One-line audit.** `npx @veritasacta/verify .veritasacta/receipts/*.json` verifies everything.

## Verify a session

```bash
npx @veritasacta/verify .veritasacta/receipts/*.json --key $(cat .veritasacta/config.json | jq -r .signer.pubkey)
```

Or export an HTML audit report:

```bash
npx @veritasacta/verify --replay-chain .veritasacta/receipts.jsonl --audit-report --output audit.html
```

## License

Apache-2.0
