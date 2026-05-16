# Profile: Cursor

Run [Cursor](https://www.cursor.com) under sb-runtime + nono + signed receipts.

Baseline is identical to [`claude-code`](../claude-code/) with a tighter network allowlist scoped to Cursor's own backends plus standard developer domains. Use this profile when Cursor's Composer mode, agent tabs, or MCP bridge is active.

## Quick start

```bash
npx @veritasacta/verify init --profile cursor
```

Or compose with nono directly (Linux, recommended for production):

```bash
nono run --caps ./nono-capabilities.yaml -- \
    sb-runtime --ring 2 --policy ./policy.cedar -- cursor
```

## What's different from claude-code

- **Network**: adds `*.cursor.com` and `*.cursor.sh` to the HTTPS allowlist (Cursor's LLM proxy and telemetry endpoints)
- **MCP extension**: if you wire third-party MCP servers through Cursor, extend the network allowlist per server. Each MCP server hostname should be explicit.

Otherwise: same reads, writes, exec allowlist, and denies as `claude-code`.

## Receipt format

Same as claude-code. Receipts land at `.veritasacta/receipts/cursor/` and verify with `npx @veritasacta/verify`.

See [`claude-code/README.md`](../claude-code/README.md) for the full threat model and composition pattern.
