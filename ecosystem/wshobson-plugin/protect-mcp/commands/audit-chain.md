---
description: Walk the receipt chain produced by the current session from tip to root, validating every previousReceiptHash link.
---

Walk the receipt chain for this protect-mcp session.

## What this command does

Finds the most recent receipt in `.protect-mcp/receipts/` and walks backward via `previousReceiptHash`, validating every link. Reports depth, links_broken, and any chain warnings.

## Implementation

```bash
# Find the most recent receipt by filename (receipts are zero-padded sequentially)
TIP=$(ls -t .protect-mcp/receipts/*.json 2>/dev/null | head -1)

if [ -z "$TIP" ]; then
    echo "No receipts found under .protect-mcp/receipts/"
    echo "Either no session has run, or protect-mcp isn't writing receipts."
    exit 2
fi

npx @veritasacta/verify chain explore "$TIP" --search-dir .protect-mcp/receipts
```

Output is an ASCII tree: tip first, root last, each link annotated with status. A broken link shows `✗` next to the hash.

## Interpreting results

- **`valid=true, links_broken=0`** — entire chain verifies. No tamper detected.
- **`links_broken > 0`** — a receipt was modified, deleted, or inserted. The warning text identifies the failure point.
- **`Chain ends at receipt[N]: previousReceiptHash ... not found in searchDir`** — the chain is incomplete. Either the root was reached (if `previousReceiptHash` is absent) or an ancestor file is missing.

For compliance-grade output (HTML report, self-contained, auditor-ready), use:

```bash
npx @veritasacta/verify --replay-chain .protect-mcp/receipts.jsonl \
    --audit-report --output audit.html
```

## When to run

- At session end — confirm no receipts were tampered with during the run.
- Before shipping an audit bundle — proves chain integrity.
- After a suspicious tool call — verify the chain wasn't rewritten to hide the event.
