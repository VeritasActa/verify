---
description: Verify a single Ed25519 signed receipt produced by protect-mcp. Runs @veritasacta/verify offline against the file and reports exit code semantics.
argument-hint: "<path>"
---

Verify a Claude Code receipt produced by protect-mcp.

## What this command does

Runs `npx @veritasacta/verify <path> --key <pubkey>` against the file path in $ARGUMENTS. Reports:

- **exit 0** — valid: signature + JCS canonicalization + chain linkage all check out
- **exit 1** — invalid: proven tampering somewhere (signature or chain)
- **exit 2** — undecidable: malformed JSON, missing key, unsupported algorithm

## Implementation

Run the verification:

```bash
PUBKEY=$(cat .protect-mcp/signer.json 2>/dev/null | jq -r .public_key)

if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "null" ]; then
    echo "No .protect-mcp/signer.json found. Run \`npx protect-mcp init\` first."
    exit 2
fi

npx @veritasacta/verify "$ARGUMENTS" --key "$PUBKEY"
```

If the user wants JSON output (for piping or scripting), the `--json` flag produces machine-readable results.

## Interpreting results

| Exit | Meaning | What to tell the user |
|---|---|---|
| 0 | Valid | "Receipt verifies. Signature OK. Payload has not been modified." |
| 1 | Invalid | "Receipt does NOT verify. Someone modified this file after it was signed. This is a proven tamper." |
| 2 | Undecidable | Explain *which* of: malformed JSON, missing key, unsupported algorithm |

For tamper cases, suggest the `/audit-chain` command to find where in the session the tamper occurred.
