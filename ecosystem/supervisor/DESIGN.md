# Runtime Supervisor with Approval Workflows (v0.6.0 target)

Dynamic permission expansion with human-in-the-loop approval. Complements
sb-runtime's static sandbox with live approval flows for operations that
fall outside the initial allowlist.

## Goal

Agents need dynamic, just-in-time permissions for legitimate long-tail
operations without broadening the static sandbox. Supervisor wraps the
agent with an approval channel that a human (or a higher-authority agent)
can use to grant or deny out-of-sandbox requests.

## Design

### Supervisor daemon

```
veritasacta supervisor --policy base.cedar --approval-channel slack://...
```

- Intercepts deny events from sb-runtime / protect-mcp
- Routes them through an approval channel (Slack, PagerDuty, CLI tty)
- On approval, widens the sandbox for a scoped duration
- Emits signed receipts for both the original deny AND the approval

### Approval receipt format

```json
{
  "payload": {
    "type": "veritasacta:supervisor:approval",
    "subject_action": { "tool": "...", "args_hash": "..." },
    "original_decision": "deny",
    "approved_decision": "allow",
    "approver": "did:web:jane.acme.example",
    "approval_scope": { "duration_seconds": 300, "tool_pattern": "curl:github.com/*" },
    "issued_at": "..."
  },
  "signature": { "alg": "EdDSA", "kid": "...", "sig": "..." }
}
```

### Composition with Veritas Acta receipts

The approval receipt is chained into the session's receipt stream. An
auditor walking the chain sees: denial → approval → allow. The agent
never runs an action without cryptographic evidence of authorization.

## License

Apache-2.0 once shipped.
