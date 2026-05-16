# wshobson/agents — `protect-mcp` plugin (PR-staging)

PR-ready tree for submitting `protect-mcp` to [wshobson/agents](https://github.com/wshobson/agents), a 33K-star community Claude Code plugin marketplace.

Directly addresses open issue [#471](https://github.com/wshobson/agents/issues/471).

## Structure

```
protect-mcp/
├── .claude-plugin/plugin.json
├── README.md
├── skills/protect-mcp-setup/SKILL.md
├── agents/policy-enforcer.md
├── agents/receipt-verifier.md
├── commands/verify-receipt.md
├── commands/audit-chain.md
└── hooks/hooks.json
```

## Submission steps

1. Fork [wshobson/agents](https://github.com/wshobson/agents)
2. Copy this tree under `plugins/protect-mcp/` in the fork
3. Add the marketplace entry (see below)
4. Open PR titled: `Add protect-mcp plugin (closes #471)`
5. PR body quotes issue #471's request and points to the included skills/agents/commands.

## Marketplace entry (to add under `.claude-plugin/marketplace.json`)

```json
{
  "name": "protect-mcp",
  "source": "./plugins/protect-mcp",
  "description": "Cedar policy enforcement + Ed25519 signed receipts for Claude Code tool calls. First cryptographic-governance plugin.",
  "version": "0.1.0",
  "author": { "name": "Tom Farley", "email": "tommy@scopeblind.com" },
  "homepage": "https://scopeblind.com",
  "license": "MIT",
  "category": "security"
}
```

## Suggested PR body

> Closes #471.
>
> Adds the `protect-mcp` plugin — first Claude Code plugin that enforces policies **cryptographically**, not just via hooks. Every tool call is:
>
> 1. Evaluated against a Cedar policy at `PreToolUse`
> 2. Signed as an Ed25519 receipt at `PostToolUse`
> 3. Chain-linked via `previousReceiptHash`
> 4. Verifiable offline with `@veritasacta/verify`
>
> **Why this design.** Hook-only approaches can be bypassed (disable the hook, tool call runs unenforced). Signing the decision makes the receipt tamper-evident — an attacker who disables the hook still cannot forge evidence that a denied action was allowed.
>
> **What ships:**
> - 1 skill — `protect-mcp-setup` (step-by-step setup)
> - 2 agents — `policy-enforcer` (Cedar authoring), `receipt-verifier` (chain audit)
> - 2 commands — `/verify-receipt`, `/audit-chain`
> - hooks.json wiring PreToolUse + PostToolUse
>
> **Dependencies:** `protect-mcp` (MIT) + `@veritasacta/verify` (Apache-2.0). Both on npm. No network at runtime.
>
> **Reviewer checklist:**
> - [ ] `claude plugin install wshobson/agents/protect-mcp` installs successfully
> - [ ] Receipt files appear in `.protect-mcp/receipts/` after a tool call
> - [ ] `npx @veritasacta/verify .protect-mcp/receipts/*.json` exits 0
> - [ ] Tampering with a receipt causes exit 1
>
> Thanks @<issue-author> for opening #471 — this PR directly implements the structure you requested.

## Strategic context

- **wshobson/agents has 33.6K stars** — huge discovery surface for Claude Code users.
- **Pioneers `governance` category** in a marketplace that currently has `security` but no cryptographic-governance entries.
- **Every install exercises `@veritasacta/verify`** — adoption multiplier for the verifier.
