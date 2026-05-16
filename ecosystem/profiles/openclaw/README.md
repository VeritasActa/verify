# Profile: OpenClaw

Run [OpenClaw](https://github.com/openclaw-ai/openclaw) under sb-runtime + nono + signed receipts, **composing with OpenClaw's own guard-rail framework** rather than replacing it.

## Composition model

OpenClaw has in-process behavioural guards (prompt injection defense, PII detection, tool-use heuristics). This profile is designed to complement those:

- **OpenClaw guards** handle behavioural and content-level checks
- **sb-runtime + Cedar policy** handles structural checks (which file path, which command, which host)
- **nono** handles kernel-level enforcement (the final boundary)

Defense in depth: all three run. An exploit that bypasses OpenClaw's prompt-injection defense still has to clear the Cedar policy and the kernel sandbox.

## Network allowlist

Broader than claude-code because OpenClaw is model-agnostic: includes Anthropic, OpenAI, Google endpoints plus standard dev domains. Tighten per deployment.

## Quick start

```bash
npx @veritasacta/verify init --profile openclaw

# Or with explicit composition:
nono run --caps ./nono-capabilities.yaml -- \
    sb-runtime --ring 2 --policy ./policy.cedar -- openclaw
```

## Contributing updates

OpenClaw's API is evolving. If a profile update is needed as OpenClaw's tool-use conventions change, open a PR against this directory.
