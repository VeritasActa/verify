# Profile: Google Gemini CLI

> **Reference material:** This integration is not release-qualified by the core verifier CI.
> Commands, package versions and deployment claims below may be historical.
> Read the [current ecosystem status](../../README.md) before using it.


Run [Google Gemini CLI](https://github.com/google-gemini/gemini-cli) under sb-runtime + nono + signed receipts.

Baseline is similar to `claude-code` with Google-specific network endpoints (`googleapis.com`, `generativelanguage.googleapis.com`, `google.com`) instead of Anthropic's.

## Quick start

```bash
npx @veritasacta/verify init --profile gemini-cli

# Or standalone:
sb-runtime --ring 3 --profile ./profile.yaml -- gemini
```

## Network allowlist

- Google AI Studio: `generativelanguage.googleapis.com`, `*.googleapis.com`, `*.google.com`
- Standard developer domains: `api.github.com`, `githubusercontent.com`, `pypi.org`, `npmjs.org`

## Exec allowlist

Same dev tools as claude-code: `git`, `pytest`, `npm`, `node`, `python`, `go`, plus the safe inspection commands.

See [`claude-code/README.md`](../claude-code/README.md) for the full threat model and composition pattern.
