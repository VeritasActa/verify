# Pre-built sandbox profiles

Drop-in Cedar policies + nono capability manifests for common AI coding assistants and agent CLIs. Each profile is designed so the tool **just works under sb-runtime + nono + signed receipts** without requiring the operator to author a policy from scratch.

## Available profiles

| Profile | Target tool | Policy shape |
|---|---|---|
| [`claude-code/`](./claude-code/) | [Anthropic Claude Code](https://www.claude.com/product/claude-code) | Allow read-only source inspection + scoped git/tests; deny network to metadata endpoints, deny writes to system paths |
| [`cursor/`](./cursor/) | [Cursor](https://www.cursor.com/) | Same baseline as claude-code + additional allow for Cursor's MCP bridge |
| [`codex/`](./codex/) | [OpenAI Codex CLI](https://github.com/openai/codex) | Stricter default deny, explicit allow per exec |
| [`gemini-cli/`](./gemini-cli/) | [Google Gemini CLI](https://github.com/google-gemini/gemini-cli) | Read-only review mode + scoped shell |
| [`openclaw/`](./openclaw/) | [OpenClaw](https://github.com/openclaw-ai/openclaw) | OpenClaw-aligned conventions; composes with their existing guard rails |

## Each profile contains

```
<profile>/
├── profile.yaml         # metadata: tool, version, recommended sb-runtime ring, nono capability refs
├── policy.cedar         # Cedar policy (consumable by sb-runtime, bindu-scopeblind, cedar-for-agents)
├── nono-capabilities.yaml  # nono capability set (if composing with nono for kernel sandbox)
└── README.md            # how to use + what it allows / denies
```

## Usage

### Option A: via `verify init`

```bash
cd my-project
npx @veritasacta/verify init --profile claude-code
```

Auto-installs the profile, generates keys, writes `.veritasacta/config.json`.

### Option B: via sb-runtime directly

```bash
sb-runtime run --profile claude-code --ring 3 -- claude
```

### Option C: copy manually

Copy `policy.cedar` into your Cedar policy directory. The file is pure Cedar and works with any compliant evaluator.

## Why profiles?

A Cedar policy written from scratch for `claude-code` takes a new operator ~1-2 hours of trial and error (allow this syscall, deny that path, figure out what Claude Code actually does under the hood). Profiles compress that to one command.

The profiles are maintained by the ScopeBlind ecosystem team based on real deployment experience. Each profile is explicit about what it allows / denies; there are no hidden escape hatches, and every change is reviewed.

## Contributing a profile

Adding a new tool is a small PR:

1. `<tool>/profile.yaml` with metadata
2. `<tool>/policy.cedar` with the policy
3. `<tool>/README.md` explaining the threat model and design decisions
4. Optional: `<tool>/nono-capabilities.yaml` for kernel-sandbox composition

All profiles live in `packages/verify-cli/ecosystem/profiles/` and are Apache-2.0.

## License

Apache-2.0. Each profile is usable in any context without restriction; the Veritas Acta receipt format is the interoperable artifact.
