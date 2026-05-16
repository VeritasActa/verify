# Veritas Acta Ecosystem — Shipped and Planned Artifacts

Beyond the verifier CLI itself, the `@veritasacta/verify` ecosystem
includes adoption and distribution artifacts. This directory contains
scaffolds, specs, and plans for each.

## Shipped in v0.5.0

| Artifact | Location | Description |
|---|---|---|
| CLI verifier | `packages/verify-cli/` | Unified offline verifier with `init` / `proxy` / `daemon` subcommands |
| GitHub Action | `ecosystem/github-action/` | Drop-in verification step for any repo |
| Claude Code plugin | `ecosystem/claude-code-plugin/` | One-click Claude Code install |
| Homebrew formula | `ecosystem/homebrew-tap/` | `brew install veritasacta-verify` |
| JS SDK | `ecosystem/sdk-js/` | `@veritasacta/sdk` tiny signing helper |
| Python SDK | `ecosystem/sdk-py/` | `veritasacta-sdk` Python signing helper |
| LangChain adapter | `ecosystem/adapters/langchain/` | Reference adapter (full implementation) |
| 7 other framework adapters | `ecosystem/adapters/*/` | LangGraph, CrewAI, OpenAI Agents, Vercel AI, Smolagents, Pydantic AI, AutoGen |
| Sigil naming doc | `ecosystem/SIGIL-NAMING.md` + `ecosystem/RELEASE-NAMING.md` | Public brand convention |

## Scaffolded, deployment pending

| Artifact | Location | Purpose | Blocker |
|---|---|---|---|
| Implementations registry | `ecosystem/registry-worker/` | `registry.veritasacta.com` mirror | Cloudflare Worker deployment |
| Badge service | `ecosystem/badge-worker/` | `verify.veritasacta.com/badge/*` SVG badges | Cloudflare Worker deployment |
| Interop leaderboard | `ecosystem/interop-leaderboard/` | Weekly cross-implementation CI | Workflow placement in registry repo |

## Planned for v0.6.0 / v0.7.0 (design docs in place)

| Artifact | Location | Notes |
|---|---|---|
| VS Code extension | `ecosystem/vscode-extension/` | Receipt editor support |
| Cosign / Sigstore compat | `ecosystem/cosign-compat/DESIGN.md` | DSSE wrap + Rekor anchor (v0.6.0) |
| Filesystem rollback | `ecosystem/rollback/DESIGN.md` | Content-addressed snapshots (nono-style) |
| Runtime supervisor | `ecosystem/supervisor/DESIGN.md` | Dynamic permission expansion with approval |
| Issuer reputation | `ecosystem/reputation/DESIGN.md` | Bayesian reputation over receipt issuers |
| Audit dashboard GUI | `ecosystem/dashboard/DESIGN.md` | Web dashboard (Signet-style) |
| Browser extension | `ecosystem/browser-extension/DESIGN.md` | Claude.ai / ChatGPT injection |
| eBPF OS observer | `ecosystem/ebpf-observer/DESIGN.md` | Kernel-level auto-instrumentation |
| Conformance certification | `ecosystem/CONFORMANCE-CERTIFICATION.md` | Commercial tier |

## Deployment order (after v0.5.0 npm publish)

1. GitHub Action released as `VeritasActa/verify-action@v1`
2. Registry worker deployed at `registry.veritasacta.com`
3. Badge worker deployed at `verify.veritasacta.com`
4. Interop leaderboard workflow committed to `VeritasActa/agt-integration-profile`
5. README updates propagated across implementation repos (sb-runtime,
   protect-mcp, protect-mcp-adk) to embed badges
6. VS Code extension shipped (v0.5.1)
7. Cosign compatibility landed (v0.6.0)
8. Certification service pilot launched (Q3 2026)

Each numbered step is independent; they can happen in any order as
bandwidth allows.
