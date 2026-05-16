# scopeblind-swarms

Ed25519 signed decision receipts for [kyegomez/swarms](https://github.com/kyegomez/swarms) multi-agent systems. Wrap any tool with tamper-evident, offline-verifiable receipts in the [Veritas Acta receipt format](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — the same format used by Microsoft Agent Governance Toolkit, protect-mcp, sb-runtime, hermes-decision-receipts, and Signet.

**MIT · Python · Runs alongside any Swarms agent · No fork of Swarms required**

## Why this exists

Swarms orchestrates agents that call real-world tools. When things go wrong, operators need cryptographic evidence of *which decisions were made by which agent under which policy*. `scopeblind-swarms` emits an Ed25519-signed, chain-linked receipt for every governed tool call. Receipts verify offline with `npx @veritasacta/verify` against a public key the operator publishes out-of-band.

No dependency on ScopeBlind infrastructure. No vendor lock-in. The receipt format is an open IETF Internet-Draft.

## Install

```bash
pip install scopeblind-swarms
# plus swarms itself:
pip install swarms
```

## Quick start

```python
from swarms import Agent
from scopeblind_swarms import ReceiptChain, sign_tool

# 1. Create a receipt chain. One per agent (or per session).
chain = ReceiptChain.from_key_file(
    signer_key_path="/etc/scopeblind/issuer.key",
    agent_id="did:swarms:researcher",
    policy_id="allow-web-read",
)

# 2. Define tools normally.
def web_search(query: str) -> str:
    # ... your search implementation
    return f"results for {query}"

# 3. Wrap tools with signed-receipt emission.
signed_search = sign_tool(web_search, chain=chain)

# 4. Use the wrapped tool in an Agent.
agent = Agent(
    agent_name="researcher",
    tools=[signed_search],
    model_name="gpt-4",
    # ... your other Agent config
)
agent.run("find recent papers on agent governance")

# Every tool invocation produced a signed receipt. Access the most
# recent one from the wrapped tool:
print(signed_search.last_receipt)

# Or iterate the chain:
print(f"Chain tip hash: {chain.current_tip}")
```

## Bulk wrapping

```python
from scopeblind_swarms import sign_tools

agent = Agent(
    agent_name="researcher",
    tools=sign_tools([web_search, summarize, post_draft], chain=chain),
    ...,
)
```

## Decorator form

```python
from scopeblind_swarms import ReceiptChain, sign_tool

chain = ReceiptChain.from_key_file("/etc/scopeblind/issuer.key", agent_id="did:swarms:writer")

@sign_tool(chain=chain, policy_id="allow-draft-only")
def post_draft(content: str) -> str:
    return f"drafted: {content[:50]}..."
```

## What's in a receipt

```json
{
  "payload": {
    "type": "scopeblind:swarms:tool-call",
    "agent_id": "did:swarms:researcher",
    "issuer_id": "swarms:agent:HJY4k2aN",
    "tool_name": "web_search",
    "action": "swarms:tool:web_search",
    "action_ref": "sha256:a8f3...c91e",
    "decision": "allow",
    "policy_id": "allow-web-read",
    "result_hash": "sha256:4b2c...d71f",
    "issued_at": "2026-04-19T15:42:01.773Z",
    "previousReceiptHash": "Zk4p..."
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "HJY4k2aNqRwXcdEfGh...",
    "sig": "..."
  }
}
```

Fields:

- `action_ref` — SHA-256 of the JCS-canonicalized tool arguments. Agents can cross-correlate the same tool invocation across engines.
- `result_hash` — SHA-256 of the tool return value. The receipt attests to what the tool returned without carrying raw output (privacy default).
- `previousReceiptHash` — SHA-256 of the prior receipt in this chain. Successive tool calls form a tamper-evident chain.
- `policy_id`, `policy_digest` — bound into every receipt so an auditor can confirm which policy the agent was operating under.

## Offline verification

Any receipt verifies with `@veritasacta/verify`, with no dependency on `scopeblind-swarms` or Swarms:

```bash
npx @veritasacta/verify receipt.json --key operator-public.pem
```

Exit code `0` is proven valid; exit `1` is proven tampering; exit `2` is undecidable (malformed, missing key).

Your operator public key is published out-of-band (JWKS URL, DID document service endpoint, pinned trust anchor, or GitHub-backed SBOM artifact). Never embedded in the receipt. Per draft-farley-acta-signed-receipts-02 §9.

## Design notes

- **Swarms extension point.** Swarms does not expose pre/post tool hooks; the canonical interception point is wrapping the tool callable before passing it to `Agent(tools=[...])`. `scopeblind-swarms` uses that extension point exactly; it does not patch Swarms' internals.
- **Thread safety.** A `ReceiptChain` is safe to share across parallel tool invocations within a single agent (async Swarms agents often run tools concurrently). Chain integrity is preserved via an internal lock.
- **No kernel sandboxing.** This adapter covers the receipts layer. For kernel-level agent isolation, compose with [`sb-runtime`](https://github.com/ScopeBlind/sb-runtime) (Landlock + seccomp) or [nono](https://github.com/always-further/nono).
- **No embedded keys.** `sign_receipt` and `verify_receipt` reject any payload carrying `verification_key`, `issuer_key`, or `signer_public_key`. Fail-closed posture matches the rest of the ecosystem after the April 2026 desiorac stress-test.

## Policy evaluation

`scopeblind-swarms` doesn't ship a Cedar evaluator. If you want Cedar policy enforcement, pair with one of:

- [`bindu-scopeblind`](https://github.com/ScopeBlind/bindu-scopeblind) — Python Cedar extension
- [`sb-runtime`](https://github.com/ScopeBlind/sb-runtime) — Rust binary with Cedar + sandbox + receipts
- Direct use of `cedarpy` in your `decision` computation before calling `sign_tool`

The `decision` field in every receipt accepts `"allow" | "deny" | "require_approval"`; you can vary it per call from your own policy evaluation logic.

## Related

- **Microsoft Agent Governance Toolkit** — [docs/integrations/sb-runtime.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/integrations/sb-runtime.md) (same receipt format)
- **Reference verifier** — [`@veritasacta/verify`](https://github.com/ScopeBlind/verify) (Apache-2.0, offline)
- **IETF draft** — [draft-farley-acta-signed-receipts-02](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- **Conformance profile** — [VeritasActa/agt-integration-profile](https://github.com/VeritasActa/agt-integration-profile)
- **Other framework adapters** — LangChain, CrewAI, OpenAI Agents SDK, Vercel AI SDK, Smolagents, Pydantic AI, AutoGen, LangGraph (all in the same ecosystem)

## License

MIT.
