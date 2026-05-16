# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""scopeblind-swarms: Ed25519 signed decision receipts for Swarms agents.

Wraps any Python callable used as a Swarms tool with tamper-evident
receipt emission. Matches the receipt format specified by
draft-farley-acta-signed-receipts (Veritas Acta). Receipts verify
offline against @veritasacta/verify without Swarms or scopeblind-swarms
installed on the verifier side.

Typical usage:

    from swarms import Agent
    from scopeblind_swarms import ReceiptChain, sign_tool

    chain = ReceiptChain(signer_key_path="/etc/scopeblind/issuer.key",
                         agent_id="did:swarms:researcher-1")

    def web_search(query: str) -> str:
        ...

    signed_web_search = sign_tool(web_search, chain=chain, policy_id="allow-web-read")

    agent = Agent(
        agent_name="researcher",
        tools=[signed_web_search],
        ...,
    )

Every invocation of the wrapped tool produces a signed receipt. The
chain binds successive receipts via `previousReceiptHash` so tampering
is detectable across the whole session.
"""

from scopeblind_swarms.chain import ReceiptChain
from scopeblind_swarms.receipts import (
    Signer,
    receipt_hash,
    sign_receipt,
    verify_receipt,
)
from scopeblind_swarms.tools import SignedToolResult, sign_tool, sign_tools

__all__ = [
    "ReceiptChain",
    "SignedToolResult",
    "Signer",
    "receipt_hash",
    "sign_receipt",
    "sign_tool",
    "sign_tools",
    "verify_receipt",
]

__version__ = "0.1.0"
