# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""ReceiptChain: per-agent session receipt signer with chain linkage.

A Swarms agent typically makes many tool calls in a single run. A
ReceiptChain keeps the signer + agent identity + policy context stable
across those calls, tracking previous-receipt-hash internally so every
successive receipt chains to the prior one.

Instantiate once per agent (or once per session); pass to `sign_tool`
to wrap each tool with signed emission.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from scopeblind_swarms.receipts import (
    Signer,
    receipt_hash,
    sign_receipt,
)


@dataclass
class ReceiptChain:
    """Per-agent signing chain.

    Thread-safe for concurrent tool calls within the same agent
    (async Swarms agents call tools in parallel).
    """

    signer: Signer
    agent_id: str
    issuer_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_digest: Optional[str] = None
    session_id: Optional[str] = None

    _previous_hash: Optional[str] = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @classmethod
    def from_key_file(
        cls,
        signer_key_path: str | Path,
        agent_id: str,
        *,
        policy_id: Optional[str] = None,
        policy_digest: Optional[str] = None,
        session_id: Optional[str] = None,
        issuer_id: Optional[str] = None,
    ) -> "ReceiptChain":
        signer = Signer.from_pem_file(str(signer_key_path))
        return cls(
            signer=signer,
            agent_id=agent_id,
            issuer_id=issuer_id or f"swarms:agent:{signer.kid[:12]}",
            policy_id=policy_id,
            policy_digest=policy_digest,
            session_id=session_id,
        )

    @classmethod
    def generate(
        cls,
        agent_id: str,
        *,
        policy_id: Optional[str] = None,
        policy_digest: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> "ReceiptChain":
        """Convenience factory for tests / ephemeral deployments.

        Generates a fresh in-memory Ed25519 key. Not suitable for
        production (no key rotation, no persistence); use
        ``from_key_file`` with an operator-managed PEM for that.
        """
        signer = Signer.generate()
        return cls(
            signer=signer,
            agent_id=agent_id,
            issuer_id=f"swarms:agent:{signer.kid[:12]}",
            policy_id=policy_id,
            policy_digest=policy_digest,
            session_id=session_id,
        )

    def sign_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Mapping[str, Any],
        tool_result_hash: Optional[str] = None,
        decision: str = "allow",
        policy_id: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> dict:
        """Sign a receipt for a single tool invocation.

        Args are hashed (not carried raw) per AIP-0001 privacy defaults.
        The receipt payload records the tool name, args hash, optional
        result hash, policy digest, decision, and chain linkage.
        """
        args_canonical_hash = _hash_json(tool_args)

        payload: dict[str, Any] = {
            "type": "scopeblind:swarms:tool-call",
            "agent_id": self.agent_id,
            "issuer_id": self.issuer_id or self.agent_id,
            "tool_name": tool_name,
            "action": f"swarms:tool:{tool_name}",
            "action_ref": f"sha256:{args_canonical_hash}",
            "decision": decision,
        }
        if self.policy_id or policy_id:
            payload["policy_id"] = policy_id or self.policy_id
        if self.policy_digest:
            payload["policy_digest"] = self.policy_digest
        if self.session_id:
            payload["iteration_id"] = self.session_id
        if tool_result_hash:
            payload["result_hash"] = tool_result_hash
        if extra:
            payload.update(dict(extra))

        with self._lock:
            envelope = sign_receipt(
                payload=payload,
                signer=self.signer,
                previous_receipt_hash=self._previous_hash,
            )
            self._previous_hash = receipt_hash(envelope)

        return envelope

    def reset_chain(self) -> None:
        """Clear the previous-hash pointer.

        Call at session boundaries if you want a fresh chain. Does not
        affect the signing key.
        """
        with self._lock:
            self._previous_hash = None

    @property
    def current_tip(self) -> Optional[str]:
        """Hash of the most recent receipt, or None if chain empty."""
        return self._previous_hash


def _hash_json(obj: Mapping[str, Any]) -> str:
    """Deterministic SHA-256 of JCS-canonical JSON, hex-encoded."""
    import json as _json

    canonical = _json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
