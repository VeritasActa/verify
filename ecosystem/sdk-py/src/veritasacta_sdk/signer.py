"""veritasacta_sdk.signer — Ed25519 + JCS receipt signing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from nacl.signing import SigningKey


def _canonicalize(obj: Any) -> str:
    """JCS-like canonical serialization (sorted keys, no whitespace)."""
    def sort_deep(o):
        if isinstance(o, dict):
            return {k: sort_deep(o[k]) for k in sorted(o)}
        if isinstance(o, list):
            return [sort_deep(v) for v in o]
        return o
    return json.dumps(sort_deep(obj), separators=(",", ":"), ensure_ascii=False)


@dataclass
class Receipt:
    """An Ed25519-signed decision receipt."""
    payload: dict[str, Any]
    signature: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class Signer:
    """Sign draft-farley-acta-signed-receipts-03 decision receipts."""

    def __init__(self, signing_key: SigningKey, kid: str, issuer_id: Optional[str] = None):
        self._signing_key = signing_key
        self.kid = kid
        self.issuer_id = issuer_id or kid
        self.pub_hex = signing_key.verify_key.encode().hex()
        self.sequence = 0
        self.previous_receipt_hash: Optional[str] = None

    @classmethod
    def from_key_file(cls, path: str) -> "Signer":
        """Load a signer from a key file (produced by `veritasacta init`)."""
        data = json.loads(Path(path).read_text())
        priv_bytes = bytes.fromhex(data["privateDer"])
        # PKCS#8 wrapper: last 32 bytes are the raw private key
        raw = priv_bytes[-32:] if len(priv_bytes) >= 32 else priv_bytes
        return cls(SigningKey(raw), kid=data["kid"])

    @classmethod
    def generate(cls, kid_prefix: str = "sdk") -> "Signer":
        """Generate a new signing key (for tests / demos)."""
        key = SigningKey.generate()
        pub_hex = key.verify_key.encode().hex()
        kid = f"{kid_prefix}:{pub_hex[:12]}"
        return cls(key, kid)

    def sign_decision(
        self,
        tool: str,
        args: Optional[dict[str, Any]] = None,
        decision: str = "allow",
        policy_id: Optional[str] = None,
        policy_hash: Optional[str] = None,
        skill_version_hash: Optional[str] = None,
        delegation_chain_root: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Receipt:
        """Sign a single tool-call decision."""
        self.sequence += 1
        arg_str = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        tool_input_hash = "sha256:" + hashlib.sha256(arg_str.encode("utf-8")).hexdigest()

        payload: dict[str, Any] = {
            "type": "veritasacta:decision",
            "spec": "draft-farley-acta-signed-receipts-03",
            "tool_name": tool,
            "tool_input_hash": tool_input_hash,
            "decision": decision,
            "issued_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "issuer_id": self.issuer_id,
            "sequence": self.sequence,
            "previousReceiptHash": self.previous_receipt_hash,
        }
        if policy_id:
            payload["policy_id"] = policy_id
        if policy_hash:
            payload["policy_hash"] = policy_hash
        if skill_version_hash:
            payload["skill_version_hash"] = skill_version_hash
        if delegation_chain_root:
            payload["delegation_chain_root"] = delegation_chain_root
        if metadata:
            payload["metadata"] = metadata

        canonical = _canonicalize(payload)
        sig = self._signing_key.sign(canonical.encode("utf-8")).signature

        # Chain linkage
        self.previous_receipt_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return Receipt(
            payload=payload,
            signature={"alg": "EdDSA", "kid": self.kid, "sig": sig.hex()},
        )
