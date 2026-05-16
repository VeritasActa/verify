# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""Ed25519 signing + JCS canonical JSON for Swarms signed receipts.

Byte-compatible with the unified @veritasacta/verify@0.5.0 CLI and
with the AGT sb-runtime-skill provider shim. Tokens signed here verify
with `npx @veritasacta/verify receipt.json --key <pubkey>` with no
runtime dependency on this package or on Swarms.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


EMBEDDED_KEY_FIELDS = ("verification_key", "issuer_key", "signer_public_key")


class EmbeddedKeyRejection(ValueError):
    """Raised when a receipt payload carries its own verification key.

    Per draft-farley-acta-signed-receipts-02 Section 9, a verification
    key transported inside the signed payload does not provide
    authenticity against tampering. This adapter rejects such payloads
    at sign and verify time, matching the fail-closed posture of
    @veritasacta/verify@0.4.0+ and the rest of the ecosystem.
    """


def _assert_ascii_keys(obj: Any, path: str = "$") -> None:
    if isinstance(obj, Mapping):
        for key in obj.keys():
            if not isinstance(key, str):
                raise ValueError(f"Non-string key at {path}: {key!r}")
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    f"Non-ASCII key at {path}.{key!r} violates AIP-0001"
                ) from exc
            _assert_ascii_keys(obj[key], f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _assert_ascii_keys(item, f"{path}[{i}]")


def _canonicalize(obj: Any) -> bytes:
    _assert_ascii_keys(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s = s + ("=" * pad)
    return base64.urlsafe_b64decode(s)


def _jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64url(raw)}
    digest = hashlib.sha256(_canonicalize(jwk)).digest()
    return _b64url(digest)


def _check_no_embedded_key(payload: Mapping[str, Any]) -> None:
    for field in EMBEDDED_KEY_FIELDS:
        if field in payload:
            raise EmbeddedKeyRejection(
                f"Receipt payload carries embedded key field '{field}'. "
                "See draft-farley-acta-signed-receipts-02 \u00a79."
            )


@dataclass
class Signer:
    """Ed25519 signing key wrapper."""

    private_key: Ed25519PrivateKey
    kid: str

    @classmethod
    def generate(cls, kid: Optional[str] = None) -> "Signer":
        pk = Ed25519PrivateKey.generate()
        return cls(
            private_key=pk,
            kid=kid or _jwk_thumbprint(pk.public_key()),
        )

    @classmethod
    def from_pem_file(cls, path: str, kid: Optional[str] = None) -> "Signer":
        with open(path, "rb") as f:
            pem = f.read()
        pk = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(pk, Ed25519PrivateKey):
            raise ValueError("PEM must contain an Ed25519 private key")
        return cls(
            private_key=pk,
            kid=kid or _jwk_thumbprint(pk.public_key()),
        )

    @classmethod
    def from_pem(cls, pem: bytes, kid: Optional[str] = None) -> "Signer":
        pk = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(pk, Ed25519PrivateKey):
            raise ValueError("PEM must contain an Ed25519 private key")
        return cls(
            private_key=pk,
            kid=kid or _jwk_thumbprint(pk.public_key()),
        )

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def sign_receipt(
    payload: Mapping[str, Any],
    signer: Signer,
    previous_receipt_hash: Optional[str] = None,
) -> dict:
    _check_no_embedded_key(payload)

    final_payload = dict(payload)
    final_payload.setdefault(
        "issued_at",
        datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    if previous_receipt_hash is not None:
        final_payload["previousReceiptHash"] = previous_receipt_hash

    canonical = _canonicalize(final_payload)
    signature = signer.private_key.sign(canonical)

    return {
        "payload": final_payload,
        "signature": {
            "alg": "EdDSA",
            "kid": signer.kid,
            "sig": _b64url(signature),
        },
    }


def verify_receipt(envelope: Mapping[str, Any], public_key: Ed25519PublicKey) -> bool:
    if not isinstance(envelope, Mapping):
        raise ValueError("Envelope must be a mapping")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if payload is None or signature is None:
        raise ValueError("Envelope must contain payload and signature")

    _check_no_embedded_key(payload)

    if signature.get("alg") != "EdDSA":
        return False
    sig_b64 = signature.get("sig")
    if not isinstance(sig_b64, str):
        return False

    canonical = _canonicalize(payload)
    try:
        public_key.verify(_b64url_decode(sig_b64), canonical)
    except InvalidSignature:
        return False
    return True


def receipt_hash(envelope: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonicalize(envelope)).digest()
    return _b64url(digest)
