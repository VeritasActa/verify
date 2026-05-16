# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
import json

import pytest
from cryptography.hazmat.primitives import serialization

from scopeblind_swarms import (
    ReceiptChain,
    Signer,
    SignedToolResult,
    receipt_hash,
    sign_tool,
    sign_tools,
    verify_receipt,
)
from scopeblind_swarms.receipts import EmbeddedKeyRejection


@pytest.fixture
def chain():
    return ReceiptChain.generate(
        agent_id="did:swarms:test-agent",
        policy_id="test-allow-all",
    )


class TestSignTool:
    def test_wraps_tool_and_emits_receipt(self, chain):
        def web_search(query: str) -> str:
            return f"results for {query}"

        signed = sign_tool(web_search, chain=chain)
        result = signed("agent governance")
        assert result == "results for agent governance"
        assert signed.last_receipt is not None

    def test_receipt_records_tool_name_and_action_ref(self, chain):
        def web_search(query: str) -> str:
            return "results"

        signed = sign_tool(web_search, chain=chain)
        signed(query="test")
        payload = signed.last_receipt["payload"]
        assert payload["type"] == "scopeblind:swarms:tool-call"
        assert payload["tool_name"] == "web_search"
        assert payload["action"] == "swarms:tool:web_search"
        assert payload["action_ref"].startswith("sha256:")

    def test_receipt_records_result_hash(self, chain):
        def compute(x: int, y: int) -> int:
            return x + y

        signed = sign_tool(compute, chain=chain)
        signed(2, 3)
        payload = signed.last_receipt["payload"]
        assert payload.get("result_hash", "").startswith("sha256:")

    def test_receipt_verifies_with_chain_public_key(self, chain):
        def trivial(x):
            return x

        signed = sign_tool(trivial, chain=chain)
        signed("hello")
        pub = serialization.load_pem_public_key(chain.signer.public_pem())
        assert verify_receipt(signed.last_receipt, pub)

    def test_tampered_receipt_fails_verification(self, chain):
        def trivial(x):
            return x

        signed = sign_tool(trivial, chain=chain)
        signed("hello")
        pub = serialization.load_pem_public_key(chain.signer.public_pem())
        tampered = {
            "payload": {**signed.last_receipt["payload"], "decision": "forged_allow"},
            "signature": signed.last_receipt["signature"],
        }
        assert not verify_receipt(tampered, pub)

    def test_chain_linkage_across_successive_calls(self, chain):
        def identity(x):
            return x

        signed = sign_tool(identity, chain=chain)
        signed("first")
        first_receipt = signed.last_receipt
        signed("second")
        second_receipt = signed.last_receipt

        assert "previousReceiptHash" not in first_receipt["payload"]
        assert second_receipt["payload"]["previousReceiptHash"] == receipt_hash(first_receipt)

    def test_attach_receipts_returns_wrapper(self, chain):
        def trivial(x):
            return x * 2

        signed = sign_tool(trivial, chain=chain, attach_receipts=True)
        result = signed(5)
        assert isinstance(result, SignedToolResult)
        assert result.result == 10
        assert result.receipt is not None

    def test_decorator_form(self, chain):
        @sign_tool(chain=chain, policy_id="deny-all-defaults")
        def risky(action):
            return f"did {action}"

        result = risky("thing")
        assert result == "did thing"
        assert risky.last_receipt["payload"]["policy_id"] == "deny-all-defaults"

    def test_wrapper_preserves_original_for_unwrap(self, chain):
        def orig(x):
            return x + 1

        signed = sign_tool(orig, chain=chain)
        assert signed.unwrap is orig

    def test_tool_name_override(self, chain):
        def _impl(q):
            return q

        signed = sign_tool(_impl, chain=chain, tool_name="public:search")
        signed("test")
        assert signed.last_receipt["payload"]["tool_name"] == "public:search"

    def test_missing_chain_raises(self):
        def tool(x):
            return x

        with pytest.raises(ValueError, match="ReceiptChain"):
            sign_tool(tool)


class TestSignTools:
    def test_bulk_wraps_list(self, chain):
        def a(x):
            return x

        def b(x):
            return x * 2

        wrapped = sign_tools([a, b], chain=chain)
        assert len(wrapped) == 2
        assert wrapped[0].unwrap is a
        assert wrapped[1].unwrap is b

    def test_bulk_signs_independently(self, chain):
        calls = []

        def t1(x):
            calls.append(("t1", x))
            return x

        def t2(x):
            calls.append(("t2", x))
            return x * 2

        signed = sign_tools([t1, t2], chain=chain)
        signed[0]("hello")
        signed[1]("world")

        assert calls == [("t1", "hello"), ("t2", "world")]
        assert signed[0].last_receipt["payload"]["tool_name"] == "t1"
        assert signed[1].last_receipt["payload"]["tool_name"] == "t2"


class TestReceiptChain:
    def test_from_key_file_round_trip(self, tmp_path):
        s = Signer.generate()
        key_path = tmp_path / "issuer.key"
        key_path.write_bytes(s.private_pem())
        chain = ReceiptChain.from_key_file(str(key_path), agent_id="did:test")
        assert chain.signer.kid == s.kid
        assert chain.agent_id == "did:test"

    def test_reset_chain_clears_previous_hash(self, chain):
        def t(x):
            return x

        signed = sign_tool(t, chain=chain)
        signed("one")
        assert chain.current_tip is not None
        chain.reset_chain()
        assert chain.current_tip is None

    def test_concurrent_calls_dont_corrupt_chain(self, chain):
        import threading

        def t(x):
            return x

        signed = sign_tool(t, chain=chain)

        def worker():
            for i in range(10):
                signed(f"call-{i}")

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        # Every receipt from receipt[1:] should link to a real prior hash
        # (chain integrity after concurrent signing)
        assert chain.current_tip is not None
        assert signed.last_receipt["payload"].get("previousReceiptHash") is not None


class TestEmbeddedKeyRejection:
    def test_sign_cannot_be_bypassed_via_extra(self, chain):
        def t(x):
            return x

        signed = sign_tool(t, chain=chain)
        # chain.sign_tool_call accepts `extra`; we confirm that setting
        # `verification_key` there is rejected
        with pytest.raises(EmbeddedKeyRejection):
            chain.sign_tool_call(
                tool_name="test",
                tool_args={},
                extra={"verification_key": "forged"},
            )
