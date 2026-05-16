# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""Tool-wrapping helpers for Swarms integration.

Swarms' extension point for tool calls is to wrap each tool function
before handing it to the Agent constructor (per upstream guidance on
tool interception). This module provides a decorator and a bulk helper
for wrapping one or many tools with receipt emission.

Usage:

    from swarms import Agent
    from scopeblind_swarms import ReceiptChain, sign_tool

    chain = ReceiptChain.from_key_file(
        signer_key_path="/etc/scopeblind/issuer.key",
        agent_id="did:swarms:researcher",
        policy_id="allow-web-read",
    )

    def web_search(query: str) -> str:
        return f"results for {query}"

    signed_search = sign_tool(web_search, chain=chain)

    agent = Agent(
        agent_name="researcher",
        tools=[signed_search],
        ...,
    )
    agent.run("find recent papers on agent governance")

    # The session's receipts are available on the chain or via the
    # wrapped tool's last_receipt attribute.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from scopeblind_swarms.chain import ReceiptChain


@dataclass
class SignedToolResult:
    """The raw tool return value plus its signed receipt.

    Most Swarms agents expect tools to return strings (or simple
    values); this class is returned when the caller passes
    ``attach_receipts=True`` so the agent loop can inspect both
    the business output and the evidence.
    """

    result: Any
    receipt: dict

    def __str__(self) -> str:
        return str(self.result)


def sign_tool(
    func: Optional[Callable] = None,
    *,
    chain: Optional[ReceiptChain] = None,
    policy_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    attach_receipts: bool = False,
) -> Callable:
    """Wrap a Swarms tool function to emit a signed receipt on every call.

    Can be used as a decorator (``@sign_tool(chain=chain)``) or
    called inline (``wrapped = sign_tool(func, chain=chain)``).

    :param func: the tool callable. Inferred as positional argument when
        used as a decorator.
    :param chain: the :class:`ReceiptChain` that holds the signing key,
        agent identity, and chain state. Required.
    :param policy_id: optional per-tool policy identifier. Overrides the
        chain's default policy_id for this tool's receipts.
    :param tool_name: override the detected tool name. Defaults to
        ``func.__name__``.
    :param attach_receipts: if True, return :class:`SignedToolResult`
        (receipt attached alongside the raw result). Most Swarms agents
        expect plain returns, so default is False.
    :returns: the wrapped callable. Has ``.last_receipt``, ``.chain``,
        and ``.unwrap`` attributes for introspection.
    """

    def _decorator(target: Callable) -> Callable:
        if chain is None:
            raise ValueError(
                "sign_tool requires a ReceiptChain. Create one with "
                "ReceiptChain.from_key_file(...) and pass it to sign_tool."
            )
        resolved_name = tool_name or getattr(target, "__name__", "unnamed_tool")

        @functools.wraps(target)
        def _wrapper(*args, **kwargs):
            call_args = _capture_call_args(target, args, kwargs)
            result = target(*args, **kwargs)
            result_hash = _safe_hash(result)
            receipt = chain.sign_tool_call(
                tool_name=resolved_name,
                tool_args=call_args,
                tool_result_hash=result_hash,
                decision="allow",
                policy_id=policy_id,
            )
            _wrapper.last_receipt = receipt
            if attach_receipts:
                return SignedToolResult(result=result, receipt=receipt)
            return result

        _wrapper.chain = chain
        _wrapper.last_receipt = None
        _wrapper.unwrap = target
        _wrapper.__doc__ = target.__doc__
        return _wrapper

    if func is not None:
        return _decorator(func)
    return _decorator


def sign_tools(
    tools: Iterable[Callable],
    *,
    chain: ReceiptChain,
    policy_id: Optional[str] = None,
    attach_receipts: bool = False,
) -> list[Callable]:
    """Wrap a list of tools with signed-receipt emission.

    Convenience helper for the common case of passing many tools to a
    single Agent:

        agent = Agent(
            tools=sign_tools([web_search, summarize, post_draft], chain=chain),
            ...,
        )
    """
    return [
        sign_tool(t, chain=chain, policy_id=policy_id, attach_receipts=attach_receipts)
        for t in tools
    ]


def _capture_call_args(func: Callable, args: tuple, kwargs: Mapping) -> dict:
    """Build a JSON-serializable dict of the arguments a tool was called with."""
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        captured = dict(bound.arguments)
    except (ValueError, TypeError):
        captured = {"_args": list(_safe_repr(a) for a in args), "_kwargs": {k: _safe_repr(v) for k, v in kwargs.items()}}

    # Coerce values into JSON-safe shapes. Non-serializable items become
    # their repr so args_hash is still deterministic across runs.
    safe: dict[str, Any] = {}
    for k, v in captured.items():
        try:
            json.dumps(v)
            safe[k] = v
        except (TypeError, ValueError):
            safe[k] = _safe_repr(v)
    return safe


def _safe_repr(v: Any) -> str:
    try:
        return repr(v)
    except Exception:
        return "<unreprable>"


def _safe_hash(result: Any) -> Optional[str]:
    """SHA-256 of the tool's return value if it's hashable as JSON or str.

    Used as the receipt's `result_hash` so the receipt attests to what
    the tool returned without carrying the raw output (privacy default).
    Returns None if hashing fails.
    """
    try:
        if isinstance(result, (dict, list, tuple)):
            canonical = json.dumps(
                result, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=str
            ).encode("utf-8")
        else:
            canonical = str(result).encode("utf-8")
    except Exception:
        return None
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
