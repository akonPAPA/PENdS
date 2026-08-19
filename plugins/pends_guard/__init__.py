"""Pends guard plugin — typed guard tools + forced check-command gate + doc-sync.

Hermes plugin registration entry point.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from . import (
    code_execution_audit,
    handlers,  # noqa: E402
    ptt,
    schemas,  # noqa: E402
    state,  # noqa: E402
)
from .skill_receipts import (
    advance_context_generation,
    binding_readiness,
    record_binding_turn,
    record_delivery_turn,
)
from .terminal_policy import block_terminal_command

__all__ = ["register", "TOOLS", "REGISTERED_TOOLS", "tools"]

TOOLS = handlers
tools = handlers

_SESSION_ENGAGEMENTS: dict[str, str] = {}
_TARGET_TOOLS = {
    "pends_exec",
    "pends_exec_burst",
    "pends_httpx",
    "pends_nuclei",
    "pends_ffuf",
    "pends_listener",
}
_BROWSER_TARGET_TOOLS = {
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_select",
    "browser_scroll",
}

# Tool names registered with the Hermes plugin loader. Kept in sync with the
# registration tuple below; the release gate compares these against
# plugin.yaml's provides_tools.
REGISTERED_TOOLS = [
    "pends_check_command",
    "pends_record_ptt",
    "pends_record_hypothesis",
    "pends_exec",
    "pends_exec_status",
    "pends_exec_cancel",
    "pends_review_batch",
    "pends_rebind_pending_batch",
    "pends_heartbeat_done",
    "pends_exec_burst",
    "pends_target",
    "pends_status",
    "pends_search_exploit",
    "pends_httpx",
    "pends_nuclei",
    "pends_ffuf",
    "pends_listener",
]


def register(ctx) -> None:
    """Called once by the plugin loader during discovery."""
    for name, schema, handler, emoji in (
        ("pends_check_command", schemas.CHECK_COMMAND_SCHEMA, handlers.handle_check_command, "🛡️"),
        ("pends_record_ptt", schemas.RECORD_PTT_SCHEMA, handlers.handle_record_ptt, "📝"),
        (
            "pends_record_hypothesis",
            schemas.RECORD_HYPOTHESIS_SCHEMA,
            handlers.handle_record_hypothesis,
            "🔎",
        ),
        ("pends_exec", schemas.EXEC_SCHEMA, handlers.handle_exec, "⚡"),
        ("pends_exec_status", schemas.EXEC_STATUS_SCHEMA, handlers.handle_exec_status, "i"),
        ("pends_exec_cancel", schemas.EXEC_CANCEL_SCHEMA, handlers.handle_exec_cancel, "x"),
        (
            "pends_review_batch",
            schemas.REVIEW_BATCH_SCHEMA,
            handlers.handle_review_batch,
            "✅",
        ),
        (
            "pends_rebind_pending_batch",
            schemas.REBIND_PENDING_BATCH_SCHEMA,
            handlers.handle_rebind_pending_batch,
            "↔",
        ),
        (
            "pends_heartbeat_done",
            schemas.HEARTBEAT_DONE_SCHEMA,
            handlers.handle_heartbeat_done,
            "💓",
        ),
        ("pends_exec_burst", schemas.EXEC_BURST_SCHEMA, handlers.handle_exec_burst, "🚀"),
        ("pends_target", schemas.TARGET_SCHEMA, handlers.handle_target, "🎯"),
        ("pends_status", schemas.STATUS_SCHEMA, handlers.handle_status, "📊"),
        (
            "pends_search_exploit",
            schemas.SEARCH_EXPLOIT_SCHEMA,
            handlers.handle_search_exploit,
            "?",
        ),
        ("pends_httpx", schemas.HTTPX_SCHEMA, handlers.handle_httpx, "H"),
        ("pends_nuclei", schemas.NUCLEI_SCHEMA, handlers.handle_nuclei, "V"),
        ("pends_ffuf", schemas.FFUF_SCHEMA, handlers.handle_ffuf, "F"),
        ("pends_listener", schemas.LISTENER_SCHEMA, handlers.handle_listener, "L"),
    ):
        ctx.register_tool(
            name=name,
            toolset="pends_guard",
            schema=schema,
            handler=handler,
            emoji=emoji,
        )

    ctx.register_hook("pre_tool_call", _pre_tool_call_hook)
    ctx.register_hook("post_tool_call", _post_tool_call_hook)
    ctx.register_hook("pre_llm_call", _pre_llm_call_hook)
    ctx.register_hook("on_session_reset", _on_session_reset_hook)
    ctx.register_hook("on_session_finalize", _on_session_finalize_hook)


# ---------------------------------------------------------------------------
# Tool policy hooks
# ---------------------------------------------------------------------------


def _pre_tool_call_hook(tool_name=None, args=None, **kwargs):
    """Apply the raw-terminal classifier and the execute-code audit gate.

    Pends-specific execution tools carry the engagement context required for
    full scope/state validation.  The built-in terminal has no such fields, so
    it remains available only for host-local work; clearly target-touching
    commands must use ``pends_exec`` or ``pends_exec_burst``.
    """
    args = args if isinstance(args, dict) else {}
    session_id = str(kwargs.get("session_id") or args.get("session_id") or "")
    eng_dir = str(args.get("eng_dir") or "")
    if session_id and eng_dir:
        _SESSION_ENGAGEMENTS[session_id] = eng_dir
        state.record_session_id(eng_dir, session_id)
    if tool_name in _TARGET_TOOLS or tool_name in _BROWSER_TARGET_TOOLS:
        blocked = _check_turn_binding(tool_name, args, kwargs)
        if blocked:
            return {"action": "block", "message": blocked}
    if tool_name == "execute_code":
        _metadata, message = code_execution_audit.validate_source(args.get("code"))
        return None if message is None else {"action": "block", "message": message}
    if tool_name != "terminal":
        return None
    message = block_terminal_command(args.get("command", ""))
    return None if message is None else {"action": "block", "message": message}


def _post_tool_call_hook(tool_name=None, args=None, result=None, duration_ms=0, **kwargs):
    """Write the auditable execute-code source receipt after dispatch."""
    if tool_name == "execute_code" and isinstance(args, dict):
        with contextlib.suppress(Exception):
            code_execution_audit.record_completion(args.get("code"), result, duration_ms)
    if tool_name in {"web_search", "web_extract"}:
        session_id = str(kwargs.get("session_id") or "")
        eng_dir = _SESSION_ENGAGEMENTS.get(session_id)
        if eng_dir:
            with contextlib.suppress(Exception):
                state.record_research_attempt(eng_dir, tool_name, not bool(result is None))
    if tool_name not in {"pends_record_ptt", "pends_review_batch"}:
        return
    args = args if isinstance(args, dict) else {}
    eng_dir = str(args.get("eng_dir") or "")
    turn_id = str(kwargs.get("turn_id") or "")
    api_request_id = str(kwargs.get("api_request_id") or "")
    if not eng_dir or (not turn_id and not api_request_id):
        return
    try:
        payload = json.loads(result) if isinstance(result, str) else result
        if not isinstance(payload, dict):
            return
        skill = payload.get("skill") or {}
        delivery_id = str(skill.get("delivery_id") or "")
        if payload.get("status") == "skill_prepared" and delivery_id:
            record_delivery_turn(
                eng_dir,
                delivery_id=delivery_id,
                turn_id=turn_id,
                api_request_id=api_request_id,
            )
        task_id = ""
        if tool_name == "pends_record_ptt":
            task_id = str(payload.get("task_id") or "")
        elif tool_name == "pends_review_batch":
            task_id = str(payload.get("binding_task_id") or "")
        if payload.get("status") == "ok" and task_id:
            record_binding_turn(
                eng_dir,
                task_id=task_id,
                turn_id=turn_id,
                api_request_id=api_request_id,
            )
    except Exception:
        return


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------


def _pre_llm_call_hook(session_id=None, eng_dir=None, **kwargs):
    """Lifecycle heartbeat: tick the message counter before each LLM call."""
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            state.record_session_id(str(eng_dir), session_id)
            if session_id:
                _SESSION_ENGAGEMENTS[str(session_id)] = str(eng_dir)
    return None


def _on_session_reset_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session reset (context compression, /goal set, etc.)."""
    eng_dir = eng_dir or (_SESSION_ENGAGEMENTS.get(str(session_id)) if session_id else None)
    if eng_dir:
        with contextlib.suppress(Exception):
            state.tick_message(str(eng_dir))
            advance_context_generation(str(eng_dir), str(session_id or "reset"))


def _check_turn_binding(tool_name: str, args: dict, hook: dict) -> str | None:
    """Stop target/browser activity until an earlier-turn receipt is bound."""

    session_id = str(hook.get("session_id") or args.get("session_id") or "")
    eng_dir = str(args.get("eng_dir") or _SESSION_ENGAGEMENTS.get(session_id) or "")
    if not eng_dir:
        return (
            f"{tool_name} needs an engagement associated through pends_status or a Pends tool "
            "before browser or target activity is allowed"
        )
    tasks = ptt.parse_ptt(Path(eng_dir) / "state" / "ptt.md")
    active = ptt.find_active_task(tasks)
    if not active:
        return "target activity requires exactly one active [~] PTT task"
    binding, reason = binding_readiness(eng_dir, task_id=active.id, session_id=session_id)
    if reason:
        return f"target activity blocked: {reason}; select and prepare a routed skill first"
    api_request_id = str(hook.get("api_request_id") or "")
    receipt_request_ids = {
        str(binding.get("bound_api_request_id") or ""),
        str(binding.get("delivered_api_request_id") or ""),
    }
    receipt_request_ids.discard("")
    same_model_call = bool(api_request_id and api_request_id in receipt_request_ids)
    if not receipt_request_ids:
        turn_id = str(hook.get("turn_id") or "")
        same_model_call = bool(
            turn_id
            and turn_id
            in {
                str(binding.get("bound_turn_id") or ""),
                str(binding.get("delivered_turn_id") or ""),
            }
        )
    if same_model_call:
        return (
            "target activity is blocked in the same model call as skill delivery/binding; "
            "process the tool result and retry in the next model continuation"
        )
    return None


def _on_session_finalize_hook(session_id=None, eng_dir=None, **kwargs) -> None:
    """Hook: session finalize.

    Closeout gates are explicit (pends_review_batch / close command). On finalize
    we leave a continuity marker so a fresh session can re-read pending state.
    """
    if eng_dir:
        with contextlib.suppress(Exception):
            pending = state.has_pending_sync(str(eng_dir))
            if pending:
                state.set_heartbeat_pending(
                    str(eng_dir),
                    "session finalized with a pending sync lock; run pends_review_batch",
                )
