"""Shared base utilities and error serialization wrappers for tool handlers."""

from __future__ import annotations

import json
import logging
from functools import wraps
from pathlib import Path
from typing import Any

from .. import command as cmd_module
from .. import state
from ..command import CheckCommandArgs

logger = logging.getLogger(__name__)


def _running_background_command(eng_dir: str, command: str) -> bool:
    """Return True if command is currently running as an acknowledged background process."""
    exec_dir = _eng_path(eng_dir) / "evidence" / "executions"
    if not exec_dir.exists():
        return False
    for path in exec_dir.glob("*.json"):
        if path.name.endswith(".lock") or path.name.endswith(".tmp"):
            continue
        record = state.read_json(path)
        if (
            isinstance(record, dict)
            and record.get("background")
            and record.get("command") == command
            and record.get("status") in {"running", "starting"}
        ):
            return True
    return False


def _eng_path(eng_dir: str) -> Path:
    return state.resolve_eng_dir(eng_dir)


def _json(status_name: str, **payload) -> str:
    payload.pop("status", None)
    return json.dumps({"schema_version": 2, "status": status_name, **payload})


def _result(r) -> dict[str, list[str]]:
    return {"errors": r.errors, "warnings": r.warnings, "infos": r.infos}


def _check_command_internal(a) -> cmd_module.CheckResult:
    return cmd_module.check_command(
        CheckCommandArgs(
            command=a.get("command", ""),
            phase=a.get("phase", ""),
            eng_dir=a.get("eng_dir", ""),
            scope=a.get("scope", ""),
            target=a.get("target"),
            session_id=a.get("session_id"),
        )
    )


def _call(fn, args, **kwargs) -> Any:
    """Wrap a handler function with uniform error serialisation."""
    try:
        return fn(args or {}, **kwargs)
    except (ValueError, TypeError, OSError, KeyError) as exc:
        return _json("error", error=str(exc))
    except Exception as exc:
        logger.exception("Unexpected handler error during execution: %s", exc)
        return _json("error", error=str(exc))


def _serialise_errors(fn):
    """Keep every model-visible handler on the stable JSON response contract."""

    @wraps(fn)
    def wrapped(args=None, **kwargs):
        return _call(fn, args, **kwargs)

    return wrapped
