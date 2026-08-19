"""Hypothesis tracking handlers."""

from __future__ import annotations

import yaml

from .. import hypotheses, state
from ..targets import scope_hosts
from .base import _eng_path, _json, _serialise_errors


def _scope_hosts(eng_dir: str) -> set[str] | None:
    """Return the in-scope host set from scope.yaml, or None if no scope file."""
    scope_path = _eng_path(eng_dir) / "scope" / "scope.yaml"
    if not scope_path.exists():
        return None
    try:
        data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return scope_hosts(data) or None


@_serialise_errors
def handle_record_hypothesis(a, **kwargs):
    eng_dir = a["eng_dir"]
    fields = {k: v for k, v in a.items() if k != "eng_dir"}
    in_scope = _scope_hosts(eng_dir)
    h = hypotheses.update_hypothesis(
        _eng_path(eng_dir) / "hypotheses.md", in_scope_hosts=in_scope, **fields
    )
    state.clear_semantic_lock(eng_dir)
    return _json("ok", hypothesis=h.to_dict())
