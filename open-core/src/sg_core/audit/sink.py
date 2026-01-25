"""
Experimental: audit sink contracts.

sg-core should be able to emit audit events without knowing where they go.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """
    A sink receives already-structured audit event dicts.

    Event shape is intentionally flexible. Recommended keys:
      - timestamp (str or float)
      - event_type (str)
      - request_id (str)
      - actor_type (str)
      - actor_id (str | None)
      - summary (str)
      - details (dict)
    """

    def emit(self, event: Dict[str, Any]) -> None:
        ...


class CompositeAuditSink:
    """Fan-out sink to multiple sinks."""

    def __init__(self, sinks: List[AuditSink]) -> None:
        self._sinks = sinks

    def emit(self, event: Dict[str, Any]) -> None:
        for s in self._sinks:
            try:
                s.emit(event)
            except Exception:
                # Never let audit failures take down enforcement.
                # Implementations may want stricter behavior.
                pass
