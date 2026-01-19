from __future__ import annotations
from typing import Protocol
from .models import GateRequest, GateDecision

class ObligationAdapter(Protocol):
    """
    Tiny interface for interpreting obligations outside the core.

    The Open Core returns obligations as data. An adapter consumes them and performs
    side effects in the appropriate environment (email, Slack, ticketing, UI, etc.).
    """
    def handle(self, request: GateRequest, decision: GateDecision) -> None:
        ...
