"""
Experimental: connector interfaces.

A Connector is the “actuator surface” for executing an action after
SluiceGate policy evaluation allows it.

This module is intentionally interface-only to support:
- open-source community connectors
- commercial SDK connectors
- enterprise connectors with stricter controls
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Protocol, runtime_checkable


class ExecutionStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ExecutionResult:
    """
    Connector execution outcome. Keep this format stable: it becomes part of
    the demo + audit trail and may be relied on by adapters.
    """
    status: ExecutionStatus
    ok: bool
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @staticmethod
    def success(output: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return ExecutionResult(status=ExecutionStatus.OK, ok=True, output=output or {})

    @staticmethod
    def failure(error: str, output: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return ExecutionResult(status=ExecutionStatus.ERROR, ok=False, error=error, output=output or {})


@runtime_checkable
class Connector(Protocol):
    """
    A connector executes one or more action names, e.g. "stripe.refund".

    NOTE: We do not prescribe auth handling here. Implementations can:
    - read env vars
    - use injected clients
    - use secrets managers
    """

    name: str  # human-readable identifier, e.g. "stripe"

    def can_handle(self, action_name: str) -> bool:
        """Return True if this connector can execute action_name."""
        ...

    def execute(self, action_name: str, params: Dict[str, Any], context: Dict[str, Any]) -> ExecutionResult:
        """
        Execute an allowed action.
        - action_name: canonical string like "stripe.refund"
        - params: action params (typically from request.action.params)
        - context: request context (typically from request.context)
        """
        ...


class ConnectorRegistry:
    """
    Minimal registry for mapping action_name -> connector.
    Kept intentionally small for OSS adoption.
    """

    def __init__(self) -> None:
        self._connectors: list[Connector] = []

    def register(self, connector: Connector) -> None:
        self._connectors.append(connector)

    def resolve(self, action_name: str) -> Optional[Connector]:
        for c in self._connectors:
            if c.can_handle(action_name):
                return c
        return None

    def execute(self, action_name: str, params: Dict[str, Any], context: Dict[str, Any]) -> ExecutionResult:
        connector = self.resolve(action_name)
        if connector is None:
            return ExecutionResult.failure(f"Unknown action '{action_name}'")
        return connector.execute(action_name, params=params, context=context)
