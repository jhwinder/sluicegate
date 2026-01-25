"""
Experimental: connector interfaces (no implementations).

Connectors are responsible for executing actions (tool calls / API calls)
when the gate decision is ALLOW or when a PAUSE is later approved.
"""

from .base import (
    Connector,
    ConnectorRegistry,
    ExecutionResult,
    ExecutionStatus,
)

__all__ = [
    "Connector",
    "ConnectorRegistry",
    "ExecutionResult",
    "ExecutionStatus",
]
