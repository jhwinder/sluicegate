"""Agent integration primitives for the PAUSE outcome.

These adapters give agent builders a small, consistent control-flow contract:

  - If GateDecision is PAUSE, wait for resolution (approve/deny/expire)
  - If resolved to ALLOW, continue
  - If resolved to BLOCK, report blocked + alternatives

The goal is to avoid per-agent bespoke logic while keeping the core
SluiceGate engine runtime-agnostic.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional

from .decision_loop import Gate
from .models import GateDecision


class PauseAdapter(ABC):
    """Abstract adapter for handling PAUSE in an agent runtime."""

    @abstractmethod
    def handle(self, gate: Gate, decision: GateDecision) -> GateDecision:
        """Handle a GateDecision, potentially waiting for PAUSE resolution."""


class PollingPauseAdapter(PauseAdapter):
    """Synchronous PAUSE handler using polling.

    This is the most portable option: it works with any runtime that can
    block/sleep.
    """

    def __init__(self, *, poll_interval_s: float = 1.0, max_wait_s: Optional[float] = None):
        self.poll_interval_s = float(poll_interval_s)
        self.max_wait_s = max_wait_s

    def handle(self, gate: Gate, decision: GateDecision) -> GateDecision:
        if decision.decision != "PAUSE" or not decision.resume_token:
            return decision

        start = time.time()
        while True:
            resolved = gate.resolve_pause(decision.resume_token)
            if resolved is None:
                # Fail-closed if token disappears.
                return GateDecision(
                    request_id=decision.request_id,
                    decision="BLOCK",
                    policy_hash=decision.policy_hash,
                    obligations=decision.obligations,
                    message="Paused token not found.",
                    resume_token=decision.resume_token,
                    pause_status="EXPIRED",
                    pause_timeout_at=decision.pause_timeout_at,
                    reason_code=decision.reason_code,
                )

            if resolved.decision != "PAUSE":
                return resolved

            if self.max_wait_s is not None and (time.time() - start) >= float(self.max_wait_s):
                # Caller-chosen timeout is separate from policy TTL.
                return GateDecision(
                    request_id=resolved.request_id,
                    decision="BLOCK",
                    policy_hash=resolved.policy_hash,
                    obligations=resolved.obligations,
                    message="Client wait timed out.",
                    resume_token=resolved.resume_token,
                    pause_status=resolved.pause_status,
                    pause_timeout_at=resolved.pause_timeout_at,
                    reason_code="client_wait_timeout",
                )

            time.sleep(self.poll_interval_s)


class AsyncPollingPauseAdapter:
    """Async PAUSE handler using polling.

    Useful for asyncio-based agent runtimes.
    """

    def __init__(self, *, poll_interval_s: float = 1.0, max_wait_s: Optional[float] = None):
        self.poll_interval_s = float(poll_interval_s)
        self.max_wait_s = max_wait_s

    async def handle(self, gate: Gate, decision: GateDecision) -> GateDecision:
        if decision.decision != "PAUSE" or not decision.resume_token:
            return decision

        start = time.time()
        while True:
            resolved = gate.resolve_pause(decision.resume_token)
            if resolved is None:
                return GateDecision(
                    request_id=decision.request_id,
                    decision="BLOCK",
                    policy_hash=decision.policy_hash,
                    obligations=decision.obligations,
                    message="Paused token not found.",
                    resume_token=decision.resume_token,
                    pause_status="EXPIRED",
                    pause_timeout_at=decision.pause_timeout_at,
                    reason_code=decision.reason_code,
                )

            if resolved.decision != "PAUSE":
                return resolved

            if self.max_wait_s is not None and (time.time() - start) >= float(self.max_wait_s):
                return GateDecision(
                    request_id=resolved.request_id,
                    decision="BLOCK",
                    policy_hash=resolved.policy_hash,
                    obligations=resolved.obligations,
                    message="Client wait timed out.",
                    resume_token=resolved.resume_token,
                    pause_status=resolved.pause_status,
                    pause_timeout_at=resolved.pause_timeout_at,
                    reason_code="client_wait_timeout",
                )

            await asyncio.sleep(self.poll_interval_s)
