from __future__ import annotations
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass
import time
import uuid

from .models import GateRequest, GateDecision
from .policy import PolicyEngine

def _rid() -> str:
    return uuid.uuid4().hex[:8]

class Gate:
    """
    Public, bulletproof entrypoint for Open Core Beta.

    Gate is transport-agnostic: invoke via Python call, HTTP adapter, gRPC, etc.
    """

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.policy_engine = policy_engine
        self.audit_sink = audit_sink

    def evaluate(self, req: GateRequest) -> GateDecision:
        rid = _rid()

        self._audit({
            "ts": time.time(),
            "event": "REQUEST_CREATED",
            "request_id": rid,
            "summary": "Gate request received",
            "details": {"actor": req.actor, "action": req.action, "target": req.target, "context": req.context},
        })

        ctx = {
            "actor": req.actor,
            "action": req.action,
            "target": req.target,
            "context": req.context,
        }

        decision, obligations, policy_hash = self.policy_engine.decide(ctx)

        self._audit({
            "ts": time.time(),
            "event": "GATE_DECIDED",
            "request_id": rid,
            "summary": f"Gate decided: {decision}",
            "details": {"decision": decision, "policy_hash": policy_hash, "obligations": [o.__dict__ for o in obligations]},
        })

        msg = {
            "ALLOW": "Allowed by policy.",
            "PAUSE": "Paused pending approval.",
            "BLOCK": "Blocked by policy.",
        }.get(decision, "Decision made.")

        return GateDecision(
            request_id=rid,
            decision=decision,
            policy_hash=policy_hash,
            obligations=obligations,
            message=msg,
        )

    def _audit(self, event: Dict[str, Any]) -> None:
        if self.audit_sink:
            self.audit_sink(event)
