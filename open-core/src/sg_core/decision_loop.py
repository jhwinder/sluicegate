from __future__ import annotations

import time
import uuid
import threading
from dataclasses import asdict
from typing import Any, Callable, Dict, Optional

from .models import GateRequest, GateDecision, ExplainResult, PauseRecord


class PauseNotifier:
    """Interface for pause/resume notifications.

    This is intentionally tiny so different transports can be plugged in
    (SSE, WebSocket, queues, webhooks, etc.).
    """

    def publish(self, resume_token: str, payload: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class InMemoryPauseNotifier(PauseNotifier):
    """In-process pub/sub for PAUSE updates.

    - Supports multiple subscribers per resume_token
    - Thread-safe for basic usage
    - Best-effort delivery (intended for demo / single-process deployments)
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: Dict[str, set] = {}

    def subscribe(self, resume_token: str, callback: Callable[[Dict[str, Any]], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.setdefault(resume_token, set()).add(callback)

        def _unsubscribe() -> None:
            with self._lock:
                subs = self._subscribers.get(resume_token)
                if subs and callback in subs:
                    subs.remove(callback)
                if subs is not None and len(subs) == 0:
                    self._subscribers.pop(resume_token, None)

        return _unsubscribe

    def publish(self, resume_token: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subscribers.get(resume_token, set()))
        for cb in subs:
            try:
                cb(payload)
            except Exception:
                # Best-effort notifier; never break the gate hot-path.
                pass
from .policy import PolicyEngine

def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _token() -> str:
    # Longer token for pause/resume so it can safely be used as a handle.
    return uuid.uuid4().hex


class InMemoryPauseStore:
    """Minimal pause store.

    - In-memory only (resets on restart)
    - Fail-closed behavior on missing/expired tokens
    """

    def __init__(self, *, default_ttl_s: int = 3600):
        self.default_ttl_s = default_ttl_s
        self._items: Dict[str, PauseRecord] = {}

    def create(
        self,
        *,
        req: GateRequest,
        policy_hash: str,
        obligations,
        message: str,
        reason_code: Optional[str] = None,
        ttl_s: Optional[int] = None,
    ) -> PauseRecord:
        now = time.time()
        token = _token()
        ttl = self.default_ttl_s if ttl_s is None else int(ttl_s)
        timeout_at = now + ttl if ttl > 0 else None

        rec = PauseRecord(
            resume_token=token,
            created_at=now,
            timeout_at=timeout_at,
            status="PENDING",
            request=req,
            policy_hash=policy_hash,
            obligations=list(obligations or []),
            message=message,
            reason_code=reason_code,
        )
        self._items[token] = rec
        return rec

    def get(self, resume_token: str) -> Optional[PauseRecord]:
        rec = self._items.get(resume_token)
        if not rec:
            return None
        if rec.status == "PENDING" and rec.timeout_at is not None and time.time() >= rec.timeout_at:
            rec.status = "EXPIRED"
            rec.resolved_at = time.time()
        return rec

    def resolve(self, resume_token: str, *, approved: bool, approver: str, comment: str = "") -> Optional[PauseRecord]:
        rec = self.get(resume_token)
        if not rec:
            return None
        if rec.status != "PENDING":
            return rec
        rec.status = "APPROVED" if approved else "DENIED"
        rec.approver = approver
        rec.approver_comment = comment
        rec.resolved_at = time.time()
        return rec

class Gate:
    """
    Public entrypoint for Open Core Beta.

    - evaluate(): returns GateDecision (decision + obligations)
    - explain(): returns ExplainResult (decision + obligations + trace)
    """

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        pause_store: Optional[InMemoryPauseStore] = None,
        pause_notifier: Optional[PauseNotifier] = None,
    ):
        self.policy_engine = policy_engine
        self.audit_sink = audit_sink
        self.pause_store = pause_store or InMemoryPauseStore()
        self.pause_notifier = pause_notifier

    def get_pause(self, resume_token: str) -> Optional[PauseRecord]:
        """Fetch a pause record (and auto-expire if TTL elapsed)."""
        rec = self.pause_store.get(resume_token)
        if rec and rec.status == "EXPIRED":
            # Emit a best-effort notification so waiters can wake up.
            self._notify_pause_update(rec)
        return rec

    def approve(self, resume_token: str, *, approver: str, comment: str = "") -> Optional[PauseRecord]:
        rec = self.pause_store.resolve(resume_token, approved=True, approver=approver, comment=comment)
        if rec:
            self._audit({
                "ts": time.time(),
                "event": "PAUSE_RESOLVED",
                "request_id": None,
                "summary": "Paused action approved",
                "details": {"resume_token": resume_token, "status": rec.status, "approver": approver, "comment": comment},
            })
            self._notify_pause_update(rec)
        return rec

    def deny(self, resume_token: str, *, approver: str, comment: str = "") -> Optional[PauseRecord]:
        rec = self.pause_store.resolve(resume_token, approved=False, approver=approver, comment=comment)
        if rec:
            self._audit({
                "ts": time.time(),
                "event": "PAUSE_RESOLVED",
                "request_id": None,
                "summary": "Paused action denied",
                "details": {"resume_token": resume_token, "status": rec.status, "approver": approver, "comment": comment},
            })
            self._notify_pause_update(rec)
        return rec

    def resolve_pause(self, resume_token: str) -> Optional[GateDecision]:
        """Convert a pause record into a GateDecision suitable for agents.

        Semantics:
        - PENDING => decision remains PAUSE
        - APPROVED => decision becomes ALLOW
        - DENIED/EXPIRED => decision becomes BLOCK
        """
        rec = self.pause_store.get(resume_token)
        if not rec:
            return None

        rid = _rid()
        if rec.status == "PENDING":
            return GateDecision(
                request_id=rid,
                decision="PAUSE",
                policy_hash=rec.policy_hash,
                obligations=rec.obligations,
                message=rec.message or "Paused pending approval.",
                resume_token=rec.resume_token,
                pause_status=rec.status,
                pause_timeout_at=rec.timeout_at,
                reason_code=rec.reason_code,
            )

        if rec.status == "APPROVED":
            return GateDecision(
                request_id=rid,
                decision="ALLOW",
                policy_hash=rec.policy_hash,
                obligations=rec.obligations,
                message="Approved. Proceed.",
                resume_token=rec.resume_token,
                pause_status=rec.status,
                pause_timeout_at=rec.timeout_at,
                reason_code=rec.reason_code,
            )

        # DENIED or EXPIRED
        msg = "Denied by approver." if rec.status == "DENIED" else "Approval timed out."
        return GateDecision(
            request_id=rid,
            decision="BLOCK",
            policy_hash=rec.policy_hash,
            obligations=rec.obligations,
            message=msg,
            resume_token=rec.resume_token,
            pause_status=rec.status,
            pause_timeout_at=rec.timeout_at,
            reason_code=rec.reason_code,
        )

    def evaluate(self, req: GateRequest) -> GateDecision:
        rid = _rid()

        self._audit({
            "ts": time.time(),
            "event": "REQUEST_CREATED",
            "request_id": rid,
            "summary": "Gate request received",
            "details": {"actor": req.actor, "action": req.action, "target": req.target, "context": req.context},
        })

        ctx = {"actor": req.actor, "action": req.action, "target": req.target, "context": req.context}
        decision, obligations, policy_hash = self.policy_engine.decide(ctx)

        self._audit({
            "ts": time.time(),
            "event": "GATE_DECIDED",
            "request_id": rid,
            "summary": f"Gate decided: {decision}",
            "details": {
                "decision": decision,
                "policy_hash": policy_hash,
                "obligations": [o.__dict__ for o in obligations],
            },
        })

        msg = {
            "ALLOW": "Allowed by policy.",
            "PAUSE": "Paused pending approval.",
            "BLOCK": "Blocked by policy.",
        }.get(decision, "Decision made.")

        # --- PAUSE primitive: create a resumable continuation ---
        if decision == "PAUSE":
            # Optional policy-driven TTL via an obligation payload.
            ttl_s: Optional[int] = None
            reason_code: Optional[str] = "human_approval_required"
            for o in obligations:
                if getattr(o, "type", None) in ("approval", "pause"):
                    ttl_s = (o.data or {}).get("ttl_s", ttl_s)
                    reason_code = (o.data or {}).get("reason_code", reason_code)

            rec = self.pause_store.create(
                req=req,
                policy_hash=policy_hash,
                obligations=obligations,
                message=msg,
                reason_code=reason_code,
                ttl_s=ttl_s,
            )

            self._notify_pause_update(rec)

            self._audit({
                "ts": time.time(),
                "event": "PAUSE_CREATED",
                "request_id": rid,
                "summary": "Action paused pending approval",
                "details": {
                    "resume_token": rec.resume_token,
                    "timeout_at": rec.timeout_at,
                    "policy_hash": policy_hash,
                    "obligations": [asdict(o) if hasattr(o, "__dataclass_fields__") else getattr(o, "__dict__", {}) for o in obligations],
                },
            })

            return GateDecision(
                request_id=rid,
                decision="PAUSE",
                policy_hash=policy_hash,
                obligations=obligations,
                message=msg,
                resume_token=rec.resume_token,
                pause_status=rec.status,
                pause_timeout_at=rec.timeout_at,
                reason_code=reason_code,
            )

        # Non-PAUSE (existing behavior)
        return GateDecision(
            request_id=rid,
            decision=decision,
            policy_hash=policy_hash,
            obligations=obligations,
            message=msg,
        )

    def explain(self, req: GateRequest) -> ExplainResult:
        """
        Pure policy simulation and trace.
        No execution. No side effects. No audit emission by default.
        """
        ctx = {"actor": req.actor, "action": req.action, "target": req.target, "context": req.context}
        return self.policy_engine.explain(ctx)

    def _audit(self, event: Dict[str, Any]) -> None:
        if self.audit_sink:
            self.audit_sink(event)

    def _notify_pause_update(self, rec: PauseRecord) -> None:
        """Publish pause status updates to any registered notifier."""
        if not self.pause_notifier:
            return
        payload: Dict[str, Any] = {
            "resume_token": rec.resume_token,
            "status": rec.status,
            "created_at": rec.created_at,
            "timeout_at": rec.timeout_at,
            "resolved_at": rec.resolved_at,
            "policy_hash": rec.policy_hash,
            "reason_code": rec.reason_code,
            "approver": rec.approver,
            "approver_comment": rec.approver_comment,
            "message": rec.message,
        }
        try:
            self.pause_notifier.publish(rec.resume_token, payload)
        except Exception:
            # Best-effort: never break the gate hot-path.
            pass
