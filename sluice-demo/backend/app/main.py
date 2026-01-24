from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from typing import Dict, Optional, Any
import os

# Demo-layer models (FastAPI / UI only)
from app.models import (
    ActionRequest,
    CreateDecisionResponse,
    StoredRequest,
    new_request_id,
    now_ts,
)

# sg-core primitives (published package)
from sg_core import PolicyEngine
from sg_core.decision_loop import Gate
from sg_core.models import GateRequest

# Demo glue
from app.audit import AUDIT_LOG, log_event
from app.connectors import execute_action
from app.approvals import maybe_send_email_approval

app = FastAPI(title="SluiceGate Demo (powered by sg-core)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

POLICY_PATH = os.environ.get("POLICY_PATH", "/policies/policy.yml")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
UI_URL = os.environ.get("UI_URL", "http://localhost:8080").rstrip("/")

# ------------------------------------------------------------------------------
# In-memory demo store (UI convenience only)
# ------------------------------------------------------------------------------

STORE: Dict[str, StoredRequest] = {}

# ------------------------------------------------------------------------------
# sg-core initialization
# ------------------------------------------------------------------------------

policy_engine = PolicyEngine(POLICY_PATH)

# These are the only event_type values the demo audit model accepts.
_ALLOWED_EVENT_TYPES = {
    "REQUEST_CREATED",
    "GATE_DECIDED",
    "NOTIFICATION_ATTEMPTED",
    "APPROVED",
    "REJECTED",
    "EXECUTION_STARTED",
    "EXECUTION_COMPLETED",
    "EXECUTION_FAILED",
}


def _resolve_request_id_from_resume_token(resume_token: Optional[str]) -> str:
    if not resume_token:
        return ""
    for rid, rec in STORE.items():
        if getattr(rec, "resume_token", None) == resume_token:
            return rid
    return ""


def audit_sink(evt: Dict[str, Any]) -> None:
    """
    Translate sg-core audit events into the demo audit log format.

    sg-core emits events shaped like:
      {"event": "...", "request_id": <str|None>, "summary": "...", "details": {...}}

    The demo expects:
      event_type in a fixed literal set, and request_id must be a string.
    """
    try:
        # sg-core uses "event", not "event_type"
        raw_type = evt.get("event") or evt.get("event_type") or "GATE_DECIDED"
        event_type = raw_type if raw_type in _ALLOWED_EVENT_TYPES else "GATE_DECIDED"

        # sg-core sometimes emits request_id=None (e.g., PAUSE_RESOLVED). Coerce safely.
        rid = evt.get("request_id")
        request_id = str(rid) if rid is not None else ""

        # If sg-core didn't include a request_id, try to resolve via resume_token
        if not request_id:
            details = evt.get("details") or {}
            token = details.get("resume_token") if isinstance(details, dict) else None
            request_id = _resolve_request_id_from_resume_token(token)

        log_event(
            request_id=request_id or "",
            event_type=event_type,  # type: ignore[arg-type]
            actor_type="SYSTEM",
            actor_id="sg-core",
            summary=evt.get("summary", "") or "",
            details=evt.get("details", {}) or {},
        )
    except Exception:
        # Audit must never crash the gate hot-path.
        return


gate = Gate(
    policy_engine=policy_engine,
    audit_sink=audit_sink,
)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------


def ui_redirect(request_id: str) -> RedirectResponse:
    return RedirectResponse(
        url=f"{UI_URL}/?request_id={request_id}",
        status_code=303,
    )


def _execute_and_record(request_id: str, r: StoredRequest, summary_suffix: str = "") -> None:
    """
    Execute the requested action via the demo connector.
    Never raise. Always record outcome to r.status / r.executed_result.
    """
    suffix = f" {summary_suffix}".rstrip()

    log_event(
        request_id=request_id,
        event_type="EXECUTION_STARTED",
        actor_type="SYSTEM",
        actor_id="connector",
        summary=f"Execution started{suffix}",
        details={"action": r.payload.action},
    )

    try:
        r.executed_result = execute_action(
            r.payload.action,
            r.payload.amount,
            r.payload.currency,
            r.payload.metadata,
        )
        r.status = "EXECUTED"
        log_event(
            request_id=request_id,
            event_type="EXECUTION_COMPLETED",
            actor_type="SYSTEM",
            actor_id="connector",
            summary=f"Execution completed{suffix}",
            details={"result": r.executed_result},
        )
    except Exception as e:
        r.status = "BLOCKED"
        r.executed_result = {"ok": False, "error": str(e)}
        log_event(
            request_id=request_id,
            event_type="EXECUTION_FAILED",
            actor_type="SYSTEM",
            actor_id="connector",
            summary=f"Execution failed{suffix}",
            details={"error": str(e)},
        )


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/decide", response_model=CreateDecisionResponse)
def decide(req: ActionRequest):
    request_id = new_request_id()

    log_event(
        request_id=request_id,
        event_type="REQUEST_CREATED",
        actor_type="SYSTEM",
        actor_id="api",
        summary="Execution request created",
        details={
            "action": req.action,
            "amount": req.amount,
            "currency": req.currency,
            "metadata": req.metadata,
        },
    )

    # Build sg-core GateRequest
    gate_request = GateRequest(
        actor={
            "type": "AGENT",
            "id": req.metadata.get("agent_type", "Unknown"),
        },
        action={
            "name": req.action,
            "params": {
                **req.metadata,
            },
        },
        target={
            "type": "API",
            "id": req.action,
        },
        context={
            "demo": True,
            "amount": req.amount,
            "currency": (req.currency or "").upper(),
        },
    )

    decision = gate.evaluate(gate_request)

    # Always log a decision at the demo layer (in addition to any sg-core audit events)
    log_event(
        request_id=request_id,
        event_type="GATE_DECIDED",
        actor_type="POLICY",
        actor_id="sg-core",
        summary=f"Gate decided: {decision.decision}",
        details={
            "decision": decision.decision,
            "policy_hash": decision.policy_hash,
            "resume_token": decision.resume_token,
            "message": getattr(decision, "message", None),
        },
    )

    status = (
        "PENDING"
        if decision.decision == "PAUSE"
        else "BLOCKED"
        if decision.decision == "BLOCK"
        else "EXECUTED"
    )

    stored = StoredRequest(
        request_id=request_id,
        created_at=now_ts(),
        payload=req,
        decision=decision.decision,
        status=status,
        policy_hash=decision.policy_hash,
        resume_token=decision.resume_token,
        executed_result=None,
    )

    # Immediate execution if allowed
    if decision.decision == "ALLOW":
        _execute_and_record(request_id, stored)

    # Human approval required
    if decision.decision == "PAUSE":
        log_event(
            request_id=request_id,
            event_type="NOTIFICATION_ATTEMPTED",
            actor_type="SYSTEM",
            actor_id="email",
            summary="Approval notification attempted",
            details={"approver": os.environ.get("APPROVER_EMAIL", "")},
        )
        maybe_send_email_approval(
            request_id=request_id,
            action=req.action,
            amount=req.amount,
            currency=req.currency,
            base_url=BASE_URL,
        )

    STORE[request_id] = stored

    return CreateDecisionResponse(
        request_id=request_id,
        decision=decision.decision,
        status=stored.status,
        message=decision.message,
        resume_token=decision.resume_token,
    )


@app.get("/api/requests/{request_id}")
def get_request(request_id: str):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    return r.model_dump()


@app.api_route("/api/requests/{request_id}/approve", methods=["GET", "POST"])
def approve(request_id: str, request: Request):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    if r.status != "PENDING":
        return ui_redirect(request_id) if request.method == "GET" else {"ok": True, "status": r.status, "note": "No-op (not pending)"}

    if not r.resume_token:
        raise HTTPException(status_code=500, detail="Missing resume_token")

    # Resolve the PAUSE inside sg-core (must not 500 the user experience)
    try:
        gate.approve(
            r.resume_token,
            approver="email_link" if request.method == "GET" else "api_client",
            comment="approved",
        )
    except Exception as e:
        log_event(
            request_id=request_id,
            event_type="EXECUTION_FAILED",
            actor_type="SYSTEM",
            actor_id="sg-core",
            summary="Approval failed inside sg-core",
            details={"error": str(e)},
        )
        # Still redirect to UI instead of showing a stacktrace
        return ui_redirect(request_id) if request.method == "GET" else {"ok": False, "error": str(e)}

    log_event(
        request_id=request_id,
        event_type="APPROVED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request approved",
    )

    _execute_and_record(request_id, r, summary_suffix="(after approval)")
    STORE[request_id] = r

    return ui_redirect(request_id) if request.method == "GET" else {"ok": True, "status": r.status, "executed_result": r.executed_result}


@app.api_route("/api/requests/{request_id}/reject", methods=["GET", "POST"])
def reject(request_id: str, request: Request):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    if r.status != "PENDING":
        return ui_redirect(request_id) if request.method == "GET" else {"ok": True, "status": r.status, "note": "No-op (not pending)"}

    if not r.resume_token:
        raise HTTPException(status_code=500, detail="Missing resume_token")

    try:
        gate.deny(
            r.resume_token,
            approver="email_link" if request.method == "GET" else "api_client",
            comment="rejected",
        )
    except Exception as e:
        log_event(
            request_id=request_id,
            event_type="EXECUTION_FAILED",
            actor_type="SYSTEM",
            actor_id="sg-core",
            summary="Rejection failed inside sg-core",
            details={"error": str(e)},
        )
        return ui_redirect(request_id) if request.method == "GET" else {"ok": False, "error": str(e)}

    r.status = "REJECTED"
    STORE[request_id] = r

    log_event(
        request_id=request_id,
        event_type="REJECTED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request rejected",
    )

    return ui_redirect(request_id) if request.method == "GET" else {"ok": True, "status": r.status}


@app.get("/api/audit")
def get_audit(request_id: Optional[str] = None, limit: int = 200):
    events = AUDIT_LOG[::-1]
    if request_id:
        events = [e for e in events if e.request_id == request_id]
    limit = max(1, min(int(limit), 1000))
    return [e.model_dump() for e in events[:limit]]


@app.post("/api/policy/reload")
def reload_policy():
    policy_engine.reload()
    return {"ok": True, "message": "Policy reloaded"}
