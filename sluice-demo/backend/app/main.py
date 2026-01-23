from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from typing import Dict, Optional
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


def audit_sink(evt: Dict) -> None:
    """
    Translate sg-core audit events into the demo audit log format.
    """
    log_event(
        request_id=evt.get("request_id", ""),
        event_type=evt.get("event_type", "GATE_DECIDED"),
        actor_type="SYSTEM",
        actor_id="sg-core",
        summary=evt.get("summary", ""),
        details=evt.get("details", {}) or {},
    )


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
                "amount": req.amount,
                "currency": req.currency,
                **req.metadata,
            },
        },
        target={
            "type": "API",
            "id": req.action,
        },
        context={
            "demo": True,
        },
    )

    decision = gate.evaluate(gate_request)

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
        log_event(
            request_id=request_id,
            event_type="EXECUTION_STARTED",
            actor_type="SYSTEM",
            actor_id="connector",
            summary="Execution started",
            details={"action": req.action},
        )
        try:
            stored.executed_result = execute_action(
                req.action,
                req.amount,
                req.currency,
                req.metadata,
            )
            stored.status = "EXECUTED"
            log_event(
                request_id=request_id,
                event_type="EXECUTION_COMPLETED",
                actor_type="SYSTEM",
                actor_id="connector",
                summary="Execution completed",
                details={"result": stored.executed_result},
            )
        except Exception as e:
            stored.status = "BLOCKED"
            log_event(
                request_id=request_id,
                event_type="EXECUTION_FAILED",
                actor_type="SYSTEM",
                actor_id="connector",
                summary="Execution failed",
                details={"error": str(e)},
            )

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
        return ui_redirect(request_id) if request.method == "GET" else {"ok": True}

    if not r.resume_token:
        raise HTTPException(status_code=500, detail="Missing resume_token")

    gate.approve(
        r.resume_token,
        approver="email_link" if request.method == "GET" else "api_client",
        comment="approved",
    )

    log_event(
        request_id=request_id,
        event_type="APPROVED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request approved",
    )

    # Execute after approval
    log_event(
        request_id=request_id,
        event_type="EXECUTION_STARTED",
        actor_type="SYSTEM",
        actor_id="connector",
        summary="Execution started (after approval)",
        details={"action": r.payload.action},
    )

    r.executed_result = execute_action(
        r.payload.action,
        r.payload.amount,
        r.payload.currency,
        r.payload.metadata,
    )
    r.status = "EXECUTED"
    STORE[request_id] = r

    log_event(
        request_id=request_id,
        event_type="EXECUTION_COMPLETED",
        actor_type="SYSTEM",
        actor_id="connector",
        summary="Execution completed (after approval)",
        details={"result": r.executed_result},
    )

    return ui_redirect(request_id) if request.method == "GET" else {"ok": True}


@app.api_route("/api/requests/{request_id}/reject", methods=["GET", "POST"])
def reject(request_id: str, request: Request):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    if r.status != "PENDING":
        return ui_redirect(request_id) if request.method == "GET" else {"ok": True}

    if not r.resume_token:
        raise HTTPException(status_code=500, detail="Missing resume_token")

    gate.deny(
        r.resume_token,
        approver="email_link" if request.method == "GET" else "api_client",
        comment="rejected",
    )

    r.status = "REJECTED"
    STORE[request_id] = r

    log_event(
        request_id=request_id,
        event_type="REJECTED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request rejected",
    )

    return ui_redirect(request_id) if request.method == "GET" else {"ok": True}


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
