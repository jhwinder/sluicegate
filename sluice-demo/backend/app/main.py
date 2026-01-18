from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from typing import Dict, Optional
import os

from .models import ActionRequest, CreateDecisionResponse, StoredRequest, new_request_id, now_ts
from .policy import PolicyEngine, default_policy_path
from .audit import AUDIT_LOG, log_event
from .decision_loop import run_decision_loop
from .connectors import execute_action

app = FastAPI(title="SluiceGate Demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORE: Dict[str, StoredRequest] = {}
policy_engine = PolicyEngine(default_policy_path())


def base_url() -> str:
    # Used to construct approve/reject links in email notifications
    return os.environ.get("BASE_URL", "http://localhost:8000")


def ui_url(request_id: str) -> str:
    # Where to send people after clicking approve/reject in email
    base = os.environ.get("UI_URL", "http://localhost:8080").rstrip("/")
    return f"{base}/?request_id={request_id}"


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/decide", response_model=CreateDecisionResponse)
def decide(req: ActionRequest):
    return run_decision_loop(
        req,
        policy_engine=policy_engine,
        store=STORE,
        base_url=base_url(),
    )


@app.get("/api/requests/{request_id}")
def get_request(request_id: str):
    if request_id not in STORE:
        raise HTTPException(status_code=404, detail="Not found")
    return STORE[request_id].model_dump()


@app.api_route("/api/requests/{request_id}/approve", methods=["GET", "POST"])
def approve(request_id: str, request: Request):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    # If it's not pending, don't change anything
    if r.status != "PENDING":
        if request.method == "GET":
            return RedirectResponse(url=ui_url(request_id), status_code=303)
        return {"ok": True, "status": r.status, "note": "No-op (not pending)"}

    log_event(
        request_id=request_id,
        event_type="APPROVED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request approved",
    )

    log_event(
        request_id=request_id,
        event_type="EXECUTION_STARTED",
        actor_type="SYSTEM",
        actor_id="connector",
        summary="Execution started (after approval)",
        details={"action": r.payload.action},
    )

    # Approve then execute
    r.status = "APPROVED"
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
        details={"result_ok": bool((r.executed_result or {}).get("ok", False))},
    )

    if request.method == "GET":
        return RedirectResponse(url=ui_url(request_id), status_code=303)
    return {"ok": True, "status": r.status}


@app.api_route("/api/requests/{request_id}/reject", methods=["GET", "POST"])
def reject(request_id: str, request: Request):
    r = STORE.get(request_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")

    # If it's not pending, don't change anything
    if r.status != "PENDING":
        if request.method == "GET":
            return RedirectResponse(url=ui_url(request_id), status_code=303)
        return {"ok": True, "status": r.status, "note": "No-op (not pending)"}

    r.status = "REJECTED"
    STORE[request_id] = r

    log_event(
        request_id=request_id,
        event_type="REJECTED",
        actor_type="HUMAN",
        actor_id="email_link" if request.method == "GET" else "api_client",
        summary="Request rejected",
    )

    if request.method == "GET":
        return RedirectResponse(url=ui_url(request_id), status_code=303)
    return {"ok": True, "status": r.status}


@app.get("/api/audit")
def get_audit(request_id: Optional[str] = None, limit: int = 200):
    # newest-first
    events = AUDIT_LOG[::-1]
    if request_id:
        events = [e for e in events if e.request_id == request_id]
    limit = max(1, min(int(limit), 1000))
    return [e.model_dump() for e in events[:limit]]


@app.post("/api/policy/reload")
def reload_policy():
    policy_engine.reload()
    return {"ok": True, "message": "Policy reloaded"}
