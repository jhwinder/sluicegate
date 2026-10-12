from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.approvals import maybe_send_email_approval
from app.models import (
    ActionRequest,
    CreateDecisionResponse,
)

app = FastAPI(title="SluiceGate Demo BFF (connected to sg_service)")

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

SG_SERVICE_URL = os.environ.get("SG_SERVICE_URL", "http://sg-service:8443").rstrip("/")
SG_AGENT_API_KEY = os.environ.get("SG_AGENT_API_KEY", "")
SG_ADMIN_API_KEY = os.environ.get("SG_ADMIN_API_KEY", "")

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
UI_URL = os.environ.get("UI_URL", "http://localhost:8080").rstrip("/")


def ui_redirect(request_id: str) -> RedirectResponse:
    return RedirectResponse(
        url=f"{UI_URL}/?request_id={request_id}",
        status_code=303,
    )


def agent_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {SG_AGENT_API_KEY}",
        "Content-Type": "application/json",
    }


def admin_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {SG_ADMIN_API_KEY}",
        "Content-Type": "application/json",
    }


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------


@app.get("/health")
def health():
    service_ok = False
    try:
        r = requests.get(f"{SG_SERVICE_URL}/health", timeout=3.0)
        service_ok = (r.status_code == 200)
    except Exception:
        pass
    return {"ok": True, "sg_service_connected": service_ok}


@app.post("/api/decide", response_model=CreateDecisionResponse)
def decide(req: ActionRequest):
    action_payload = {
        "capability": req.action,
        "target": {"type": "API", "id": req.action},
        "parameters": {
            "amount": req.amount,
            "currency": (req.currency or "USD").upper(),
            **req.metadata,
        },
        "context": {
            "demo": True,
            "amount": req.amount,
            "currency": (req.currency or "USD").upper(),
            "agent_type": req.metadata.get("agent_type", "Billing Agent"),
        },
    }

    try:
        submit_resp = requests.post(
            f"{SG_SERVICE_URL}/api/v1/actions",
            json=action_payload,
            headers=agent_headers(),
            timeout=10.0,
        )
        if submit_resp.status_code not in (200, 202):
            raise HTTPException(status_code=submit_resp.status_code, detail=submit_resp.text)
        data = submit_resp.json()
        request_id = data["request_id"]
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=f"Failed to communicate with sg_service: {e}")

    try:
        admin_resp = requests.get(
            f"{SG_SERVICE_URL}/admin/v1/requests/{request_id}",
            headers=admin_headers(),
            timeout=10.0,
        )
        admin_data = admin_resp.json() if admin_resp.status_code == 200 else {}
    except requests.RequestException:
        admin_data = {}

    decision = admin_data.get("policy_decision", "ALLOW" if data.get("status") == "ACCEPTED" else "BLOCK")
    mission_status = admin_data.get("status", "QUEUED")

    if decision == "PAUSE" or mission_status == "WAITING_FOR_APPROVAL":
        ui_status = "PENDING"
    elif decision == "BLOCK" or mission_status in ("CLOSED", "MISSION_REJECTED"):
        ui_status = "BLOCKED"
    elif mission_status == "MISSION_COMPLETE_SUCCEEDED":
        ui_status = "EXECUTED"
    else:
        ui_status = "EXECUTED" if decision == "ALLOW" else "PENDING"

    message = (
        "Allowed by policy."
        if decision == "ALLOW"
        else "Paused pending approval."
        if decision == "PAUSE"
        else "Blocked by policy."
    )

    if decision == "PAUSE":
        maybe_send_email_approval(
            request_id=request_id,
            action=req.action,
            amount=req.amount,
            currency=req.currency,
            base_url=BASE_URL,
        )

    return CreateDecisionResponse(
        request_id=request_id,
        decision=decision,
        status=ui_status,
        message=message,
        resume_token=request_id,
    )


@app.get("/api/requests/{request_id}")
def get_request(request_id: str):
    try:
        r = requests.get(
            f"{SG_SERVICE_URL}/admin/v1/requests/{request_id}",
            headers=admin_headers(),
            timeout=10.0,
        )
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Not found")
        data = r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=f"sg_service error: {e}")

    decision = data.get("policy_decision", "BLOCK")
    mission_status = data.get("status", "")

    if mission_status == "WAITING_FOR_APPROVAL":
        ui_status = "PENDING"
    elif mission_status in ("CLOSED", "MISSION_REJECTED", "MISSION_COMPLETE_FAILED"):
        ui_status = "REJECTED" if decision == "REJECTED" else "BLOCKED"
    elif mission_status in ("MISSION_COMPLETE_SUCCEEDED", "QUEUED", "CLAIMED", "MISSION_ACKNOWLEDGED", "MISSION_IN_PROGRESS"):
        ui_status = "EXECUTED"
    else:
        ui_status = "PENDING"

    return {
        "request_id": request_id,
        "created_at": data.get("created_at", 0),
        "payload": {
            "action": "stripe.refund",
            "amount": 0,
            "currency": "USD",
            "metadata": {},
        },
        "decision": decision,
        "status": ui_status,
        "policy_hash": data.get("policy_hash", ""),
        "resume_token": request_id,
        "executed_result": {"status": mission_status, "minion_id": data.get("minion_id")},
    }


@app.api_route("/api/requests/{request_id}/approve", methods=["GET", "POST"])
def approve(request_id: str, request: Request):
    approver = "email_link" if request.method == "GET" else "admin_user"
    try:
        r = requests.post(
            f"{SG_SERVICE_URL}/admin/v1/requests/{request_id}/approve",
            json={"approver": approver, "comment": "Approved via SluiceGate Demo UI"},
            headers=admin_headers(),
            timeout=10.0,
        )
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Not found")
        data = r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=f"sg_service error: {e}")

    if request.method == "GET":
        return ui_redirect(request_id)
    return {"ok": True, "status": data.get("status")}


@app.api_route("/api/requests/{request_id}/reject", methods=["GET", "POST"])
def reject(request_id: str, request: Request):
    approver = "email_link" if request.method == "GET" else "admin_user"
    try:
        r = requests.post(
            f"{SG_SERVICE_URL}/admin/v1/requests/{request_id}/reject",
            json={"approver": approver, "comment": "Rejected via SluiceGate Demo UI"},
            headers=admin_headers(),
            timeout=10.0,
        )
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Not found")
        data = r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=f"sg_service error: {e}")

    if request.method == "GET":
        return ui_redirect(request_id)
    return {"ok": True, "status": data.get("status")}


@app.get("/api/audit")
def get_audit(request_id: Optional[str] = None, limit: int = 200):
    try:
        r = requests.get(
            f"{SG_SERVICE_URL}/admin/v1/missions",
            headers=admin_headers(),
            timeout=10.0,
        )
        missions = r.json() if r.status_code == 200 else []
    except Exception:
        missions = []

    events = []
    for m in missions:
        rid = m.get("request_id", "")
        if request_id and rid != request_id:
            continue
        events.append({
            "request_id": rid,
            "event_type": "GATE_DECIDED" if m.get("status") in ("QUEUED", "WAITING_FOR_APPROVAL") else "EXECUTION_COMPLETED",
            "actor_type": "SYSTEM",
            "actor_id": "sg_service",
            "summary": f"Mission {m.get('mission_id')}: {m.get('status')}",
            "details": {"minion_id": m.get("minion_id"), "status": m.get("status")},
            "timestamp": m.get("updated_at", 0),
        })

    return events[:limit]


@app.post("/api/policy/reload")
def reload_policy():
    try:
        r = requests.post(
            f"{SG_SERVICE_URL}/admin/v1/policy/reload",
            headers=admin_headers(),
            timeout=10.0,
        )
        if r.status_code == 200:
            return {"ok": True, "message": "Policy reloaded in sg_service"}
        raise HTTPException(status_code=r.status_code, detail=r.text)
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=f"Failed to reload policy: {e}")
