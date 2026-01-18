# decision_loop.py
from typing import Dict
from .models import ActionRequest, CreateDecisionResponse, StoredRequest, now_ts, new_request_id
from .policy import PolicyEngine, short_hash
from .connectors import execute_action
from .approvals import maybe_send_email_approval, maybe_send_email_blocked
from .audit import log_event


def run_decision_loop(
    req: ActionRequest,
    *,
    policy_engine: PolicyEngine,
    store: Dict[str, StoredRequest],
    base_url: str,
) -> CreateDecisionResponse:
    """
    Canonical SluiceGate flow:
      INPUT -> POLICY -> DECISION -> (EXECUTE | BLOCK | PAUSE) -> AUDIT
    """
    rid = new_request_id()
    agent_type = req.metadata.get("agent_type", "Unknown Agent")

    # Audit: request received
    log_event(
        request_id=rid,
        event_type="REQUEST_CREATED",
        actor_type="SYSTEM",
        actor_id=agent_type,
        summary=f"Execution request received from {agent_type}",
        details={
            "agent_type": agent_type,
            "action": req.action,
            "amount": req.amount,
            "currency": req.currency,
        },
    )

    decision = policy_engine.decide(req.model_dump())

    # Audit: gate decision (include policy hash for provenance)
    short_policy_hash = short_hash(policy_engine.policy_hash)

    log_event(
        request_id=rid,
        event_type="GATE_DECIDED",
        actor_type="POLICY",
        actor_id=short_policy_hash,
        summary=f"Gate decision for {agent_type}: {decision}",
        details={
            "decision": decision,
            "agent_type": agent_type,
            "policy_hash": short_policy_hash,
            "policy_path": policy_engine.policy_path,
        },
    )

    if decision == "ALLOW":
        log_event(
            request_id=rid,
            event_type="EXECUTION_STARTED",
            actor_type="SYSTEM",
            actor_id="connector",
            summary="Execution started (ALLOW)",
            details={"action": req.action},
        )

        result = execute_action(req.action, req.amount, req.currency, req.metadata)

        log_event(
            request_id=rid,
            event_type="EXECUTION_COMPLETED",
            actor_type="SYSTEM",
            actor_id="connector",
            summary="Execution completed (ALLOW)",
            details={"result_ok": bool(result.get("ok", False))},
        )

        stored = StoredRequest(
            request_id=rid,
            created_at=now_ts(),
            status="EXECUTED",
            decision="ALLOW",
            payload=req,
            executed_result=result,
        )
        store[rid] = stored

        return CreateDecisionResponse(
            request_id=rid,
            decision="ALLOW",
            status=stored.status,
            message="Allowed and executed immediately.",
        )

    if decision == "BLOCK":
        stored = StoredRequest(
            request_id=rid,
            created_at=now_ts(),
            status="BLOCKED",
            decision="BLOCK",
            payload=req,
        )
        store[rid] = stored

        maybe_send_email_blocked(
            rid, req.action, req.amount, req.currency, base_url, agent_type=agent_type
        )

        return CreateDecisionResponse(
            request_id=rid,
            decision="BLOCK",
            status=stored.status,
            message="Blocked by policy.",
        )

    # PAUSE
    stored = StoredRequest(
        request_id=rid,
        created_at=now_ts(),
        status="PENDING",
        decision="PAUSE",
        payload=req,
    )
    store[rid] = stored

    maybe_send_email_approval(rid, req.action, req.amount, req.currency, base_url)

    log_event(
        request_id=rid,
        event_type="NOTIFICATION_ATTEMPTED",
        actor_type="SYSTEM",
        actor_id="email",
        summary="Approval notification attempted",
        details={"channel": "email"},
    )

    return CreateDecisionResponse(
        request_id=rid,
        decision="PAUSE",
        status=stored.status,
        message="Paused for approval.",
    )
