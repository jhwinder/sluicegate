import os
from typing import Any, Dict, Optional

import resend
from sg_core.adapters import ApprovalAdapter, ApprovalRequest

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
APPROVER_EMAIL = os.environ.get("APPROVER_EMAIL", "").strip()
RESEND_FROM = os.environ.get("RESEND_FROM", "onboarding@resend.dev").strip()

# UI link (for informational emails / convenience)
UI_URL = os.environ.get("UI_URL", "http://localhost:8080").rstrip("/")

# -----------------------------------------------------------------------------
# Demo Email Approval Adapter (implements sg_core.adapters.ApprovalAdapter)
# -----------------------------------------------------------------------------

class DemoEmailApprovalAdapter(ApprovalAdapter):
    """
    Demo-only email approval adapter.

    This lives in sluice-demo (host app) and implements the sg_core ApprovalAdapter
    contract. It can later be moved into a separate sg_adapters package unchanged.
    """

    name = "demo-email"

    def __init__(self) -> None:
        if not RESEND_API_KEY:
            raise RuntimeError("RESEND_API_KEY is not set")
        if not APPROVER_EMAIL:
            raise RuntimeError("APPROVER_EMAIL is not set")

        resend.api_key = RESEND_API_KEY

    def send(self, approval: ApprovalRequest) -> None:
        subject = f"SluiceGate approval required: {approval.action_name} — {approval.summary}"

        text = (
            "SluiceGate approval required\n\n"
            f"request_id: {approval.request_id}\n"
            f"action: {approval.action_name}\n"
            f"summary: {approval.summary}\n"
            f"details: {approval.details}\n\n"
            f"APPROVE: {approval.approve_url}\n"
            f"REJECT:  {approval.reject_url}\n\n"
            "Nothing executes without passing SluiceGate.\n"
        )

        resend.Emails.send(
            {
                "from": RESEND_FROM,
                "to": [APPROVER_EMAIL],
                "subject": subject,
                "text": text,
            }
        )


# Singleton instance (fine for demo)
_EMAIL_ADAPTER = DemoEmailApprovalAdapter()

# -----------------------------------------------------------------------------
# Demo-facing functions (called by main.py)
# -----------------------------------------------------------------------------

def maybe_send_email_approval(
    request_id: str,
    action: str,
    amount: int,
    currency: str,
    base_url: str,
    reason: Optional[str] = None,
    approver_group: Optional[str] = None,
) -> None:
    """
    Send an approval email (Approve/Reject links) for a PAUSE decision.
    """
    approve_url = f"{base_url.rstrip('/')}/api/requests/{request_id}/approve"
    reject_url = f"{base_url.rstrip('/')}/api/requests/{request_id}/reject"

    approval = ApprovalRequest(
        request_id=request_id,
        action_name=action,
        summary=f"{amount} {currency}".strip(),
        details={"amount": amount, "currency": currency},
        approve_url=approve_url,
        reject_url=reject_url,
        reason=reason,
        approver_group=approver_group,
    )

    _EMAIL_ADAPTER.send(approval)


def maybe_send_email_blocked(
    request_id: str,
    action: str,
    amount: int,
    currency: str,
    agent_type: str = "Unknown Agent",
    policy_hash: Optional[str] = None,
    message: Optional[str] = None,
) -> None:
    """
    Send an informational email when a request is BLOCKED by policy.
    (No action required.)
    """
    subject = f"SluiceGate BLOCKED: {agent_type} → {action} ({amount} {currency})"

    view_url = f"{UI_URL}/?request_id={request_id}"

    lines = [
        "SluiceGate blocked an autonomous action",
        "",
        f"request_id: {request_id}",
        f"agent_type: {agent_type}",
        f"action: {action}",
        f"amount: {amount} {currency}",
    ]
    if policy_hash:
        lines.append(f"policy_hash: {policy_hash}")
    if message:
        lines.extend(["", f"message: {message}"])

    lines.extend(
        [
            "",
            "Result: BLOCKED by policy",
            "",
            f"View in demo UI: {view_url}",
            "",
            "Principle: nothing executes without passing the gate.",
        ]
    )

    resend.Emails.send(
        {
            "from": RESEND_FROM,
            "to": [APPROVER_EMAIL],
            "subject": subject,
            "text": "\n".join(lines),
        }
    )


def build_approval_request(
    request_id: str,
    action: str,
    amount: int,
    currency: str,
    base_url: str,
    reason: Optional[str] = None,
    approver_group: Optional[str] = None,
) -> ApprovalRequest:
    """
    Convenience helper if you prefer to create ApprovalRequest in main.py and call adapter.send().
    """
    approve_url = f"{base_url.rstrip('/')}/api/requests/{request_id}/approve"
    reject_url = f"{base_url.rstrip('/')}/api/requests/{request_id}/reject"

    return ApprovalRequest(
        request_id=request_id,
        action_name=action,
        summary=f"{amount} {currency}".strip(),
        details={"amount": amount, "currency": currency},
        approve_url=approve_url,
        reject_url=reject_url,
        reason=reason,
        approver_group=approver_group,
    )
