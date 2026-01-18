import os

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
APPROVER_EMAIL = os.environ.get("APPROVER_EMAIL", "").strip()

def maybe_send_email_approval(request_id: str, action: str, amount: int, currency: str, base_url: str) -> None:
    """
    Sends an email with Approve/Reject links.
    If env vars aren't present, it becomes a no-op (demo still works via UI).
    """
    if not RESEND_API_KEY or not APPROVER_EMAIL:
        return

    approve_url = f"{base_url}/api/requests/{request_id}/approve"
    reject_url = f"{base_url}/api/requests/{request_id}/reject"

    subject = f"SluiceGate approval required: {action} ({amount} {currency})"

    text = (
        "SluiceGate approval required\n\n"
        f"request_id: {request_id}\n"
        f"action: {action}\n"
        f"amount: {amount} {currency}\n\n"
        f"APPROVE: {approve_url}\n"
        f"REJECT:  {reject_url}\n\n"
        "Nothing executes without passing SluiceGate!\n"
    )

    try:
        import resend  # type: ignore
        resend.api_key = RESEND_API_KEY

        # Resend requires a verified From address on your account.
        # Use your verified sender/domain here:
        from_email = os.environ.get("RESEND_FROM", "onboarding@resend.dev")

        resend.Emails.send({
            "from": from_email,
            "to": [APPROVER_EMAIL],
            "subject": subject,
            "text": text,
        })
    except Exception:
        # Don't break the demo if email fails.
        pass
    
def maybe_send_email_blocked(request_id: str, action: str, amount: int, currency: str, base_url: str, agent_type: str = "Unknown Agent") -> None:
    """
    Sends an informational email when a request is BLOCKED by policy.
    """
    if not RESEND_API_KEY or not APPROVER_EMAIL:
        return

    # Link back to UI to view the record (status, audit trail, etc.)
    ui_base = os.environ.get("UI_URL", "http://localhost:8080").rstrip("/")
    view_url = f"{ui_base}/?request_id={request_id}"

    subject = f"SluiceGate BLOCKED: {agent_type} → {action} ({amount} {currency})"

    text = (
        "SluiceGate blocked an autonomous action\n\n"
        f"request_id: {request_id}\n"
        f"agent_type: {agent_type}\n"
        f"action: {action}\n"
        f"amount: {amount} {currency}\n\n"
        "Result: BLOCKED by policy\n\n"
        f"View in demo UI: {view_url}\n"
        "\n"
        "Principle: nothing executes without passing the gate.\n"
    )

    try:
        import resend  # type: ignore
        resend.api_key = RESEND_API_KEY
        from_email = os.environ.get("RESEND_FROM", "onboarding@resend.dev")

        resend.Emails.send({
            "from": from_email,
            "to": [APPROVER_EMAIL],
            "subject": subject,
            "text": text,
        })
    except Exception:
        # Don't break the demo if email fails.
        pass
