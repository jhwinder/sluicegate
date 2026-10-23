from __future__ import annotations

import re
import smtplib
import ssl
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from sg_service import notifications


class InlineExecutor:
    def submit(self, fn, *args):
        fn(*args)


def setup_test_service(tmp_path: Path, monkeypatch):
    from sg_service import mission_control as service

    monkeypatch.setattr(service, "NOTIFICATION_EXECUTOR", InlineExecutor())
    database_path = tmp_path / "service.sqlite3"
    signing_key_path = tmp_path / "sg-signing-key.pem"
    policy_path = tmp_path / "policy.yml"

    service_private_key = ed25519.Ed25519PrivateKey.generate()
    signing_key_path.write_bytes(
        service_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    monkeypatch.setattr(service, "DATABASE_PATH", database_path)
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", signing_key_path)
    monkeypatch.setattr(service, "POLICY_PATH", policy_path)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "test-admin-secret")

    policy_content = "\n".join([
        "version: 1",
        "default: {decision: BLOCK}",
        "rules:",
        "  - name: allow-authorized-target-after-approval",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "      - {path: target.servers, eq: [SERVER_PAUSE_01.example.gov]}",
        "      - {path: context.approval.approved, eq: true}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER_PAUSE_01.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus, nessus_catalog]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "      - type: allowed_patch_executables",
        "        executables: [msiexec.exe]",
        "    decision: ALLOW",
        "  - name: pause-authorized-target-before-approval",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "      - {path: target.servers, eq: [SERVER_PAUSE_01.example.gov]}",
        "      - {path: context.approval.approved, exists: false}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER_PAUSE_01.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus, nessus_catalog]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "      - type: allowed_patch_executables",
        "        executables: [msiexec.exe]",
        "    decision: PAUSE",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service


def test_notification_profiles_adapters_and_delivery_audit(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    with TestClient(service.app) as client:
        # Bootstrap admin
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        # 1. Register Notification Adapter
        ad_resp = client.post(
            "/admin/v1/notification-adapters",
            json={
                "adapter_id": "email-security-team",
                "adapter_type": "mock",
                "name": "Security Team Email Mock",
                "config": {"provider": "mock", "sender": "sluicegate@example.gov"},
            },
            headers=admin_headers,
        )
        assert ad_resp.status_code == 201

        # 2. Create Notification Profile for PAUSE_CREATED & REQUEST_APPROVED
        prof_resp = client.post(
            "/admin/v1/notification-profiles",
            json={
                "profile_id": "profile-pause-approvals",
                "name": "Approvals Required Alerts",
                "event_types": ["PAUSE_CREATED", "REQUEST_APPROVED"],
                "adapter_id": "email-security-team",
                "recipients": ["approver-lead@example.gov"],
            },
            headers=admin_headers,
        )
        assert prof_resp.status_code == 201

        # 3. Register agent and submit request that will PAUSE
        agent_data = client.post(
            "/admin/v1/agents",
            json={"name": "Alerting Test Agent"},
            headers=admin_headers,
        ).json()
        agent_headers = {"Authorization": f"Bearer {agent_data['api_key']}"}

        sub_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_PAUSE_01.example.gov"]},
            headers=agent_headers,
        )
        assert sub_resp.status_code == 202
        req_id = sub_resp.json()["request_id"]

        # 4. Check notification delivery audit for PAUSE_CREATED
        delivs = client.get(
            f"/admin/v1/notification-deliveries?request_id={req_id}",
            headers=admin_headers,
        ).json()
        assert len(delivs) == 1
        assert delivs[0]["event_type"] == "PAUSE_CREATED"
        assert delivs[0]["status"] == "DELIVERED"
        assert delivs[0]["profile_id"] == "profile-pause-approvals"
        assert delivs[0]["adapter_id"] == "email-security-team"

        # 5. Admin approves the request
        approve_resp = client.post(
            f"/admin/v1/requests/{req_id}/approve",
            json={"approver": "lead-admin", "comment": "Verified"},
            headers=admin_headers,
        )
        assert approve_resp.status_code == 200

        # Check notification delivery audit now has REQUEST_APPROVED as well
        delivs_after = client.get(
            f"/admin/v1/notification-deliveries?request_id={req_id}",
            headers=admin_headers,
        ).json()
        assert len(delivs_after) == 2
        event_types = [d["event_type"] for d in delivs_after]
        assert "PAUSE_CREATED" in event_types
        assert "REQUEST_APPROVED" in event_types

        # 6. Profile CRUD: update and delete
        patch_prof = client.patch(
            "/admin/v1/notification-profiles/profile-pause-approvals",
            json={"name": "Renamed Profile", "enabled": False},
            headers=admin_headers,
        )
        assert patch_prof.status_code == 200
        assert patch_prof.json()["enabled"] == 0

        del_resp = client.delete(
            "/admin/v1/notification-profiles/profile-pause-approvals",
            headers=admin_headers,
        )
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "DELETED"


def admin_headers(client: TestClient) -> dict[str, str]:
    key = client.post(
        "/admin/v1/credentials/admin/admin",
        headers={"Authorization": "Bearer test-admin-secret"},
    ).json()["api_key"]
    return {"Authorization": f"Bearer {key}"}


def create_pause_request(client: TestClient, headers: dict[str, str]) -> str:
    agent = client.post("/admin/v1/agents", json={"name": "Mail Test Agent"}, headers=headers).json()
    response = client.post(
        "/api/v1/patch-requests",
        json={"servers": ["SERVER_PAUSE_01.example.gov"]},
        headers={"Authorization": f"Bearer {agent['api_key']}"},
    )
    assert response.status_code == 202
    return response.json()["request_id"]


def adapter_state(client: TestClient, headers: dict[str, str], adapter_id: str = "mail") -> dict:
    return next(item for item in client.get("/admin/v1/notification-adapters", headers=headers).json() if item["adapter_id"] == adapter_id)


def deliveries(client: TestClient, headers: dict[str, str], request_id: str) -> list[dict]:
    return client.get(f"/admin/v1/notification-deliveries?request_id={request_id}", headers=headers).json()


RESEND_CONFIG = {"sender": "sluicegate@example.gov"}


def create_email_adapter_and_profile(client: TestClient, headers: dict[str, str], events: list[str]) -> None:
    created = client.post(
        "/admin/v1/notification-adapters",
        json={"adapter_id": "mail", "adapter_type": "resend", "name": "Mail", "config": RESEND_CONFIG},
        headers=headers,
    )
    assert created.status_code == 201
    profile = client.post(
        "/admin/v1/notification-profiles",
        json={"profile_id": "approvals", "name": "Approvals", "event_types": events, "adapter_id": "mail", "recipients": ["approver@example.gov"]},
        headers=headers,
    )
    assert profile.status_code == 201


def verify_adapter(client: TestClient, headers: dict[str, str], sent: list) -> None:
    response = client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}, headers=headers)
    assert response.status_code == 200
    token = re.search(r"/notification-verify/([A-Za-z0-9_-]+)", sent[-1][4]).group(1)
    assert client.post(f"/notification-verify/{token}").status_code == 200
    assert adapter_state(client, headers)["verified"] is True


@pytest.fixture
def mail_env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_secret_value")
    monkeypatch.delenv("RESEND_API_KEY_FILE", raising=False)
    monkeypatch.setenv("SG_PUBLIC_URL", "https://sluice.example.gov")


def test_unverified_email_adapter_does_not_send(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        request_id = create_pause_request(client, headers)
        delivery = deliveries(client, headers, request_id)[0]

    assert sent == []
    assert delivery["status"] == "FAILED"
    assert "not verified" in delivery["detail"]["error"]


def test_adapter_verification_link_flow_and_invalidation(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        created = client.post(
            "/admin/v1/notification-adapters",
            json={"adapter_id": "mail", "adapter_type": "resend", "name": "Mail", "config": RESEND_CONFIG},
            headers=headers,
        )
        assert created.json()["verified"] is False
        assert created.json()["secrets_configured"] == {"RESEND_API_KEY": True}
        assert "re_secret_value" not in created.text

        assert client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "not-an-address"}, headers=headers).status_code == 422
        assert client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}).status_code == 401
        assert client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}, headers=headers).status_code == 200
        message = sent[-1][4]
        assert "https://sluice.example.gov/notification-verify/" in message
        token = re.search(r"/notification-verify/([A-Za-z0-9_-]+)", message).group(1)

        # Opening the link must not verify; only the explicit confirmation does.
        assert client.get(f"/notification-verify/{token}").status_code == 200
        assert adapter_state(client, headers)["verified"] is False
        assert client.post(f"/notification-verify/{token}").status_code == 200
        assert adapter_state(client, headers)["verified"] is True
        assert client.post(f"/notification-verify/{token}").status_code == 410
        assert client.get("/notification-verify/not-a-real-token").status_code == 410

        monkeypatch.setenv("RESEND_API_KEY", "re_rotated_value")
        assert adapter_state(client, headers)["verified"] is False
        monkeypatch.setenv("RESEND_API_KEY", "re_secret_value")
        assert adapter_state(client, headers)["verified"] is True

        client.post(
            "/admin/v1/notification-adapters",
            json={"adapter_id": "mail", "adapter_type": "resend", "name": "Mail", "config": {"sender": "other@example.gov"}},
            headers=headers,
        )
        assert adapter_state(client, headers)["verified"] is False


def test_expired_verification_link_is_rejected(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))
    monkeypatch.setattr(service, "NOTIFICATION_VERIFICATION_TTL_SECONDS", -1)

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}, headers=headers)
        token = re.search(r"/notification-verify/([A-Za-z0-9_-]+)", sent[-1][4]).group(1)
        assert client.post(f"/notification-verify/{token}").status_code == 410
        assert adapter_state(client, headers)["verified"] is False


def test_verification_requires_service_secrets_and_reports_send_failures(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    def failing_send(*args):
        raise notifications.NotificationError("Resend rejected the message (HTTP 401)", retryable=False)

    monkeypatch.setattr(notifications, "send_email", failing_send)
    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        failed = client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}, headers=headers)
        assert failed.status_code == 502
        assert "re_secret_value" not in failed.text
        monkeypatch.delenv("RESEND_API_KEY")
        missing = client.post("/admin/v1/notification-adapters/mail/verify", json={"recipient": "approver@example.gov"}, headers=headers)
        assert missing.status_code == 409
        assert "RESEND_API_KEY" in missing.json()["detail"]


def test_pause_notification_email_links_to_authenticated_console(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED", "REQUEST_REJECTED"])
        verify_adapter(client, headers, sent)
        sent.clear()

        request_id = create_pause_request(client, headers)
        assert deliveries(client, headers, request_id)[0]["status"] == "DELIVERED"
        adapter_type, _config, recipients, subject, body, _key = sent[0]
        assert adapter_type == "resend" and recipients == ["approver@example.gov"]
        assert "paused pending approval" in subject
        assert "https://sluice.example.gov/admin/ui#approvals" in body

        # Email can only lead to the console; approval itself requires an authenticated explicit action.
        assert client.post(f"/admin/v1/requests/{request_id}/approve").status_code == 401
        assert client.get(f"/admin/v1/requests/{request_id}/approve", headers=headers).status_code == 405
        assert client.get(f"/admin/v1/requests/{request_id}", headers=headers).json()["status"] == "WAITING_FOR_APPROVAL"


def test_failed_delivery_is_retried_then_delivered(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        verify_adapter(client, headers, sent)

        outcomes = [notifications.NotificationError("Resend returned HTTP 503", retryable=True), None]

        def flaky(*args):
            outcome = outcomes.pop(0)
            if outcome:
                raise outcome

        monkeypatch.setattr(notifications, "send_email", flaky)
        request_id = create_pause_request(client, headers)
        first = deliveries(client, headers, request_id)[0]
        assert first["status"] == "RETRYING" and first["attempts"] == 1
        assert first["detail"]["error"] == "Resend returned HTTP 503"

        service.process_due_deliveries(now=time.time())
        assert deliveries(client, headers, request_id)[0]["attempts"] == 1  # backoff has not elapsed

        service.process_due_deliveries(now=time.time() + 3600)
        final = deliveries(client, headers, request_id)[0]
        assert final["status"] == "DELIVERED" and final["attempts"] == 2


def test_permanent_failure_is_not_retried(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        verify_adapter(client, headers, sent)

        def rejected(*args):
            raise notifications.NotificationError("SMTP authentication failed", retryable=False)

        monkeypatch.setattr(notifications, "send_email", rejected)
        request_id = create_pause_request(client, headers)
        service.process_due_deliveries(now=time.time() + 3600)
        delivery = deliveries(client, headers, request_id)[0]

    assert delivery["status"] == "FAILED" and delivery["attempts"] == 1
    assert delivery["detail"]["error"] == "SMTP authentication failed"


def test_retries_are_bounded(tmp_path: Path, monkeypatch, mail_env) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    sent: list = []
    monkeypatch.setattr(notifications, "send_email", lambda *args: sent.append(args))
    monkeypatch.setattr(service, "NOTIFICATION_MAX_ATTEMPTS", 2)

    with TestClient(service.app) as client:
        headers = admin_headers(client)
        create_email_adapter_and_profile(client, headers, ["PAUSE_CREATED"])
        verify_adapter(client, headers, sent)

        def unavailable(*args):
            raise notifications.NotificationError("Resend request timed out", retryable=True)

        monkeypatch.setattr(notifications, "send_email", unavailable)
        request_id = create_pause_request(client, headers)
        service.process_due_deliveries(now=time.time() + 3600)
        service.process_due_deliveries(now=time.time() + 7200)
        delivery = deliveries(client, headers, request_id)[0]

    assert delivery["status"] == "FAILED" and delivery["attempts"] == 2


def test_duplicate_events_create_one_delivery(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        headers = admin_headers(client)
        client.post("/admin/v1/notification-adapters", json={"adapter_id": "audit", "adapter_type": "mock", "name": "Audit"}, headers=headers)
        client.post(
            "/admin/v1/notification-profiles",
            json={"profile_id": "p", "name": "P", "event_types": ["PAUSE_CREATED"], "adapter_id": "audit"},
            headers=headers,
        )
        for _ in range(3):
            service.dispatch_notifications("PAUSE_CREATED", "REQ-DUP", "summary", {})
        assert len(deliveries(client, headers, "REQ-DUP")) == 1


def test_adapter_and_profile_validation(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        headers = admin_headers(client)

        def adapter(adapter_type: str, config: dict) -> int:
            return client.post(
                "/admin/v1/notification-adapters",
                json={"adapter_id": "a", "adapter_type": adapter_type, "name": "A", "config": config},
                headers=headers,
            ).status_code

        assert adapter("email", {}) == 422
        assert adapter("resend", {}) == 422
        assert adapter("resend", {"sender": "bad address"}) == 422
        assert adapter("resend", {"sender": "a@example.gov", "api_key": "inline-secret"}) == 422
        assert adapter("smtp", {"sender": "a@example.gov"}) == 422
        assert adapter("smtp", {"sender": "a@example.gov", "host": "mail.example.gov", "tls_mode": "none", "auth_mode": "login"}) == 422
        assert adapter("smtp", {"sender": "a@example.gov", "host": "mail.example.gov", "port": 70000}) == 422
        assert adapter("webhook", {"url": "ftp://example.gov"}) == 422
        assert adapter("smtp", {"sender": "a@example.gov", "host": "mail.example.gov"}) == 201
        stored = adapter_state(client, headers, "a")
        assert stored["config"]["port"] == 587 and stored["config"]["tls_mode"] == "starttls"

        profile = {"profile_id": "p", "name": "P", "event_types": ["PAUSE_CREATED"], "adapter_id": "a", "recipients": ["ok@example.gov"]}
        assert client.post("/admin/v1/notification-profiles", json={**profile, "adapter_id": "missing"}, headers=headers).status_code == 422
        assert client.post("/admin/v1/notification-profiles", json={**profile, "recipients": []}, headers=headers).status_code == 422
        assert client.post("/admin/v1/notification-profiles", json={**profile, "recipients": ["x@example.gov\nBcc: y@example.gov"]}, headers=headers).status_code == 422
        assert client.post("/admin/v1/notification-profiles", json=profile, headers=headers).status_code == 201
        assert client.delete("/admin/v1/notification-adapters/a", headers=headers).status_code == 409


def test_webhook_failures_are_recorded(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setattr(notifications.httpx, "post", lambda *a, **k: SimpleNamespace(status_code=404))
    with TestClient(service.app) as client:
        headers = admin_headers(client)
        client.post(
            "/admin/v1/notification-adapters",
            json={"adapter_id": "hook", "adapter_type": "webhook", "name": "Hook", "config": {"url": "https://hooks.example.gov/x"}},
            headers=headers,
        )
        client.post(
            "/admin/v1/notification-profiles",
            json={"profile_id": "p", "name": "P", "event_types": ["PAUSE_CREATED"], "adapter_id": "hook"},
            headers=headers,
        )
        service.dispatch_notifications("PAUSE_CREATED", "REQ-HOOK", "summary", {})
        delivery = deliveries(client, headers, "REQ-HOOK")[0]

    assert delivery["status"] == "FAILED"
    assert "HTTP 404" in delivery["detail"]["error"]


class FakeSMTP:
    behavior: dict = {}
    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        if "connect" in self.behavior:
            raise self.behavior["connect"]
        self.calls: list = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        if "starttls" in self.behavior:
            raise self.behavior["starttls"]
        self.calls.append("starttls")

    def login(self, username, password):
        if "login" in self.behavior:
            raise self.behavior["login"]
        self.calls.append(("login", username, password))

    def send_message(self, message):
        if "send" in self.behavior:
            raise self.behavior["send"]
        self.calls.append(("send", message["To"], message["Subject"]))


SMTP_CONFIG = {"sender": "sluicegate@example.gov", "host": "mail.example.gov", "port": 587, "tls_mode": "starttls", "auth_mode": "login"}


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.behavior, FakeSMTP.instances = {}, []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SG_SMTP_USERNAME", "svc-sluicegate")
    monkeypatch.setenv("SG_SMTP_PASSWORD", "smtp-secret")
    return FakeSMTP


def send_smtp(config: dict = SMTP_CONFIG) -> None:
    notifications.send_email("smtp", config, ["approver@example.gov"], "Subject\r\nBcc: x@example.gov", "body", "key")


def test_smtp_sends_with_starttls_and_login(fake_smtp) -> None:
    send_smtp()
    calls = fake_smtp.instances[0].calls
    assert calls[:4] == ["ehlo", "starttls", "ehlo", ("login", "svc-sluicegate", "smtp-secret")]
    assert calls[4][0] == "send" and "\n" not in calls[4][2]


def test_smtp_relay_without_authentication(fake_smtp, monkeypatch) -> None:
    monkeypatch.delenv("SG_SMTP_USERNAME")
    send_smtp({**SMTP_CONFIG, "auth_mode": "none", "tls_mode": "none", "port": 25})
    assert [call for call in fake_smtp.instances[0].calls if isinstance(call, tuple)][0][0] == "send"


@pytest.mark.parametrize(
    ("behavior", "retryable"),
    [
        ({"login": smtplib.SMTPAuthenticationError(535, b"denied")}, False),
        ({"starttls": ssl.SSLCertVerificationError("certificate verify failed")}, False),
        ({"connect": ConnectionRefusedError()}, True),
        ({"connect": TimeoutError()}, True),
        ({"send": smtplib.SMTPResponseException(451, b"try later")}, True),
        ({"send": smtplib.SMTPResponseException(550, b"no such user")}, False),
        ({"send": smtplib.SMTPServerDisconnected("closed")}, True),
        ({"starttls": smtplib.SMTPNotSupportedError("no STARTTLS")}, False),
    ],
)
def test_smtp_failures_are_classified(fake_smtp, behavior, retryable) -> None:
    fake_smtp.behavior = behavior
    with pytest.raises(notifications.NotificationError) as caught:
        send_smtp()
    assert caught.value.retryable is retryable
    assert "smtp-secret" not in str(caught.value) and "svc-sluicegate" not in str(caught.value)


def test_smtp_missing_credentials_fail_without_connecting(fake_smtp, monkeypatch) -> None:
    monkeypatch.delenv("SG_SMTP_PASSWORD")
    with pytest.raises(notifications.NotificationError) as caught:
        send_smtp()
    assert caught.value.retryable is False and fake_smtp.instances == []


def test_resend_request_and_error_classification(monkeypatch) -> None:
    monkeypatch.setenv("RESEND_API_KEY", "re_secret_value")
    monkeypatch.delenv("RESEND_API_KEY_FILE", raising=False)
    captured: dict = {}

    def respond(status_code=200, error=None):
        def post(url, json=None, headers=None, timeout=None):
            captured.update(url=url, json=json, headers=headers)
            if error:
                raise error
            return SimpleNamespace(status_code=status_code)

        return post

    def send() -> None:
        notifications.send_email("resend", {"sender": "sluicegate@example.gov"}, ["approver@example.gov"], "Subject", "body", "delivery-1")

    monkeypatch.setattr(notifications.httpx, "post", respond(200))
    send()
    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["headers"] == {"Authorization": "Bearer re_secret_value", "Idempotency-Key": "delivery-1"}
    assert captured["json"]["to"] == ["approver@example.gov"]

    for status_code, retryable in [(429, True), (503, True), (401, False), (422, False), (302, False)]:
        monkeypatch.setattr(notifications.httpx, "post", respond(status_code))
        with pytest.raises(notifications.NotificationError) as caught:
            send()
        assert caught.value.retryable is retryable
        assert "re_secret_value" not in str(caught.value)

    for error in (httpx.ReadTimeout("slow"), httpx.ConnectError("down")):
        monkeypatch.setattr(notifications.httpx, "post", respond(error=error))
        with pytest.raises(notifications.NotificationError) as caught:
            send()
        assert caught.value.retryable is True

    monkeypatch.delenv("RESEND_API_KEY")
    with pytest.raises(notifications.NotificationError) as caught:
        send()
    assert caught.value.retryable is False


def test_secret_file_takes_precedence_over_environment(tmp_path: Path, monkeypatch) -> None:
    secret_file = tmp_path / "resend-key"
    secret_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("RESEND_API_KEY", "from-env")
    monkeypatch.setenv("RESEND_API_KEY_FILE", str(secret_file))
    assert notifications.resolve_secret("RESEND_API_KEY") == "from-file"
    monkeypatch.setenv("RESEND_API_KEY_FILE", str(tmp_path / "missing"))
    assert notifications.resolve_secret("RESEND_API_KEY") is None
