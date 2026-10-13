from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def setup_test_service(tmp_path: Path, monkeypatch):
    from sg_service import minion_mission_control as service

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
        "default: {decision: PAUSE}",
        "rules:",
        "  - name: allow-approved",
        "    when:",
        "      - {path: context.approval.approved, eq: true}",
        "    decision: ALLOW",
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
