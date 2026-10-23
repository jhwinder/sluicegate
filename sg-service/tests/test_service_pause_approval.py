from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def test_service_pause_and_approval_workflow(tmp_path: Path, monkeypatch) -> None:
    from sg_service import mission_control as service

    database_path = tmp_path / "service.sqlite3"
    signing_key_path = tmp_path / "sg-signing-key.pem"
    policy_path = tmp_path / "policy.yml"

    service_private_key = ed25519.Ed25519PrivateKey.generate()
    minion_private_key = ed25519.Ed25519PrivateKey.generate()
    signing_key_path.write_bytes(
        service_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    minion_public_key = minion_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    monkeypatch.setattr(service, "DATABASE_PATH", database_path)
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", signing_key_path)
    monkeypatch.setattr(service, "POLICY_PATH", policy_path)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "test-admin-secret")

    # Policy with approval requirement rule:
    # If not approved yet, PAUSE. If approved, ALLOW.
    policy_content = "\n".join([
        "version: 1",
        "default: {decision: BLOCK}",
        "rules:",
        "  - name: allow-server-when-approved",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "      - {path: target.servers, eq: [SERVER01.example.gov]}",
        "      - {path: context.approval.approved, eq: true}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER01.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus, nessus_catalog]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: true",
        "        maintenance_window: null",
        "    decision: ALLOW",
        "  - name: pause-server-before-approval",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "      - {path: target.servers, eq: [SERVER01.example.gov]}",
        "      - {path: context.approval.approved, exists: false}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER01.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus, nessus_catalog]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: true",
        "        maintenance_window: null",
        "    decision: PAUSE",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")

    with TestClient(service.app) as client:
        # Issue credentials
        admin_resp = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        )
        admin_key = admin_resp.json()["api_key"]

        agent_key = client.post(
            "/admin/v1/credentials/agent/patch-agent",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]

        minion_key = client.post(
            "/admin/v1/credentials/minion/PATCH-01",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]

        client.post(
            "/admin/v1/minions/PATCH-01/enroll",
            params={"public_key": minion_public_key},
            headers={"Authorization": f"Bearer {admin_key}"},
        )

        # 1. Agent submits request requiring reboot -> Policy evaluates to PAUSE
        req_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER01.example.gov"]},
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert req_resp.status_code == 202
        request_id = req_resp.json()["request_id"]

        # Agent sees PENDING
        status_resp = client.get(
            f"/api/v1/requests/{request_id}",
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert status_resp.json()["status"] == "PENDING"

        # Minion tries to claim -> nothing claimable!
        claim_resp = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert claim_resp.json() is None

        # 2. Admin approves the request
        approve_resp = client.post(
            f"/admin/v1/requests/{request_id}/approve",
            json={"approver": "sec-lead", "comment": "Approved for maintenance window"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert approve_resp.status_code == 200
        assert approve_resp.json()["decision"] == "ALLOW"
        assert approve_resp.json()["status"] == "QUEUED"

        # 3. Now Minion can claim the newly authorized mission!
        claim_after = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert claim_after.status_code == 200
        claimed_mission = claim_after.json()
        assert claimed_mission is not None
        assert claimed_mission["envelope"]["policy_decision"] == "ALLOW"
        assert claimed_mission["envelope"]["approval_evidence"]["approver"] == "sec-lead"


def test_service_rejection_workflow(tmp_path: Path, monkeypatch) -> None:
    from sg_service import mission_control as service

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
        "  - name: pause-approved-target",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "      - {path: target.servers, eq: [SERVER02.example.gov]}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER02.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "    decision: PAUSE",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")

    with TestClient(service.app) as client:
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]

        agent_key = client.post(
            "/admin/v1/credentials/agent/patch-agent",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]

        req_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER02.example.gov"]},
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        request_id = req_resp.json()["request_id"]

        # Admin rejects
        reject_resp = client.post(
            f"/admin/v1/requests/{request_id}/reject",
            json={"approver": "sec-lead", "comment": "Disallowed by change freeze"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert reject_resp.status_code == 200
        assert reject_resp.json()["decision"] == "REJECTED"
        assert reject_resp.json()["status"] == "CLOSED"

        # Agent sees CLOSED
        agent_status = client.get(
            f"/api/v1/requests/{request_id}",
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert agent_status.json()["status"] == "CLOSED"
