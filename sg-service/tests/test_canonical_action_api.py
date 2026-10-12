from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def setup_test_service(tmp_path: Path, monkeypatch):
    from sg_service import minion_central_command as service

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
        "  - name: allow-small-refund",
        "    when:",
        "      - {path: action.name, eq: payments.refund}",
        "      - {path: action.params.amount, lte: 100}",
        "    decision: ALLOW",
        "  - name: allow-approved-refund",
        "    when:",
        "      - {path: action.name, eq: payments.refund}",
        "      - {path: action.params.amount, gt: 100}",
        "      - {path: context.approval.approved, eq: true}",
        "    decision: ALLOW",
        "  - name: pause-large-refund",
        "    when:",
        "      - {path: action.name, eq: payments.refund}",
        "      - {path: action.params.amount, gt: 100}",
        "    decision: PAUSE",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service, service_private_key


def test_canonical_action_api_allow_pause_approval(tmp_path: Path, monkeypatch) -> None:
    service, service_priv = setup_test_service(tmp_path, monkeypatch)

    minion_priv = ed25519.Ed25519PrivateKey.generate()
    minion_pub_pem = minion_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    with TestClient(service.app) as client:
        # Bootstrap admin & register refund minion
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        minion_reg = client.post(
            "/admin/v1/minions",
            json={
                "minion_id": "REFUND-MINION-01",
                "name": "Payments Refund Minion",
                "capabilities": ["payments.refund"],
                "public_key": minion_pub_pem,
            },
            headers=admin_headers,
        ).json()
        minion_key = minion_reg["api_key"]
        minion_headers = {"Authorization": f"Bearer {minion_key}"}

        # Register billing agent
        agent_data = client.post(
            "/admin/v1/agents",
            json={"name": "Billing Agent", "owner_team": "Finance"},
            headers=admin_headers,
        ).json()
        agent_key = agent_data["api_key"]
        agent_headers = {"Authorization": f"Bearer {agent_key}"}

        # 1. Submit ALLOW action: $50 refund
        r1 = client.post(
            "/api/v1/actions",
            json={
                "capability": "payments.refund",
                "target": {"account_id": "ACC-12345"},
                "parameters": {"amount": 50, "currency": "USD"},
            },
            headers=agent_headers,
        )
        assert r1.status_code == 202
        req_id1 = r1.json()["request_id"]

        # Deduplication check: duplicate submit returns same request_id
        r1_dup = client.post(
            "/api/v1/actions",
            json={
                "capability": "payments.refund",
                "target": {"account_id": "ACC-12345"},
                "parameters": {"amount": 50, "currency": "USD"},
            },
            headers=agent_headers,
        )
        assert r1_dup.status_code == 202
        assert r1_dup.json()["request_id"] == req_id1

        # Claim the mission
        claimed1 = client.post(
            "/internal/v1/minions/REFUND-MINION-01/missions/claim",
            headers=minion_headers,
        )
        assert claimed1.status_code == 200
        mission1 = claimed1.json()
        assert mission1["envelope"]["minion_id"] == "REFUND-MINION-01"
        assert mission1["envelope"]["parameters"]["amount"] == 50

        # 2. Submit PAUSE action: $500 refund
        r2 = client.post(
            "/api/v1/actions",
            json={
                "capability": "payments.refund",
                "target": {"account_id": "ACC-99999"},
                "parameters": {"amount": 500, "currency": "USD"},
            },
            headers=agent_headers,
        )
        assert r2.status_code == 202
        req_id2 = r2.json()["request_id"]

        # Agent sees PENDING
        assert client.get(f"/api/v1/requests/{req_id2}", headers=agent_headers).json()["status"] == "PENDING"

        # Not claimable while paused
        assert client.post(
            "/internal/v1/minions/REFUND-MINION-01/missions/claim",
            headers=minion_headers,
        ).json() is None

        # Admin approves
        approve_resp = client.post(
            f"/admin/v1/requests/{req_id2}/approve",
            json={"approver": "finance-vp", "comment": "Approved VIP refund"},
            headers=admin_headers,
        )
        assert approve_resp.status_code == 200
        assert approve_resp.json()["decision"] == "ALLOW"
        assert approve_resp.json()["status"] == "QUEUED"

        # Now claimable by Minion
        claimed2 = client.post(
            "/internal/v1/minions/REFUND-MINION-01/missions/claim",
            headers=minion_headers,
        )
        assert claimed2.status_code == 200
        mission2 = claimed2.json()
        assert mission2["envelope"]["parameters"]["amount"] == 500
        assert mission2["envelope"]["approval_evidence"]["approver"] == "finance-vp"
