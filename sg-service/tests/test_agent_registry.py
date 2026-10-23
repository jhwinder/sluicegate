from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def setup_test_service(tmp_path: Path, monkeypatch):
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
        "  - name: allow-agent-registry-test-servers",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER01.example.gov, SERVER03.example.gov, SERVER_A.example.gov, SERVER_B.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "    decision: ALLOW",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service


def test_agent_registration_crud_and_rotation(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    with TestClient(service.app) as client:
        # Bootstrap admin
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        # 1. Register agent
        reg_resp = client.post(
            "/admin/v1/agents",
            json={
                "name": "DevOps Patch Bot",
                "description": "Automated patch reconciliation",
                "owner_team": "Infrastructure",
                "environment": "stage",
                "rate_limit_per_minute": 5,
                "poll_rate_limit_per_minute": 10,
            },
            headers=admin_headers,
        )
        assert reg_resp.status_code == 201
        agent_data = reg_resp.json()
        agent_id = agent_data["agent_id"]
        agent_key = agent_data["api_key"]
        assert agent_data["name"] == "DevOps Patch Bot"

        # 2. Get agent details
        get_resp = client.get(f"/admin/v1/agents/{agent_id}", headers=admin_headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["owner_team"] == "Infrastructure"

        # 3. Agent can submit requests
        agent_headers = {"Authorization": f"Bearer {agent_key}"}
        sub_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER01.example.gov"]},
            headers=agent_headers,
        )
        assert sub_resp.status_code == 202

        # 4. Disable agent
        patch_resp = client.patch(
            f"/admin/v1/agents/{agent_id}",
            json={"enabled": False},
            headers=admin_headers,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["enabled"] == 0

        # Submitting while disabled -> 403 Forbidden
        disabled_sub = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER02.example.gov"]},
            headers=agent_headers,
        )
        assert disabled_sub.status_code == 403
        assert "disabled" in disabled_sub.json()["detail"].lower()

        # 5. Re-enable agent & rotate key
        client.patch(
            f"/admin/v1/agents/{agent_id}",
            json={"enabled": True},
            headers=admin_headers,
        )
        rotate_resp = client.post(f"/admin/v1/agents/{agent_id}/rotate-key", headers=admin_headers)
        assert rotate_resp.status_code == 200
        new_key = rotate_resp.json()["api_key"]

        # Old key now fails -> 401
        assert client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER01.example.gov"]},
            headers=agent_headers,
        ).status_code == 401

        # New key works -> 202
        new_headers = {"Authorization": f"Bearer {new_key}"}
        assert client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER03.example.gov"]},
            headers=new_headers,
        ).status_code == 202


def test_agent_rate_limiting_and_deduplication(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    with TestClient(service.app) as client:
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        # Register agent with submit rate limit = 2
        agent_data = client.post(
            "/admin/v1/agents",
            json={
                "name": "Strict Agent",
                "rate_limit_per_minute": 2,
                "poll_rate_limit_per_minute": 2,
            },
            headers=admin_headers,
        ).json()
        agent_key = agent_data["api_key"]
        agent_headers = {"Authorization": f"Bearer {agent_key}"}

        # 1. First submission (server A) -> 202
        r1 = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_A.example.gov"]},
            headers=agent_headers,
        )
        assert r1.status_code == 202
        req_id1 = r1.json()["request_id"]

        # 2. Second submission: Identical request (server A) -> Deduplicated! Returns same request_id
        r2 = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_A.example.gov"]},
            headers=agent_headers,
        )
        assert r2.status_code == 202
        assert r2.json()["request_id"] == req_id1

        # 3. Third submission (distinct servers: server B) -> Exceeds rate limit (2) -> 429
        r3 = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_B.example.gov"]},
            headers=agent_headers,
        )
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers

        # 4. Polling rate limit test
        p1 = client.get(f"/api/v1/requests/{req_id1}", headers=agent_headers)
        assert p1.status_code == 200
        p2 = client.get(f"/api/v1/requests/{req_id1}", headers=agent_headers)
        assert p2.status_code == 200
        p3 = client.get(f"/api/v1/requests/{req_id1}", headers=agent_headers)
        assert p3.status_code == 429
