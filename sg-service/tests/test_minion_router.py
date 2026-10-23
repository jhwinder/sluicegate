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
        "  - name: allow-router-test-servers",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER_DYN_01.example.gov, SERVER_DYN_02.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "    decision: ALLOW",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service


def test_minion_registration_router_and_checkin(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    minion_priv = ed25519.Ed25519PrivateKey.generate()
    minion_pub_pem = minion_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    with TestClient(service.app) as client:
        # Bootstrap admin
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        # 1. Register Minion via Admin API
        reg_resp = client.post(
            "/admin/v1/minions",
            json={
                "minion_id": "DYNAMIC-PATCHER-01",
                "name": "Dynamic Windows Patching Minion",
                "runtime_type": "powershell",
                "environment": "prod",
                "capabilities": ["windows.patch.reconcile", "windows.patch.status"],
                "public_key": minion_pub_pem,
            },
            headers=admin_headers,
        )
        assert reg_resp.status_code == 201
        minion_info = reg_resp.json()
        assert minion_info["minion_id"] == "DYNAMIC-PATCHER-01"
        minion_key = minion_info["api_key"]

        # 2. Check-in updates last_contact_at
        minion_headers = {"Authorization": f"Bearer {minion_key}"}
        check_resp = client.post(
            "/internal/v1/minions/DYNAMIC-PATCHER-01/check-in",
            headers=minion_headers,
        )
        assert check_resp.status_code == 200
        assert check_resp.json()["status"] == "CONNECTED"

        details = client.get("/admin/v1/minions/DYNAMIC-PATCHER-01", headers=admin_headers).json()
        assert details["last_contact_at"] is not None

        # 3. Register an agent to submit requests
        agent_data = client.post(
            "/admin/v1/agents",
            json={"name": "Test Patcher Agent"},
            headers=admin_headers,
        ).json()
        agent_headers = {"Authorization": f"Bearer {agent_data['api_key']}"}

        # 4. Agent submits patch request -> Router automatically assigns to DYNAMIC-PATCHER-01!
        req_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_DYN_01.example.gov"]},
            headers=agent_headers,
        )
        assert req_resp.status_code == 202

        # 5. Minion claims mission assigned dynamically to it
        claim_resp = client.post(
            "/internal/v1/minions/DYNAMIC-PATCHER-01/missions/claim",
            headers=minion_headers,
        )
        assert claim_resp.status_code == 200
        claimed = claim_resp.json()
        assert claimed is not None
        assert claimed["envelope"]["minion_id"] == "DYNAMIC-PATCHER-01"
        assert claimed["envelope"]["capability"] == "windows.patch.reconcile"

        # 6. Disable Minion -> Router can no longer route to it
        client.patch(
            "/admin/v1/minions/DYNAMIC-PATCHER-01",
            json={"enabled": False},
            headers=admin_headers,
        )
        # Unset fallback env var to verify dynamic failure when no enabled minion exists
        monkeypatch.setattr(service, "PATCH_MINION_ID", "")
        unroutable = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_DYN_02.example.gov"]},
            headers=agent_headers,
        )
        assert unroutable.status_code == 503
        assert "No eligible Minion found" in unroutable.json()["detail"]
