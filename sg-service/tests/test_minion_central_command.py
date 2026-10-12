from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def test_patch_request_claim_status_ownership_and_signed_result(tmp_path: Path, monkeypatch) -> None:
    from sg_service import minion_central_command as service

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
    policy_path.write_text(
        "\n".join(
            [
                "version: 1",
                "default: {decision: BLOCK}",
                "rules:",
                "  - name: allow-security-no-reboot",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: action.params.allowed_patch_types, eq: [SECURITY]}",
                "      - {path: action.params.allow_reboot, eq: false}",
                "    decision: ALLOW",
                "  - name: pause-reboot-allowed-security",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: action.params.allowed_patch_types, eq: [SECURITY]}",
                "      - {path: action.params.allow_reboot, eq: true}",
                "    decision: PAUSE",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "bootstrap-admin-secret")

    with TestClient(service.app) as client:
        admin_response = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer bootstrap-admin-secret"},
        )
        assert admin_response.status_code == 201
        admin_key = admin_response.json()["api_key"]
        agent_one = client.post(
            "/admin/v1/credentials/agent/agent-one",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]
        agent_two = client.post(
            "/admin/v1/credentials/agent/agent-two",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]
        minion_key = client.post(
            "/admin/v1/credentials/minion/PATCH-01",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]
        assert client.post(
            "/admin/v1/minions/PATCH-01/enroll",
            params={"public_key": minion_public_key},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).status_code == 201

        request_response = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER03.example.gov"], "allowed_patch_types": ["SECURITY"]},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert request_response.status_code == 202
        request_id = request_response.json()["request_id"]

        paused_request = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER03.example.gov"], "allowed_patch_types": ["SECURITY"], "allow_reboot": True},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert paused_request.status_code == 202
        assert client.get(
            f"/api/v1/requests/{paused_request.json()['request_id']}",
            headers={"Authorization": f"Bearer {agent_one}"},
        ).json()["status"] == "PENDING"
        paused_admin = client.get(
            f"/admin/v1/requests/{paused_request.json()['request_id']}",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert paused_admin.json()["policy_decision"] == "PAUSE"
        assert paused_admin.json()["status"] == "WAITING_FOR_APPROVAL"

        blocked_request = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER03.example.gov"], "allowed_patch_types": ["FEATURE"], "allow_reboot": False},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert blocked_request.status_code == 202
        assert blocked_request.json()["status"] == "CLOSED"
        blocked_admin = client.get(
            f"/admin/v1/requests/{blocked_request.json()['request_id']}",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert blocked_admin.json()["policy_decision"] == "BLOCK"
        assert blocked_admin.json()["status"] == "CLOSED"

        assert client.get(
            f"/api/v1/requests/{request_id}",
            headers={"Authorization": f"Bearer {agent_two}"},
        ).status_code == 404

        claimed = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert claimed.status_code == 200
        envelope = claimed.json()["envelope"]
        signature = bytes.fromhex(envelope.pop("signature"))
        service_private_key.public_key().verify(signature, service.canonical_json(envelope))
        mission_id = claimed.json()["mission_id"]

        acknowledged = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-ack", "status": "MISSION_ACKNOWLEDGED"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert acknowledged.status_code == 200
        progress = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-progress", "status": "MISSION_IN_PROGRESS"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert progress.status_code == 200

        result_payload = {
            "event_id": "evt-result",
            "mission_id": mission_id,
            "minion_id": "PATCH-01",
            "status": "MISSION_COMPLETE_SUCCEEDED",
            "result": {"targets": [{"server": "SERVER03.example.gov", "patches": []}]},
        }
        result_signature = minion_private_key.sign(service.canonical_json(result_payload)).hex()
        result_response = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={
                "event_id": result_payload["event_id"],
                "status": result_payload["status"],
                "result": result_payload["result"],
                "signature": result_signature,
            },
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert result_response.status_code == 200
        assert client.get(
            f"/api/v1/requests/{request_id}",
            headers={"Authorization": f"Bearer {agent_one}"},
        ).json()["status"] == "SUCCEEDED"

        assert client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={**result_payload, "signature": "00"},
            headers={"Authorization": f"Bearer {minion_key}"},
        ).status_code == 409
