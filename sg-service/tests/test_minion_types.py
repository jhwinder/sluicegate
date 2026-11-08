from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from test_minion_router import setup_test_service


def test_type_and_deployment_lifecycle(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    manifest = {
        "schema_version": 1,
        "type_id": "patcher-1",
        "name": "Patcher",
        "version": "1.2",
        "runtime_type": "powershell",
        "artifact": "patcher.zip",
        "package_sha256": "a" * 64,
        "capabilities": ["windows.patch.reconcile", "windows.patch.status"],
        "requires_target_scope": True,
        "instance_fields": [{"id": "owner", "label": "Owner team", "required": True}],
    }
    key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    with TestClient(service.app) as client:
        headers = {"Authorization": "Bearer test-admin-secret"}
        assert client.get("/admin/v1/minion-types").status_code == 401
        assert client.post("/admin/v1/minion-types", json=manifest, headers=headers).status_code == 201
        assert client.post("/admin/v1/minion-types", json=manifest, headers=headers).status_code == 409
        assert client.post("/admin/v1/minion-types", json={**manifest, "type_id": "bad", "package_sha256": "bad"}, headers=headers).status_code == 422
        body = {"type_id": "patcher-1", "minion_id": "PATCH-01", "capabilities": ["windows.patch.reconcile"], "scope_metadata": {"targets": ["server-*"]}, "instance_metadata": {"owner": "Operations"}, "public_key": key}
        assert client.post("/admin/v1/minions", json={**body, "instance_metadata": {}}, headers=headers).status_code == 422
        assert client.post("/admin/v1/minions", json={**body, "instance_metadata": {"owner": "Operations", "extra": "value"}}, headers=headers).status_code == 422
        assert client.post("/admin/v1/minions", json={**body, "capabilities": ["unsupported"]}, headers=headers).status_code == 422
        assert client.post("/admin/v1/minions", json={**body, "scope_metadata": {"targets": []}}, headers=headers).status_code == 422
        assert client.post("/admin/v1/minions", json={**body, "version": "fake"}, headers=headers).status_code == 422
        created = client.post("/admin/v1/minions", json=body, headers=headers)
        assert created.status_code == 201
        api_key = created.json()["api_key"]
        details = client.get("/admin/v1/minions/PATCH-01", headers=headers).json()
        assert details["type_id"] == "patcher-1" and details["version"] == "1.2"
        assert details["instance_metadata"] == {"owner": "Operations"}
        assert client.get("/admin/v1/minion-types", headers=headers).json()[0]["deployment_count"] == 1
        assert client.patch("/admin/v1/minion-types/patcher-1", json={"enabled": False}, headers=headers).status_code == 409
        assert client.delete("/admin/v1/minion-types/patcher-1", headers=headers).status_code == 409
        assert client.patch("/admin/v1/minions/PATCH-01", json={"capabilities": ["unsupported"]}, headers=headers).status_code == 422
        assert client.patch("/admin/v1/minions/PATCH-01", json={"version": "fake"}, headers=headers).status_code == 422
        assert client.patch("/admin/v1/minions/PATCH-01", json={"instance_metadata": {"owner": ""}}, headers=headers).status_code == 422
        assert client.patch("/admin/v1/minions/PATCH-01", json={"capabilities": ["windows.patch.status"]}, headers=headers).status_code == 200
        assert client.patch("/admin/v1/minions/PATCH-01", json={"enabled": False}, headers=headers).status_code == 200
        assert client.post("/internal/v1/minions/PATCH-01/check-in", headers={"Authorization": f"Bearer {api_key}"}).status_code == 403
        extra_key = client.post("/admin/v1/credentials/minion/PATCH-01", headers=headers).json()["api_key"]
        assert client.post("/internal/v1/minions/PATCH-01/check-in", headers={"Authorization": f"Bearer {extra_key}"}).status_code == 403
        assert client.patch("/admin/v1/minions/PATCH-01", json={"enabled": True}, headers=headers).status_code == 200
        with service.transaction() as connection:
            connection.execute(
                "INSERT INTO missions (mission_id, request_id, agent_id, minion_id, envelope, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("mission-1", "req-1", "agent-1", "PATCH-01", "{}", "QUEUED", 1, 1),
            )
        assert client.delete("/admin/v1/minions/PATCH-01", headers=headers).status_code == 409
        with service.transaction() as connection:
            connection.execute("UPDATE missions SET status = 'CLOSED' WHERE mission_id = 'mission-1'")
        assert client.delete("/admin/v1/minions/PATCH-01", headers=headers).status_code == 200
        assert client.post("/internal/v1/minions/PATCH-01/check-in", headers={"Authorization": f"Bearer {api_key}"}).status_code == 401
        assert client.post("/internal/v1/minions/PATCH-01/check-in", headers={"Authorization": f"Bearer {extra_key}"}).status_code == 401
        assert client.post("/admin/v1/minions", json=body, headers=headers).status_code == 409
        assert client.patch("/admin/v1/minion-types/patcher-1", json={"enabled": False}, headers=headers).status_code == 200
        assert client.post("/admin/v1/minions", json={**body, "minion_id": "PATCH-02"}, headers=headers).status_code == 422
        assert client.delete("/admin/v1/minion-types/patcher-1", headers=headers).status_code == 200
