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


def test_release_reporting_assignment_and_claim_gate(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)
    monkeypatch.setattr(service, "PATCH_MINION_ID", "PATCH-01")
    key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    release = {
        "schema_version": 2, "type_id": "patcher-1", "family": "patcher",
        "name": "Patcher", "version": "1.0", "runtime_type": "powershell",
        "artifact": "patcher.zip", "package_sha256": "a" * 64,
        "capabilities": ["windows.patch.reconcile"], "requires_target_scope": True,
        "release_files": ["worker.py"],
    }
    newer = {**release, "type_id": "patcher-2", "version": "2.0", "package_sha256": "b" * 64}
    incompatible = {**newer, "type_id": "patcher-3", "version": "3.0", "capabilities": ["windows.patch.status"]}
    other_family = {**newer, "type_id": "other-1", "family": "other", "version": "1.0"}
    with TestClient(service.app) as client:
        admin = {"Authorization": "Bearer test-admin-secret"}
        assert client.post("/admin/v1/minion-types", json=release, headers=admin).status_code == 201
        assert client.post("/admin/v1/minion-types", json=newer, headers=admin).status_code == 201
        assert client.post("/admin/v1/minion-types", json=incompatible, headers=admin).status_code == 201
        assert client.post("/admin/v1/minion-types", json=other_family, headers=admin).status_code == 201
        created = client.post("/admin/v1/minions", json={
            "type_id": "patcher-1", "minion_id": "PATCH-01",
            "capabilities": ["windows.patch.reconcile"], "scope_metadata": {"targets": ["*"]},
            "public_key": key,
        }, headers=admin)
        assert created.status_code == 201
        headers = {"Authorization": f"Bearer {created.json()['api_key']}"}
        agent = client.post("/admin/v1/agents", json={"name": "Release test"}, headers=admin).json()
        agent_headers = {"Authorization": f"Bearer {agent['api_key']}"}

        def route():
            return client.post("/api/v1/patch-requests", headers=agent_headers, json={"servers": ["SERVER_DYN_01.example.gov"]})

        def status():
            return client.get("/admin/v1/minions/PATCH-01", headers=admin).json()["release_status"]

        def check(version, fingerprint):
            return client.post("/internal/v1/minions/PATCH-01/check-in", headers=headers, json={"version": version, "fingerprint": fingerprint})

        claim = "/internal/v1/minions/PATCH-01/missions/claim"
        assert status() == "NOT REPORTED"
        assert route().status_code == 503
        assert client.post(claim, headers=headers).status_code == 409
        assert check("1.0", "f" * 64).status_code == 200
        assert status() == "MISMATCH"
        assert route().status_code == 503
        assert client.post(claim, headers=headers).status_code == 409
        assert check("1.0", "a" * 64).status_code == 200
        assert status() == "MATCH"
        assert client.post(claim, headers=headers).status_code == 200
        with service.transaction() as connection:
            connection.execute(
                "INSERT INTO missions (mission_id, request_id, agent_id, minion_id, envelope, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("mission-1", "req-1", "agent-1", "PATCH-01", "{}", "QUEUED", 1, 1),
            )
        assert check("1.0", "f" * 64).status_code == 200
        assert client.post(claim, headers=headers).status_code == 409
        with service.connect() as connection:
            assert connection.execute("SELECT status FROM missions WHERE mission_id = 'mission-1'").fetchone()["status"] == "QUEUED"
        assign = "/admin/v1/minions/PATCH-01/release"
        assert client.post(assign, headers=admin, json={"type_id": "patcher-2"}).status_code == 409
        with service.transaction() as connection:
            connection.execute("UPDATE missions SET status = 'CLOSED' WHERE mission_id = 'mission-1'")
        assert client.post(assign, headers=admin, json={"type_id": "patcher-3"}).status_code == 422
        assert client.post(assign, headers=admin, json={"type_id": "other-1"}).status_code == 422
        assert client.patch("/admin/v1/minion-types/patcher-2", headers=admin, json={"enabled": False}).status_code == 200
        assert client.post(assign, headers=admin, json={"type_id": "patcher-2"}).status_code == 422
        assert client.patch("/admin/v1/minion-types/patcher-2", headers=admin, json={"enabled": True}).status_code == 200
        assert client.post(assign, headers=admin, json={"type_id": "patcher-2"}).status_code == 200
        assert status() == "NOT REPORTED"
        assert client.post(claim, headers=headers).status_code == 409
        assert check("1.0", "a" * 64).status_code == 200
        assert status() == "MISMATCH"
        assert check("2.0", "b" * 64).status_code == 200
        assert status() == "MATCH"
        assert route().status_code == 202
        assert client.post("/internal/v1/minions/PATCH-01/check-in", headers=headers).status_code == 200
        assert status() == "NOT REPORTED"
        assert client.delete("/admin/v1/minion-types/patcher-1", headers=admin).status_code == 200
        assert client.post("/admin/v1/minion-types", json={**release, "package_sha256": "c" * 64}, headers=admin).status_code == 409
        assert client.post("/admin/v1/minion-types", json={**release, "type_id": "different-id"}, headers=admin).status_code == 409
        assert client.post("/admin/v1/minion-types", json=release, headers=admin).status_code == 201
