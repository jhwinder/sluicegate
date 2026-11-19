from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import check_in_test_minion
from test_admin_ui import setup_test_service


def test_normal_startup_does_not_register_demo_or_test(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "separation-admin")
    with TestClient(service.app) as client:
        auth = {"Authorization": "Bearer separation-admin"}
        assert client.get("/admin/v1/minions", headers=auth).json() == []
        assert client.get("/admin/v1/minion-types", headers=auth).json() == []


def test_explicit_demo_bootstrap_only_provisions_payment_capabilities(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    root = Path(__file__).resolve().parents[2]
    manifest_path = root / "minion-registry/minions/demo_stub/minion-release.json"
    monkeypatch.setenv("SG_DEV_BOOTSTRAP", "true")
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "separation-admin")
    monkeypatch.setenv("SG_DEV_AGENT_KEY", "demo-agent-key")
    monkeypatch.setenv("SG_DEV_MINION_KEY", "demo-minion-key")
    public_key = tmp_path / "public.pem"
    public_key.write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setenv("SG_DEV_MINION_PUBLIC_KEY_PATH", str(public_key))
    monkeypatch.setenv("SG_DEV_MINION_MANIFEST_PATH", str(manifest_path))
    service.POLICY_PATH.write_bytes((root / "sg-service/policies/demo-policy.yml").read_bytes())
    with TestClient(service.app) as client:
        auth = {"Authorization": "Bearer separation-admin"}
        minions = client.get("/admin/v1/minions", headers=auth).json()
        assert len(minions) == 1
        assert minions[0]["minion_id"] == "DEMO-STUB-01"
        assert set(minions[0]["capabilities"]) == {"stripe.refund", "stripe.charge"}
        assert set(minions[0]["scope_metadata"]["targets"]) == {"stripe.refund", "stripe.charge"}
        types = client.get("/admin/v1/minion-types", headers=auth).json()
        assert [item["type_id"] for item in types] == ["DEMO-STUB-1.1.0"]
        request_id = client.post("/api/v1/patch-requests", headers={"Authorization": "Bearer demo-agent-key"}, json={"servers": ["patch-test.example.gov"]}).json()["request_id"]
        detail = client.get(f"/admin/v1/requests/{request_id}", headers=auth).json()
        assert detail["policy_decision"] == "BLOCK" and detail["minion_id"] == "UNASSIGNED"
        assert "windows.patch." not in service.POLICY_PATH.read_text()
    test_manifest = json.loads((root / "minion-registry/minions/test_stub/minion-release.json").read_text())
    assert test_manifest["family"] != json.loads(manifest_path.read_text())["family"]
    assert test_manifest["capabilities"] == ["windows.patch.reconcile"]


def test_existing_demo_release_upgrades_explicitly_without_rewriting_history(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "upgrade-admin")
    root = Path(__file__).resolve().parents[2]
    current = json.loads((root / "minion-registry/minions/demo_stub/minion-release.json").read_text())
    legacy = {**current, "type_id": "DEMO-STUB-1.0.0", "version": "1.0.0", "capabilities": ["windows.patch.reconcile", "demo.action", "stripe.refund", "stripe.charge"]}
    key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    auth = {"Authorization": "Bearer upgrade-admin"}
    with TestClient(service.app) as client:
        assert client.post("/admin/v1/minion-types", headers=auth, json=legacy).status_code == 201
        created = client.post("/admin/v1/minions", headers=auth, json={
            "minion_id": "DEMO-STUB-01", "type_id": legacy["type_id"], "capabilities": legacy["capabilities"],
            "scope_metadata": {"targets": ["*"]}, "public_key": key,
        }).json()
        check_in_test_minion(client, created)
        agent = client.post("/admin/v1/agents", headers=auth, json={"name": "Upgrade agent"}).json()
        request_id = client.post("/api/v1/actions", headers={"Authorization": f"Bearer {agent['api_key']}"}, json={
            "capability": "stripe.refund", "target": {"id": "stripe.refund"}, "parameters": {"amount": 100, "currency": "USD"},
        }).json()["request_id"]
        original = client.get(f"/admin/v1/requests/{request_id}", headers=auth).json()
        history = client.get("/admin/v1/audit-events", headers=auth, params={"request_id": request_id}).json()
        assert client.post("/admin/v1/minion-types", headers=auth, json=current).status_code == 201
        assert client.post("/admin/v1/minions/DEMO-STUB-01/release", headers=auth, json={"type_id": current["type_id"]}).status_code == 409
        # Model the old worker finishing its outstanding mission before the upgrade.
        with service.transaction() as connection:
            connection.execute("UPDATE missions SET status = 'MISSION_COMPLETE_SUCCEEDED' WHERE request_id = ?", (request_id,))
        assert client.patch("/admin/v1/minions/DEMO-STUB-01", headers=auth, json={
            "capabilities": current["capabilities"], "scope_metadata": {"targets": current["capabilities"]},
        }).status_code == 200
        assigned = client.post("/admin/v1/minions/DEMO-STUB-01/release", headers=auth, json={"type_id": current["type_id"]})
        assert assigned.status_code == 200
        assert assigned.json()["release_status"] == "NOT REPORTED"
        check_in_test_minion(client, {**assigned.json(), "api_key": created["api_key"]})
        service.initialize()
        assert client.get("/admin/v1/minions/DEMO-STUB-01", headers=auth).json()["release_status"] == "MATCH"
        after = client.get(f"/admin/v1/requests/{request_id}", headers=auth).json()
        assert after["submitted_request"] == original["submitted_request"]
        assert after["mission_envelope"] == original["mission_envelope"]
        assert client.get("/admin/v1/audit-events", headers=auth, params={"request_id": request_id}).json() == history
        with service.connect() as connection:
            remembered = json.loads(connection.execute("SELECT manifest FROM minion_release_history WHERE type_id = ?", (legacy["type_id"],)).fetchone()["manifest"])
        assert remembered == {**legacy, "instance_fields": []}
