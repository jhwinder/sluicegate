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

    policy_content = "\n".join([
        "version: 1",
        "default: {decision: ALLOW}",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service


def test_admin_ui_endpoints(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    with TestClient(service.app) as client:
        # 1. /admin redirects to /admin/ui
        r_redir = client.get("/admin", follow_redirects=False)
        assert r_redir.status_code == 307
        assert r_redir.headers["location"] == "/admin/ui"

        # 2. /admin/ui serves the HTML console
        r_ui = client.get("/admin/ui")
        assert r_ui.status_code == 200
        assert "text/html" in r_ui.headers["content-type"]
        assert "SluiceGate Control Plane" in r_ui.text
        assert "Agent Registry" in r_ui.text
        assert "Minion Registry" in r_ui.text
        assert "Policies" in r_ui.text
        assert "Save and Activate" in r_ui.text


def test_policy_admin_workflow_is_authenticated_validated_and_audited(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "policy-admin-secret")
    valid_policy = "version: 1\ndefault:\n  decision: BLOCK\nrules: []\n"

    with TestClient(service.app) as client:
        assert client.get("/admin/v1/policy").status_code == 401
        assert client.post(
            "/admin/v1/policy/validate",
            json={"content": valid_policy},
        ).status_code == 401

        headers = {"Authorization": "Bearer policy-admin-secret"}
        current = client.get("/admin/v1/policy", headers=headers)
        assert current.status_code == 200
        initial_hash = current.json()["file_hash"]

        validation = client.post(
            "/admin/v1/policy/validate",
            json={"content": valid_policy},
            headers=headers,
        )
        assert validation.status_code == 200
        assert validation.json()["is_valid"] is True

        invalid_policy = client.post(
            "/admin/v1/policy/validate",
            json={"content": "version: 1\ndefault: INVALID\nrules: []\n"},
            headers=headers,
        )
        assert invalid_policy.status_code == 200
        assert invalid_policy.json()["is_valid"] is False

        invalid_save = client.post(
            "/admin/v1/policy",
            json={
                "content": "version: 1\ndefault: INVALID\nrules: []\n",
                "expected_file_hash": initial_hash,
            },
            headers=headers,
        )
        assert invalid_save.status_code == 422
        assert service.POLICY_PATH.read_text(encoding="utf-8") == current.json()["content"]

        stale_save = client.post(
            "/admin/v1/policy",
            json={"content": valid_policy, "expected_file_hash": "0" * 64},
            headers=headers,
        )
        assert stale_save.status_code == 409

        save = client.post(
            "/admin/v1/policy",
            json={"content": valid_policy, "expected_file_hash": initial_hash},
            headers=headers,
        )
        assert save.status_code == 200
        saved = save.json()
        assert saved["status"] == "RELOADED"
        assert saved["policy_hash_full"] == service.policy_engine.policy_hash_full
        assert (service.POLICY_PATH.parent / saved["backup_file"]).is_file()
        assert service.POLICY_PATH.read_text(encoding="utf-8") == valid_policy

        connection = service.connect()
        try:
            event = connection.execute(
                "SELECT actor, action, outcome, previous_hash, policy_hash FROM policy_events ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        assert event["actor"] == "admin"
        assert event["action"] == "SAVE_AND_ACTIVATE"
        assert event["outcome"] == "SUCCEEDED"
        assert event["previous_hash"] == initial_hash
        assert event["policy_hash"] == saved["policy_hash_full"]

        service.POLICY_PATH.write_text("version: 1\ndefault: INVALID\nrules: []\n", encoding="utf-8")
        failed_reload = client.post("/admin/v1/policy/reload", headers=headers)
        assert failed_reload.status_code == 422
        assert service.policy_engine.policy_hash_full == saved["policy_hash_full"]
        connection = service.connect()
        try:
            reload_event = connection.execute(
                "SELECT actor, action, outcome, policy_hash FROM policy_events ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        assert reload_event["actor"] == "admin"
        assert reload_event["action"] == "RELOAD"
        assert reload_event["outcome"] == "VALIDATION_FAILED"
        assert reload_event["policy_hash"] is None
