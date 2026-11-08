from __future__ import annotations

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import create_routable_test_minion


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
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)

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
        assert "<h1>SluiceGate " in r_ui.text
        assert "Agent Registry" in r_ui.text
        assert "Minion Registry" in r_ui.text
        assert "Generate Minion Configuration" in r_ui.text
        assert "Download JSON" in r_ui.text
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
        assert client.get("/admin/v1/policy/time-zones").status_code == 401
        assert client.post("/admin/v1/policy/visual", json={"content": valid_policy}).status_code == 401
        assert client.post("/admin/v1/policy/visual", json={"content": valid_policy}, headers=headers).json()["default"]["decision"] == "BLOCK"
        assert client.post("/admin/v1/policy/visual", json={"content": "default: INVALID"}, headers=headers).status_code == 422
        zones = client.get("/admin/v1/policy/time-zones", headers=headers)
        assert zones.status_code == 200
        assert zones.json() == sorted(service.supported_time_zones())
        assert "UTC" in zones.json()
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


def test_audit_history_is_filtered_authenticated_append_only_and_persistent(tmp_path: Path, monkeypatch) -> None:
    import json
    import sqlite3

    import pytest

    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "audit-admin-secret")

    with TestClient(service.app) as client:
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer audit-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}
        create_routable_test_minion(client, admin_headers)
        agent = client.post("/admin/v1/agents", json={"name": "Audit agent"}, headers=admin_headers).json()
        agent_headers = {"Authorization": f"Bearer {agent['api_key']}"}

        denied = client.get("/admin/v1/audit-events")
        assert denied.status_code == 401

        submission = client.post(
            "/api/v1/actions",
            json={"capability": "demo.action", "target": {"id": "AUDIT-TARGET"}, "parameters": {"safe": True}},
            headers=agent_headers,
        )
        assert submission.status_code == 202
        request_id = submission.json()["request_id"]
        mission = next(
            item for item in client.get("/admin/v1/missions", headers=admin_headers).json()
            if item["request_id"] == request_id
        )
        assert mission["policy_decision"] == "ALLOW"
        assert mission["status"] == "QUEUED"
        assert "envelope" not in mission

        history = client.get("/admin/v1/audit-events", params={"request_id": request_id}, headers=admin_headers)
        assert history.status_code == 200
        events = history.json()["events"]
        assert [event["event_type"] for event in events] == [
            "mission.issued", "routing.selected", "policy.decision", "request.received",
        ]
        assert all(event["request_id"] == request_id and event["agent_id"] == agent["agent_id"] for event in events)
        issued = next(event for event in events if event["event_type"] == "mission.issued")
        assert issued["detail"]["signed_envelope"]["signature"]
        assert "api_key" not in json.dumps(events).lower()

        filtered = client.get(
            "/admin/v1/audit-events",
            params={"agent_id": agent["agent_id"], "event_type": "policy.decision", "status_filter": "ALLOW"},
            headers=admin_headers,
        )
        assert len(filtered.json()["events"]) == 1

        mission_id = issued["mission_id"]
        minion_id = issued["minion_id"]
        time_filtered = client.get(
            "/admin/v1/audit-events",
            params={"mission_id": mission_id, "minion_id": minion_id, "status_filter": "QUEUED", "since": 0, "until": 4_000_000_000},
            headers=admin_headers,
        )
        assert len(time_filtered.json()["events"]) == 1
        page_one = client.get("/admin/v1/audit-events", params={"request_id": request_id, "limit": 2}, headers=admin_headers).json()
        assert len(page_one["events"]) == 2 and page_one["next_before_id"] is not None
        page_two = client.get(
            "/admin/v1/audit-events",
            params={"request_id": request_id, "limit": 2, "before_id": page_one["next_before_id"]},
            headers=admin_headers,
        ).json()
        assert len(page_two["events"]) == 2
        assert client.get("/admin/v1/audit-events", params={"since": 10, "until": 1}, headers=admin_headers).status_code == 422

        admin_mutation = client.get("/admin/v1/audit-events", params={"event_type": "admin.mutation"}, headers=admin_headers)
        assert any(event["actor_id"].endswith(":KEY-BOOTSTRAP-ADMIN") for event in admin_mutation.json()["events"])
        assert any(event["detail"]["path"] == "/admin/v1/agents" for event in admin_mutation.json()["events"])

        with service.connect() as connection:
            audit_id = events[0]["audit_id"]
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute("UPDATE audit_events SET status = 'CHANGED' WHERE audit_id = ?", (audit_id,))
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute("DELETE FROM audit_events WHERE audit_id = ?", (audit_id,))

        service.initialize()
        after_restart = client.get("/admin/v1/audit-events", params={"request_id": request_id}, headers=admin_headers)
        assert after_restart.status_code == 200
        assert len(after_restart.json()["events"]) == 4
        admin_after_restart = client.get(
            "/admin/v1/audit-events", params={"event_type": "admin.mutation"}, headers=admin_headers
        ).json()["events"]
        assert any(event["detail"]["path"] == "/admin/v1/agents" for event in admin_after_restart)
