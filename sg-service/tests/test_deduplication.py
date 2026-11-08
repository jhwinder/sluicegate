from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import create_routable_test_minion

CONCURRENCY = 8
OPEN_STATUSES = ("QUEUED", "WAITING_FOR_APPROVAL", "CLAIMED", "MISSION_ACKNOWLEDGED", "MISSION_IN_PROGRESS", "MISSION_WAITING_FOR_REBOOT")

POLICY = "\n".join([
    "version: 1",
    "default: {decision: BLOCK}",
    "rules:",
    "  - name: allow-patching",
    "    when:",
    "      - {path: action.name, eq: windows.patch.reconcile}",
    "    obligations:",
    "      - type: allowed_patch_targets",
    "        servers: [SERVER_A.example.gov, SERVER_B.example.gov]",
    "      - type: patch_constraints",
    "        patch_sources: [wsus]",
    "        allowed_patch_types: [SECURITY]",
    "        allow_reboot: false",
    "        maintenance_window: null",
    "    decision: ALLOW",
    "  - name: allow-demo",
    "    when:",
    "      - {path: action.name, eq: demo.action}",
    "    decision: ALLOW",
])


def setup_test_service(tmp_path: Path, monkeypatch):
    from sg_service import mission_control as service

    signing_key_path = tmp_path / "sg-signing-key.pem"
    policy_path = tmp_path / "policy.yml"
    signing_key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    policy_path.write_text(POLICY, encoding="utf-8")
    monkeypatch.setattr(service, "DATABASE_PATH", tmp_path / "service.sqlite3")
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", signing_key_path)
    monkeypatch.setattr(service, "POLICY_PATH", policy_path)
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "test-admin-secret")
    return service


def make_agent(client, name: str) -> dict[str, str]:
    admin_key = client.post("/admin/v1/credentials/admin/admin", headers={"Authorization": "Bearer test-admin-secret"}).json()["api_key"]
    admin_headers = {"Authorization": f"Bearer {admin_key}"}
    if not client.get("/admin/v1/minions", headers=admin_headers).json():
        create_routable_test_minion(client, admin_headers)
    agent = client.post("/admin/v1/agents", json={"name": name}, headers={"Authorization": f"Bearer {admin_key}"}).json()
    return {"Authorization": f"Bearer {agent['api_key']}"}


def hold_requests_before_insert(service, monkeypatch) -> None:
    """Make every concurrent request pass the pre-insert duplicate check before any of them inserts."""
    barrier = threading.Barrier(CONCURRENCY, timeout=15)
    original = service.signing_private_key

    def synchronized():
        barrier.wait()
        return original()

    monkeypatch.setattr(service, "signing_private_key", synchronized)


def submit_concurrently(client, path: str, body: dict, headers: dict[str, str]) -> list[dict]:
    def submit(_):
        response = client.post(path, json=body, headers=headers)
        assert response.status_code == 202
        return response.json()

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        return list(pool.map(submit, range(CONCURRENCY)))


def open_mission_count(service) -> int:
    with service.connect() as connection:
        return connection.execute(
            f"SELECT COUNT(*) FROM missions WHERE status IN ({','.join('?' * len(OPEN_STATUSES))})", OPEN_STATUSES
        ).fetchone()[0]


def test_concurrent_equivalent_patch_requests_create_one_mission(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Concurrent agent")
        hold_requests_before_insert(service, monkeypatch)
        results = submit_concurrently(client, "/api/v1/patch-requests", {"servers": ["SERVER_A.example.gov"]}, agent)
        assert len({result["request_id"] for result in results}) == 1
        assert open_mission_count(service) == 1


def test_concurrent_equivalent_actions_create_one_mission(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Concurrent agent")
        hold_requests_before_insert(service, monkeypatch)
        body = {"capability": "demo.action", "target": {"id": "T-1"}, "parameters": {"b": 2, "a": 1}}
        results = submit_concurrently(client, "/api/v1/actions", body, agent)
        assert len({result["request_id"] for result in results}) == 1
        assert open_mission_count(service) == 1


def test_server_order_and_repeats_do_not_defeat_deduplication(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Agent")
        first = client.post("/api/v1/patch-requests", json={"servers": ["SERVER_A.example.gov", "SERVER_B.example.gov"]}, headers=agent).json()
        second = client.post(
            "/api/v1/patch-requests", json={"servers": ["SERVER_B.example.gov", "SERVER_A.example.gov", "SERVER_B.example.gov"]}, headers=agent
        ).json()
        assert first["request_id"] == second["request_id"]


def test_different_agents_and_different_work_are_not_deduplicated(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        first_agent = make_agent(client, "First")
        second_agent = make_agent(client, "Second")
        body = {"servers": ["SERVER_A.example.gov"]}
        a = client.post("/api/v1/patch-requests", json=body, headers=first_agent).json()
        b = client.post("/api/v1/patch-requests", json=body, headers=second_agent).json()
        c = client.post("/api/v1/patch-requests", json={"servers": ["SERVER_B.example.gov"]}, headers=first_agent).json()
        assert len({a["request_id"], b["request_id"], c["request_id"]}) == 3


def test_equivalent_request_after_terminal_state_creates_new_mission(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Agent")
        body = {"servers": ["SERVER_A.example.gov"]}
        first = client.post("/api/v1/patch-requests", json=body, headers=agent).json()
        with service.transaction() as connection:
            connection.execute("UPDATE missions SET status = 'MISSION_COMPLETE_SUCCEEDED' WHERE request_id = ?", (first["request_id"],))
        second = client.post("/api/v1/patch-requests", json=body, headers=agent).json()
        assert second["request_id"] != first["request_id"]
        assert open_mission_count(service) == 1


def test_open_equivalent_missions_are_rejected_by_the_database(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    import pytest

    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Agent")
        client.post("/api/v1/patch-requests", json={"servers": ["SERVER_A.example.gov"]}, headers=agent)
        with service.transaction() as connection:
            row = dict(connection.execute("SELECT * FROM missions").fetchone())
        row["mission_id"], row["request_id"] = "MISSION-DUP", "REQ-DUP"
        columns = ", ".join(row)
        with pytest.raises(sqlite3.IntegrityError):
            with service.transaction() as connection:
                connection.execute(f"INSERT INTO missions ({columns}) VALUES ({','.join('?' * len(row))})", tuple(row.values()))


def test_existing_open_duplicates_are_backfilled_without_blocking_startup(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = make_agent(client, "Agent")
        first = client.post("/api/v1/patch-requests", json={"servers": ["SERVER_A.example.gov"]}, headers=agent).json()
        with service.transaction() as connection:
            row = dict(connection.execute("SELECT * FROM missions").fetchone())
            connection.execute("DROP INDEX missions_open_equivalence")
            connection.execute("UPDATE missions SET equivalence_key = NULL")
            row["mission_id"], row["request_id"], row["created_at"] = "MISSION-OLD", "REQ-OLD", row["created_at"] - 10
            row["equivalence_key"] = None
            connection.execute(f"INSERT INTO missions ({', '.join(row)}) VALUES ({','.join('?' * len(row))})", tuple(row.values()))
        service.initialize()
        with service.connect() as connection:
            keyed = [r["request_id"] for r in connection.execute("SELECT request_id FROM missions WHERE equivalence_key IS NOT NULL")]
        assert keyed == [first["request_id"]]
        again = client.post("/api/v1/patch-requests", json={"servers": ["SERVER_A.example.gov"]}, headers=agent).json()
        assert again["request_id"] == first["request_id"]
