from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def test_patch_request_claim_status_ownership_and_signed_result(tmp_path: Path, monkeypatch) -> None:
    from sg_service import mission_control as service

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
                "  - name: pause-server04-until-approved",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: target.servers, eq: [SERVER04.example.gov]}",
                "      - {path: context.approval.approved, exists: false}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [SERVER04.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus, nessus_catalog]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: true",
                "        maintenance_window: null",
                "      - type: allowed_patch_executables",
                "        executables: [msiexec.exe]",
                "    decision: PAUSE",
                "  - name: allow-window-test-server",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: target.servers, eq: [SERVER05.example.gov]}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [SERVER05.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                "        maintenance_window:",
                "          start_utc: '2999-01-01T00:00:00Z'",
                "          end_utc: '3000-01-01T00:00:00Z'",
                "        outside_window_decision: PAUSE",
                "    decision: ALLOW",
                "  - name: allow-authorized-pilot-servers",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [SERVER03.example.gov, SERVER04.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus, nessus_catalog]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                "        maintenance_window: null",
                "      - type: allowed_patch_executables",
                "        executables: [msiexec.exe]",
                "    decision: ALLOW",
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
            json={"servers": ["SERVER03.example.gov", "UNAPPROVED.example.gov"]},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert request_response.status_code == 202
        request_id = request_response.json()["request_id"]
        assert client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER03.example.gov"], "allow_reboot": True},
            headers={"Authorization": f"Bearer {agent_one}"},
        ).status_code == 422

        paused_request = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER04.example.gov"]},
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
            json={"servers": ["UNAPPROVED.example.gov"]},
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
        assert envelope["target"]["servers"] == ["server03.example.gov"]
        assert envelope["parameters"]["patch_constraints"] == {
            "allowed_patch_types": ["SECURITY"],
            "allow_reboot": False,
            "outside_window_decision": None,
        }
        assert envelope["execution"] == {
            "max_attempts": 3,
            "retry_interval_seconds": 30,
            "attempt_timeout_seconds": 300,
            "overall_timeout_seconds": 900,
            "heartbeat_interval_seconds": 30,
            "claim_lease_seconds": 120,
        }
        assert envelope["obligations"] == [
            {"type": "allowed_patch_targets", "data": {"servers": ["SERVER03.example.gov", "SERVER04.example.gov"]}},
            {
                "type": "patch_constraints",
                "data": {
                    "patch_sources": ["wsus", "nessus_catalog"],
                    "allowed_patch_types": ["SECURITY"],
                    "allow_reboot": False,
                    "maintenance_window": None,
                },
            },
            {"type": "allowed_patch_executables", "data": {"executables": ["msiexec.exe"]}},
        ]
        signature = bytes.fromhex(envelope.pop("signature"))
        service_private_key.public_key().verify(signature, service.canonical_json(envelope))
        mission_id = claimed.json()["mission_id"]
        first_claim_token = claimed.json()["claim_token"]
        assert claimed.json()["attempt"] == 1
        assert claimed.json()["resume"] is False
        first_acknowledgement = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-ack", "claim_token": first_claim_token, "status": "MISSION_ACKNOWLEDGED"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert first_acknowledgement.status_code == 200
        first_heartbeat = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/heartbeat",
            json={
                "claim_token": first_claim_token,
                "process_id": 4321,
                "process_started_at": time.time(),
                "detail": {"process_detail": {"phase": "INSTALLING", "target_process_id": 1234}},
            },
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert first_heartbeat.status_code == 200
        connection = service.connect()
        try:
            stored_claim = connection.execute(
                "SELECT worker_process_id, process_detail, lease_expires_at FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
        finally:
            connection.close()
        assert stored_claim["worker_process_id"] == 4321
        assert json.loads(stored_claim["process_detail"]) == {"process_detail": {"phase": "INSTALLING", "target_process_id": 1234}}
        assert stored_claim["lease_expires_at"] > first_heartbeat.json()["server_time"]

        connection = service.connect()
        try:
            connection.execute(
                "UPDATE missions SET lease_expires_at = ? WHERE mission_id = ?",
                (time.time() - 1, mission_id),
            )
            connection.commit()
        finally:
            connection.close()
        resumed_claim = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert resumed_claim.status_code == 200
        assert resumed_claim.json()["resume"] is True
        assert resumed_claim.json()["attempt"] == 1
        assert resumed_claim.json()["resume_status"] == "MISSION_ACKNOWLEDGED"
        claim_token = resumed_claim.json()["claim_token"]
        assert claim_token != first_claim_token
        stale_heartbeat = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/heartbeat",
            json={"claim_token": first_claim_token},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert stale_heartbeat.status_code == 409
        stale_status = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-stale", "claim_token": first_claim_token, "status": "MISSION_IN_PROGRESS"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert stale_status.status_code == 409

        ack_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-ack", "claim_token": claim_token, "status": "MISSION_ACKNOWLEDGED"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert ack_retry.status_code == 200
        assert ack_retry.json() == {"event_id": "evt-ack", "status": "ALREADY_RECORDED"}
        conflicting_ack_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-ack", "claim_token": claim_token, "status": "MISSION_ACKNOWLEDGED", "detail": {"changed": True}},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert conflicting_ack_retry.status_code == 409
        progress = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-progress", "claim_token": claim_token, "status": "MISSION_IN_PROGRESS"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert progress.status_code == 200

        retry_failure_payload = {
            "event_id": "evt-retry-failure",
            "mission_id": mission_id,
            "minion_id": "PATCH-01",
            "status": "MISSION_COMPLETE_FAILED",
            "result": {"retryable": True, "error": "Temporary target communication failure."},
        }
        retry_failure_signature = minion_private_key.sign(service.canonical_json(retry_failure_payload)).hex()
        retry_failure = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={
                "event_id": retry_failure_payload["event_id"],
                "claim_token": claim_token,
                "status": retry_failure_payload["status"],
                "result": retry_failure_payload["result"],
                "signature": retry_failure_signature,
            },
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert retry_failure.status_code == 200
        assert retry_failure.json()["status"] == "RETRY_SCHEDULED"
        delayed_claim = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert delayed_claim.json() == {"retry_after_seconds": 30}
        connection = service.connect()
        try:
            connection.execute("UPDATE missions SET next_retry_at = ? WHERE mission_id = ?", (time.time() - 1, mission_id))
            connection.commit()
        finally:
            connection.close()
        second_attempt = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt.status_code == 200
        assert second_attempt.json()["attempt"] == 2
        assert second_attempt.json()["claim_generation"] == 3
        stale_attempt_token = claim_token
        claim_token = second_attempt.json()["claim_token"]
        assert client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/heartbeat",
            json={"claim_token": stale_attempt_token},
            headers={"Authorization": f"Bearer {minion_key}"},
        ).status_code == 409
        second_attempt_ack = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-ack-attempt-2", "claim_token": claim_token, "status": "MISSION_ACKNOWLEDGED"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt_ack.status_code == 200
        second_attempt_progress = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json={"event_id": "evt-progress-attempt-2", "claim_token": claim_token, "status": "MISSION_IN_PROGRESS"},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt_progress.status_code == 200

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
                "claim_token": claim_token,
                "status": result_payload["status"],
                "result": result_payload["result"],
                "signature": result_signature,
            },
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert result_response.status_code == 200
        retry_response = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={**result_payload, "claim_token": claim_token, "signature": result_signature},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert retry_response.status_code == 200
        assert retry_response.json() == {"status": "ALREADY_RECORDED"}
        conflicting_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={**result_payload, "claim_token": claim_token, "result": {"different": True}, "signature": result_signature},
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert conflicting_retry.status_code == 409
        oversized_result = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={
                "event_id": "evt-oversized",
                "claim_token": claim_token,
                "status": "MISSION_COMPLETE_FAILED",
                "result": {"output": "x" * (256 * 1024 + 1)},
                "signature": "00",
            },
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert oversized_result.status_code == 413
        assert client.get(
            f"/api/v1/requests/{request_id}",
            headers={"Authorization": f"Bearer {agent_one}"},
        ).json()["status"] == "SUCCEEDED"

        assert client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={**result_payload, "claim_token": claim_token, "signature": "00"},
            headers={"Authorization": f"Bearer {minion_key}"},
        ).status_code == 409

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: True)
        window_request = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER05.example.gov"]},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert window_request.status_code == 202
        window_request_id = window_request.json()["request_id"]

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: False)
        assert client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        ).json() is None
        paused_window_request = client.get(
            f"/admin/v1/requests/{window_request_id}",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()
        assert paused_window_request["status"] == "WAITING_FOR_APPROVAL"
        assert paused_window_request["policy_decision"] == "PAUSE"

        still_paused = client.post(
            f"/admin/v1/requests/{window_request_id}/approve",
            json={"approver": "sec-lead"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert still_paused.status_code == 200
        assert still_paused.json()["decision"] == "PAUSE"

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: True)
        approved_window = client.post(
            f"/admin/v1/requests/{window_request_id}/approve",
            json={"approver": "sec-lead"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert approved_window.status_code == 200
        assert approved_window.json()["decision"] == "ALLOW"
        claimed_window_mission = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert claimed_window_mission.status_code == 200
        assert claimed_window_mission.json()["envelope"]["target"]["servers"] == ["server05.example.gov"]

        retry_mission_id = claimed_window_mission.json()["mission_id"]
        now = time.time()
        connection = service.connect()
        try:
            connection.execute(
                "UPDATE missions SET attempt_started_at = ?, execution_started_at = ?, lease_expires_at = ? WHERE mission_id = ?",
                (now - 301, now, now - 1, retry_mission_id),
            )
            connection.commit()
        finally:
            connection.close()
        retry_wait = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert retry_wait.status_code == 200
        assert retry_wait.json() == {"retry_after_seconds": 30}
        connection = service.connect()
        try:
            retry_row = connection.execute(
                "SELECT status, attempt_count, next_retry_at FROM missions WHERE mission_id = ?",
                (retry_mission_id,),
            ).fetchone()
            connection.execute(
                "UPDATE missions SET next_retry_at = ? WHERE mission_id = ?",
                (now - 1, retry_mission_id),
            )
            connection.commit()
        finally:
            connection.close()
        assert retry_row["status"] == "QUEUED"
        assert retry_row["attempt_count"] == 1
        assert retry_row["next_retry_at"] > now
        second_attempt = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt.status_code == 200
        assert second_attempt.json()["attempt"] == 2
        assert second_attempt.json()["resume"] is False

        connection = service.connect()
        try:
            connection.execute(
                "UPDATE missions SET attempt_count = 3, attempt_started_at = ?, execution_started_at = ?, lease_expires_at = ? WHERE mission_id = ?",
                (now - 301, now - 901, now - 1, retry_mission_id),
            )
            connection.commit()
        finally:
            connection.close()
        exhausted = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert exhausted.status_code == 200
        assert exhausted.json() is None
        connection = service.connect()
        try:
            expired_status = connection.execute(
                "SELECT status FROM missions WHERE mission_id = ?",
                (retry_mission_id,),
            ).fetchone()["status"]
        finally:
            connection.close()
        assert expired_status == "MISSION_EXPIRED"


def test_outside_window_decision_comes_from_policy_obligation(monkeypatch) -> None:
    from sg_service import mission_control as service

    window = {"start_utc": "2999-01-01T00:00:00Z", "end_utc": "3000-01-01T00:00:00Z"}
    target_obligation = SimpleNamespace(type="allowed_patch_targets", data={"servers": ["server.example.gov"]})

    def policy_with(outside_decision: str | None):
        constraints = {
            "patch_sources": ["wsus"],
            "allowed_patch_types": ["SECURITY"],
            "allow_reboot": False,
            "maintenance_window": window,
        }
        if outside_decision is not None:
            constraints["outside_window_decision"] = outside_decision
        patch_obligation = SimpleNamespace(type="patch_constraints", data=constraints)
        return SimpleNamespace(decide=lambda _: ("ALLOW", [target_obligation, patch_obligation], "policy-hash"))

    monkeypatch.setattr(service, "policy_engine", policy_with("PAUSE"))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "PAUSE"
    assert service.decide_patch_policy(
        "agent",
        ["server.example.gov"],
        context={"approval": {"approved": True}},
    )[0] == "PAUSE"

    monkeypatch.setattr(service, "policy_engine", policy_with("BLOCK"))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "BLOCK"

    monkeypatch.setattr(service, "policy_engine", policy_with(None))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "BLOCK"
