from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import register_test_minion

from sg_service.protocol import canonical_json


def signed_status(key, minion_id, mission_id, claim_token, generation, event_id, status, detail=None, occurred_at=1_800_000_000):
    detail = detail or {}
    payload = {"event_id": event_id, "mission_id": mission_id, "minion_id": minion_id, "claim_generation": generation, "status": status, "detail": detail, "occurred_at": occurred_at}
    return {"event_id": event_id, "claim_token": claim_token, "claim_generation": generation, "status": status, "detail": detail, "occurred_at": occurred_at, "signature": key.sign(canonical_json(payload)).hex()}


def signed_result(key, minion_id, mission_id, claim_token, generation, event_id, status, result):
    payload = {"event_id": event_id, "mission_id": mission_id, "minion_id": minion_id, "claim_generation": generation, "status": status, "result": result}
    return {"event_id": event_id, "claim_token": claim_token, "claim_generation": generation, "status": status, "result": result, "signature": key.sign(canonical_json(payload)).hex()}


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
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)
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
                "          timezone: America/New_York",
                "          days: [SAT]",
                "          start: '01:00'",
                "          end: '05:00'",
                "        outside_window: WAIT",
                "    decision: ALLOW",
                "  - name: pause-urgent-server06",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: target.servers, eq: [SERVER06.example.gov]}",
                "      - {path: context.approval.approved, exists: false}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [SERVER06.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                "        maintenance_window:",
                "          timezone: America/New_York",
                "          days: [SAT]",
                "          start: '01:00'",
                "          end: '05:00'",
                "        outside_window: WAIT",
                "    decision: PAUSE",
                "  - name: allow-urgent-server06-after-approval",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: target.servers, eq: [SERVER06.example.gov]}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [SERVER06.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                "        maintenance_window:",
                "          timezone: America/New_York",
                "          days: [SAT]",
                "          start: '01:00'",
                "          end: '05:00'",
                "        outside_window: WAIT",
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
        registered = register_test_minion(
            client, {"Authorization": f"Bearer {admin_key}"},
            {"minion_id": "PATCH-01", "scope_metadata": {"targets": ["*"]}, "public_key": minion_public_key},
        )
        assert registered.status_code == 201
        minion_key = registered.json()["api_key"]

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
        blocked_history = client.get(
            "/admin/v1/audit-events",
            params={"transaction_id": blocked_request.json()["request_id"], "event_type": "policy.decision"},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert len(blocked_history) == 1 and blocked_history[0]["status"] == "BLOCK"
        paused_history = client.get(
            "/admin/v1/audit-events",
            params={"request_id": paused_request.json()["request_id"], "event_type": "policy.decision"},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert len(paused_history) == 1 and paused_history[0]["status"] == "PAUSE"

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
            "outside_window": None,
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
            json=signed_status(minion_private_key, "PATCH-01", mission_id, first_claim_token, claimed.json()["claim_generation"], "evt-ack", "MISSION_ACKNOWLEDGED"),
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
            json=signed_status(minion_private_key, "PATCH-01", mission_id, first_claim_token, claimed.json()["claim_generation"], "evt-stale", "MISSION_IN_PROGRESS"),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert stale_status.status_code == 409

        ack_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json=signed_status(minion_private_key, "PATCH-01", mission_id, claim_token, resumed_claim.json()["claim_generation"], "evt-ack", "MISSION_ACKNOWLEDGED"),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert ack_retry.status_code == 200
        assert ack_retry.json() == {"event_id": "evt-ack", "status": "ALREADY_RECORDED"}
        conflicting_ack_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json=signed_status(minion_private_key, "PATCH-01", mission_id, claim_token, resumed_claim.json()["claim_generation"], "evt-ack", "MISSION_ACKNOWLEDGED", {"changed": True}),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert conflicting_ack_retry.status_code == 409
        progress = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json=signed_status(minion_private_key, "PATCH-01", mission_id, claim_token, resumed_claim.json()["claim_generation"], "evt-progress", "MISSION_IN_PROGRESS"),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert progress.status_code == 200

        retry_failure_body = signed_result(
            minion_private_key, "PATCH-01", mission_id, claim_token, resumed_claim.json()["claim_generation"],
            "evt-retry-failure", "MISSION_COMPLETE_FAILED", {"retryable": True, "error": "Temporary target communication failure."},
        )
        retry_failure = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json=retry_failure_body,
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
            json=signed_status(minion_private_key, "PATCH-01", mission_id, claim_token, second_attempt.json()["claim_generation"], "evt-ack-attempt-2", "MISSION_ACKNOWLEDGED"),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt_ack.status_code == 200
        second_attempt_progress = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status",
            json=signed_status(minion_private_key, "PATCH-01", mission_id, claim_token, second_attempt.json()["claim_generation"], "evt-progress-attempt-2", "MISSION_IN_PROGRESS"),
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert second_attempt_progress.status_code == 200

        result_body = signed_result(
            minion_private_key, "PATCH-01", mission_id, claim_token, second_attempt.json()["claim_generation"],
            "evt-result", "MISSION_COMPLETE_SUCCEEDED", {"targets": [{"server": "SERVER03.example.gov", "patches": []}]},
        )
        result_response = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json=result_body,
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert result_response.status_code == 200
        retry_response = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json=result_body,
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert retry_response.status_code == 200
        assert retry_response.json() == {"status": "ALREADY_RECORDED"}
        terminal_history = client.get(
            "/admin/v1/audit-events",
            params={"transaction_id": request_id},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert any(event["event_type"] == "minion.event_duplicate" for event in terminal_history)
        assert any(event["event_type"] == "minion.result" and event["signature_verified"] is True for event in terminal_history)
        conflicting_result = signed_result(
            minion_private_key, "PATCH-01", mission_id, claim_token, second_attempt.json()["claim_generation"],
            "evt-result", "MISSION_COMPLETE_SUCCEEDED", {"different": True},
        )
        conflicting_retry = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json=conflicting_result,
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert conflicting_retry.status_code == 409
        oversized_result = client.post(
            f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result",
            json={
                "event_id": "evt-oversized",
                "claim_token": claim_token,
                "claim_generation": second_attempt.json()["claim_generation"],
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
            json={**result_body, "signature": "0" * 128},
            headers={"Authorization": f"Bearer {minion_key}"},
        ).status_code == 401
        rejected_signature = client.get(
            "/admin/v1/audit-events",
            params={"mission_id": mission_id, "event_type": "signature.verification", "status_filter": "REJECTED"},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert rejected_signature and rejected_signature[0]["signature_verified"] is False

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: False)
        window_request = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER05.example.gov"]},
            headers={"Authorization": f"Bearer {agent_one}"},
        )
        assert window_request.status_code == 202
        window_request_id = window_request.json()["request_id"]
        waiting_window_request = client.get(
            f"/admin/v1/requests/{window_request_id}",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()
        assert waiting_window_request["status"] == "QUEUED"
        assert waiting_window_request["policy_decision"] == "ALLOW"
        assert client.get(
            f"/api/v1/requests/{window_request_id}",
            headers={"Authorization": f"Bearer {agent_one}"},
        ).json()["status"] == "WAITING"
        for _ in range(2):
            assert client.post(
                "/internal/v1/minions/PATCH-01/missions/claim",
                headers={"Authorization": f"Bearer {minion_key}"},
            ).json() is None
        waiting_events = client.get(
            "/admin/v1/audit-events",
            params={"request_id": window_request_id, "event_type": "mission.waiting_for_window"},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert len(waiting_events) == 1

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: True)
        claimed_window_mission = client.post(
            "/internal/v1/minions/PATCH-01/missions/claim",
            headers={"Authorization": f"Bearer {minion_key}"},
        )
        assert claimed_window_mission.status_code == 200
        assert claimed_window_mission.json()["envelope"]["target"]["servers"] == ["server05.example.gov"]
        assert "window_override" not in claimed_window_mission.json()["envelope"]["parameters"]["patch_constraints"]

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

        service.initialize()
        restored_history = client.get(
            "/admin/v1/audit-events",
            params={"request_id": request_id},
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["events"]
        assert any(event["event_type"] == "signature.verification" and event["signature_verified"] is False for event in restored_history)
        assert any(event["event_type"] == "minion.result" and event["status"] == "MISSION_COMPLETE_SUCCEEDED" for event in restored_history)
        assert any(event["event_type"] == "mission.claim_reissued" for event in restored_history)


def test_outside_window_behavior_comes_from_policy_obligation(monkeypatch) -> None:
    from sg_service import mission_control as service

    window = {"timezone": "UTC", "days": ["SAT"], "start": "01:00", "end": "05:00"}
    target_obligation = SimpleNamespace(type="allowed_patch_targets", data={"servers": ["server.example.gov"]})

    def policy_with(outside_window: str | None, decision: str = "ALLOW", **extra):
        constraints = {
            "patch_sources": ["wsus"],
            "allowed_patch_types": ["SECURITY"],
            "allow_reboot": False,
            "maintenance_window": window,
            **extra,
        }
        if outside_window is not None:
            constraints["outside_window"] = outside_window
        patch_obligation = SimpleNamespace(type="patch_constraints", data=constraints)
        return SimpleNamespace(decide=lambda _: (decision, [target_obligation, patch_obligation], "policy-hash"))

    monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: False)

    monkeypatch.setattr(service, "policy_engine", policy_with("WAIT"))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "ALLOW"

    monkeypatch.setattr(service, "policy_engine", policy_with(None))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "ALLOW"

    monkeypatch.setattr(service, "policy_engine", policy_with("BLOCK"))
    assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "BLOCK"
    assert service.decide_patch_policy(
        "agent", ["server.example.gov"], context={"approval": {"approved": True}}
    )[0] == "ALLOW"

    for invalid in ("PAUSE", "DEFER", "wait"):
        monkeypatch.setattr(service, "policy_engine", policy_with(invalid))
        assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "BLOCK"
    for invalid_hours in (0, "12", True, service.MAX_WAIT_MAX_HOURS + 1):
        monkeypatch.setattr(service, "policy_engine", policy_with("WAIT", wait_max_hours=invalid_hours))
        assert service.decide_patch_policy("agent", ["server.example.gov"])[0] == "BLOCK"


def test_recurring_maintenance_window_evaluation() -> None:
    from datetime import datetime, timezone
    from sg_service import mission_control as service

    def at(text: str) -> datetime:
        return datetime.fromisoformat(text).astimezone(timezone.utc)

    saturday = {"timezone": "America/New_York", "days": ["SAT"], "start": "01:00", "end": "05:00"}
    assert service.is_maintenance_window_open(None)
    # 2026-11-07 is a Saturday; New York is UTC-5 after the November 1 DST change.
    assert service.is_maintenance_window_open(saturday, now=at("2026-11-07T01:00:00-05:00"))
    assert service.is_maintenance_window_open(saturday, now=at("2026-11-07T06:30:00+00:00"))
    assert not service.is_maintenance_window_open(saturday, now=at("2026-11-07T05:00:00-05:00"))
    assert not service.is_maintenance_window_open(saturday, now=at("2026-11-07T00:59:59-05:00"))
    assert not service.is_maintenance_window_open(saturday, now=at("2026-11-08T02:00:00-05:00"))
    assert service.is_maintenance_window_open(saturday, now=at("2026-11-14T02:00:00-05:00"))

    overnight = {"timezone": "UTC", "days": ["FRI"], "start": "22:00", "end": "04:00"}
    assert service.is_maintenance_window_open(overnight, now=at("2026-11-06T23:00:00+00:00"))
    assert service.is_maintenance_window_open(overnight, now=at("2026-11-07T03:59:00+00:00"))
    assert not service.is_maintenance_window_open(overnight, now=at("2026-11-07T04:00:00+00:00"))
    assert not service.is_maintenance_window_open(overnight, now=at("2026-11-07T23:00:00+00:00"))

    for invalid in (
        {"timezone": "Not/AZone", "days": ["SAT"], "start": "01:00", "end": "05:00"},
        {"timezone": "UTC", "days": [], "start": "01:00", "end": "05:00"},
        {"timezone": "UTC", "days": ["SAT", "SAT"], "start": "01:00", "end": "05:00"},
        {"timezone": "UTC", "days": ["SATURDAY"], "start": "01:00", "end": "05:00"},
        {"timezone": "UTC", "days": ["SAT"], "start": "1:00", "end": "05:00"},
        {"timezone": "UTC", "days": ["SAT"], "start": "24:00", "end": "05:00"},
        {"timezone": "UTC", "days": ["SAT"], "start": "01:00", "end": "01:00"},
        {"timezone": "UTC", "days": ["SAT"], "start": "01:00"},
        {"start_utc": "2026-10-16T00:00:00Z", "end_utc": "2026-10-16T04:00:00Z"},
    ):
        assert not service.is_valid_maintenance_window(invalid), invalid
        assert not service.is_maintenance_window_open(invalid)


def test_approved_pause_outside_window_runs_now_with_signed_override(tmp_path: Path, monkeypatch) -> None:
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
    monkeypatch.setattr(service, "DATABASE_PATH", tmp_path / "service.sqlite3")
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", signing_key_path)
    monkeypatch.setattr(service, "POLICY_PATH", policy_path)
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)
    window = [
        "        maintenance_window:",
        "          timezone: America/New_York",
        "          days: [SAT]",
        "          start: '01:00'",
        "          end: '05:00'",
        "        outside_window: WAIT",
    ]
    policy_path.write_text(
        "\n".join(
            [
                "version: 1",
                "default: {decision: BLOCK}",
                "rules:",
                "  - name: pause-urgent",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "      - {path: context.approval.approved, exists: false}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [server06.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                *window,
                "    decision: PAUSE",
                "  - name: allow-after-approval",
                "    when:",
                "      - {path: action.name, eq: windows.patch.reconcile}",
                "    obligations:",
                "      - type: allowed_patch_targets",
                "        servers: [server06.example.gov]",
                "      - type: patch_constraints",
                "        patch_sources: [wsus]",
                "        allowed_patch_types: [SECURITY]",
                "        allow_reboot: false",
                *window,
                "    decision: ALLOW",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "bootstrap-admin-secret")

    def approve_while(window_open: bool, client, request_id: str, admin_key: str) -> dict:
        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: window_open)
        response = client.post(
            f"/admin/v1/requests/{request_id}/approve",
            json={"approver": "sec-lead"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "ALLOW"
        with service.connect() as connection:
            row = connection.execute("SELECT envelope, status FROM missions WHERE request_id = ?", (request_id,)).fetchone()
        assert row["status"] == "QUEUED"
        return json.loads(row["envelope"])

    with TestClient(service.app) as client:
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer bootstrap-admin-secret"},
        ).json()["api_key"]
        agent_key = client.post(
            "/admin/v1/credentials/agent/agent-one",
            headers={"Authorization": f"Bearer {admin_key}"},
        ).json()["api_key"]

        def request_patch() -> str:
            response = client.post(
                "/api/v1/patch-requests",
                json={"servers": ["server06.example.gov"]},
                headers={"Authorization": f"Bearer {agent_key}"},
            )
            assert response.status_code == 202
            return response.json()["request_id"]

        monkeypatch.setattr(service, "is_maintenance_window_open", lambda _window, now=None: False)
        outside_request = request_patch()
        assert client.get(
            f"/admin/v1/requests/{outside_request}", headers={"Authorization": f"Bearer {admin_key}"}
        ).json()["status"] == "WAITING_FOR_APPROVAL"
        envelope = approve_while(False, client, outside_request, admin_key)
        override = envelope["parameters"]["patch_constraints"]["window_override"]
        assert override["approved_by"] == "admin" or override["approved_by"]
        assert service.envelope_waits_for_window(envelope) is False
        assert service.schema_errors("envelope", envelope) == []

        # Cancel the first request's open slot so an equivalent request can be raised again.
        with service.connect() as connection:
            connection.execute("UPDATE missions SET status = 'MISSION_CANCELLED' WHERE request_id = ?", (outside_request,))
            connection.commit()

        inside_request = request_patch()
        envelope = approve_while(True, client, inside_request, admin_key)
        assert "window_override" not in envelope["parameters"]["patch_constraints"]


def test_time_zone_map_matches_minion_and_resolves_in_zoneinfo() -> None:
    import re
    from zoneinfo import ZoneInfo

    from sg_service.protocol import protocol_dir, supported_time_zones

    mapping = json.loads((protocol_dir() / "windows-timezones.json").read_text(encoding="utf-8"))
    engine = (protocol_dir().parent / "minions" / "patching" / "PatchingEngine.psm1").read_text(encoding="utf-8")
    block = engine.split("$script:IanaToWindowsTimeZone = @{", 1)[1].split("\n}", 1)[0]
    assert dict(re.findall(r"'([^']+)' = '([^']+)'", block)) == mapping
    assert supported_time_zones() == frozenset(mapping)
    for name in mapping:
        ZoneInfo(name)
