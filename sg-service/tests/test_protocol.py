from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import register_test_minion

from sg_service.protocol import canonical_json, protocol_dir, schema_errors

VECTORS = protocol_dir() / "test-vectors"

POLICY = "\n".join([
    "version: 1",
    "default: {decision: BLOCK}",
    "rules:",
    "  - name: allow-patching",
    "    when:",
    "      - {path: action.name, eq: windows.patch.reconcile}",
    "    obligations:",
    "      - type: allowed_patch_targets",
    "        servers: [SERVER_A.example.gov]",
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


def public_pem(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def signed_status(key, minion_id, mission_id, claim, event_id, status, detail=None, generation=None, occurred_at=1_800_000_000):
    detail = {} if detail is None else detail
    generation = claim["claim_generation"] if generation is None else generation
    payload = {"event_id": event_id, "mission_id": mission_id, "minion_id": minion_id, "claim_generation": generation, "status": status, "detail": detail, "occurred_at": occurred_at}
    return {"event_id": event_id, "claim_token": claim["claim_token"], "claim_generation": generation, "status": status, "detail": detail, "occurred_at": occurred_at, "signature": key.sign(canonical_json(payload)).hex()}


def signed_result(key, minion_id, mission_id, claim, event_id, status, result, generation=None):
    generation = claim["claim_generation"] if generation is None else generation
    payload = {"event_id": event_id, "mission_id": mission_id, "minion_id": minion_id, "claim_generation": generation, "status": status, "result": result}
    return {"event_id": event_id, "claim_token": claim["claim_token"], "claim_generation": generation, "status": status, "result": result, "signature": key.sign(canonical_json(payload)).hex()}


@pytest.fixture
def mission(tmp_path: Path, monkeypatch):
    """A claimed patch Mission for PATCH-01 plus helpers to talk to Mission Control as that Minion."""
    from sg_service import mission_control as service

    signing_key_path = tmp_path / "sg-signing-key.pem"
    policy_path = tmp_path / "policy.yml"
    service_key = ed25519.Ed25519PrivateKey.generate()
    signing_key_path.write_bytes(service_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    policy_path.write_text(POLICY, encoding="utf-8")
    monkeypatch.setattr(service, "DATABASE_PATH", tmp_path / "service.sqlite3")
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", signing_key_path)
    monkeypatch.setattr(service, "POLICY_PATH", policy_path)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "test-admin-secret")

    minion_key = ed25519.Ed25519PrivateKey.generate()
    with TestClient(service.app) as client:
        admin = {"Authorization": "Bearer " + client.post("/admin/v1/credentials/admin/admin", headers={"Authorization": "Bearer test-admin-secret"}).json()["api_key"]}
        registered = register_test_minion(
            client, admin, {"minion_id": "PATCH-01", "name": "Patcher", "capabilities": ["windows.patch.reconcile", "demo.action"], "scope_metadata": {"targets": ["*"]}, "public_key": public_pem(minion_key)},
        ).json()
        minion = {"Authorization": f"Bearer {registered['api_key']}"}
        client.post("/internal/v1/minions/PATCH-01/check-in", headers=minion)
        agent = {"Authorization": "Bearer " + client.post("/admin/v1/agents", json={"name": "Agent"}, headers=admin).json()["api_key"]}

        def claim(body: dict | None = None, path: str = "/api/v1/patch-requests") -> dict:
            assert client.post(path, json=body or {"servers": ["SERVER_A.example.gov"]}, headers=agent).status_code == 202
            claimed = client.post("/internal/v1/minions/PATCH-01/missions/claim", headers=minion).json()
            assert claimed and claimed.get("mission_id")
            return claimed

        yield SimpleNamespace(
            service=service, client=client, admin=admin, minion=minion, agent=agent, service_key=service_key, minion_key=minion_key,
            claim=claim, claimed=claim(),
            status=lambda mission_id, body: client.post(f"/internal/v1/minions/PATCH-01/missions/{mission_id}/status", json=body, headers=minion),
            result=lambda mission_id, body: client.post(f"/internal/v1/minions/PATCH-01/missions/{mission_id}/result", json=body, headers=minion),
        )


def test_issued_patch_envelope_matches_the_schema_and_signature(mission) -> None:
    envelope = dict(mission.claimed["envelope"])
    assert schema_errors("envelope", envelope) == []
    signature = bytes.fromhex(envelope.pop("signature"))
    mission.service_key.public_key().verify(signature, canonical_json(envelope))


def test_issued_generic_envelope_matches_the_schema(mission) -> None:
    mission.status(mission.claimed["mission_id"], signed_status(mission.minion_key, "PATCH-01", mission.claimed["mission_id"], mission.claimed, "evt-ack", "MISSION_REJECTED"))
    generic = mission.claim({"capability": "demo.action", "target": {"id": "T-1"}, "parameters": {"amount": 5}}, "/api/v1/actions")
    assert generic["envelope"]["capability"] == "demo.action"
    assert generic["envelope"]["execution"]["max_attempts"] == 3
    assert schema_errors("envelope", generic["envelope"]) == []


def test_unsigned_status_event_is_rejected(mission) -> None:
    body = signed_status(mission.minion_key, "PATCH-01", mission.claimed["mission_id"], mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED")
    del body["signature"]
    assert mission.status(mission.claimed["mission_id"], body).status_code == 422


@pytest.mark.parametrize("change", [{"status": "MISSION_FOO"}, {"signature": "ZZ" * 64}, {"signature": "00"}, {"occurred_at": -1}, {"extra": 1}])
def test_malformed_status_event_is_rejected_by_the_schema(mission, change) -> None:
    body = {**signed_status(mission.minion_key, "PATCH-01", mission.claimed["mission_id"], mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED"), **change}
    assert mission.status(mission.claimed["mission_id"], body).status_code == 422


def test_status_signed_by_another_key_is_rejected(mission) -> None:
    body = signed_status(ed25519.Ed25519PrivateKey.generate(), "PATCH-01", mission.claimed["mission_id"], mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED")
    assert mission.status(mission.claimed["mission_id"], body).status_code == 401


def test_status_with_tampered_detail_is_rejected(mission) -> None:
    body = signed_status(mission.minion_key, "PATCH-01", mission.claimed["mission_id"], mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED", {"a": 1})
    body["detail"] = {"a": 2}
    assert mission.status(mission.claimed["mission_id"], body).status_code == 401


def test_status_for_a_stale_claim_generation_is_rejected(mission) -> None:
    mission_id = mission.claimed["mission_id"]
    body = signed_status(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED", generation=mission.claimed["claim_generation"] + 1)
    response = mission.status(mission_id, body)
    assert response.status_code == 409 and "generation" in response.json()["detail"]


def test_status_signed_for_another_mission_is_rejected(mission) -> None:
    body = signed_status(mission.minion_key, "PATCH-01", "MISSION-OTHER", mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED")
    assert mission.status(mission.claimed["mission_id"], body).status_code == 401


def test_status_with_unicode_floats_and_nesting_verifies(mission) -> None:
    mission_id = mission.claimed["mission_id"]
    detail = {"note": "Zugriff verweigert: é 日本 😀 <x>", "ratio": 0.5, "whole": 3.0, "nested": {"list": [1, 2.25, None, True]}}
    body = signed_status(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED", detail)
    assert mission.status(mission_id, body).status_code == 200


def test_revoked_minion_key_cannot_submit_signed_events(mission) -> None:
    mission_id = mission.claimed["mission_id"]
    body = signed_status(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-1", "MISSION_ACKNOWLEDGED")
    assert mission.client.patch("/admin/v1/minions/PATCH-01", json={"enabled": False}, headers=mission.admin).status_code == 200
    assert mission.status(mission_id, body).status_code in {401, 403}


def test_result_with_invalid_signature_is_rejected(mission) -> None:
    mission_id = mission.claimed["mission_id"]
    mission.status(mission_id, signed_status(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-ack", "MISSION_ACKNOWLEDGED"))
    mission.status(mission_id, signed_status(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-run", "MISSION_IN_PROGRESS"))
    body = signed_result(ed25519.Ed25519PrivateKey.generate(), "PATCH-01", mission_id, mission.claimed, "evt-result", "MISSION_COMPLETE_SUCCEEDED", {"ok": True})
    assert mission.result(mission_id, body).status_code == 401


def test_result_for_a_stale_claim_generation_is_rejected(mission) -> None:
    mission_id = mission.claimed["mission_id"]
    body = signed_result(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-result", "MISSION_COMPLETE_SUCCEEDED", {"ok": True}, generation=99)
    assert mission.result(mission_id, body).status_code == 409


@pytest.mark.parametrize("change", [{"signature": "nothex"}, {"status": "MISSION_IN_PROGRESS"}, {"result": ["not", "an", "object"]}, {"claim_generation": 0}])
def test_malformed_result_is_rejected_by_the_schema(mission, change) -> None:
    mission_id = mission.claimed["mission_id"]
    body = {**signed_result(mission.minion_key, "PATCH-01", mission_id, mission.claimed, "evt-result", "MISSION_COMPLETE_SUCCEEDED", {"ok": True}), **change}
    assert mission.result(mission_id, body).status_code in {400, 422}


def test_canonical_vectors_match_the_python_implementation() -> None:
    for case in json.loads((VECTORS / "canonical-json.json").read_text(encoding="utf-8"))["canonical"]:
        assert canonical_json(json.loads(case["input"])).decode() == case["canonical"], case["name"]


def test_signature_vector_verifies() -> None:
    vector = json.loads((VECTORS / "canonical-json.json").read_text(encoding="utf-8"))["signature"]
    assert canonical_json(vector["payload"]).decode() == vector["canonical"]
    public_key = serialization.load_pem_public_key(vector["public_key_pem"].encode())
    public_key.verify(bytes.fromhex(vector["signature_hex"]), vector["canonical"].encode())


def test_envelope_fixtures_agree_with_the_schema() -> None:
    for fixture in json.loads((VECTORS / "envelope-fixtures.json").read_text(encoding="utf-8"))["fixtures"]:
        assert (schema_errors("envelope", fixture["envelope"]) == []) == fixture["valid"], fixture["name"]


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_numbers_cannot_be_signed(value) -> None:
    with pytest.raises(ValueError):
        canonical_json({"x": value})
