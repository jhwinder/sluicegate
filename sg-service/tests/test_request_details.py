from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import check_in_test_minion, register_test_minion
from test_admin_ui import setup_test_service


@pytest.fixture
def request_stack(tmp_path, monkeypatch):
    """Exercise the demo reader against a real, isolated service database."""
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_DEV_BOOTSTRAP", "false")
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "request-detail-admin")
    service.POLICY_PATH.write_text(
        (Path(__file__).resolve().parents[1] / "policies/demo-policy.yml").read_text(),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "sluice-demo/backend"))
    demo = importlib.import_module("app.main")
    with TestClient(service.app) as client:
        admin = {"Authorization": "Bearer request-detail-admin"}
        public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        minion = register_test_minion(client, admin, {
            "minion_id": "DETAIL-01", "public_key": public_key,
            "capabilities": ["stripe.charge", "stripe.refund"],
            "scope_metadata": {"targets": ["stripe.charge", "stripe.refund"]},
        }).json()
        check_in_test_minion(client, minion)
        agent = client.post("/admin/v1/agents", headers=admin, json={"name": "Detail agent"}).json()
        monkeypatch.setattr(demo, "SG_AGENT_API_KEY", agent["api_key"])
        monkeypatch.setattr(demo, "SG_ADMIN_API_KEY", "request-detail-admin")

        def get(url, **kwargs):
            kwargs.pop("timeout", None)
            return client.get(url.removeprefix(demo.SG_SERVICE_URL), **kwargs)

        def post(url, **kwargs):
            kwargs.pop("timeout", None)
            return client.post(url.removeprefix(demo.SG_SERVICE_URL), **kwargs)

        monkeypatch.setattr(demo.requests, "get", get)
        monkeypatch.setattr(demo.requests, "post", post)
        with TestClient(demo.app) as demo_client:
            yield service, client, demo_client, admin, agent


@pytest.mark.parametrize(("amount", "decision"), [(100, "ALLOW"), (500, "PAUSE"), (1000, "BLOCK"), (0, "ALLOW")])
def test_demo_and_admin_report_stored_input_through_lifecycle(request_stack, amount, decision):
    service, client, demo, admin, agent = request_stack
    payload = {"action": "stripe.charge", "amount": amount, "currency": "usd", "metadata": {"trial": amount}}
    result = demo.post("/api/decide", json=payload)
    assert result.status_code == 200, result.text
    assert result.json()["decision"] == decision
    request_id = result.json()["request_id"]
    path = f"/admin/v1/requests/{request_id}"
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"Authorization": f"Bearer {agent['api_key']}"}).status_code == 401
    detail = client.get(path, headers=admin).json()
    assert detail["agent_id"] == agent["agent_id"]
    assert detail["submitted_request"]["parameters"]["amount"] == amount
    assert detail["submitted_request"]["context"]["demo_metadata"] == payload["metadata"]
    assert detail["mission_envelope"]["parameters"]["amount"] == amount
    assert detail["request_source"] == "stored_request"
    expected = {**payload, "currency": "USD"}
    assert demo.get(f"/api/requests/{request_id}").json()["payload"] == expected

    history_before = client.get("/admin/v1/audit-events", headers=admin, params={"request_id": request_id}).json()
    if decision == "PAUSE":
        assert client.post(path + "/approve", headers=admin, json={}).status_code == 200
        assert client.get(path, headers=admin).json()["submitted_request"] == detail["submitted_request"]
    if decision == "BLOCK":
        assert detail["minion_id"] == "UNASSIGNED"
    service.initialize()
    with TestClient(demo.app) as restarted_demo:
        assert restarted_demo.get(f"/api/requests/{request_id}").json()["payload"] == expected
    history_after = client.get("/admin/v1/audit-events", headers=admin, params={"request_id": request_id}).json()
    original_ids = {event["audit_id"] for event in history_before["events"]}
    assert [event for event in history_after["events"] if event["audit_id"] in original_ids] == history_before["events"]


def test_demo_metadata_cannot_override_amount_currency_or_lose_its_own_values(request_stack):
    _, client, demo, admin, _ = request_stack
    payload = {
        "action": "stripe.refund", "amount": 1000, "currency": "eur",
        "metadata": {"amount": 1, "currency": "USD", "note": "original metadata"},
    }
    result = demo.post("/api/decide", json=payload).json()
    request_id = result["request_id"]
    parameters = client.get(f"/admin/v1/requests/{request_id}", headers=admin).json()["submitted_request"]["parameters"]
    assert parameters["amount"] == 1000 and parameters["currency"] == "EUR"
    assert demo.get(f"/api/requests/{request_id}").json()["payload"] == {**payload, "currency": "EUR"}


@pytest.mark.parametrize("raw", [None, "{}", "[]", "invalid JSON"])
def test_legacy_missing_request_uses_labeled_envelope_fallback(request_stack, raw):
    service, client, demo, admin, _ = request_stack
    request_id = demo.post("/api/decide", json={
        "action": "stripe.refund", "amount": 1000, "currency": "USD", "metadata": {"trial": "legacy"},
    }).json()["request_id"]
    with service.transaction() as connection:
        connection.execute("UPDATE missions SET raw_request = ? WHERE request_id = ?", (raw, request_id))
    detail = client.get(f"/admin/v1/requests/{request_id}", headers=admin).json()
    assert detail["submitted_request"] is None and detail["request_source"] == "unavailable"
    response = demo.get(f"/api/requests/{request_id}").json()
    assert response["payload_source"] == "mission_envelope"
    assert response["payload"] == {"action": "stripe.refund", "amount": 1000, "currency": "USD", "metadata": {"trial": "legacy"}}
    with service.transaction() as connection:
        envelope = detail["mission_envelope"]
        envelope.pop("parameters")
        connection.execute("UPDATE missions SET envelope = ? WHERE request_id = ?", (json.dumps(envelope), request_id))
    assert demo.get(f"/api/requests/{request_id}").json()["payload"]["amount"] is None
    assert demo.get("/api/requests/REQ-missing").status_code == 404


def test_generic_and_blocked_patch_requests_keep_their_original_details(request_stack):
    _, client, _, admin, agent = request_stack
    auth = {"Authorization": f"Bearer {agent['api_key']}"}
    submitted = {"capability": "inventory.read", "target": {"id": "host-1"}, "parameters": {"fields": ["version"]}, "context": {"ticket": "T-1"}}
    request_id = client.post("/api/v1/actions", headers=auth, json=submitted).json()["request_id"]
    detail = client.get(f"/admin/v1/requests/{request_id}", headers=admin).json()
    assert detail["submitted_request"] == submitted
    patch = {"servers": ["unauthorized.example.invalid"]}
    request_id = client.post("/api/v1/patch-requests", headers=auth, json=patch).json()["request_id"]
    detail = client.get(f"/admin/v1/requests/{request_id}", headers=admin).json()
    assert detail["submitted_request"] == patch
    assert detail["policy_decision"] == "BLOCK"
    assert detail["mission_envelope"]["target"] != patch


def test_demo_does_not_fabricate_details_when_service_lookup_fails(request_stack, monkeypatch):
    _, _, demo, _, _ = request_stack
    module = importlib.import_module("app.main")
    class Unavailable:
        status_code = 503
        def json(self):
            pytest.fail("An unsuccessful response must not be used as request data")
    monkeypatch.setattr(module.requests, "get", lambda *args, **kwargs: Unavailable())
    assert demo.get("/api/requests/REQ-any").status_code == 503
