from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from minion_helpers import register_test_minion


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
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "test-admin-secret")

    policy_content = "\n".join([
        "version: 1",
        "default: {decision: BLOCK}",
        "rules:",
        "  - name: allow-router-test-servers",
        "    when:",
        "      - {path: action.name, eq: windows.patch.reconcile}",
        "    obligations:",
        "      - type: allowed_patch_targets",
        "        servers: [SERVER_DYN_01.example.gov, SERVER_DYN_02.example.gov]",
        "      - type: patch_constraints",
        "        patch_sources: [wsus]",
        "        allowed_patch_types: [SECURITY]",
        "        allow_reboot: false",
        "        maintenance_window: null",
        "    decision: ALLOW",
    ])
    policy_path.write_text(policy_content, encoding="utf-8")
    return service


def test_minion_registration_router_and_checkin(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)

    minion_priv = ed25519.Ed25519PrivateKey.generate()
    minion_pub_pem = minion_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    with TestClient(service.app) as client:
        # Bootstrap admin
        admin_key = client.post(
            "/admin/v1/credentials/admin/admin",
            headers={"Authorization": "Bearer test-admin-secret"},
        ).json()["api_key"]
        admin_headers = {"Authorization": f"Bearer {admin_key}"}

        # 1. Register Minion via Admin API
        reg_resp = register_test_minion(
            client, admin_headers, {
                "minion_id": "DYNAMIC-PATCHER-01",
                "name": "Dynamic Windows Patching Minion",
                "runtime_type": "powershell",
                "environment": "prod",
                "capabilities": ["windows.patch.reconcile", "windows.patch.status"],
                "scope_metadata": {"targets": ["server_dyn_*.example.gov"]},
                "version": "2.4.1",
                "package_sha256": "a" * 64,
                "public_key": minion_pub_pem,
            },
        )
        assert reg_resp.status_code == 201
        minion_info = reg_resp.json()
        assert minion_info["minion_id"] == "DYNAMIC-PATCHER-01"
        minion_key = minion_info["api_key"]
        assert minion_info["package_approved"] is True
        assert minion_info["version"] == "2.4.1"
        package_audit = client.get(
            "/admin/v1/audit-events", params={"minion_id": "DYNAMIC-PATCHER-01", "event_type": "minion.package_approved"}, headers=admin_headers
        ).json()["events"]
        assert package_audit[0]["detail"] == {"version": "2.4.1", "sha256": "a" * 64}

        # 2. Check-in updates last_contact_at
        minion_headers = {"Authorization": f"Bearer {minion_key}"}
        check_resp = client.post(
            "/internal/v1/minions/DYNAMIC-PATCHER-01/check-in",
            headers=minion_headers,
        )
        assert check_resp.status_code == 200
        assert check_resp.json()["status"] == "CONNECTED"

        details = client.get("/admin/v1/minions/DYNAMIC-PATCHER-01", headers=admin_headers).json()
        assert details["last_contact_at"] is not None
        assert details["health_status"] == "HEALTHY"
        assert details["scope_metadata"]["targets"] == ["server_dyn_*.example.gov"]
        assert details["package_sha256"] == "a" * 64
        assert details["keys"][0]["status"] == "ACTIVE"
        assert "secret_hash" not in details["keys"][0] and minion_key not in str(details)

        # 3. Register an agent to submit requests
        agent_data = client.post(
            "/admin/v1/agents",
            json={"name": "Test Patcher Agent"},
            headers=admin_headers,
        ).json()
        agent_headers = {"Authorization": f"Bearer {agent_data['api_key']}"}

        # 4. Agent submits patch request -> Router automatically assigns to DYNAMIC-PATCHER-01!
        req_resp = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_DYN_01.example.gov"]},
            headers=agent_headers,
        )
        assert req_resp.status_code == 202

        # 5. Minion claims mission assigned dynamically to it
        claim_resp = client.post(
            "/internal/v1/minions/DYNAMIC-PATCHER-01/missions/claim",
            headers=minion_headers,
        )
        assert claim_resp.status_code == 200
        claimed = claim_resp.json()
        assert claimed is not None
        assert claimed["envelope"]["minion_id"] == "DYNAMIC-PATCHER-01"
        assert claimed["envelope"]["capability"] == "windows.patch.reconcile"
        recent = client.get("/admin/v1/minions/DYNAMIC-PATCHER-01/missions", headers=admin_headers).json()
        assert recent[0]["mission_id"] == claimed["mission_id"]
        assert recent[0]["capability"] == "windows.patch.reconcile"

        # 6. Disable Minion -> Router can no longer route to it
        client.patch(
            "/admin/v1/minions/DYNAMIC-PATCHER-01",
            json={"enabled": False},
            headers=admin_headers,
        )
        disabled_details = client.get("/admin/v1/minions/DYNAMIC-PATCHER-01", headers=admin_headers).json()
        assert disabled_details["health_status"] == "DISABLED"
        # Disabled Minion with the fallback off (the default): no eligible Minion exists
        unroutable = client.post(
            "/api/v1/patch-requests",
            json={"servers": ["SERVER_DYN_02.example.gov"]},
            headers=agent_headers,
        )
        assert unroutable.status_code == 503
        assert "No eligible Minion found" in unroutable.json()["detail"]


def _routing_fixture(service, client, scope_targets, capabilities=("windows.patch.reconcile",), check_in=True):
    minion_pub_pem = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    admin_key = client.post("/admin/v1/credentials/admin/admin", headers={"Authorization": "Bearer test-admin-secret"}).json()["api_key"]
    admin_headers = {"Authorization": f"Bearer {admin_key}"}
    minion = register_test_minion(
        client, admin_headers, {
            "minion_id": "ROUTE-01",
            "name": "Route test",
            "environment": "prod",
            "capabilities": list(capabilities),
            "scope_metadata": {"targets": scope_targets} if scope_targets is not None else {},
            "public_key": minion_pub_pem,
        },
    ).json()
    if check_in:
        client.post("/internal/v1/minions/ROUTE-01/check-in", headers={"Authorization": f"Bearer {minion['api_key']}"})
    agent = client.post("/admin/v1/agents", json={"name": "Route agent"}, headers=admin_headers).json()
    return {"Authorization": f"Bearer {agent['api_key']}"}


def _patch(client, agent_headers, *servers):
    return client.post("/api/v1/patch-requests", json={"servers": list(servers)}, headers=agent_headers)


def test_routing_requires_scope_covering_every_server(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, ["server_dyn_01.example.gov"])
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 202
        mixed = _patch(client, agent, "SERVER_DYN_01.example.gov", "SERVER_DYN_02.example.gov")
        assert mixed.status_code == 503
        assert "No eligible Minion found" in mixed.json()["detail"]


def test_minion_without_scope_is_not_routable(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, None)
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 503


def test_stale_or_never_contacted_minion_is_not_routable(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, ["*"], check_in=False)
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 503

        with service.transaction() as connection:
            connection.execute("UPDATE minions SET last_contact_at = ?", (service.time.time() - service.MINION_STALE_SECONDS - 5,))
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 503

        with service.transaction() as connection:
            connection.execute("UPDATE minions SET last_contact_at = ?", (service.time.time(),))
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 202


def test_capability_mismatch_is_not_routable(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, ["*"], capabilities=("windows.patch.status",))
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 503


def test_fallback_requires_explicit_flag_and_is_recorded(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "PATCH_MINION_ID", "FALLBACK-01")
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, ["other-*"])
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 503

        monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", True)
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 202
        with service.connect() as connection:
            row = connection.execute("SELECT minion_id, routing FROM missions").fetchone()
        routing = service.json.loads(row["routing"])
        assert row["minion_id"] == "FALLBACK-01"
        assert routing["fallback"] is True and routing["reason"] == "development fallback"


def test_minion_configuration_export_matches_runtime_contract_without_secrets(tmp_path: Path, monkeypatch) -> None:
    import json

    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_PUBLIC_URL", "https://control.example.gov")
    with TestClient(service.app) as client:
        _routing_fixture(service, client, ["server-*.example.gov"])
        assert client.get("/admin/v1/minions/ROUTE-01/configuration").status_code == 401
        admin_headers = {"Authorization": "Bearer test-admin-secret"}
        defaults_response = client.get("/admin/v1/minions/ROUTE-01/configuration", headers=admin_headers)
        assert defaults_response.status_code == 200
        defaults = defaults_response.json()["defaults"]
        assert defaults["mission_control_url"] == "https://control.example.gov"
        assert defaults["dry_run"] is True and defaults["poll_interval_seconds"] == 60
        assert defaults["api_key_path"].endswith("minion-api-key.txt")

        defaults.update(catalog_path=r"\\fileserver\patchrepo\patch_catalog.csv", nessus_mapping_path=r"\\fileserver\patchrepo\nessus_mapping.csv")
        downloaded = client.post("/admin/v1/minions/ROUTE-01/configuration", json=defaults, headers=admin_headers)
        assert downloaded.status_code == 200
        assert "attachment; filename=\"minion.config.json\"" == downloaded.headers["content-disposition"]
        configuration = json.loads(downloaded.content)
        required = {
            "MissionControlUrl", "MinionId", "SupportedCapabilities", "ApiKeyPath", "SluiceGatePublicKeyPath", "MinionPrivateKeyPath",
            "CatalogPath", "NessusMappingPath", "NonceStorePath", "MissionDiaryDirectory", "PollIntervalSeconds", "DryRun",
        }
        assert required.issubset(configuration)
        assert configuration["MissionControlUrl"] == "https://control.example.gov"
        assert configuration["MinionId"] == "ROUTE-01" and configuration["DryRun"] is True
        assert configuration["SupportedCapabilities"] == ["windows.patch.reconcile"]
        assert "ApiKey" not in configuration and "test-admin-secret" not in downloaded.text
        assert downloaded.headers["cache-control"] == "no-store"
        assert configuration["PollIntervalSeconds"] == 60


def test_minion_configuration_export_rejects_http_and_bad_trust_fingerprints(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        _routing_fixture(service, client, ["*"])
        headers = {"Authorization": "Bearer test-admin-secret"}
        defaults = client.get("/admin/v1/minions/ROUTE-01/configuration", headers=headers).json()["defaults"]
        defaults.update(catalog_path="C:\\patch_catalog.csv", nessus_mapping_path="C:\\mapping.csv", mission_control_url="http://control.example.gov")
        assert client.post("/admin/v1/minions/ROUTE-01/configuration", json=defaults, headers=headers).status_code == 422
        defaults["mission_control_url"] = "https://control.example.gov"
        defaults["trusted_server_certificate_sha256"] = ["not-a-fingerprint"]
        assert client.post("/admin/v1/minions/ROUTE-01/configuration", json=defaults, headers=headers).status_code == 422


def test_routing_decision_is_persisted_for_eligible_minion(tmp_path: Path, monkeypatch) -> None:
    service = setup_test_service(tmp_path, monkeypatch)
    with TestClient(service.app) as client:
        agent = _routing_fixture(service, client, ["*"])
        assert _patch(client, agent, "SERVER_DYN_01.example.gov").status_code == 202
        with service.connect() as connection:
            routing = service.json.loads(connection.execute("SELECT routing FROM missions").fetchone()["routing"])
        assert routing["minion_id"] == "ROUTE-01" and routing["reason"] == "eligible" and routing["fallback"] is False
