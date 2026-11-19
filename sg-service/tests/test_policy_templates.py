from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from test_admin_ui import setup_test_service


def test_template_catalog_supports_wizard_and_new_yaml_file_without_activation(tmp_path, monkeypatch):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_DEV_BOOTSTRAP", "false")
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "template-admin")
    headers = {"Authorization": "Bearer template-admin"}
    with TestClient(service.app) as client:
        assert client.get("/admin/v1/policy/templates").status_code == 401
        assert client.get("/admin/v1/policy/templates/patching").status_code == 401
        original = client.get("/admin/v1/policy", headers=headers).json()
        catalog = client.get("/admin/v1/policy/templates", headers=headers).json()
        assert [entry["id"] for entry in catalog] == ["patching"]
        assert client.get("/admin/v1/policy/templates/patching", headers=headers).json()["editor_mode"] == "patching_wizard"

        templates = tmp_path / "templates"
        templates.mkdir()
        yaml = "# Future template\nversion: 1\ndefault: {decision: BLOCK}\nrules: []\n"
        (templates / "future.yml").write_text(yaml, encoding="utf-8")
        (templates / "catalog.json").write_text(json.dumps(catalog + [{
            "id": "future", "name": "Future Policy", "description": "A generic YAML template",
            "editor_mode": "yaml", "file": "future.yml",
        }]), encoding="utf-8")
        monkeypatch.setattr(service, "POLICY_TEMPLATE_DIR", templates)
        listing = client.get("/admin/v1/policy/templates", headers=headers).json()
        assert [entry["id"] for entry in listing] == ["patching", "future"]
        assert all("file" not in entry for entry in listing)
        selected = client.get("/admin/v1/policy/templates/future", headers=headers)
        assert selected.status_code == 200 and selected.json()["content"] == yaml
        assert client.get("/admin/v1/policy/templates/unknown", headers=headers).status_code == 404
        assert client.get("/admin/v1/policy", headers=headers).json() == original
        assert not list(service.POLICY_PATH.parent.glob("*.bak"))


@pytest.mark.parametrize(("file", "content", "expected"), [
    ("missing.yml", None, 503),
    ("invalid.yml", "default: INVALID", 422),
    ("../outside.yml", "version: 1\ndefault: {decision: BLOCK}\nrules: []\n", 503),
])
def test_template_load_failure_does_not_read_outside_catalog_directory_or_change_policy(tmp_path, monkeypatch, file, content, expected):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "template-admin")
    templates = tmp_path / "templates"
    templates.mkdir()
    if content is not None:
        (templates / file).write_text(content, encoding="utf-8")
    (templates / "catalog.json").write_text(json.dumps([{
        "id": "bad", "name": "Broken", "description": "Unavailable template", "editor_mode": "yaml", "file": file,
    }]), encoding="utf-8")
    monkeypatch.setattr(service, "POLICY_TEMPLATE_DIR", templates)
    original = service.POLICY_PATH.read_bytes()
    with TestClient(service.app) as client:
        response = client.get("/admin/v1/policy/templates/bad", headers={"Authorization": "Bearer template-admin"})
        assert response.status_code == expected
        assert service.POLICY_PATH.read_bytes() == original


@pytest.mark.parametrize("catalog", ["not JSON", "{}", '[{"id":"x"}]', '[{"id":"x","name":"X","description":"X","editor_mode":"unknown"}]'])
def test_invalid_catalog_has_no_silent_fallback(tmp_path, monkeypatch, catalog):
    service = setup_test_service(tmp_path, monkeypatch)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", "template-admin")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "catalog.json").write_text(catalog, encoding="utf-8")
    monkeypatch.setattr(service, "POLICY_TEMPLATE_DIR", templates)
    with TestClient(service.app) as client:
        assert client.get("/admin/v1/policy/templates", headers={"Authorization": "Bearer template-admin"}).status_code == 503
