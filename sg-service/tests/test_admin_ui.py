from __future__ import annotations

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def setup_test_service(tmp_path: Path, monkeypatch):
    from sg_service import minion_central_command as service

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
