from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def register_test_minion(client, headers, body):
    """Create a test-only release manifest before deploying its instance."""
    manifest = {
        "schema_version": 2,
        "type_id": f"test-{body['minion_id']}",
        "family": f"test-{body['minion_id']}",
        "name": body.get("name", "Test Minion"),
        "version": body.get("version", "1.0"),
        "runtime_type": body.get("runtime_type", "powershell"),
        "artifact": "test-artifact",
        "package_sha256": body.get("package_sha256") or "0" * 64,
        "capabilities": body.get("capabilities", ["windows.patch.reconcile"]),
        "requires_target_scope": False,
        "release_files": ["worker.py"],
    }
    response = client.post("/admin/v1/minion-types", json=manifest, headers=headers)
    assert response.status_code == 201, response.text
    instance = {
        "minion_id": body["minion_id"],
        "type_id": manifest["type_id"],
        "environment": body.get("environment", "prod"),
        "capabilities": manifest["capabilities"],
        "scope_metadata": body.get("scope_metadata", {}),
        "public_key": body["public_key"],
    }
    return client.post("/admin/v1/minions", json=instance, headers=headers)


def check_in_test_minion(client, minion):
    response = client.post(
        f"/internal/v1/minions/{minion['minion_id']}/check-in",
        headers={"Authorization": f"Bearer {minion['api_key']}"},
        json={"version": minion["version"], "fingerprint": minion["package_sha256"]},
    )
    assert response.status_code == 200, response.text


def create_routable_test_minion(client, headers):
    key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    response = register_test_minion(client, headers, {
        "minion_id": "PATCH-01", "public_key": key, "scope_metadata": {"targets": ["*"]},
        "capabilities": ["windows.patch.reconcile", "demo.action"],
    })
    assert response.status_code == 201, response.text
    check_in_test_minion(client, response.json())
    return response.json()
