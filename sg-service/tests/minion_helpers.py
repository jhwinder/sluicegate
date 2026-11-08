def register_test_minion(client, headers, body):
    """Create a test-only release manifest before deploying its instance."""
    manifest = {
        "schema_version": 1,
        "type_id": f"test-{body['minion_id']}",
        "name": body.get("name", "Test Minion"),
        "version": body.get("version", "1.0"),
        "runtime_type": body.get("runtime_type", "powershell"),
        "artifact": "test-artifact",
        "package_sha256": body.get("package_sha256") or "0" * 64,
        "capabilities": body.get("capabilities", ["windows.patch.reconcile"]),
        "requires_target_scope": False,
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
