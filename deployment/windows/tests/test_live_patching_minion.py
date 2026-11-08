"""Live Mission Control and PowerShell Minion smoke test; all patching is dry-run."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / "minion-registry/minions/patching/minion-release.json"
POLICY = """\
version: 1
default: {decision: BLOCK}
rules:
  - name: allow-test-patch
    when:
      - {path: action.name, eq: windows.patch.reconcile}
    obligations:
      - type: allowed_patch_targets
        servers: [target.example.test]
      - type: patch_constraints
        patch_sources: [nessus_catalog]
        allowed_patch_types: [SECURITY]
        allow_reboot: false
        maintenance_window: null
      - type: allowed_patch_executables
        executables: [msiexec.exe]
    decision: ALLOW
"""


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell is required")
def test_real_worker_processes_signed_dry_run_and_rejects_bad_hash(tmp_path, monkeypatch):
    from sg_service import mission_control as service

    service_key = ed25519.Ed25519PrivateKey.generate()
    worker_key = ed25519.Ed25519PrivateKey.generate()

    def private_bytes(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def public_bytes(key):
        return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    (tmp_path / "service-key.pem").write_bytes(private_bytes(service_key))
    (tmp_path / "service-public.pem").write_bytes(public_bytes(service_key))
    (tmp_path / "worker-key.pem").write_bytes(private_bytes(worker_key))
    (tmp_path / "policy.yml").write_text(POLICY, encoding="utf-8")
    admin_key = secrets.token_urlsafe(32)
    monkeypatch.setattr(service, "DATABASE_PATH", tmp_path / "service.sqlite3")
    monkeypatch.setattr(service, "SIGNING_KEY_PATH", tmp_path / "service-key.pem")
    monkeypatch.setattr(service, "POLICY_PATH", tmp_path / "policy.yml")
    monkeypatch.setattr(service, "ALLOW_FALLBACK_MINION", False)
    monkeypatch.setenv("SG_BOOTSTRAP_ADMIN_KEY", admin_key)
    monkeypatch.setenv("SG_DEV_BOOTSTRAP", "false")

    install = tmp_path / "Minion"
    runtime = install / "runtime"
    (runtime / "protocol").mkdir(parents=True)
    for source, target in [
        ("deployment/windows/Minion/SluiceGate.Minion.Service.exe", "SluiceGate.Minion.Service.exe"),
        ("minion-registry/minions/patching/PatchingMinion.ps1", "runtime/PatchingMinion.ps1"),
        ("minion-registry/minions/patching/PatchingCatalog.psm1", "runtime/PatchingCatalog.psm1"),
        ("minion-registry/minions/patching/PatchingEngine.psm1", "runtime/PatchingEngine.psm1"),
        ("minion-registry/templates/powershell/SluiceGate.Minion.Core.psm1", "runtime/SluiceGate.Minion.Core.psm1"),
        ("minion-registry/protocol/mission-envelope.schema.json", "runtime/protocol/mission-envelope.schema.json"),
    ]:
        shutil.copyfile(ROOT / source, install / target)
    shutil.copyfile(RELEASE, runtime / "minion-release.json")

    patch = tmp_path / "synthetic-patch.msi"
    patch.write_bytes(b"synthetic test data; not an installer")
    catalog = tmp_path / "catalog.csv"
    with catalog.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["patch_status", "plugin_id", "iavm_id", "vendor", "title", "patch_id", "patch_title", "patch_type", "requires_reboot", "patch_path", "patch_sha256", "source_url", "install_command", "notes"])
        writer.writerow(["APPROVED", "101", "TEST", "Test", "Test", "TEST-1", "Test", "SECURITY", "false", str(patch), hashlib.sha256(patch.read_bytes()).hexdigest(), "", 'msiexec.exe /i "%PATCHPATH%" /qn', "synthetic"])
    mapping = tmp_path / "mapping.csv"
    mapping.write_text("PLUGIN_ID,DNS_NAME\n101,target.example.test\n", encoding="utf-8")

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(service.app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 30
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert server.started, "Mission Control failed to start"
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=15, trust_env=False) as client:
            admin = {"Authorization": f"Bearer {admin_key}"}

            def post(path, body, headers):
                response = client.post(path, json=body, headers=headers)
                assert response.is_success, f"{path}: {response.status_code} {response.text}"
                return response.json()

            manifest = json.loads(RELEASE.read_text(encoding="utf-8"))
            post("/admin/v1/minion-types", manifest, admin)
            instance = post("/admin/v1/minions", {
                "type_id": manifest["type_id"], "minion_id": "PATCH-01",
                "capabilities": ["windows.patch.reconcile"], "scope_metadata": {"targets": ["target.example.test"]},
                "public_key": public_bytes(worker_key).decode(),
            }, admin)
            agent = post("/admin/v1/agents", {"name": "Windows smoke test"}, admin)
            agent_headers = {"Authorization": f"Bearer {agent['api_key']}"}
            (tmp_path / "api-key.txt").write_text(instance["api_key"], encoding="utf-8")
            config = {
                "MissionControlUrl": f"http://127.0.0.1:{port}", "AllowInsecureHttp": True,
                "MinionId": "PATCH-01", "ApiKeyPath": str(tmp_path / "api-key.txt"),
                "SluiceGatePublicKeyPath": str(tmp_path / "service-public.pem"),
                "MinionPrivateKeyPath": str(tmp_path / "worker-key.pem"),
                "CatalogPath": str(catalog), "NessusMappingPath": str(mapping),
                "NonceStorePath": str(tmp_path / "nonces.txt"),
                "MissionDiaryDirectory": str(tmp_path / "diaries"), "DryRun": True,
            }
            config_path = tmp_path / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            def worker_pass():
                process = subprocess.run(
                    ["pwsh", "-NoProfile", "-File", str(runtime / "PatchingMinion.ps1"), "-ConfigPath", str(config_path), "-SinglePass"],
                    capture_output=True, text=True, timeout=180, env={**os.environ, "ProgramData": str(tmp_path)},
                )
                assert process.returncode == 0, f"Worker failed:\n{process.stdout}\n{process.stderr}"
                return process.stdout

            worker_pass()
            assert client.get("/admin/v1/minions/PATCH-01", headers=admin).json()["release_status"] == "MATCH"

            def run_mission():
                submission = post("/api/v1/patch-requests", {"servers": ["target.example.test"]}, agent_headers)
                output = worker_pass()
                response = client.get("/admin/v1/audit-events", params={"request_id": submission["request_id"]}, headers=admin)
                response.raise_for_status()
                events = response.json()["events"]
                result = next((event for event in events if event["event_type"] == "minion.result"), None)
                assert result is not None, f"No signed result. Worker output:\n{output}"
                assert result["signature_verified"] is True
                return result["detail"]["signed_payload"]

            result = run_mission()
            assert result["status"] == "MISSION_COMPLETE_SUCCEEDED"
            patch_result = result["result"]["target_results"][0]["catalog_patches"][0]
            assert patch_result["status"] == "SUCCESS"
            assert patch_result["error"] == "DryRun: Verification succeeded."

            patch.write_bytes(b"changed after catalog approval")
            result = run_mission()
            assert result["status"] == "MISSION_COMPLETE_FAILED"
            assert "SHA-256 hash check failed" in result["result"]["target_results"][0]["catalog_patches"][0]["error"]
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        listener.close()
        assert not thread.is_alive(), "Mission Control did not stop"
