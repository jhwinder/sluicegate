from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_mission_control_tls import REPOSITORY, make_certificate


def run_powershell(script: str, work_dir: Path) -> dict:
    relative = f"deployment/windows/tests/{script}"
    local = shutil.which("pwsh")
    if local:
        command = [local, "-NoProfile", "-File", str(REPOSITORY / relative), "-WorkDir", str(work_dir)]
    else:
        docker = shutil.which("docker")
        image = os.environ.get("SG_TEST_POWERSHELL_IMAGE", "mcr.microsoft.com/powershell:lts-debian-12")
        if not docker or subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode != 0:
            pytest.skip("PowerShell (pwsh, or the Microsoft PowerShell container image) is not available")
        command = [
            docker, "run", "--rm",
            "-v", f"{REPOSITORY / 'minion-registry'}:/minion-registry:ro",
            "-v", f"{REPOSITORY / 'deployment'}:/deployment:ro",
            "-v", f"{work_dir}:/work",
            image, "pwsh", "-NoProfile", "-File", f"/{relative}", "-WorkDir", "/work",
        ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_installer_helpers_and_api_key_loading(tmp_path: Path) -> None:
    first, second = make_certificate("first", ("a.example",)), make_certificate("second", ("b.example",))
    (tmp_path / "bundle.pem").write_bytes(first.certificate_pem + second.certificate_pem)
    (tmp_path / "garbage.pem").write_text("not a certificate")
    (tmp_path / "api-key.txt").write_text("minion-api-key-value\r\n")
    (tmp_path / "empty-key.txt").write_text("  \n")

    results = run_powershell("Test-Package.ps1", tmp_path)

    assert results["fingerprints"]["value"] == [first.sha256, second.sha256]
    assert not results["fingerprint_of_garbage"]["ok"] and "No PEM-encoded certificate" in results["fingerprint_of_garbage"]["message"]

    plain = results["config_without_certificate"]["value"]
    assert plain["MinionId"] == "PATCH-02" and plain["MissionControlUrl"] == "https://sluicegate.example.internal"
    assert plain["DryRun"] is True
    assert "ApiKey" not in plain and plain["ApiKeyPath"].endswith("minion-api-key.txt")
    assert "TrustedServerCertificatePath" not in plain and "TrustedServerCertificateSha256" not in plain
    assert plain["PollIntervalSeconds"] == 3600  # template values the installer does not override are kept

    trusted = results["config_with_certificate"]["value"]
    assert trusted["TrustedServerCertificatePath"].endswith("sg-server-cert.pem")
    assert trusted["TrustedServerCertificateSha256"] == ["AA11", "BB22"]

    assert results["config_drops_inline_api_key"]["value"] is False

    assert results["api_key"]["value"] == "minion-api-key-value"
    for name, fragment in {
        "api_key_inline": "inline ApiKey",
        "api_key_unset": "ApiKeyPath is required",
        "api_key_missing_file": "not found",
        "api_key_empty_file": "empty",
    }.items():
        assert not results[name]["ok"], name
        assert fragment in results[name]["message"], (name, results[name])
        assert "inline-secret" not in results[name]["message"]


def test_bundle_contains_everything_the_installer_requires(tmp_path: Path) -> None:
    results = run_powershell("Test-Bundle.ps1", tmp_path)
    bundle = tmp_path / "bundle"

    # Keep in step with $requiredArtifacts in Install-SluiceGate.ps1 (Minion-only portion).
    required = [
        "Minion/SluiceGate.Minion.Service.exe",
        "Minion/runtime/PatchingMinion.ps1",
        "Minion/runtime/PatchingCatalog.psm1",
        "Minion/runtime/PatchingEngine.psm1",
        "Minion/runtime/SluiceGate.Minion.Core.psm1",
        "Minion/runtime/protocol/mission-envelope.schema.json",
        "Minion/runtime/version.json",
        "minion.config.template.json",
        "Install-SluiceGate.ps1",
        "Uninstall-SluiceGate.ps1",
        "Set-MinionApiKey.ps1",
        "MinionInstallHelpers.ps1",
    ]
    for name in required:
        assert (bundle / name).is_file(), name

    version = json.loads((bundle / "Minion/runtime/version.json").read_text(encoding="utf-8-sig"))
    assert version["version"] == "9.9.9"

    template = json.loads((bundle / "minion.config.template.json").read_text(encoding="utf-8-sig"))
    assert "ApiKey" not in template and "ApiKeyPath" in template and template["DryRun"] is True

    manifest = {}
    for line in (bundle / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        manifest[name] = digest
    assert set(manifest) == {str(path.relative_to(bundle)).replace(os.sep, "/") for path in bundle.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"}
    for name, digest in manifest.items():
        assert hashlib.sha256((bundle / name).read_bytes()).hexdigest() == digest, name

    assert "not empty" in results["secondRun"]
