from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from sg_poledit.validate import validate_policy_dict
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

    # Keep in step with $requiredArtifacts in Install-SluiceGate.ps1.
    required = [
        "Minion/SluiceGate.Minion.Service.exe",
        "Minion/runtime/PatchingMinion.ps1",
        "Minion/runtime/PatchingCatalog.psm1",
        "Minion/runtime/PatchingEngine.psm1",
        "Minion/runtime/SluiceGate.Minion.Core.psm1",
        "Minion/runtime/protocol/mission-envelope.schema.json",
        "Minion/runtime/version.json",
        "minion.config.template.json",
        "service.env.example",
        "policy.starter.yml",
        "new-selfsigned-certificate.sh",
        "images/sg-service-image.tar",
        "Install-SluiceGate.ps1",
        "Uninstall-SluiceGate.ps1",
        "Set-MinionApiKey.ps1",
        "MinionInstallHelpers.ps1",
        "WslServiceContainer.ps1",
    ]
    for name in required:
        assert (bundle / name).is_file(), name

    version = json.loads((bundle / "Minion/runtime/version.json").read_text(encoding="utf-8-sig"))
    assert version["version"] == "9.9.9" and version["serviceImage"] == "sluicegate/sg-service:9.9.9"

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


def test_starter_policy_is_valid_and_blocks_everything() -> None:
    policy = yaml.safe_load((REPOSITORY / "deployment/windows/policy.starter.yml").read_text(encoding="utf-8"))
    assert validate_policy_dict(policy).is_valid
    assert policy["default"]["decision"] == "BLOCK" and policy["rules"] == []


def test_wsl_service_container_installation(tmp_path: Path) -> None:
    results = run_powershell("Test-WslContainer.ps1", tmp_path)
    first, second = results["first"], results["second"]
    root = "/opt/sluicegate"

    assert first["files"] == [
        f"{root}/policy/production-policy.yml", f"{root}/secrets/sg-signing-key.pem",
        f"{root}/service.env", f"{root}/tls/server-cert.pem", f"{root}/tls/server-key.pem",
    ]
    assert first["env_mode"] == "0600"

    env = first["env"]
    assert "\r" not in env and env.endswith("\n")
    bootstrap = re.search(r"^SG_BOOTSTRAP_ADMIN_KEY=([0-9a-f]{64})$", env, re.M).group(1)
    assert "SG_PATCH_MINION_ID=PATCH-07" in env and "SG_PUBLIC_URL=https://sluicegate.example.internal:8443" in env
    assert "SG_POLICY_PATH=/config/production-policy.yml" in env
    assert first["policy"] == "FILE:policy.starter.yml" and first["policy_mode"] == "0640"

    # The certificate names include the public host, the Minion's host, localhost, and the loopback address.
    assert first["certificate"] == "-----BEGIN CERTIFICATE-----\nCERT-FOR-sluicegate.example.internal,127.0.0.1,localhost\n-----END CERTIFICATE-----"
    assert first["returned_public_key"] == "PUBLIC-OF-" + first["signing_key"]
    assert first["returned_certificate"] == first["certificate"]

    # Secrets travel through standard input, never on a command line.
    flattened = [str(item) for item in first["all_arguments"]]
    assert not any(bootstrap in item for item in flattened)
    assert not any("SIGNING-KEY" in item for item in flattened)

    run = next(call for call in first["docker"] if call[1] == "run")
    joined = " ".join(run)
    for expected in (
        "--restart unless-stopped", "-p 127.0.0.1:8443:8443", "-v sluicegate-service-data:/data",
        f"-v {root}/secrets/sg-signing-key.pem:/run/secrets/sg-signing-key.pem:ro", f"-v {root}/tls:/run/tls:ro",
        f"-v {root}/policy:/config:rw", "-e SG_TLS_CERT_FILE=/run/tls/server-cert.pem", f"--env-file {root}/service.env",
    ):
        assert expected in joined, expected
    assert run[-1] == "sluicegate/sg-service:1.0.0"
    assert any(call[1] == "load" for call in first["docker"])
    assert first["generator_calls"] == 1

    # An upgrade keeps the secrets, the edited policy, and the certificate, and recreates the container.
    assert second["env_unchanged"] and second["key_unchanged"] and second["certificate_unchanged"]
    assert second["policy"] == "edited in the Admin Console"
    assert second["generator_calls"] == 0
    assert [call[1] for call in second["docker"] if call[1] in ("rm", "run", "load")] == ["load", "rm", "run"]
    assert results["replaced"]["generator_calls"] == 1

    ca = results["ca"]
    assert ca["certificate"] == "FILE:ca-cert.pem" and ca["generator_calls"] == 0
    assert ca["tls_key_mode"] == "0600"
    assert ca["policy"] == "FILE:ca-cert.pem"  # an explicit -PolicyFile replaces the starter policy

    assert not results["no_tls"]["ok"] and "-SelfSignedCertificate" in results["no_tls"]["message"]
    assert not results["cert_without_key"]["ok"] and "together" in results["cert_without_key"]["message"]
    assert not results["no_docker"]["ok"] and "Docker Engine is not reachable" in results["no_docker"]["message"]

    assert results["argument_quoting"] == ["plain", '"has space"', '"say \\"hi\\""', '"C:\\path with space\\\\"', '""']
    assert results["env_text"].count("\r") == 0
    assert "SG_BOOTSTRAP_ADMIN_KEY=abc123\n" in results["env_text"] and "SG_PATCH_MINION_ID=M-1\n" in results["env_text"]
    assert re.fullmatch(r"[0-9a-f]{64}", results["random_secret"])
