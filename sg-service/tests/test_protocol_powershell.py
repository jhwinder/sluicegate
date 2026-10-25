from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sg_service.protocol import canonical_json, schema_errors

REPOSITORY = Path(__file__).resolve().parents[2]
POWERSHELL_TEST = "minion-registry/templates/powershell/tests/Test-Protocol.ps1"
VECTORS = REPOSITORY / "minion-registry/protocol/test-vectors"


def powershell_command(work: Path) -> list[str]:
    script = REPOSITORY / POWERSHELL_TEST
    arguments = ["-VectorDirectory", "{vectors}", "-WorkDirectory", "{work}/out", "-ScenarioFile", "{work}/scenario.json"]
    if shutil.which("pwsh"):
        values = {"vectors": str(VECTORS), "work": str(work)}
        return ["pwsh", "-NoProfile", "-File", str(script), *[item.format(**values) for item in arguments]]
    docker = shutil.which("docker")
    image = os.environ.get("SG_TEST_POWERSHELL_IMAGE", "mcr.microsoft.com/powershell:lts-debian-12")
    if not docker or subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode != 0:
        pytest.skip("PowerShell (pwsh, or the Microsoft PowerShell container image) is not available")
    values = {"vectors": "/minion-registry/protocol/test-vectors", "work": "/work"}
    return [
        docker, "run", "--rm", "-v", f"{REPOSITORY / 'minion-registry'}:/minion-registry:ro", "-v", f"{work}:/work",
        image, "pwsh", "-NoProfile", "-File", f"/{POWERSHELL_TEST}", *[item.format(**values) for item in arguments],
    ]


def sign(envelope: dict, key: ed25519.Ed25519PrivateKey) -> dict:
    envelope = copy.deepcopy(envelope)
    envelope.pop("signature", None)
    envelope["signature"] = key.sign(canonical_json(envelope)).hex()
    return envelope


@pytest.fixture(scope="module")
def powershell_results(tmp_path_factory) -> dict:
    work = tmp_path_factory.mktemp("protocol")
    (work / "out").mkdir()
    service_key = ed25519.Ed25519PrivateKey.generate()
    other_key = ed25519.Ed25519PrivateKey.generate()
    now = int(time.time())

    fixtures = json.loads((VECTORS / "envelope-fixtures.json").read_text(encoding="utf-8"))["fixtures"]
    base = copy.deepcopy(fixtures[0]["envelope"])
    base.update(issued_at=now, expires_at=now + 86400, nonce="n-valid-0123456789abcdef")
    generic = copy.deepcopy(fixtures[3]["envelope"])
    generic.update(issued_at=now, expires_at=now + 86400, nonce="n-generic-0123456789abcd")

    def variant(**changes) -> dict:
        envelope = copy.deepcopy(base)
        envelope.update(changes)
        return envelope

    tampered = sign(base, service_key)
    tampered["target"] = {"servers": ["other.example.gov"]}
    envelopes = [
        {"name": "valid patch", "store": "a", "envelope": sign(base, service_key)},
        {"name": "replay of the same Mission", "store": "a", "envelope": sign(base, service_key)},
        {"name": "valid generic", "store": "b", "envelope": sign(generic, service_key)},
        {"name": "tampered after signing", "store": "c", "envelope": tampered},
        {"name": "signed by another key", "store": "d", "envelope": sign(variant(nonce="n-other-0123456789abcdef0"), other_key)},
        {"name": "addressed to another Minion", "store": "e", "envelope": sign(variant(minion_id="OTHER-01", nonce="n-wrong-minion-0123456789"), service_key)},
        {"name": "unsupported capability", "store": "f", "envelope": sign({**generic, "capability": "stripe.charge", "nonce": "n-capability-0123456789a"}, service_key)},
        {"name": "expired", "store": "g", "envelope": sign(variant(issued_at=now - 90000, expires_at=now - 10, nonce="n-expired-0123456789abc"), service_key)},
        {"name": "issued in the future", "store": "h", "envelope": sign(variant(issued_at=now + 3600, expires_at=now + 90000, nonce="n-future-0123456789abcd"), service_key)},
        {"name": "expires before it is issued", "store": "i", "envelope": sign(variant(issued_at=now, expires_at=now - 1, nonce="n-window-0123456789abcd"), service_key)},
        {"name": "missing nonce", "store": "j", "envelope": sign({key: value for key, value in base.items() if key != "nonce"}, service_key)},
        {"name": "unsupported protocol version", "store": "k", "envelope": sign(variant(protocol_version="2.0", nonce="n-version-0123456789abcd"), service_key)},
        {"name": "unknown field", "store": "l", "envelope": sign(variant(extra="x", nonce="n-unknown-0123456789abcd"), service_key)},
    ]
    (work / "scenario.json").write_text(
        json.dumps({
            "minion_id": "PATCH-01",
            "supported_capabilities": ["windows.patch.reconcile", "demo.action"],
            "public_key_pem": service_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "envelopes": envelopes,
        }),
        encoding="utf-8",
    )
    completed = subprocess.run(powershell_command(work), capture_output=True, text=True, timeout=600)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_powershell_canonical_json_matches_the_shared_vectors(powershell_results) -> None:
    ran = [case for case in powershell_results["canonical"] if not case.get("skipped")]
    assert ran
    for case in ran:
        assert case["actual"] == case["expected"], case["name"]


def test_powershell_signs_and_verifies_the_shared_signature_vector(powershell_results) -> None:
    assert powershell_results["signature"] == {"payload_matches": True, "verifies": True, "tampered_verifies": False, "resigned_matches": True}


def test_powershell_envelope_validator_agrees_with_the_schema(powershell_results) -> None:
    assert len(powershell_results["fixtures"]) >= 30
    for fixture in powershell_results["fixtures"]:
        assert fixture["actual"] == fixture["expected"], f"{fixture['name']}: {fixture['first_error']}"


def test_powershell_nonce_store_is_atomic_and_keeps_unexpired_nonces(powershell_results) -> None:
    assert powershell_results["nonce"] == {
        "first": True,
        "replay": False,
        "different": True,
        "expired_entry_can_be_reused": True,
        "oldest_survives_large_store": True,
        "legacy_entry_is_a_replay": True,
        "concurrent_winners": 1,
    }


def test_powershell_status_and_result_bodies_verify_in_python(powershell_results) -> None:
    vector = json.loads((VECTORS / "canonical-json.json").read_text(encoding="utf-8"))["signature"]
    public_key = serialization.load_pem_public_key(vector["public_key_pem"].encode())

    status = json.loads(powershell_results["bodies"]["status"])
    assert schema_errors("status", status) == []
    signed = {key: status[key] for key in ("event_id", "claim_generation", "status", "detail", "occurred_at")} | {"mission_id": "MISSION-1", "minion_id": "PATCH-01"}
    public_key.verify(bytes.fromhex(status["signature"]), canonical_json(signed))
    assert status["detail"]["process_detail"]["note"] == "Zugriff verweigert: é 日本 😀 <x>"

    result = json.loads(powershell_results["bodies"]["result"])
    assert schema_errors("result", result) == []
    signed = {key: result[key] for key in ("event_id", "claim_generation", "status", "result")} | {"mission_id": "MISSION-1", "minion_id": "PATCH-01"}
    public_key.verify(bytes.fromhex(result["signature"]), canonical_json(signed))
    assert result["result"]["targets"] == [{"server": "SERVER-01", "patches": []}]


def test_powershell_minion_accepts_and_rejects_python_signed_missions(powershell_results) -> None:
    outcome = {item["name"]: (item["valid"], item["reason"]) for item in powershell_results["envelopes"]}
    assert outcome == {
        "valid patch": (True, None),
        "replay of the same Mission": (False, "REPLAY_DETECTED"),
        "valid generic": (True, None),
        "tampered after signing": (False, "INVALID_SIGNATURE"),
        "signed by another key": (False, "INVALID_SIGNATURE"),
        "addressed to another Minion": (False, "MINION_ID_MISMATCH"),
        "unsupported capability": (False, "UNSUPPORTED_CAPABILITY"),
        "expired": (False, "MISSION_EXPIRED"),
        "issued in the future": (False, "INVALID_VALIDITY_WINDOW"),
        "expires before it is issued": (False, "MISSION_EXPIRED"),
        "missing nonce": (False, "SCHEMA_INVALID"),
        "unsupported protocol version": (False, "UNSUPPORTED_PROTOCOL_VERSION"),
        "unknown field": (False, "SCHEMA_INVALID"),
    }
