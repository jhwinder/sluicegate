from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI

from sg_service import __main__ as service_main

REPOSITORY = Path(__file__).resolve().parents[2]
POWERSHELL_TEST = "minion-registry/templates/powershell/tests/Test-MissionControlTls.ps1"


@dataclass
class Material:
    certificate: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    name: str

    @property
    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    @property
    def sha256(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex().upper()


def make_certificate(
    name: str,
    dns_names: tuple[str, ...] = (),
    ip_addresses: tuple[str, ...] = (),
    *,
    issuer: Material | None = None,
    is_ca: bool = False,
    expired: bool = False,
) -> Material:
    import ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_before, not_after = (now - timedelta(days=30), now - timedelta(days=1)) if expired else (now - timedelta(days=1), now + timedelta(days=30))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.certificate.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        sans = [x509.DNSName(item) for item in dns_names] + [x509.IPAddress(ipaddress.ip_address(item)) for item in ip_addresses]
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    signing_key = issuer.key if issuer else key
    return Material(builder.sign(signing_key, hashes.SHA256()), key, name)


def write_material(directory: Path, material: Material) -> tuple[Path, Path]:
    certificate_path = directory / f"{material.name}.pem"
    key_path = directory / f"{material.name}.key"
    certificate_path.write_bytes(material.certificate_pem)
    key_path.write_bytes(material.key_pem)
    return certificate_path, key_path


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


class TlsServer:
    def __init__(self, certificate_path: Path, key_path: Path) -> None:
        self.httpd = ThreadingHTTPServer(("0.0.0.0", 0), HealthHandler)
        self.httpd.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate_path, key_path)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "TlsServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def load_demo_worker():
    spec = importlib.util.spec_from_file_location("demo_worker", REPOSITORY / "minion-registry/minions/demo_stub/worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def https_get(url: str, verify: ssl.SSLContext | bool) -> int:
    with httpx.Client(verify=verify, timeout=10) as client:
        return client.get(url).status_code


def test_tls_settings_require_both_files_and_existing_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SG_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("SG_TLS_KEY_FILE", raising=False)
    assert service_main.tls_settings() == (None, None)

    monkeypatch.setenv("SG_TLS_CERT_FILE", str(tmp_path / "cert.pem"))
    with pytest.raises(SystemExit, match="must be set together"):
        service_main.tls_settings()

    monkeypatch.setenv("SG_TLS_KEY_FILE", str(tmp_path / "key.pem"))
    with pytest.raises(SystemExit, match="readable file"):
        service_main.tls_settings()

    (tmp_path / "cert.pem").write_text("x")
    (tmp_path / "key.pem").write_text("x")
    assert service_main.tls_settings() == (str(tmp_path / "cert.pem"), str(tmp_path / "key.pem"))


def test_main_serves_tls_when_configured_and_warns_when_not(tmp_path: Path, monkeypatch, capsys) -> None:
    captured: dict = {}
    monkeypatch.setattr(service_main.uvicorn, "run", lambda app, **kwargs: captured.update(app=app, **kwargs))
    monkeypatch.delenv("SG_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("SG_TLS_KEY_FILE", raising=False)
    service_main.main()
    assert captured["ssl_certfile"] is None and "plain HTTP" in capsys.readouterr().err

    (tmp_path / "cert.pem").write_text("x")
    (tmp_path / "key.pem").write_text("x")
    monkeypatch.setenv("SG_TLS_CERT_FILE", str(tmp_path / "cert.pem"))
    monkeypatch.setenv("SG_TLS_KEY_FILE", str(tmp_path / "key.pem"))
    service_main.main()
    assert captured["ssl_certfile"] == str(tmp_path / "cert.pem")
    assert captured["ssl_keyfile"] == str(tmp_path / "key.pem")
    assert captured["port"] == 8443 and "plain HTTP" not in capsys.readouterr().err


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def uvicorn_tls_server(tmp_path: Path, monkeypatch) -> Iterator[tuple[int, Material]]:
    server_material = make_certificate("service", ("localhost",), ("127.0.0.1",))
    certificate_path, key_path = write_material(tmp_path, server_material)
    monkeypatch.setenv("SG_TLS_CERT_FILE", str(certificate_path))
    monkeypatch.setenv("SG_TLS_KEY_FILE", str(key_path))
    certificate, key = service_main.tls_settings()

    app = FastAPI()
    app.add_api_route("/health", lambda: {"status": "ok"})
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=certificate, ssl_keyfile=key, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        yield port, server_material
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_service_tls_is_trusted_only_with_the_provisioned_certificate(tmp_path: Path, uvicorn_tls_server) -> None:
    port, server_material = uvicorn_tls_server
    worker = load_demo_worker()
    url = f"https://localhost:{port}/health"
    trusted_path, _ = write_material(tmp_path, server_material)

    assert https_get(url, worker.transport_verification(f"https://localhost:{port}", False, str(trusted_path))) == 200
    with pytest.raises(httpx.ConnectError):
        https_get(url, worker.transport_verification(f"https://localhost:{port}", False, ""))

    other_path, _ = write_material(tmp_path, make_certificate("other", ("localhost",), ("127.0.0.1",)))
    with pytest.raises(httpx.ConnectError):
        https_get(url, worker.transport_verification(f"https://localhost:{port}", False, str(other_path)))

    mismatched = make_certificate("mismatch", ("other.example.invalid",))
    mismatch_path, mismatch_key = write_material(tmp_path, mismatched)
    with TlsServer(mismatch_path, mismatch_key) as server:
        with pytest.raises(httpx.ConnectError):
            https_get(f"https://localhost:{server.port}/health", worker.transport_verification("https://localhost", False, str(mismatch_path)))


def test_expired_certificate_is_rejected_even_when_provisioned(tmp_path: Path) -> None:
    worker = load_demo_worker()
    expired = make_certificate("expired", ("localhost",), ("127.0.0.1",), expired=True)
    certificate_path, key_path = write_material(tmp_path, expired)
    with TlsServer(certificate_path, key_path) as server:
        with pytest.raises(httpx.ConnectError):
            https_get(f"https://localhost:{server.port}/health", worker.transport_verification("https://localhost", False, str(certificate_path)))


def test_demo_worker_refuses_plain_http_without_the_development_flag() -> None:
    worker = load_demo_worker()
    with pytest.raises(RuntimeError, match="must use https"):
        worker.transport_verification("http://sg-service:8443", False, "")
    assert worker.transport_verification("http://sg-service:8443", True, "") is True
    with pytest.raises(RuntimeError, match="Unsupported"):
        worker.transport_verification("ftp://sg-service", True, "")


def powershell_command(tmp_path: Path) -> tuple[list[str], str, str]:
    """Return (command, host name the client should use, directory prefix for files in tmp_path)."""
    script = REPOSITORY / POWERSHELL_TEST
    if shutil.which("pwsh"):
        return ["pwsh", "-NoProfile", "-File", str(script), "-ScenarioFile", str(tmp_path / "scenarios.json")], "localhost", str(tmp_path)
    docker = shutil.which("docker")
    image = os.environ.get("SG_TEST_POWERSHELL_IMAGE", "mcr.microsoft.com/powershell:lts-debian-12")
    if not docker or subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode != 0:
        pytest.skip("PowerShell (pwsh, or the Microsoft PowerShell container image) is not available")
    command = [
        docker, "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
        "-v", f"{REPOSITORY / 'minion-registry'}:/minion-registry:ro", "-v", f"{tmp_path}:/work:ro",
        image, "pwsh", "-NoProfile", "-File", f"/{POWERSHELL_TEST}",
        "-ScenarioFile", "/work/scenarios.json",
    ]
    return command, "host.docker.internal", "/work"


def test_powershell_minion_validates_mission_control_certificates(tmp_path: Path) -> None:
    command, host, prefix = powershell_command(tmp_path)
    names, ips = (host, "localhost"), ("127.0.0.1",)

    trusted = make_certificate("trusted", names, ips)
    other = make_certificate("other", names, ips)
    wrong_name = make_certificate("wrongname", ("other.example.invalid",))
    expired = make_certificate("expired", names, ips, expired=True)
    rotated = make_certificate("rotated", names, ips)
    root = make_certificate("root", is_ca=True)
    leaf = make_certificate("leaf", names, ips, issuer=root)
    other_root = make_certificate("otherroot", is_ca=True)
    foreign_leaf = make_certificate("foreignleaf", names, ips, issuer=other_root)

    materials = [trusted, other, wrong_name, expired, rotated, root, leaf, other_root, foreign_leaf]
    paths = {item.name: write_material(tmp_path, item) for item in materials}
    (tmp_path / "bundle.pem").write_bytes(trusted.certificate_pem + rotated.certificate_pem)
    (tmp_path / "garbage.pem").write_text("not a certificate")

    def trust(name: str) -> str:
        return f"{prefix}/{name}.pem"

    servers = {item.name: TlsServer(*paths[item.name]) for item in (trusted, wrong_name, expired, rotated, leaf, foreign_leaf)}
    for server in servers.values():
        server.__enter__()
    try:
        def url(name: str) -> str:
            return f"https://{host}:{servers[name].port}"

        scenarios = [
            {"name": "pinned-self-signed", "url": url("trusted"), "trustedCertificatePath": trust("trusted")},
            {"name": "pinned-with-fingerprint", "url": url("trusted"), "trustedCertificatePath": trust("trusted"), "trustedCertificateSha256": [trusted.sha256]},
            {"name": "system-trust-rejects-self-signed", "url": url("trusted")},
            {"name": "different-certificate-pinned", "url": url("trusted"), "trustedCertificatePath": trust("other")},
            {"name": "hostname-mismatch", "url": url("wrongname"), "trustedCertificatePath": trust("wrongname")},
            {"name": "expired", "url": url("expired"), "trustedCertificatePath": trust("expired")},
            {"name": "fingerprint-mismatch", "url": url("trusted"), "trustedCertificatePath": trust("trusted"), "trustedCertificateSha256": [other.sha256], "configOnly": True},
            {"name": "private-ca", "url": url("leaf"), "trustedCertificatePath": trust("root")},
            {"name": "foreign-ca", "url": url("foreignleaf"), "trustedCertificatePath": trust("root")},
            {"name": "rotation-bundle", "url": url("rotated"), "trustedCertificatePath": f"{prefix}/bundle.pem"},
            {"name": "garbage-certificate-file", "url": url("trusted"), "trustedCertificatePath": f"{prefix}/garbage.pem"},
            {"name": "missing-certificate-file", "url": url("trusted"), "trustedCertificatePath": f"{prefix}/missing.pem"},
            {"name": "http-rejected", "url": "http://127.0.0.1:9", "configOnly": True},
            {"name": "http-non-loopback-rejected-even-with-flag", "url": "http://example.com", "allowInsecureHttp": True, "configOnly": True},
            {"name": "http-loopback-with-flag-accepted", "url": "http://127.0.0.1:9", "allowInsecureHttp": True, "configOnly": True},
        ]
        (tmp_path / "scenarios.json").write_text(json.dumps(scenarios))
        completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
        assert completed.returncode == 0, completed.stderr
        results = {item["name"]: item for item in json.loads(completed.stdout.strip().splitlines()[-1])}
    finally:
        for server in servers.values():
            server.__exit__(None, None, None)

    for name in ("pinned-self-signed", "pinned-with-fingerprint", "private-ca", "rotation-bundle", "http-loopback-with-flag-accepted"):
        assert results[name]["outcome"] == "success", (name, results[name])

    expectations = {
        "system-trust-rejects-self-signed": "not trusted by this computer",
        "different-certificate-pinned": "not the provisioned trusted certificate",
        "hostname-mismatch": "host name",
        "expired": "expired",
        "fingerprint-mismatch": "unexpected SHA-256",
        "foreign-ca": "TLS validation failed",
        "garbage-certificate-file": "no PEM-encoded certificate",
        "missing-certificate-file": "not found",
        "http-rejected": "must use https",
        "http-non-loopback-rejected-even-with-flag": "must use https",
    }
    for name, fragment in expectations.items():
        assert results[name]["outcome"] == "failure", (name, results[name])
        assert fragment in results[name]["detail"], (name, results[name])
