from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn


def tls_settings() -> tuple[str | None, str | None]:
    """Return (certificate, key) paths for in-service TLS, or (None, None) for plain HTTP."""
    certificate = os.environ.get("SG_TLS_CERT_FILE", "").strip()
    key = os.environ.get("SG_TLS_KEY_FILE", "").strip()
    if bool(certificate) != bool(key):
        sys.exit("SG_TLS_CERT_FILE and SG_TLS_KEY_FILE must be set together")
    for name, path in (("SG_TLS_CERT_FILE", certificate), ("SG_TLS_KEY_FILE", key)):
        if path and not Path(path).is_file():
            sys.exit(f"{name} does not point to a readable file: {path}")
    return (certificate or None, key or None)


# TLS 1.2 is the floor (Python's server default); these suites are forward-secret AEAD only. TLS 1.3 suites are not affected.
DEFAULT_TLS_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"


def main() -> None:
    certificate, key = tls_settings()
    if certificate is None:
        print(
            "WARNING: serving plain HTTP. Use this only on loopback behind a TLS proxy or for local development; "
            "set SG_TLS_CERT_FILE and SG_TLS_KEY_FILE to serve HTTPS.",
            file=sys.stderr,
            flush=True,
        )
    uvicorn.run(
        "sg_service.mission_control:app",
        host=os.environ.get("SG_BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("SG_BIND_PORT", "8443")),
        ssl_certfile=certificate,
        ssl_keyfile=key,
        ssl_ciphers=os.environ.get("SG_TLS_CIPHERS", "").strip() or DEFAULT_TLS_CIPHERS,
        timeout_keep_alive=int(os.environ.get("SG_KEEP_ALIVE_SECONDS", "5")),
    )


if __name__ == "__main__":
    main()
