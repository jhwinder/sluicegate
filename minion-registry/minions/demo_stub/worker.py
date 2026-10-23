from __future__ import annotations

import json
import os
import ssl
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

MISSION_CONTROL_URL = os.environ.get("MINION_MISSION_CONTROL_URL", os.environ.get("MINION_CENTRAL_COMMAND_URL", "http://sg-service:8443"))
MINION_ID = os.environ.get("MINION_ID", "DEMO-STUB-01")
MINION_API_KEY = os.environ.get("MINION_API_KEY", "")
MINION_PRIVATE_KEY_PATH = Path(os.environ.get("MINION_PRIVATE_KEY_PATH", "/run/secrets/demo-minion-key.pem"))
POLL_INTERVAL_SECONDS = float(os.environ.get("MINION_POLL_INTERVAL_SECONDS", "2"))
ALLOW_INSECURE_HTTP = os.environ.get("MINION_ALLOW_INSECURE_HTTP", "").lower() == "true"
TRUSTED_CERT_PATH = os.environ.get("MINION_TRUSTED_CERT_PATH", "").strip()


def transport_verification(url: str = MISSION_CONTROL_URL, allow_insecure_http: bool = ALLOW_INSECURE_HTTP, trusted_cert_path: str = TRUSTED_CERT_PATH) -> ssl.SSLContext | bool:
    """Return the TLS verification setting for Mission Control, or refuse an insecure configuration."""
    scheme = urlsplit(url).scheme
    if scheme == "http":
        if not allow_insecure_http:
            raise RuntimeError("Mission Control URL must use https; set MINION_ALLOW_INSECURE_HTTP=true only for local development")
        return True
    if scheme != "https":
        raise RuntimeError(f"Unsupported Mission Control URL scheme: {scheme or 'none'}")
    if trusted_cert_path:
        # With a cafile, only that certificate (or CAs it issued) is trusted; the host name is still verified.
        return ssl.create_default_context(cafile=trusted_cert_path)
    return True


def event_id() -> str:
    return f"evt-{uuid.uuid4().hex}"


def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {MINION_API_KEY}"}


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def handle_mission(client: httpx.Client, mission: dict[str, Any]) -> None:
    mission_id = mission["mission_id"]
    claim_token = mission["claim_token"]
    for state in ("MISSION_ACKNOWLEDGED", "MISSION_IN_PROGRESS"):
        response = client.post(
            f"/internal/v1/minions/{MINION_ID}/missions/{mission_id}/status",
            headers=headers(),
            json={"event_id": event_id(), "claim_token": claim_token, "status": state, "detail": {"mode": "safe-demo-noop"}},
        )
        response.raise_for_status()

    result = {
        "demo": True,
        "executed": False,
        "message": "Safe demo Minion completed a no-op Mission.",
    }
    signed_payload = {
        "event_id": event_id(),
        "claim_token": claim_token,
        "mission_id": mission_id,
        "minion_id": MINION_ID,
        "status": "MISSION_COMPLETE_SUCCEEDED",
        "result": result,
    }
    private_key = serialization.load_pem_private_key(MINION_PRIVATE_KEY_PATH.read_bytes(), password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise RuntimeError("Demo Minion signing key must be Ed25519")
    signature = private_key.sign(canonical_json(signed_payload)).hex()
    response = client.post(
        f"/internal/v1/minions/{MINION_ID}/missions/{mission_id}/result",
        headers=headers(),
        json={**signed_payload, "signature": signature},
    )
    response.raise_for_status()


def main() -> None:
    if not MINION_API_KEY:
        raise RuntimeError("MINION_API_KEY must be configured")
    if not MINION_PRIVATE_KEY_PATH.is_file():
        raise RuntimeError(f"Minion signing key is missing: {MINION_PRIVATE_KEY_PATH}")
    with httpx.Client(base_url=MISSION_CONTROL_URL, timeout=20, verify=transport_verification()) as client:
        while True:
            try:
                check_in = client.post(f"/internal/v1/minions/{MINION_ID}/check-in", headers=headers())
                check_in.raise_for_status()
                claim = client.post(f"/internal/v1/minions/{MINION_ID}/missions/claim", headers=headers())
                claim.raise_for_status()
                mission = claim.json()
                if mission:
                    handle_mission(client, mission)
            except httpx.HTTPError as exc:
                print(f"Minion Mission Control unavailable; retrying: {exc}", flush=True)
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
