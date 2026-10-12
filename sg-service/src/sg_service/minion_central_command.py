from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Generator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from sg_core import GateRequest, PolicyEngine

DATABASE_PATH = Path(os.environ.get("SG_DATABASE_PATH", "/data/sg-service.sqlite3"))
SIGNING_KEY_PATH = Path(os.environ.get("SG_SIGNING_KEY_PATH", "/run/secrets/sg-signing-key.pem"))
PATCH_MINION_ID = os.environ.get("SG_PATCH_MINION_ID", "PATCH-01")
POLICY_PATH = Path(os.environ.get("SG_POLICY_PATH", "/config/policy.yml"))


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    initialize()
    yield


app = FastAPI(title="SluiceGate Service", version="0.1.0", lifespan=lifespan)
policy_engine: PolicyEngine | None = None


class PatchRequest(BaseModel):
    servers: list[str] = Field(min_length=1)
    patch_sources: list[str] = Field(default_factory=lambda: ["wsus", "nessus_catalog"])
    allowed_patch_types: list[str] = Field(default_factory=lambda: ["SECURITY"])
    allow_reboot: bool = False
    maintenance_window: str | None = None


class CanonicalActionRequest(BaseModel):
    capability: str = Field(min_length=1)
    target: Any = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class MissionStatusRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=160)
    status: str
    detail: dict[str, Any] = Field(default_factory=dict)
    occurred_at: float | None = None


class MissionResultRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=160)
    status: str
    result: dict[str, Any] = Field(default_factory=dict)
    signature: str


class ApprovalActionRequest(BaseModel):
    approver: str | None = None
    comment: str = ""


class RegisterAgentRequest(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""
    owner_team: str = ""
    environment: str = "prod"
    rate_limit_per_minute: int = 60
    poll_rate_limit_per_minute: int = 120


class UpdateAgentRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    owner_team: str | None = None
    environment: str | None = None
    enabled: bool | None = None
    rate_limit_per_minute: int | None = None
    poll_rate_limit_per_minute: int | None = None


class RegisterMinionRequest(BaseModel):
    minion_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    runtime_type: str = "powershell"
    version: str = "1.0"
    environment: str = "prod"
    capabilities: list[str] = Field(default_factory=lambda: ["windows.patch.reconcile"])
    scope_metadata: dict[str, Any] = Field(default_factory=dict)
    transport_type: str = "pull"
    endpoint_info: str = ""
    public_key: str = Field(min_length=1)


class UpdateMinionRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    runtime_type: str | None = None
    version: str | None = None
    environment: str | None = None
    capabilities: list[str] | None = None
    scope_metadata: dict[str, Any] | None = None
    transport_type: str | None = None
    endpoint_info: str | None = None
    enabled: bool | None = None
    public_key: str | None = None


class CreateNotificationAdapterRequest(BaseModel):
    adapter_id: str = Field(min_length=1)
    adapter_type: str = Field(default="mock")
    name: str = Field(min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class CreateNotificationProfileRequest(BaseModel):
    profile_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    event_types: list[str] = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    recipients: list[str] = Field(default_factory=list)
    template: str = ""
    enabled: bool = True


class UpdateNotificationProfileRequest(BaseModel):
    name: str | None = None
    event_types: list[str] | None = None
    adapter_id: str | None = None
    recipients: list[str] | None = None
    template: str | None = None
    enabled: bool | None = None


def connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def transaction() -> Generator[sqlite3.Connection, None, None]:
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize() -> None:
    global policy_engine
    if not POLICY_PATH.is_file():
        raise RuntimeError(f"Policy file does not exist: {POLICY_PATH}")
    policy_engine = PolicyEngine(str(POLICY_PATH))
    with transaction() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                kind TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                revoked_at REAL
            );
            CREATE TABLE IF NOT EXISTS minions (
                minion_id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                description TEXT DEFAULT '',
                runtime_type TEXT DEFAULT 'powershell',
                version TEXT DEFAULT '1.0',
                environment TEXT DEFAULT 'prod',
                capabilities TEXT NOT NULL DEFAULT '["windows.patch.reconcile"]',
                scope_metadata TEXT DEFAULT '{}',
                transport_type TEXT DEFAULT 'pull',
                endpoint_info TEXT DEFAULT '',
                public_key TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL DEFAULT 0,
                last_contact_at REAL
            );
            CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                minion_id TEXT NOT NULL,
                envelope TEXT NOT NULL,
                status TEXT NOT NULL,
                raw_request TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS missions_claim_idx
                ON missions(minion_id, status, created_at);
            CREATE TABLE IF NOT EXISTS mission_events (
                event_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                occurred_at REAL,
                received_at REAL NOT NULL,
                UNIQUE(mission_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                owner_team TEXT DEFAULT '',
                environment TEXT DEFAULT 'prod',
                enabled INTEGER NOT NULL DEFAULT 1,
                auth_method TEXT NOT NULL DEFAULT 'api_key',
                rate_limit_per_minute INTEGER DEFAULT 60,
                poll_rate_limit_per_minute INTEGER DEFAULT 120,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_used_at REAL
            );
            CREATE TABLE IF NOT EXISTS agent_rate_limits (
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS agent_rate_limits_idx
                ON agent_rate_limits(agent_id, action_type, timestamp);
            CREATE TABLE IF NOT EXISTS notification_adapters (
                adapter_id TEXT PRIMARY KEY,
                adapter_type TEXT NOT NULL,
                name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_profiles (
                profile_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                event_types TEXT NOT NULL,
                adapter_id TEXT NOT NULL,
                recipients TEXT NOT NULL DEFAULT '[]',
                template TEXT DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_deliveries (
                delivery_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                adapter_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT DEFAULT '{}',
                delivered_at REAL NOT NULL
            );
            """
        )
        try:
            connection.execute("ALTER TABLE missions ADD COLUMN raw_request TEXT")
        except sqlite3.OperationalError:
            pass
        for col, col_def in [
            ("name", "TEXT NOT NULL DEFAULT ''"),
            ("description", "TEXT DEFAULT ''"),
            ("runtime_type", "TEXT DEFAULT 'powershell'"),
            ("version", "TEXT DEFAULT '1.0'"),
            ("environment", "TEXT DEFAULT 'prod'"),
            ("capabilities", "TEXT NOT NULL DEFAULT '[\"windows.patch.reconcile\"]'"),
            ("scope_metadata", "TEXT DEFAULT '{}'"),
            ("transport_type", "TEXT DEFAULT 'pull'"),
            ("endpoint_info", "TEXT DEFAULT ''"),
            ("updated_at", "REAL NOT NULL DEFAULT 0"),
            ("last_contact_at", "REAL"),
        ]:
            try:
                connection.execute(f"ALTER TABLE minions ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                pass
        bootstrap_admin_key = os.environ.get("SG_BOOTSTRAP_ADMIN_KEY", "")
        if bootstrap_admin_key:
            connection.execute(
                "INSERT OR IGNORE INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, ?, ?)",
                ("KEY-BOOTSTRAP-ADMIN", "admin", _token_hash(bootstrap_admin_key), "admin", time.time()),
            )
        if os.environ.get("SG_DEV_BOOTSTRAP", "false").lower() == "true":
            _insert_environment_key(connection, "agent", os.environ.get("SG_DEV_AGENT_KEY", ""), "demo-agent")
            _insert_environment_key(connection, "minion", os.environ.get("SG_DEV_MINION_KEY", ""), "DEMO-STUB-01")
            development_public_key = os.environ.get("SG_DEV_MINION_PUBLIC_KEY_PATH", "")
            if development_public_key and Path(development_public_key).is_file():
                public_key = Path(development_public_key).read_text(encoding="utf-8")
                now = time.time()
                connection.execute(
                    """
                    INSERT INTO minions (minion_id, name, capabilities, public_key, created_at, updated_at)
                    VALUES ('DEMO-STUB-01', 'Demo Stub Minion', '["windows.patch.reconcile", "demo.action"]', ?, ?, ?)
                    ON CONFLICT(minion_id) DO UPDATE SET public_key = excluded.public_key, capabilities = excluded.capabilities, enabled = 1
                    """,
                    (public_key, now, now),
                )


def _insert_environment_key(connection: sqlite3.Connection, kind: str, token: str, principal_id: str) -> None:
    if not token:
        return
    connection.execute(
        "INSERT OR IGNORE INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, ?, ?)",
        (f"KEY-DEV-{kind.upper()}", principal_id, _token_hash(token), kind, time.time()),
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticated_principal(kind: str, authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ")
    with connect() as connection:
        rows = connection.execute(
            "SELECT principal_id, secret_hash, enabled FROM api_keys WHERE kind = ? AND revoked_at IS NULL",
            (kind,),
        ).fetchall()
    token_hash = _token_hash(token)
    for row in rows:
        if hmac.compare_digest(token_hash, row["secret_hash"]):
            if not bool(row["enabled"]):
                raise HTTPException(status_code=403, detail=f"{kind.capitalize()} is disabled")
            principal_id = str(row["principal_id"])
            if kind == "agent":
                with connect() as conn:
                    agent_row = conn.execute("SELECT enabled FROM agents WHERE agent_id = ?", (principal_id,)).fetchone()
                    if agent_row is not None and not bool(agent_row["enabled"]):
                        raise HTTPException(status_code=403, detail="Agent is disabled")
                with transaction() as conn:
                    conn.execute("UPDATE agents SET last_used_at = ? WHERE agent_id = ?", (time.time(), principal_id))
            return principal_id
    raise HTTPException(status_code=401, detail="Invalid credentials")


def check_agent_rate_limit(agent_id: str, action_type: str) -> None:
    now = time.time()
    cutoff = now - 60.0
    limit = 60 if action_type == "submit" else 120

    with connect() as conn:
        agent_row = conn.execute(
            "SELECT rate_limit_per_minute, poll_rate_limit_per_minute FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if agent_row:
            limit = (
                agent_row["rate_limit_per_minute"]
                if action_type == "submit"
                else agent_row["poll_rate_limit_per_minute"]
            )

    with transaction() as connection:
        connection.execute("DELETE FROM agent_rate_limits WHERE timestamp < ?", (cutoff,))
        count = connection.execute(
            "SELECT COUNT(*) FROM agent_rate_limits WHERE agent_id = ? AND action_type = ? AND timestamp >= ?",
            (agent_id, action_type, cutoff),
        ).fetchone()[0]
        if count >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded for {action_type}. Limit is {limit} req/min.",
                headers={"Retry-After": "60"},
            )
        connection.execute(
            "INSERT INTO agent_rate_limits (agent_id, action_type, timestamp) VALUES (?, ?, ?)",
            (agent_id, action_type, now),
        )


def require_agent(authorization: str | None = Header(default=None)) -> str:
    return authenticated_principal("agent", authorization)


def require_minion(authorization: str | None = Header(default=None)) -> str:
    return authenticated_principal("minion", authorization)


def require_admin(authorization: str | None = Header(default=None)) -> str:
    return authenticated_principal("admin", authorization)


def signing_private_key() -> ed25519.Ed25519PrivateKey:
    if not SIGNING_KEY_PATH.is_file():
        raise HTTPException(status_code=503, detail="SluiceGate signing key is not configured")
    key = serialization.load_pem_private_key(SIGNING_KEY_PATH.read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise HTTPException(status_code=503, detail="SluiceGate signing key must be Ed25519")
    return key


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def verify_minion_signature(minion_id: str, payload: dict[str, Any], signature: str) -> None:
    with connect() as connection:
        row = connection.execute(
            "SELECT public_key FROM minions WHERE minion_id = ? AND enabled = 1",
            (minion_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Minion is not enrolled or enabled")
    try:
        public_key = serialization.load_pem_public_key(row["public_key"].encode("utf-8"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("Minion public key must be Ed25519")
        public_key.verify(bytes.fromhex(signature), canonical_json(payload))
    except (InvalidSignature, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid Mission Result signature") from None


def validate_transition(current: str, new: str) -> None:
    transitions = {
        "CLAIMED": {"MISSION_ACKNOWLEDGED", "MISSION_REJECTED"},
        "MISSION_ACKNOWLEDGED": {"MISSION_IN_PROGRESS", "MISSION_REJECTED", "MISSION_EXPIRED", "MISSION_CANCELLED"},
        "MISSION_IN_PROGRESS": {"MISSION_IN_PROGRESS", "MISSION_WAITING_FOR_REBOOT", "MISSION_COMPLETE_SUCCEEDED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_EXPIRED", "MISSION_CANCELLED"},
        "MISSION_WAITING_FOR_REBOOT": {"MISSION_IN_PROGRESS", "MISSION_COMPLETE_SUCCEEDED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_EXPIRED", "MISSION_CANCELLED"},
    }
    if new not in transitions.get(current, set()):
        raise HTTPException(status_code=409, detail=f"Invalid Mission status transition: {current} -> {new}")


def resolve_minion(capability: str, environment: str = "prod", scope_target: dict[str, Any] | None = None) -> str:
    with connect() as conn:
        rows = conn.execute(
            "SELECT minion_id, capabilities, environment, scope_metadata FROM minions WHERE enabled = 1 ORDER BY created_at ASC"
        ).fetchall()
        for r in rows:
            if r["environment"] != environment:
                continue
            caps = json.loads(r["capabilities"] or "[]")
            if capability in caps:
                return str(r["minion_id"])
    if PATCH_MINION_ID:
        return PATCH_MINION_ID
    raise HTTPException(
        status_code=503,
        detail=f"No eligible Minion found for capability '{capability}' in environment '{environment}'",
    )


def dispatch_notifications(event_type: str, request_id: str, summary: str, details: dict[str, Any]) -> None:
    now = time.time()
    try:
        with connect() as conn:
            profiles = conn.execute(
                """
                SELECT p.profile_id, p.event_types, p.adapter_id, p.recipients, p.template,
                       a.adapter_type, a.config, a.enabled AS adapter_enabled
                FROM notification_profiles p
                JOIN notification_adapters a ON p.adapter_id = a.adapter_id
                WHERE p.enabled = 1 AND a.enabled = 1
                """
            ).fetchall()

            for prof in profiles:
                ev_types = json.loads(prof["event_types"] or "[]")
                if event_type not in ev_types:
                    continue

                recipients = json.loads(prof["recipients"] or "[]")
                adapter_type = prof["adapter_type"]
                config = json.loads(prof["config"] or "{}")

                delivery_id = f"DELIV-{uuid.uuid4().hex}"
                deliv_status = "DELIVERED"
                deliv_detail: dict[str, Any] = {"recipients": recipients, "summary": summary}

                try:
                    if adapter_type == "webhook":
                        url = config.get("url")
                        if url:
                            import httpx
                            httpx.post(
                                url,
                                json={"event": event_type, "request_id": request_id, "summary": summary, "details": details},
                                timeout=5.0,
                            )
                except Exception as ex:
                    deliv_status = "FAILED"
                    deliv_detail = {"error": str(ex), "recipients": recipients}

                with transaction() as write_conn:
                    write_conn.execute(
                        """
                        INSERT INTO notification_deliveries (delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (delivery_id, prof["profile_id"], prof["adapter_id"], request_id, event_type, deliv_status, json.dumps(deliv_detail), now),
                    )
    except Exception:
        # Notifications must never crash core policy/mission path
        pass


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/patch-requests", status_code=status.HTTP_202_ACCEPTED)
def create_patch_request(request: PatchRequest, principal: str = Depends(require_agent)) -> dict[str, Any]:
    check_agent_rate_limit(principal, "submit")

    # Idempotent deduplication check: associate matching open request
    normalized_params = json.dumps({
        "servers": sorted(request.servers),
        "patch_sources": sorted(request.patch_sources),
        "allowed_patch_types": sorted(request.allowed_patch_types),
        "allow_reboot": request.allow_reboot,
        "maintenance_window": request.maintenance_window,
    }, sort_keys=True)

    with connect() as connection:
        open_rows = connection.execute(
            """
            SELECT request_id, raw_request FROM missions
            WHERE agent_id = ? AND status IN ('QUEUED', 'WAITING_FOR_APPROVAL', 'CLAIMED', 'MISSION_ACKNOWLEDGED', 'MISSION_IN_PROGRESS', 'MISSION_WAITING_FOR_REBOOT')
            ORDER BY created_at DESC
            """,
            (principal,),
        ).fetchall()
        for open_row in open_rows:
            raw = json.loads(open_row["raw_request"] or "{}")
            raw_normalized = json.dumps({
                "servers": sorted(raw.get("servers", [])),
                "patch_sources": sorted(raw.get("patch_sources", [])),
                "allowed_patch_types": sorted(raw.get("allowed_patch_types", [])),
                "allow_reboot": raw.get("allow_reboot", False),
                "maintenance_window": raw.get("maintenance_window"),
            }, sort_keys=True)
            if raw_normalized == normalized_params:
                return {
                    "request_id": open_row["request_id"],
                    "status": "ACCEPTED",
                }

    assigned_minion_id = resolve_minion(
        capability="windows.patch.reconcile",
        environment="prod",
        scope_target={"servers": request.servers},
    )

    request_id = f"REQ-{uuid.uuid4().hex}"
    mission_id = f"MISSION-{uuid.uuid4().hex}"
    if policy_engine is None:
        raise HTTPException(status_code=503, detail="Policy engine is not initialized")
    policy_request = GateRequest(
        actor={"type": "AGENT", "id": principal},
        action={
            "name": "windows.patch.reconcile",
            "params": {
                "patch_sources": request.patch_sources,
                "allowed_patch_types": request.allowed_patch_types,
                "allow_reboot": request.allow_reboot,
            },
        },
        target={"servers": request.servers},
        context={"maintenance_window": request.maintenance_window},
    )
    decision, obligations, policy_hash = policy_engine.decide(
        {
            "actor": policy_request.actor,
            "action": policy_request.action,
            "target": policy_request.target,
            "context": policy_request.context,
        }
    )
    status_by_decision = {"ALLOW": "QUEUED", "PAUSE": "WAITING_FOR_APPROVAL", "BLOCK": "CLOSED"}
    mission_state = status_by_decision.get(decision, "CLOSED")
    envelope = {
        "protocol_version": "1.0",
        "request_id": request_id,
        "mission_id": mission_id,
        "minion_id": assigned_minion_id,
        "capability": "windows.patch.reconcile",
        "target": {"servers": request.servers},
        "parameters": {
            "patch_sources": request.patch_sources,
            "patch_constraints": {
                "allowed_patch_types": request.allowed_patch_types,
                "allow_reboot": request.allow_reboot,
            },
            "maintenance_window": request.maintenance_window,
        },
        "issued_at": time.time(),
        "expires_at": time.time() + 86400,
        "nonce": secrets.token_urlsafe(24),
        "requested_by": principal,
        "policy_hash": policy_hash,
        "policy_decision": decision,
        "obligations": [{"type": item.type, "data": item.data} for item in obligations],
    }
    envelope["signing_key_id"] = "sg-service-ed25519-v1"
    envelope["signature"] = signing_private_key().sign(canonical_json(envelope)).hex()
    raw_req_json = json.dumps(request.model_dump())
    with transaction() as connection:
        connection.execute(
            "INSERT INTO missions (mission_id, request_id, agent_id, minion_id, envelope, status, raw_request, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (mission_id, request_id, principal, assigned_minion_id, json.dumps(envelope), mission_state, raw_req_json, time.time(), time.time()),
        )
    if decision == "PAUSE":
        dispatch_notifications("PAUSE_CREATED", request_id, "Patch reconciliation paused pending approval", {"servers": request.servers})
    return {"request_id": request_id, "status": "ACCEPTED" if decision != "BLOCK" else "CLOSED"}


@app.post("/api/v1/actions", status_code=status.HTTP_202_ACCEPTED)
def create_action(request: CanonicalActionRequest, principal: str = Depends(require_agent)) -> dict[str, Any]:
    check_agent_rate_limit(principal, "submit")

    target_dict = request.target if isinstance(request.target, dict) else {"id": str(request.target)}

    # Idempotent deduplication check: associate matching open request
    normalized_params = json.dumps({
        "capability": request.capability,
        "target": target_dict,
        "parameters": request.parameters,
    }, sort_keys=True)

    with connect() as connection:
        open_rows = connection.execute(
            """
            SELECT request_id, raw_request FROM missions
            WHERE agent_id = ? AND status IN ('QUEUED', 'WAITING_FOR_APPROVAL', 'CLAIMED', 'MISSION_ACKNOWLEDGED', 'MISSION_IN_PROGRESS', 'MISSION_WAITING_FOR_REBOOT')
            ORDER BY created_at DESC
            """,
            (principal,),
        ).fetchall()
        for open_row in open_rows:
            raw = json.loads(open_row["raw_request"] or "{}")
            if "capability" in raw:
                raw_target = raw.get("target", {})
                raw_target_dict = raw_target if isinstance(raw_target, dict) else {"id": str(raw_target)}
                raw_normalized = json.dumps({
                    "capability": raw.get("capability"),
                    "target": raw_target_dict,
                    "parameters": raw.get("parameters", {}),
                }, sort_keys=True)
                if raw_normalized == normalized_params:
                    return {"request_id": open_row["request_id"], "status": "ACCEPTED"}

    assigned_minion_id = resolve_minion(
        capability=request.capability,
        environment="prod",
        scope_target=target_dict,
    )

    request_id = f"REQ-{uuid.uuid4().hex}"
    mission_id = f"MISSION-{uuid.uuid4().hex}"
    if policy_engine is None:
        raise HTTPException(status_code=503, detail="Policy engine is not initialized")

    policy_request = GateRequest(
        actor={"type": "AGENT", "id": principal},
        action={
            "name": request.capability,
            "params": request.parameters,
        },
        target=target_dict,
        context=request.context,
    )
    decision, obligations, policy_hash = policy_engine.decide(
        {
            "actor": policy_request.actor,
            "action": policy_request.action,
            "target": policy_request.target,
            "context": policy_request.context,
        }
    )
    status_by_decision = {"ALLOW": "QUEUED", "PAUSE": "WAITING_FOR_APPROVAL", "BLOCK": "CLOSED"}
    mission_state = status_by_decision.get(decision, "CLOSED")
    envelope = {
        "protocol_version": "1.0",
        "request_id": request_id,
        "mission_id": mission_id,
        "minion_id": assigned_minion_id,
        "capability": request.capability,
        "target": target_dict,
        "parameters": request.parameters,
        "issued_at": time.time(),
        "expires_at": time.time() + 86400,
        "nonce": secrets.token_urlsafe(24),
        "requested_by": principal,
        "policy_hash": policy_hash,
        "policy_decision": decision,
        "obligations": [{"type": item.type, "data": item.data} for item in obligations],
    }
    envelope["signing_key_id"] = "sg-service-ed25519-v1"
    envelope["signature"] = signing_private_key().sign(canonical_json(envelope)).hex()
    raw_req_json = json.dumps(request.model_dump())
    with transaction() as connection:
        connection.execute(
            "INSERT INTO missions (mission_id, request_id, agent_id, minion_id, envelope, status, raw_request, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (mission_id, request_id, principal, assigned_minion_id, json.dumps(envelope), mission_state, raw_req_json, time.time(), time.time()),
        )
    if decision == "PAUSE":
        dispatch_notifications("PAUSE_CREATED", request_id, f"Action '{request.capability}' paused pending approval", {"capability": request.capability, "target": target_dict})
    return {"request_id": request_id, "status": "ACCEPTED" if decision != "BLOCK" else "CLOSED"}


@app.post("/internal/v1/minions/{minion_id}/check-in")
def minion_check_in(minion_id: str, principal: str = Depends(require_minion)) -> dict[str, Any]:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    now = time.time()
    with transaction() as connection:
        connection.execute("UPDATE minions SET last_contact_at = ? WHERE minion_id = ?", (now, minion_id))
    return {"minion_id": minion_id, "status": "CONNECTED", "server_time": now}


@app.post("/internal/v1/minions/{minion_id}/missions/claim")
def claim_mission(minion_id: str, principal: str = Depends(require_minion)) -> dict[str, Any] | None:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    with transaction() as connection:
        row = connection.execute(
            "SELECT mission_id, envelope FROM missions WHERE minion_id = ? AND status = 'QUEUED' ORDER BY created_at LIMIT 1",
            (minion_id,),
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "UPDATE missions SET status = 'CLAIMED', updated_at = ? WHERE mission_id = ? AND status = 'QUEUED'",
            (time.time(), row["mission_id"]),
        )
        return {"mission_id": row["mission_id"], "envelope": json.loads(row["envelope"])}


@app.post("/internal/v1/minions/{minion_id}/missions/{mission_id}/status")
def mission_status(
    minion_id: str,
    mission_id: str,
    request: MissionStatusRequest,
    principal: str = Depends(require_minion),
) -> dict[str, str]:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    received = time.time()
    with transaction() as connection:
        row = connection.execute(
            "SELECT status FROM missions WHERE mission_id = ? AND minion_id = ?",
            (mission_id, minion_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Mission not found")
        validate_transition(str(row["status"]), request.status)
        try:
            connection.execute(
                "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request.event_id, mission_id, request.status, json.dumps(request.detail), request.occurred_at, received),
            )
        except sqlite3.IntegrityError:
            return {"event_id": request.event_id, "status": "ALREADY_RECORDED"}
        connection.execute(
            "UPDATE missions SET status = ?, updated_at = ? WHERE mission_id = ?",
            (request.status, received, mission_id),
        )
    return {"event_id": request.event_id, "status": "RECORDED"}


@app.post("/internal/v1/minions/{minion_id}/missions/{mission_id}/result")
def mission_result(
    minion_id: str,
    mission_id: str,
    request: MissionResultRequest,
    principal: str = Depends(require_minion),
) -> dict[str, str]:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    if request.status not in {"MISSION_COMPLETE_SUCCEEDED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_REJECTED", "MISSION_CANCELLED", "MISSION_EXPIRED"}:
        raise HTTPException(status_code=400, detail="Result status must be terminal")
    received = time.time()
    with transaction() as connection:
        row = connection.execute(
            "SELECT status FROM missions WHERE mission_id = ? AND minion_id = ?",
            (mission_id, minion_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Mission not found")
        validate_transition(str(row["status"]), request.status)
        signed_payload = {
            "event_id": request.event_id,
            "mission_id": mission_id,
            "minion_id": minion_id,
            "status": request.status,
            "result": request.result,
        }
        verify_minion_signature(minion_id, signed_payload, request.signature)
        try:
            connection.execute(
                "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request.event_id, mission_id, request.status, json.dumps({"result": request.result, "signature": request.signature}), received, received),
            )
        except sqlite3.IntegrityError:
            return {"status": "ALREADY_RECORDED"}
        connection.execute(
            "UPDATE missions SET status = ?, updated_at = ? WHERE mission_id = ?",
            (request.status, received, mission_id),
        )
    dispatch_notifications(request.status, mission_id, f"Mission {mission_id} reached terminal state {request.status}", {"minion_id": minion_id, "result": request.result})
    return {"status": "RECORDED"}


@app.get("/api/v1/requests/{request_id}")
def request_status(request_id: str, principal: str = Depends(require_agent)) -> dict[str, str]:
    check_agent_rate_limit(principal, "poll")
    with connect() as connection:
        row = connection.execute("SELECT status FROM missions WHERE request_id = ? AND agent_id = ?", (request_id, principal)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Request not found")
    state = row["status"]
    external = "SUCCEEDED" if state == "MISSION_COMPLETE_SUCCEEDED" else "CLOSED" if state in {"CLOSED", "BLOCKED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_REJECTED", "MISSION_CANCELLED", "MISSION_EXPIRED"} else "PENDING"
    return {"request_id": request_id, "status": external, "retry": "false"}


@app.get("/admin/v1/missions")
def list_missions(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT mission_id, request_id, minion_id, status, created_at, updated_at FROM missions ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/admin/v1/requests/{request_id}")
def admin_request_status(request_id: str, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT mission_id, minion_id, envelope, status, created_at, updated_at FROM missions WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Request not found")
    envelope = json.loads(row["envelope"])
    return {
        "request_id": request_id,
        "mission_id": row["mission_id"],
        "minion_id": row["minion_id"],
        "status": row["status"],
        "policy_decision": envelope.get("policy_decision"),
        "policy_hash": envelope.get("policy_hash"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@app.post("/admin/v1/requests/{request_id}/approve")
def approve_request(
    request_id: str,
    action: ApprovalActionRequest = ApprovalActionRequest(),
    admin: str = Depends(require_admin),
) -> dict[str, Any]:
    if policy_engine is None:
        raise HTTPException(status_code=503, detail="Policy engine is not initialized")

    with transaction() as connection:
        row = connection.execute(
            "SELECT mission_id, agent_id, minion_id, envelope, status, raw_request FROM missions WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Request not found")

        current_status = row["status"]
        if current_status != "WAITING_FOR_APPROVAL":
            raise HTTPException(status_code=409, detail=f"Request is not awaiting approval (current status: {current_status})")

        raw_req = json.loads(row["raw_request"] or "{}")
        approver_name = action.approver or admin
        now = time.time()
        approval_evidence = {
            "approved": True,
            "approver": approver_name,
            "approved_at": now,
            "comment": action.comment,
        }

        # Re-evaluate with current policy version and approval evidence in context
        if "capability" in raw_req:
            target_val = raw_req.get("target", {})
            target_dict = target_val if isinstance(target_val, dict) else {"id": str(target_val)}
            context = {
                **raw_req.get("context", {}),
                "approval": approval_evidence,
            }
            policy_request = GateRequest(
                actor={"type": "AGENT", "id": row["agent_id"]},
                action={
                    "name": raw_req["capability"],
                    "params": raw_req.get("parameters", {}),
                },
                target=target_dict,
                context=context,
            )
            capability_name = raw_req["capability"]
            target_obj = target_dict
        else:
            policy_request = GateRequest(
                actor={"type": "AGENT", "id": row["agent_id"]},
                action={
                    "name": "windows.patch.reconcile",
                    "params": {
                        "patch_sources": raw_req.get("patch_sources", ["wsus", "nessus_catalog"]),
                        "allowed_patch_types": raw_req.get("allowed_patch_types", ["SECURITY"]),
                        "allow_reboot": raw_req.get("allow_reboot", False),
                    },
                },
                target={"servers": raw_req.get("servers", [])},
                context={
                    "maintenance_window": raw_req.get("maintenance_window"),
                    "approval": approval_evidence,
                },
            )
            capability_name = "windows.patch.reconcile"
            target_obj = {"servers": raw_req.get("servers", [])}

        new_decision, new_obligations, new_policy_hash = policy_engine.decide(
            {
                "actor": policy_request.actor,
                "action": policy_request.action,
                "target": policy_request.target,
                "context": policy_request.context,
            }
        )

        envelope = json.loads(row["envelope"])
        envelope["policy_decision"] = new_decision
        envelope["policy_hash"] = new_policy_hash
        envelope["approval_evidence"] = approval_evidence
        envelope["obligations"] = [{"type": item.type, "data": item.data} for item in new_obligations]

        if new_decision == "ALLOW":
            new_status = "QUEUED"
            envelope["minion_id"] = resolve_minion(capability_name, environment="prod", scope_target=target_obj)
            envelope["signing_key_id"] = "sg-service-ed25519-v1"
            # Remove previous signature before signing
            envelope.pop("signature", None)
            envelope["signature"] = signing_private_key().sign(canonical_json(envelope)).hex()
        elif new_decision == "BLOCK":
            new_status = "CLOSED"
        else:
            new_status = "WAITING_FOR_APPROVAL"

        connection.execute(
            "UPDATE missions SET envelope = ?, status = ?, updated_at = ? WHERE request_id = ?",
            (json.dumps(envelope), new_status, now, request_id),
        )
        connection.execute(
            "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"EVT-APPROVE-{uuid.uuid4().hex}", row["mission_id"], new_status, json.dumps({"decision": new_decision, "approval": approval_evidence}), now, now),
        )

    dispatch_notifications("REQUEST_APPROVED", request_id, f"Request {request_id} approved by {approver_name}", {"decision": new_decision, "approver": approver_name})

    return {
        "request_id": request_id,
        "decision": new_decision,
        "status": new_status,
        "policy_hash": new_policy_hash,
    }


@app.post("/admin/v1/requests/{request_id}/reject")
def reject_request(
    request_id: str,
    action: ApprovalActionRequest = ApprovalActionRequest(),
    admin: str = Depends(require_admin),
) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute(
            "SELECT mission_id, envelope, status FROM missions WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Request not found")

        current_status = row["status"]
        if current_status != "WAITING_FOR_APPROVAL":
            raise HTTPException(status_code=409, detail=f"Request is not awaiting approval (current status: {current_status})")

        now = time.time()
        approver_name = action.approver or admin
        rejection_evidence = {
            "approved": False,
            "approver": approver_name,
            "rejected_at": now,
            "comment": action.comment,
        }

        envelope = json.loads(row["envelope"])
        envelope["policy_decision"] = "REJECTED"
        envelope["rejection_evidence"] = rejection_evidence

        connection.execute(
            "UPDATE missions SET envelope = ?, status = 'CLOSED', updated_at = ? WHERE request_id = ?",
            (json.dumps(envelope), now, request_id),
        )
        connection.execute(
            "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"EVT-REJECT-{uuid.uuid4().hex}", row["mission_id"], "CLOSED", json.dumps({"decision": "REJECTED", "rejection": rejection_evidence}), now, now),
        )

    dispatch_notifications("REQUEST_REJECTED", request_id, f"Request {request_id} rejected by {approver_name}", {"approver": approver_name})

    return {
        "request_id": request_id,
        "decision": "REJECTED",
        "status": "CLOSED",
    }


@app.post("/admin/v1/policy/reload")
def reload_policy(_admin: str = Depends(require_admin)) -> dict[str, str]:
    global policy_engine
    try:
        policy_engine = PolicyEngine(str(POLICY_PATH))
    except OSError:
        raise HTTPException(status_code=503, detail="Configured policy file is unavailable") from None
    return {"status": "RELOADED", "policy_hash": policy_engine.policy_hash}


@app.post("/admin/v1/credentials/{kind}/{principal_id}", status_code=status.HTTP_201_CREATED)
def issue_credential(kind: str, principal_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    if kind not in {"agent", "minion", "admin"}:
        raise HTTPException(status_code=400, detail="Unsupported credential kind")
    token = secrets.token_urlsafe(48)
    key_id = f"KEY-{uuid.uuid4().hex}"
    with transaction() as connection:
        connection.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, ?, ?)",
            (key_id, principal_id, _token_hash(token), kind, time.time()),
        )
    return {"key_id": key_id, "principal_id": principal_id, "api_key": token}


@app.post("/admin/v1/credentials/{key_id}/revoke")
def revoke_credential(key_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    with transaction() as connection:
        result = connection.execute(
            "UPDATE api_keys SET enabled = 0, revoked_at = ? WHERE key_id = ? AND enabled = 1",
            (time.time(), key_id),
        )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Active credential not found")
    return {"key_id": key_id, "status": "REVOKED"}


@app.post("/admin/v1/minions", status_code=status.HTTP_201_CREATED)
def register_minion(body: RegisterMinionRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    try:
        key = serialization.load_pem_public_key(body.public_key.encode("utf-8"))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("Expected Ed25519 public key")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key") from None

    token = secrets.token_urlsafe(48)
    key_id = f"KEY-{uuid.uuid4().hex}"
    now = time.time()
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO minions (minion_id, name, description, runtime_type, version, environment, capabilities, scope_metadata, transport_type, endpoint_info, public_key, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(minion_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                runtime_type = excluded.runtime_type,
                version = excluded.version,
                environment = excluded.environment,
                capabilities = excluded.capabilities,
                scope_metadata = excluded.scope_metadata,
                transport_type = excluded.transport_type,
                endpoint_info = excluded.endpoint_info,
                public_key = excluded.public_key,
                enabled = 1,
                updated_at = excluded.updated_at
            """,
            (
                body.minion_id,
                body.name,
                body.description,
                body.runtime_type,
                body.version,
                body.environment,
                json.dumps(body.capabilities),
                json.dumps(body.scope_metadata),
                body.transport_type,
                body.endpoint_info,
                body.public_key,
                now,
                now,
            ),
        )
        connection.execute(
            "UPDATE api_keys SET enabled = 0, revoked_at = ? WHERE principal_id = ? AND kind = 'minion' AND enabled = 1",
            (now, body.minion_id),
        )
        connection.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, 'minion', ?)",
            (key_id, body.minion_id, _token_hash(token), now),
        )

    return {
        "minion_id": body.minion_id,
        "name": body.name,
        "capabilities": body.capabilities,
        "environment": body.environment,
        "api_key": token,
        "key_id": key_id,
    }


@app.get("/admin/v1/minions")
def list_minions(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT minion_id, name, description, runtime_type, version, environment, capabilities, scope_metadata, transport_type, endpoint_info, enabled, created_at, updated_at, last_contact_at FROM minions ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d["capabilities"] or "[]")
        d["scope_metadata"] = json.loads(d["scope_metadata"] or "{}")
        result.append(d)
    return result


@app.get("/admin/v1/minions/{minion_id}")
def get_minion(minion_id: str, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT minion_id, name, description, runtime_type, version, environment, capabilities, scope_metadata, transport_type, endpoint_info, enabled, created_at, updated_at, last_contact_at FROM minions WHERE minion_id = ?",
            (minion_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Minion not found")
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"] or "[]")
    d["scope_metadata"] = json.loads(d["scope_metadata"] or "{}")
    return d


@app.patch("/admin/v1/minions/{minion_id}")
def update_minion(minion_id: str, body: UpdateMinionRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute("SELECT * FROM minions WHERE minion_id = ?", (minion_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Minion not found")

        updates: list[str] = []
        params: list[Any] = []
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name)
        if body.description is not None:
            updates.append("description = ?")
            params.append(body.description)
        if body.runtime_type is not None:
            updates.append("runtime_type = ?")
            params.append(body.runtime_type)
        if body.version is not None:
            updates.append("version = ?")
            params.append(body.version)
        if body.environment is not None:
            updates.append("environment = ?")
            params.append(body.environment)
        if body.capabilities is not None:
            updates.append("capabilities = ?")
            params.append(json.dumps(body.capabilities))
        if body.scope_metadata is not None:
            updates.append("scope_metadata = ?")
            params.append(json.dumps(body.scope_metadata))
        if body.transport_type is not None:
            updates.append("transport_type = ?")
            params.append(body.transport_type)
        if body.endpoint_info is not None:
            updates.append("endpoint_info = ?")
            params.append(body.endpoint_info)
        if body.enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if body.enabled else 0)
            if not body.enabled:
                connection.execute("UPDATE api_keys SET enabled = 0 WHERE principal_id = ? AND kind = 'minion'", (minion_id,))
            else:
                connection.execute("UPDATE api_keys SET enabled = 1 WHERE principal_id = ? AND kind = 'minion' AND revoked_at IS NULL", (minion_id,))
        if body.public_key is not None:
            try:
                key = serialization.load_pem_public_key(body.public_key.encode("utf-8"))
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise ValueError("Expected Ed25519 public key")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="Invalid Ed25519 public key") from None
            updates.append("public_key = ?")
            params.append(body.public_key)

        if updates:
            updates.append("updated_at = ?")
            params.append(time.time())
            params.append(minion_id)
            connection.execute(f"UPDATE minions SET {', '.join(updates)} WHERE minion_id = ?", params)

    return get_minion(minion_id, _admin)


@app.post("/admin/v1/minions/{minion_id}/rotate-key")
def rotate_minion_key(minion_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    token = secrets.token_urlsafe(48)
    key_id = f"KEY-{uuid.uuid4().hex}"
    now = time.time()
    with transaction() as connection:
        row = connection.execute("SELECT minion_id FROM minions WHERE minion_id = ?", (minion_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Minion not found")
        connection.execute("UPDATE api_keys SET enabled = 0, revoked_at = ? WHERE principal_id = ? AND kind = 'minion' AND enabled = 1", (now, minion_id))
        connection.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, 'minion', ?)",
            (key_id, minion_id, _token_hash(token), now),
        )
    return {"minion_id": minion_id, "key_id": key_id, "api_key": token}


@app.post("/admin/v1/minions/{minion_id}/enroll", status_code=status.HTTP_201_CREATED)
def enroll_minion(minion_id: str, public_key: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    try:
        key = serialization.load_pem_public_key(public_key.encode("utf-8"))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("Expected Ed25519 public key")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key") from None
    with transaction() as connection:
        connection.execute(
            "INSERT INTO minions (minion_id, public_key, created_at) VALUES (?, ?, ?) ON CONFLICT(minion_id) DO UPDATE SET public_key = excluded.public_key, enabled = 1",
            (minion_id, public_key, time.time()),
        )
    return {"minion_id": minion_id, "status": "ENROLLED"}


@app.post("/admin/v1/notification-adapters", status_code=status.HTTP_201_CREATED)
def create_notification_adapter(body: CreateNotificationAdapterRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    now = time.time()
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO notification_adapters (adapter_id, adapter_type, name, config, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(adapter_id) DO UPDATE SET
                adapter_type = excluded.adapter_type,
                name = excluded.name,
                config = excluded.config,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """,
            (body.adapter_id, body.adapter_type, body.name, json.dumps(body.config), 1 if body.enabled else 0, now, now),
        )
    return body.model_dump()


@app.get("/admin/v1/notification-adapters")
def list_notification_adapters(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT adapter_id, adapter_type, name, config, enabled, created_at, updated_at FROM notification_adapters ORDER BY created_at DESC"
        ).fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d["config"] = json.loads(d["config"] or "{}")
        res.append(d)
    return res


@app.post("/admin/v1/notification-profiles", status_code=status.HTTP_201_CREATED)
def create_notification_profile(body: CreateNotificationProfileRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    now = time.time()
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO notification_profiles (profile_id, name, event_types, adapter_id, recipients, template, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(profile_id) DO UPDATE SET
                name = excluded.name,
                event_types = excluded.event_types,
                adapter_id = excluded.adapter_id,
                recipients = excluded.recipients,
                template = excluded.template,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """,
            (
                body.profile_id,
                body.name,
                json.dumps(body.event_types),
                body.adapter_id,
                json.dumps(body.recipients),
                body.template,
                1 if body.enabled else 0,
                now,
                now,
            ),
        )
    return body.model_dump()


@app.get("/admin/v1/notification-profiles")
def list_notification_profiles(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT profile_id, name, event_types, adapter_id, recipients, template, enabled, created_at, updated_at FROM notification_profiles ORDER BY created_at DESC"
        ).fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d["event_types"] = json.loads(d["event_types"] or "[]")
        d["recipients"] = json.loads(d["recipients"] or "[]")
        res.append(d)
    return res


@app.get("/admin/v1/notification-profiles/{profile_id}")
def get_notification_profile(profile_id: str, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT profile_id, name, event_types, adapter_id, recipients, template, enabled, created_at, updated_at FROM notification_profiles WHERE profile_id = ?",
            (profile_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Notification profile not found")
    d = dict(row)
    d["event_types"] = json.loads(d["event_types"] or "[]")
    d["recipients"] = json.loads(d["recipients"] or "[]")
    return d


@app.patch("/admin/v1/notification-profiles/{profile_id}")
def update_notification_profile(profile_id: str, body: UpdateNotificationProfileRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute("SELECT * FROM notification_profiles WHERE profile_id = ?", (profile_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Notification profile not found")

        updates: list[str] = []
        params: list[Any] = []
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name)
        if body.event_types is not None:
            updates.append("event_types = ?")
            params.append(json.dumps(body.event_types))
        if body.adapter_id is not None:
            updates.append("adapter_id = ?")
            params.append(body.adapter_id)
        if body.recipients is not None:
            updates.append("recipients = ?")
            params.append(json.dumps(body.recipients))
        if body.template is not None:
            updates.append("template = ?")
            params.append(body.template)
        if body.enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if body.enabled else 0)

        if updates:
            updates.append("updated_at = ?")
            params.append(time.time())
            params.append(profile_id)
            connection.execute(f"UPDATE notification_profiles SET {', '.join(updates)} WHERE profile_id = ?", params)

    return get_notification_profile(profile_id, _admin)


@app.delete("/admin/v1/notification-profiles/{profile_id}")
def delete_notification_profile(profile_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    with transaction() as connection:
        result = connection.execute("DELETE FROM notification_profiles WHERE profile_id = ?", (profile_id,))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Notification profile not found")
    return {"profile_id": profile_id, "status": "DELETED"}


@app.get("/admin/v1/notification-deliveries")
def list_notification_deliveries(request_id: str | None = None, _admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        if request_id:
            rows = connection.execute(
                "SELECT delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at FROM notification_deliveries WHERE request_id = ? ORDER BY delivered_at DESC",
                (request_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at FROM notification_deliveries ORDER BY delivered_at DESC LIMIT 100"
            ).fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d["detail"] or "{}")
        res.append(d)
    return res


@app.post("/admin/v1/agents", status_code=status.HTTP_201_CREATED)
def register_agent(body: RegisterAgentRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    agent_id = f"AGENT-{uuid.uuid4().hex[:12]}"
    token = secrets.token_urlsafe(48)
    key_id = f"KEY-{uuid.uuid4().hex}"
    now = time.time()
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO agents (agent_id, name, description, owner_team, environment, enabled, auth_method, rate_limit_per_minute, poll_rate_limit_per_minute, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, 'api_key', ?, ?, ?, ?)
            """,
            (agent_id, body.name, body.description, body.owner_team, body.environment, body.rate_limit_per_minute, body.poll_rate_limit_per_minute, now, now),
        )
        connection.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, 'agent', ?)",
            (key_id, agent_id, _token_hash(token), now),
        )
    return {
        "agent_id": agent_id,
        "name": body.name,
        "api_key": token,
        "key_id": key_id,
        "rate_limit_per_minute": body.rate_limit_per_minute,
        "poll_rate_limit_per_minute": body.poll_rate_limit_per_minute,
    }


@app.get("/admin/v1/agents")
def list_agents(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT agent_id, name, description, owner_team, environment, enabled, auth_method, rate_limit_per_minute, poll_rate_limit_per_minute, created_at, updated_at, last_used_at FROM agents ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/v1/agents/{agent_id}")
def get_agent(agent_id: str, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT agent_id, name, description, owner_team, environment, enabled, auth_method, rate_limit_per_minute, poll_rate_limit_per_minute, created_at, updated_at, last_used_at FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return dict(row)


@app.patch("/admin/v1/agents/{agent_id}")
def update_agent(agent_id: str, body: UpdateAgentRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Agent not found")

        updates: list[str] = []
        params: list[Any] = []
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name)
        if body.description is not None:
            updates.append("description = ?")
            params.append(body.description)
        if body.owner_team is not None:
            updates.append("owner_team = ?")
            params.append(body.owner_team)
        if body.environment is not None:
            updates.append("environment = ?")
            params.append(body.environment)
        if body.enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if body.enabled else 0)
            if not body.enabled:
                connection.execute("UPDATE api_keys SET enabled = 0 WHERE principal_id = ? AND kind = 'agent'", (agent_id,))
            else:
                connection.execute("UPDATE api_keys SET enabled = 1 WHERE principal_id = ? AND kind = 'agent' AND revoked_at IS NULL", (agent_id,))
        if body.rate_limit_per_minute is not None:
            updates.append("rate_limit_per_minute = ?")
            params.append(body.rate_limit_per_minute)
        if body.poll_rate_limit_per_minute is not None:
            updates.append("poll_rate_limit_per_minute = ?")
            params.append(body.poll_rate_limit_per_minute)

        if updates:
            updates.append("updated_at = ?")
            params.append(time.time())
            params.append(agent_id)
            connection.execute(f"UPDATE agents SET {', '.join(updates)} WHERE agent_id = ?", params)

    return get_agent(agent_id, _admin)


@app.post("/admin/v1/agents/{agent_id}/rotate-key")
def rotate_agent_key(agent_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    token = secrets.token_urlsafe(48)
    key_id = f"KEY-{uuid.uuid4().hex}"
    now = time.time()
    with transaction() as connection:
        row = connection.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        # Revoke existing active keys
        connection.execute("UPDATE api_keys SET enabled = 0, revoked_at = ? WHERE principal_id = ? AND kind = 'agent' AND enabled = 1", (now, agent_id))
        # Insert new key
        connection.execute(
            "INSERT INTO api_keys (key_id, principal_id, secret_hash, kind, created_at) VALUES (?, ?, ?, 'agent', ?)",
            (key_id, agent_id, _token_hash(token), now),
        )
    return {"agent_id": agent_id, "key_id": key_id, "api_key": token}
