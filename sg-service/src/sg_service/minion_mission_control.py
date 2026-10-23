from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Generator

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sg_core import GateRequest, PolicyEngine
from sg_poledit.validate import validate_policy_dict

from sg_service import notifications

DATABASE_PATH = Path(os.environ.get("SG_DATABASE_PATH", "/data/sg-service.sqlite3"))
SIGNING_KEY_PATH = Path(os.environ.get("SG_SIGNING_KEY_PATH", "/run/secrets/sg-signing-key.pem"))
PATCH_MINION_ID = os.environ.get("SG_PATCH_MINION_ID", "PATCH-01")
POLICY_PATH = Path(os.environ.get("SG_POLICY_PATH", "/config/policy.yml"))
ADMIN_HTML_PATH = Path(__file__).resolve().parent / "static" / "admin.html"
MAX_MINION_RESULT_BYTES = 256 * 1024
POLICY_LOCK = threading.RLock()
MINION_MAX_ATTEMPTS = int(os.environ.get("SG_MINION_MAX_ATTEMPTS", "3"))
MINION_RETRY_INTERVAL_SECONDS = int(os.environ.get("SG_MINION_RETRY_INTERVAL_SECONDS", "30"))
MINION_ATTEMPT_TIMEOUT_SECONDS = int(os.environ.get("SG_MINION_ATTEMPT_TIMEOUT_SECONDS", "300"))
MINION_OVERALL_TIMEOUT_SECONDS = int(os.environ.get("SG_MINION_OVERALL_TIMEOUT_SECONDS", "900"))
MINION_HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("SG_MINION_HEARTBEAT_INTERVAL_SECONDS", "30"))
MINION_CLAIM_LEASE_SECONDS = int(os.environ.get("SG_MINION_CLAIM_LEASE_SECONDS", "120"))
NOTIFICATION_MAX_ATTEMPTS = int(os.environ.get("SG_NOTIFY_MAX_ATTEMPTS", "4"))
NOTIFICATION_RETRY_BASE_SECONDS = int(os.environ.get("SG_NOTIFY_RETRY_BASE_SECONDS", "30"))
NOTIFICATION_POLL_SECONDS = 5.0
NOTIFICATION_SEND_LEASE_SECONDS = 120
NOTIFICATION_VERIFICATION_TTL_SECONDS = 900
NOTIFICATION_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sg-notify")
notification_logger = logging.getLogger("sg_service.notifications")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    initialize()
    stop_retries = threading.Event()
    retry_worker = threading.Thread(target=notification_retry_loop, args=(stop_retries,), name="sg-notify-retry", daemon=True)
    retry_worker.start()
    try:
        yield
    finally:
        stop_retries.set()
        retry_worker.join(timeout=5)


app = FastAPI(title="SluiceGate Service", version="0.1.0", lifespan=lifespan)
policy_engine: PolicyEngine | None = None


class PatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: list[str] = Field(min_length=1)


class CanonicalActionRequest(BaseModel):
    capability: str = Field(min_length=1)
    target: Any = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class MissionStatusRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=160)
    claim_token: str = Field(min_length=32, max_length=128)
    status: str
    detail: dict[str, Any] = Field(default_factory=dict)
    occurred_at: float | None = None


class MissionHeartbeatRequest(BaseModel):
    claim_token: str = Field(min_length=32, max_length=128)
    process_id: int | None = Field(default=None, gt=0)
    process_started_at: float | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class MissionResultRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=160)
    claim_token: str = Field(min_length=32, max_length=128)
    status: str
    result: dict[str, Any] = Field(default_factory=dict)
    signature: str


class ApprovalActionRequest(BaseModel):
    approver: str | None = None
    comment: str = ""


class PolicyContentRequest(BaseModel):
    content: str = Field(max_length=1_000_000)


class SavePolicyRequest(PolicyContentRequest):
    expected_file_hash: str = Field(min_length=64, max_length=64)


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


class UpdateNotificationAdapterRequest(BaseModel):
    enabled: bool


class VerifyNotificationAdapterRequest(BaseModel):
    recipient: str = Field(min_length=3, max_length=254)


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


def validate_policy_content(content: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    try:
        policy = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return None, [{"severity": "error", "path": "", "message": str(exc)}], False

    validation = validate_policy_dict(policy)
    return policy, [issue.__dict__ for issue in validation.issues], validation.is_valid


def record_policy_event(
    actor: str,
    action: str,
    outcome: str,
    previous_hash: str | None,
    policy_hash: str | None,
) -> None:
    with transaction() as connection:
        connection.execute(
            "INSERT INTO policy_events (event_id, actor, action, outcome, previous_hash, policy_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f"POLICY-{uuid.uuid4().hex}", actor, action, outcome, previous_hash, policy_hash, time.time()),
        )


def write_policy_atomically(content: bytes, file_mode: int) -> None:
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{POLICY_PATH.name}.", dir=POLICY_PATH.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, file_mode)
        os.replace(temporary_path, POLICY_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def initialize() -> None:
    global policy_engine
    if (
        MINION_MAX_ATTEMPTS < 1
        or MINION_RETRY_INTERVAL_SECONDS < 1
        or MINION_ATTEMPT_TIMEOUT_SECONDS < 1
        or MINION_OVERALL_TIMEOUT_SECONDS < MINION_ATTEMPT_TIMEOUT_SECONDS
        or MINION_HEARTBEAT_INTERVAL_SECONDS < 1
        or MINION_CLAIM_LEASE_SECONDS <= MINION_HEARTBEAT_INTERVAL_SECONDS
    ):
        raise RuntimeError("Invalid Minion retry, timeout, heartbeat, or claim lease configuration")
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
                updated_at REAL NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                claim_generation INTEGER NOT NULL DEFAULT 0,
                claim_token_hash TEXT,
                lease_expires_at REAL,
                attempt_started_at REAL,
                execution_started_at REAL,
                next_retry_at REAL,
                worker_process_id INTEGER,
                worker_process_started_at REAL,
                process_detail TEXT NOT NULL DEFAULT '{}'
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
            CREATE TABLE IF NOT EXISTS policy_events (
                event_id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                previous_hash TEXT,
                policy_hash TEXT,
                created_at REAL NOT NULL
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
            CREATE TABLE IF NOT EXISTS notification_adapter_verifications (
                adapter_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                recipient TEXT NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL,
                created_at REAL NOT NULL
            );
            """
        )
        try:
            connection.execute("ALTER TABLE missions ADD COLUMN raw_request TEXT")
        except sqlite3.OperationalError:
            pass
        for col, col_def in [
            ("attempt_count", "INTEGER NOT NULL DEFAULT 0"),
            ("claim_generation", "INTEGER NOT NULL DEFAULT 0"),
            ("claim_token_hash", "TEXT"),
            ("lease_expires_at", "REAL"),
            ("attempt_started_at", "REAL"),
            ("execution_started_at", "REAL"),
            ("next_retry_at", "REAL"),
            ("worker_process_id", "INTEGER"),
            ("worker_process_started_at", "REAL"),
            ("process_detail", "TEXT NOT NULL DEFAULT '{}'"),
        ]:
            try:
                connection.execute(f"ALTER TABLE missions ADD COLUMN {col} {col_def}")
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
        for table, col, col_def in [
            ("notification_adapters", "verified_at", "REAL"),
            ("notification_adapters", "verified_fingerprint", "TEXT"),
            ("notification_deliveries", "attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("notification_deliveries", "next_attempt_at", "REAL"),
            ("notification_deliveries", "idempotency_key", "TEXT"),
            ("notification_deliveries", "payload", "TEXT NOT NULL DEFAULT '{}'"),
        ]:
            try:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                pass
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS notification_deliveries_idempotency ON notification_deliveries(idempotency_key) WHERE idempotency_key IS NOT NULL"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS notification_deliveries_due ON notification_deliveries(status, next_attempt_at)"
        )
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
                    VALUES ('DEMO-STUB-01', 'Demo Stub Minion', '["windows.patch.reconcile", "demo.action", "stripe.refund", "stripe.charge"]', ?, ?, ?)
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

def verify_claim_token(stored_hash: str | None, claim_token: str) -> None:
    if not stored_hash or not hmac.compare_digest(stored_hash, _token_hash(claim_token)):
        raise HTTPException(status_code=409, detail="Mission claim is no longer owned by this worker")


def require_live_claim(connection: sqlite3.Connection, mission_id: str, minion_id: str, claim_token: str, now: float) -> sqlite3.Row:
    row = connection.execute(
        "SELECT status, claim_token_hash, lease_expires_at, attempt_started_at, execution_started_at, envelope, attempt_count FROM missions WHERE mission_id = ? AND minion_id = ?",
        (mission_id, minion_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Mission not found")
    verify_claim_token(row["claim_token_hash"], claim_token)
    if row["lease_expires_at"] is None or float(row["lease_expires_at"]) <= now:
        raise HTTPException(status_code=409, detail="Mission claim lease expired")
    return row


def mission_execution_settings() -> dict[str, int]:
    return {
        "max_attempts": MINION_MAX_ATTEMPTS,
        "retry_interval_seconds": MINION_RETRY_INTERVAL_SECONDS,
        "attempt_timeout_seconds": MINION_ATTEMPT_TIMEOUT_SECONDS,
        "overall_timeout_seconds": MINION_OVERALL_TIMEOUT_SECONDS,
        "heartbeat_interval_seconds": MINION_HEARTBEAT_INTERVAL_SECONDS,
        "claim_lease_seconds": MINION_CLAIM_LEASE_SECONDS,
    }


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
        "MISSION_WAITING_FOR_REBOOT": {"MISSION_WAITING_FOR_REBOOT", "MISSION_IN_PROGRESS", "MISSION_COMPLETE_SUCCEEDED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_EXPIRED", "MISSION_CANCELLED"},
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


def resolve_patch_policy(
    requested_servers: list[str],
    decision: str,
    obligations: list[Any],
) -> tuple[str, list[str], dict[str, Any]]:
    obligation_data = {item.type: item.data for item in obligations}
    target_policy = obligation_data.get("allowed_patch_targets", {})
    constraints = obligation_data.get("patch_constraints", {})

    allowed_servers = target_policy.get("servers") if isinstance(target_policy, dict) else None
    normalized_allowed = {
        str(server).strip().rstrip(".").lower()
        for server in allowed_servers or []
        if isinstance(server, str) and server.strip()
    }
    authorized_servers = [
        server.strip().rstrip(".").lower()
        for server in requested_servers
        if server.strip().rstrip(".").lower() in normalized_allowed
    ]

    required_constraint_fields = {"patch_sources", "allowed_patch_types", "allow_reboot", "maintenance_window"}
    maintenance_window = constraints.get("maintenance_window") if isinstance(constraints, dict) else None
    valid_window = is_valid_maintenance_window(maintenance_window)
    if (
        decision not in {"ALLOW", "PAUSE"}
        or not normalized_allowed
        or not authorized_servers
        or not isinstance(constraints, dict)
        or not required_constraint_fields.issubset(constraints)
        or not isinstance(constraints.get("patch_sources"), list)
        or not set(constraints["patch_sources"]).issubset({"wsus", "nessus_catalog"})
        or not isinstance(constraints.get("allowed_patch_types"), list)
        or not isinstance(constraints.get("allow_reboot"), bool)
        or not valid_window
        or (
            maintenance_window is not None
            and constraints.get("outside_window_decision") not in {"PAUSE", "BLOCK"}
        )
    ):
        return "BLOCK", [], {}

    return decision, authorized_servers, constraints


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed.astimezone(timezone.utc)


def is_valid_maintenance_window(window: Any) -> bool:
    if window is None:
        return True
    if not isinstance(window, dict) or set(window) != {"start_utc", "end_utc"}:
        return False
    start = parse_utc_timestamp(window.get("start_utc"))
    end = parse_utc_timestamp(window.get("end_utc"))
    return start is not None and end is not None and end > start


def is_maintenance_window_open(window: Any, *, now: datetime | None = None) -> bool:
    if window is None:
        return True
    if not is_valid_maintenance_window(window):
        return False
    current = now or datetime.now(timezone.utc)
    start = parse_utc_timestamp(window["start_utc"])
    end = parse_utc_timestamp(window["end_utc"])
    return start <= current.astimezone(timezone.utc) < end


def decide_patch_policy(
    agent_id: str,
    requested_servers: list[str],
    context: dict[str, Any] | None = None,
) -> tuple[str, list[str], dict[str, Any], list[Any], str]:
    if policy_engine is None:
        raise HTTPException(status_code=503, detail="Policy engine is not initialized")
    policy_request = GateRequest(
        actor={"type": "AGENT", "id": agent_id},
        action={"name": "windows.patch.reconcile", "params": {}},
        target={"servers": requested_servers},
        context=context or {},
    )
    decision, obligations, policy_hash = policy_engine.decide(
        {
            "actor": policy_request.actor,
            "action": policy_request.action,
            "target": policy_request.target,
            "context": policy_request.context,
        }
    )
    decision, authorized_servers, constraints = resolve_patch_policy(
        requested_servers,
        decision,
        obligations,
    )
    if decision == "ALLOW" and not is_maintenance_window_open(constraints.get("maintenance_window")):
        decision = constraints.get("outside_window_decision", "BLOCK")
    return decision, authorized_servers, constraints, obligations, policy_hash


def public_base_url(request: Request | None = None) -> str:
    configured = os.environ.get("SG_PUBLIC_URL", "").strip().rstrip("/")
    if configured:
        return configured
    return str(request.base_url).rstrip("/") if request is not None else ""


def notification_fingerprint(adapter_type: str, config: dict[str, Any]) -> str:
    private_bytes = signing_private_key().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    key = hashlib.sha256(b"sg-notification-adapter-fingerprint\0" + private_bytes).digest()
    return notifications.adapter_fingerprint(adapter_type, config, key)


def adapter_is_verified(adapter_type: str, config: dict[str, Any], verified_fingerprint: str | None) -> bool:
    if adapter_type not in notifications.EMAIL_ADAPTER_TYPES:
        return True
    if not verified_fingerprint:
        return False
    try:
        return hmac.compare_digest(verified_fingerprint, notification_fingerprint(adapter_type, config))
    except HTTPException:
        return False


def dispatch_notifications(event_type: str, request_id: str, summary: str, details: dict[str, Any]) -> None:
    """Queue one durable delivery per matching profile; sending happens off the request path."""
    now = time.time()
    delivery_ids: list[str] = []
    try:
        with transaction() as conn:
            profiles = conn.execute(
                """
                SELECT p.profile_id, p.event_types, p.adapter_id, p.recipients, p.template
                FROM notification_profiles p
                JOIN notification_adapters a ON p.adapter_id = a.adapter_id
                WHERE p.enabled = 1 AND a.enabled = 1
                """
            ).fetchall()
            for prof in profiles:
                if event_type not in json.loads(prof["event_types"] or "[]"):
                    continue
                idempotency_key = hashlib.sha256(f"{prof['profile_id']}\n{event_type}\n{request_id}".encode("utf-8")).hexdigest()
                delivery_id = f"DELIV-{uuid.uuid4().hex}"
                payload = {
                    "event_type": event_type,
                    "request_id": request_id,
                    "summary": summary,
                    "details": details,
                    "recipients": json.loads(prof["recipients"] or "[]"),
                    "template": prof["template"] or "",
                }
                inserted = conn.execute(
                    """
                    INSERT OR IGNORE INTO notification_deliveries
                        (delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at, attempts, next_attempt_at, idempotency_key, payload)
                    VALUES (?, ?, ?, ?, ?, 'PENDING', '{}', ?, 0, ?, ?, ?)
                    """,
                    (delivery_id, prof["profile_id"], prof["adapter_id"], request_id, event_type, now, now, idempotency_key, json.dumps(payload, default=str)),
                )
                if inserted.rowcount == 1:
                    delivery_ids.append(delivery_id)
    except Exception:
        # Notifications must never crash core policy/mission path
        notification_logger.exception("Could not queue notifications for event %s", event_type)
        return
    for delivery_id in delivery_ids:
        NOTIFICATION_EXECUTOR.submit(process_delivery, delivery_id)


def attempt_delivery(row: sqlite3.Row, payload: dict[str, Any]) -> tuple[bool, str | None, bool]:
    """Return (delivered, error, retryable) for one claimed delivery."""
    adapter_type = row["adapter_type"]
    if adapter_type is None:
        return False, "Adapter no longer exists", False
    if not row["enabled"]:
        return False, "Adapter is disabled", False
    config = json.loads(row["config"] or "{}")
    try:
        if adapter_type == "mock":
            return True, None, False
        if adapter_type == "webhook":
            notifications.send_webhook(
                config,
                {key: payload[key] for key in ("summary", "details", "request_id")} | {"event": payload["event_type"]},
            )
            return True, None, False
        if adapter_type in notifications.EMAIL_ADAPTER_TYPES:
            if not adapter_is_verified(adapter_type, config, row["verified_fingerprint"]):
                return False, "Adapter is not verified for its current configuration", False
            recipients = payload.get("recipients") or []
            if not recipients or not all(notifications.is_valid_address(item) for item in recipients):
                return False, "Profile has no valid recipients", False
            console_url = f"{public_base_url()}/admin/ui#approvals" if payload["event_type"] == "PAUSE_CREATED" and public_base_url() else ""
            subject, body = notifications.build_message(
                payload["event_type"], payload["request_id"], payload["summary"], payload["details"], payload.get("template", ""), console_url
            )
            notifications.send_email(adapter_type, config, recipients, subject, body, row["delivery_id"])
            return True, None, False
        return False, f"Unsupported adapter type '{adapter_type}'", False
    except notifications.NotificationError as exc:
        return False, str(exc), exc.retryable
    except Exception as exc:
        return False, f"Unexpected delivery error ({type(exc).__name__})", False


def process_delivery(delivery_id: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    with transaction() as conn:
        row = conn.execute(
            """
            SELECT d.delivery_id, d.profile_id, d.adapter_id, d.attempts, d.payload,
                   a.adapter_type, a.config, a.enabled, a.verified_fingerprint
            FROM notification_deliveries d
            LEFT JOIN notification_adapters a ON a.adapter_id = d.adapter_id
            WHERE d.delivery_id = ? AND d.status IN ('PENDING', 'RETRYING', 'SENDING') AND d.next_attempt_at <= ?
            """,
            (delivery_id, now),
        ).fetchone()
        if row is None:
            return
        attempts = int(row["attempts"]) + 1
        conn.execute(
            "UPDATE notification_deliveries SET status = 'SENDING', attempts = ?, next_attempt_at = ?, delivered_at = ? WHERE delivery_id = ?",
            (attempts, now + NOTIFICATION_SEND_LEASE_SECONDS, now, delivery_id),
        )
    payload = json.loads(row["payload"] or "{}")
    delivered, error, retryable = attempt_delivery(row, payload)
    finished = max(now, time.time())
    detail: dict[str, Any] = {
        "recipients": payload.get("recipients", []),
        "summary": payload.get("summary", ""),
        "provider": row["adapter_type"],
        "attempts": attempts,
    }
    if delivered:
        new_status, next_attempt_at = "DELIVERED", None
    elif retryable and attempts < NOTIFICATION_MAX_ATTEMPTS:
        new_status = "RETRYING"
        next_attempt_at = finished + NOTIFICATION_RETRY_BASE_SECONDS * (4 ** (attempts - 1))
        detail["error"] = error
    else:
        new_status, next_attempt_at = "FAILED", None
        detail["error"] = error
    if new_status != "DELIVERED":
        notification_logger.warning("Notification delivery %s attempt %d: %s (%s)", delivery_id, attempts, new_status, error)
    with transaction() as conn:
        conn.execute(
            "UPDATE notification_deliveries SET status = ?, next_attempt_at = ?, detail = ?, delivered_at = ? WHERE delivery_id = ?",
            (new_status, next_attempt_at, json.dumps(detail), finished, delivery_id),
        )


def process_due_deliveries(now: float | None = None) -> None:
    due_time = time.time() if now is None else now
    with connect() as conn:
        due = [
            item["delivery_id"]
            for item in conn.execute(
                "SELECT delivery_id FROM notification_deliveries WHERE status IN ('PENDING', 'RETRYING', 'SENDING') AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT 50",
                (due_time,),
            ).fetchall()
        ]
    for delivery_id in due:
        process_delivery(delivery_id, due_time)


def notification_retry_loop(stop: threading.Event) -> None:
    while not stop.wait(NOTIFICATION_POLL_SECONDS):
        try:
            process_due_deliveries()
        except Exception:
            notification_logger.exception("Notification retry pass failed")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/admin", include_in_schema=False)
def admin_redirect() -> RedirectResponse:
    return RedirectResponse(url="/admin/ui", status_code=307)


@app.get("/admin/ui", response_class=HTMLResponse)
def admin_ui() -> HTMLResponse:
    if not ADMIN_HTML_PATH.is_file():
        raise HTTPException(status_code=404, detail="Admin UI file not found")
    return HTMLResponse(content=ADMIN_HTML_PATH.read_text(encoding="utf-8"))


@app.post("/api/v1/patch-requests", status_code=status.HTTP_202_ACCEPTED)
def create_patch_request(request: PatchRequest, principal: str = Depends(require_agent)) -> dict[str, Any]:
    check_agent_rate_limit(principal, "submit")

    # Idempotent deduplication check: associate matching open request
    normalized_params = json.dumps({"servers": sorted(request.servers)}, sort_keys=True)

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
            raw_normalized = json.dumps({"servers": sorted(raw.get("servers", []))}, sort_keys=True)
            if raw_normalized == normalized_params:
                return {
                    "request_id": open_row["request_id"],
                    "status": "ACCEPTED",
                }

    request_id = f"REQ-{uuid.uuid4().hex}"
    mission_id = f"MISSION-{uuid.uuid4().hex}"
    decision, authorized_servers, patch_constraints, obligations, policy_hash = decide_patch_policy(
        principal,
        request.servers,
    )
    assigned_minion_id = (
        resolve_minion(
            capability="windows.patch.reconcile",
            environment="prod",
            scope_target={"servers": authorized_servers},
        )
        if decision in {"ALLOW", "PAUSE"}
        else "UNASSIGNED"
    )
    status_by_decision = {"ALLOW": "QUEUED", "PAUSE": "WAITING_FOR_APPROVAL", "BLOCK": "CLOSED"}
    mission_state = status_by_decision.get(decision, "CLOSED")
    envelope = {
        "protocol_version": "1.0",
        "request_id": request_id,
        "mission_id": mission_id,
        "minion_id": assigned_minion_id,
        "capability": "windows.patch.reconcile",
        "target": {"servers": authorized_servers},
        "parameters": {
            "patch_sources": patch_constraints.get("patch_sources", []),
            "patch_constraints": {
                "allowed_patch_types": patch_constraints.get("allowed_patch_types", []),
                "allow_reboot": patch_constraints.get("allow_reboot", False),
                "outside_window_decision": patch_constraints.get("outside_window_decision"),
            },
            "maintenance_window": patch_constraints.get("maintenance_window"),
        },
        "execution": mission_execution_settings(),
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
            dispatch_notifications("PAUSE_CREATED", request_id, "Patch reconciliation paused pending approval", {"servers": authorized_servers})
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


@app.post("/internal/v1/minions/{minion_id}/missions/{mission_id}/heartbeat")
def mission_heartbeat(
    minion_id: str,
    mission_id: str,
    request: MissionHeartbeatRequest,
    principal: str = Depends(require_minion),
) -> dict[str, Any]:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    detail_bytes = json.dumps(request.detail, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(detail_bytes) > 16 * 1024:
        raise HTTPException(status_code=413, detail="Mission heartbeat detail exceeds the 16 KiB limit")

    now = time.time()
    expired = False
    with transaction() as connection:
        row = require_live_claim(connection, mission_id, minion_id, request.claim_token, now)
        if row["status"] not in {"CLAIMED", "MISSION_ACKNOWLEDGED", "MISSION_IN_PROGRESS", "MISSION_WAITING_FOR_REBOOT"}:
            raise HTTPException(status_code=409, detail="Mission is not in an active state")
        envelope = json.loads(row["envelope"])
        execution = envelope.get("execution", {})
        overall_timeout = int(execution.get("overall_timeout_seconds", MINION_OVERALL_TIMEOUT_SECONDS))
        attempt_timeout = int(execution.get("attempt_timeout_seconds", MINION_ATTEMPT_TIMEOUT_SECONDS))
        retry_interval = int(execution.get("retry_interval_seconds", MINION_RETRY_INTERVAL_SECONDS))
        max_attempts = int(execution.get("max_attempts", MINION_MAX_ATTEMPTS))
        lease_seconds = int(execution.get("claim_lease_seconds", MINION_CLAIM_LEASE_SECONDS))
        execution_started_at = row["execution_started_at"] or row["attempt_started_at"]
        if execution_started_at is not None and now >= float(execution_started_at) + overall_timeout:
            connection.execute(
                "UPDATE missions SET status = 'MISSION_EXPIRED', claim_token_hash = NULL, lease_expires_at = NULL, updated_at = ? WHERE mission_id = ?",
                (now, mission_id),
            )
            connection.execute(
                "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (f"EVT-OVERALL-EXPIRED-{uuid.uuid4().hex}", mission_id, "MISSION_EXPIRED", json.dumps({"reason": "OVERALL_TIMEOUT"}), now, now),
            )
            expired = True
            lease_expires_at = None
        elif row["attempt_started_at"] is not None and now >= float(row["attempt_started_at"]) + attempt_timeout:
            if int(row["attempt_count"]) >= max_attempts:
                connection.execute(
                    "UPDATE missions SET status = 'MISSION_EXPIRED', claim_token_hash = NULL, lease_expires_at = NULL, updated_at = ? WHERE mission_id = ?",
                    (now, mission_id),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"EVT-ATTEMPT-EXPIRED-{uuid.uuid4().hex}", mission_id, "MISSION_EXPIRED", json.dumps({"reason": "ATTEMPT_TIMEOUT", "attempts": int(row["attempt_count"])}), now, now),
                )
            else:
                connection.execute(
                    "UPDATE missions SET status = 'QUEUED', claim_token_hash = NULL, lease_expires_at = NULL, next_retry_at = ?, updated_at = ? WHERE mission_id = ?",
                    (now + retry_interval, now, mission_id),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"EVT-ATTEMPT-RETRY-{uuid.uuid4().hex}", mission_id, "QUEUED", json.dumps({"reason": "ATTEMPT_TIMEOUT", "attempts": int(row["attempt_count"]), "retry_at": now + retry_interval}), now, now),
                )
            expired = True
            lease_expires_at = None
        else:
            lease_expires_at = now + lease_seconds
            connection.execute(
                "UPDATE missions SET lease_expires_at = ?, worker_process_id = ?, worker_process_started_at = ?, process_detail = ?, updated_at = ? WHERE mission_id = ?",
                (
                    lease_expires_at,
                    request.process_id,
                    request.process_started_at,
                    json.dumps(request.detail, ensure_ascii=False),
                    now,
                    mission_id,
                ),
            )
            connection.execute("UPDATE minions SET last_contact_at = ? WHERE minion_id = ?", (now, minion_id))
    if expired:
        raise HTTPException(status_code=409, detail="Mission overall timeout expired")
    return {
        "mission_id": mission_id,
        "status": "LEASE_RENEWED",
        "server_time": now,
        "lease_expires_at": lease_expires_at,
    }


@app.post("/internal/v1/minions/{minion_id}/missions/claim")
def claim_mission(minion_id: str, principal: str = Depends(require_minion)) -> dict[str, Any] | None:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    outside_window_notifications: list[tuple[str, str]] = []
    claimed_mission: dict[str, Any] | None = None
    retry_deadlines: list[float] = []
    with transaction() as connection:
        rows = connection.execute(
            "SELECT mission_id, request_id, envelope, status, attempt_count, claim_generation, lease_expires_at, attempt_started_at, execution_started_at, next_retry_at FROM missions WHERE minion_id = ? AND status IN ('QUEUED', 'CLAIMED', 'MISSION_ACKNOWLEDGED', 'MISSION_IN_PROGRESS', 'MISSION_WAITING_FOR_REBOOT') ORDER BY created_at",
            (minion_id,),
        ).fetchall()
        now = time.time()
        for row in rows:
            envelope = json.loads(row["envelope"])
            execution = envelope.get("execution", {})
            max_attempts = int(execution.get("max_attempts", MINION_MAX_ATTEMPTS))
            retry_interval = int(execution.get("retry_interval_seconds", MINION_RETRY_INTERVAL_SECONDS))
            attempt_timeout = int(execution.get("attempt_timeout_seconds", MINION_ATTEMPT_TIMEOUT_SECONDS))
            overall_timeout = int(execution.get("overall_timeout_seconds", MINION_OVERALL_TIMEOUT_SECONDS))
            lease_seconds = int(execution.get("claim_lease_seconds", MINION_CLAIM_LEASE_SECONDS))
            status_before_claim = str(row["status"])
            is_new_attempt = status_before_claim == "QUEUED"

            if is_new_attempt:
                next_retry_at = row["next_retry_at"]
                if next_retry_at is not None and float(next_retry_at) > now:
                    retry_deadlines.append(float(next_retry_at))
                    continue
            else:
                lease_expires_at = row["lease_expires_at"]
                if lease_expires_at is not None and float(lease_expires_at) > now:
                    retry_deadlines.append(float(lease_expires_at))
                    continue

            execution_started_at = row["execution_started_at"]
            if execution_started_at is not None and now >= float(execution_started_at) + overall_timeout:
                connection.execute(
                    "UPDATE missions SET status = 'MISSION_EXPIRED', claim_token_hash = NULL, lease_expires_at = NULL, updated_at = ? WHERE mission_id = ?",
                    (now, row["mission_id"]),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"EVT-EXPIRED-{uuid.uuid4().hex}", row["mission_id"], "MISSION_EXPIRED", json.dumps({"reason": "OVERALL_TIMEOUT"}), now, now),
                )
                continue

            attempt_started_at = row["attempt_started_at"]
            if not is_new_attempt and attempt_started_at is not None and now >= float(attempt_started_at) + attempt_timeout:
                if int(row["attempt_count"]) >= max_attempts:
                    connection.execute(
                        "UPDATE missions SET status = 'MISSION_EXPIRED', claim_token_hash = NULL, lease_expires_at = NULL, updated_at = ? WHERE mission_id = ?",
                        (now, row["mission_id"]),
                    )
                    connection.execute(
                        "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (f"EVT-EXPIRED-{uuid.uuid4().hex}", row["mission_id"], "MISSION_EXPIRED", json.dumps({"reason": "ATTEMPT_TIMEOUT", "attempts": int(row["attempt_count"])}), now, now),
                    )
                    continue
                connection.execute(
                    "UPDATE missions SET status = 'QUEUED', claim_token_hash = NULL, lease_expires_at = NULL, next_retry_at = ?, updated_at = ? WHERE mission_id = ?",
                    (now + retry_interval, now, row["mission_id"]),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"EVT-ATTEMPT-TIMEOUT-{uuid.uuid4().hex}", row["mission_id"], "QUEUED", json.dumps({"reason": "ATTEMPT_TIMEOUT", "attempts": int(row["attempt_count"]), "retry_at": now + retry_interval}), now, now),
                )
                retry_deadlines.append(now + retry_interval)
                continue

            if is_new_attempt and int(row["attempt_count"]) >= max_attempts:
                connection.execute(
                    "UPDATE missions SET status = 'MISSION_EXPIRED', updated_at = ? WHERE mission_id = ?",
                    (now, row["mission_id"]),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"EVT-ATTEMPTS-{uuid.uuid4().hex}", row["mission_id"], "MISSION_EXPIRED", json.dumps({"reason": "MAX_ATTEMPTS_EXHAUSTED", "attempts": int(row["attempt_count"])}), now, now),
                )
                continue

            window = envelope.get("parameters", {}).get("maintenance_window")
            if not is_maintenance_window_open(window, now=datetime.fromtimestamp(now, timezone.utc)):
                outside_decision = envelope.get("parameters", {}).get("patch_constraints", {}).get("outside_window_decision")
                if outside_decision not in {"PAUSE", "BLOCK"}:
                    outside_decision = "BLOCK"
                next_status = "WAITING_FOR_APPROVAL" if outside_decision == "PAUSE" else "CLOSED"
                envelope["policy_decision"] = outside_decision
                envelope.pop("signature", None)
                envelope["signature"] = signing_private_key().sign(canonical_json(envelope)).hex()
                connection.execute(
                    "UPDATE missions SET envelope = ?, status = ?, updated_at = ? WHERE mission_id = ? AND status = 'QUEUED'",
                    (json.dumps(envelope), next_status, now, row["mission_id"]),
                )
                connection.execute(
                    "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        f"EVT-WINDOW-{uuid.uuid4().hex}",
                        row["mission_id"],
                        next_status,
                        json.dumps({"reason": "OUTSIDE_MAINTENANCE_WINDOW", "decision": outside_decision}),
                        now,
                        now,
                    ),
                )
                if outside_decision == "PAUSE":
                    outside_window_notifications.append((row["request_id"], row["mission_id"]))
                continue

            connection.execute(
                "UPDATE missions SET status = ?, attempt_count = ?, claim_generation = ?, claim_token_hash = ?, lease_expires_at = ?, attempt_started_at = ?, execution_started_at = COALESCE(execution_started_at, ?), next_retry_at = NULL, worker_process_id = CASE WHEN ? THEN NULL ELSE worker_process_id END, worker_process_started_at = CASE WHEN ? THEN NULL ELSE worker_process_started_at END, process_detail = CASE WHEN ? THEN '{}' ELSE process_detail END, updated_at = ? WHERE mission_id = ?",
                (
                    "CLAIMED" if is_new_attempt else status_before_claim,
                    int(row["attempt_count"]) + (1 if is_new_attempt else 0),
                    int(row["claim_generation"]) + 1,
                    _token_hash(claim_token := secrets.token_urlsafe(48)),
                    now + lease_seconds,
                    now if is_new_attempt else attempt_started_at,
                    now,
                    is_new_attempt,
                    is_new_attempt,
                    is_new_attempt,
                    now,
                    row["mission_id"],
                ),
            )
            claimed_mission = {
                "mission_id": row["mission_id"],
                "envelope": envelope,
                "claim_token": claim_token,
                "attempt": int(row["attempt_count"]) + (1 if is_new_attempt else 0),
                "claim_generation": int(row["claim_generation"]) + 1,
                "resume": not is_new_attempt,
                "resume_status": status_before_claim if not is_new_attempt else "CLAIMED",
                "lease_expires_at": now + lease_seconds,
            }
            break

        if claimed_mission is None and retry_deadlines:
            claimed_mission = {"retry_after_seconds": max(1, int(min(retry_deadlines) - now + 0.999))}

    for request_id, mission_id in outside_window_notifications:
        dispatch_notifications(
            "PAUSE_CREATED",
            request_id,
            "Patch reconciliation is outside its approved maintenance window",
            {"mission_id": mission_id, "reason": "OUTSIDE_MAINTENANCE_WINDOW"},
        )
    return claimed_mission


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
            "SELECT status, claim_token_hash, lease_expires_at, attempt_started_at, execution_started_at, envelope, attempt_count FROM missions WHERE mission_id = ? AND minion_id = ?",
            (mission_id, minion_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Mission not found")
        envelope = json.loads(row["envelope"])
        lease_seconds = int(envelope.get("execution", {}).get("claim_lease_seconds", MINION_CLAIM_LEASE_SECONDS))
        existing_event = connection.execute(
            "SELECT mission_id, status, detail, occurred_at FROM mission_events WHERE event_id = ?",
            (request.event_id,),
        ).fetchone()
        if existing_event is not None:
            if (
                existing_event["mission_id"] == mission_id
                and existing_event["status"] == request.status
                and json.loads(existing_event["detail"]) == request.detail
                and existing_event["occurred_at"] == request.occurred_at
            ):
                verify_claim_token(row["claim_token_hash"], request.claim_token)
                return {"event_id": request.event_id, "status": "ALREADY_RECORDED"}
            raise HTTPException(status_code=409, detail="Event ID is already used for a different status")

        require_live_claim(connection, mission_id, minion_id, request.claim_token, received)
        validate_transition(str(row["status"]), request.status)
        try:
            connection.execute(
                "INSERT INTO mission_events (event_id, mission_id, status, detail, occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request.event_id, mission_id, request.status, json.dumps(request.detail), request.occurred_at, received),
            )
        except sqlite3.IntegrityError:
            existing_event = connection.execute(
                "SELECT mission_id, status, detail, occurred_at FROM mission_events WHERE event_id = ?",
                (request.event_id,),
            ).fetchone()
            if (
                existing_event is not None
                and existing_event["mission_id"] == mission_id
                and existing_event["status"] == request.status
                and json.loads(existing_event["detail"]) == request.detail
                and existing_event["occurred_at"] == request.occurred_at
            ):
                verify_claim_token(row["claim_token_hash"], request.claim_token)
                return {"event_id": request.event_id, "status": "ALREADY_RECORDED"}
            raise HTTPException(status_code=409, detail="Event ID is already used for a different status") from None
        terminal_status = request.status in {"MISSION_REJECTED", "MISSION_CANCELLED", "MISSION_EXPIRED"}
        connection.execute(
            "UPDATE missions SET status = ?, worker_process_id = COALESCE(?, worker_process_id), worker_process_started_at = COALESCE(?, worker_process_started_at), process_detail = CASE WHEN ? THEN ? ELSE process_detail END, execution_started_at = CASE WHEN ? = 'MISSION_IN_PROGRESS' THEN COALESCE(execution_started_at, ?) ELSE execution_started_at END, lease_expires_at = CASE WHEN ? THEN NULL ELSE ? END, updated_at = ? WHERE mission_id = ?",
            (
                request.status,
                request.detail.get("worker_process_id"),
                request.detail.get("worker_process_started_at"),
                "process_detail" in request.detail,
                json.dumps(request.detail.get("process_detail", {}), ensure_ascii=False),
                request.status,
                received,
                terminal_status,
                received + lease_seconds,
                received,
                mission_id,
            ),
        )
    return {"event_id": request.event_id, "status": "RECORDED"}


@app.post("/internal/v1/minions/{minion_id}/missions/{mission_id}/result")
def mission_result(
    minion_id: str,
    mission_id: str,
    request: MissionResultRequest,
    principal: str = Depends(require_minion),
) -> dict[str, Any]:
    if minion_id != principal:
        raise HTTPException(status_code=403, detail="Minion identity not authorized")
    if request.status not in {"MISSION_COMPLETE_SUCCEEDED", "MISSION_COMPLETE_PARTIAL", "MISSION_COMPLETE_FAILED", "MISSION_REJECTED", "MISSION_CANCELLED", "MISSION_EXPIRED"}:
        raise HTTPException(status_code=400, detail="Result status must be terminal")
    result_bytes = json.dumps(request.result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(result_bytes) > MAX_MINION_RESULT_BYTES:
        raise HTTPException(status_code=413, detail="Mission result exceeds the 256 KiB limit")
    received = time.time()
    with transaction() as connection:
        row = connection.execute(
            "SELECT status, claim_token_hash, lease_expires_at, attempt_started_at, execution_started_at, envelope, attempt_count FROM missions WHERE mission_id = ? AND minion_id = ?",
            (mission_id, minion_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Mission not found")
        result_detail = {"result": request.result, "signature": request.signature}
        existing_event = connection.execute(
            "SELECT mission_id, status, detail FROM mission_events WHERE event_id = ?",
            (request.event_id,),
        ).fetchone()
        if existing_event is not None:
            if (
                existing_event["mission_id"] == mission_id
                and existing_event["status"] == request.status
                and json.loads(existing_event["detail"]) == result_detail
            ):
                verify_claim_token(row["claim_token_hash"], request.claim_token)
                return {"status": "ALREADY_RECORDED"}
            raise HTTPException(status_code=409, detail="Event ID is already used for a different result")

        require_live_claim(connection, mission_id, minion_id, request.claim_token, received)
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
                (request.event_id, mission_id, request.status, json.dumps(result_detail), received, received),
            )
        except sqlite3.IntegrityError:
            existing_event = connection.execute(
                "SELECT mission_id, status, detail FROM mission_events WHERE event_id = ?",
                (request.event_id,),
            ).fetchone()
            if (
                existing_event is not None
                and existing_event["mission_id"] == mission_id
                and existing_event["status"] == request.status
                and json.loads(existing_event["detail"]) == result_detail
            ):
                return {"status": "ALREADY_RECORDED"}
            raise HTTPException(status_code=409, detail="Event ID is already used for a different result") from None
        envelope = json.loads(row["envelope"])
        execution = envelope.get("execution", {})
        max_attempts = int(execution.get("max_attempts", MINION_MAX_ATTEMPTS))
        retry_interval = int(execution.get("retry_interval_seconds", MINION_RETRY_INTERVAL_SECONDS))
        overall_timeout = int(execution.get("overall_timeout_seconds", MINION_OVERALL_TIMEOUT_SECONDS))
        execution_started_at = row["execution_started_at"] or row["attempt_started_at"] or received
        retryable = (
            request.status == "MISSION_COMPLETE_FAILED"
            and request.result.get("retryable") is True
            and int(row["attempt_count"]) < max_attempts
            and received < float(execution_started_at) + overall_timeout
        )
        if retryable:
            retry_at = received + retry_interval
            connection.execute(
                "UPDATE missions SET status = 'QUEUED', claim_token_hash = NULL, lease_expires_at = NULL, attempt_started_at = NULL, next_retry_at = ?, worker_process_id = NULL, worker_process_started_at = NULL, updated_at = ? WHERE mission_id = ?",
                (retry_at, received, mission_id),
            )
        else:
            retry_at = None
            connection.execute(
                "UPDATE missions SET status = ?, lease_expires_at = NULL, worker_process_id = NULL, worker_process_started_at = NULL, updated_at = ? WHERE mission_id = ?",
                (request.status, received, mission_id),
            )
    if retry_at is not None:
        return {"status": "RETRY_SCHEDULED", "retry_at": retry_at}
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
            new_decision, authorized_servers, patch_constraints, new_obligations, new_policy_hash = decide_patch_policy(
                row["agent_id"],
                raw_req.get("servers", []),
                context={"approval": approval_evidence},
            )
            capability_name = "windows.patch.reconcile"
            target_obj = {"servers": authorized_servers}
            envelope = json.loads(row["envelope"])
            envelope["target"] = target_obj
            envelope["parameters"] = {
                "patch_sources": patch_constraints.get("patch_sources", []),
                "patch_constraints": {
                    "allowed_patch_types": patch_constraints.get("allowed_patch_types", []),
                    "allow_reboot": patch_constraints.get("allow_reboot", False),
                    "outside_window_decision": patch_constraints.get("outside_window_decision"),
                },
                "maintenance_window": patch_constraints.get("maintenance_window"),
            }

            if not authorized_servers:
                new_decision = "BLOCK"

        if "capability" in raw_req:
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


@app.get("/admin/v1/policy")
def get_policy(_admin: str = Depends(require_admin)) -> dict[str, str]:
    with POLICY_LOCK:
        try:
            content = POLICY_PATH.read_text(encoding="utf-8")
        except OSError:
            raise HTTPException(status_code=503, detail="Configured policy file is unavailable") from None
        return {
            "content": content,
            "file_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "active_policy_hash": policy_engine.policy_hash_full if policy_engine else "",
        }


@app.post("/admin/v1/policy/validate")
def validate_policy(request: PolicyContentRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    _, issues, is_valid = validate_policy_content(request.content)
    return {"is_valid": is_valid, "issues": issues}


@app.post("/admin/v1/policy")
def save_policy(request: SavePolicyRequest, admin: str = Depends(require_admin)) -> dict[str, str]:
    global policy_engine
    _, issues, is_valid = validate_policy_content(request.content)
    if not is_valid:
        try:
            record_policy_event(admin, "SAVE_AND_ACTIVATE", "VALIDATION_FAILED", None, None)
        except sqlite3.Error:
            pass
        raise HTTPException(status_code=422, detail={"message": "Policy validation failed", "issues": issues})

    content_bytes = request.content.encode("utf-8")
    with POLICY_LOCK:
        try:
            current_bytes = POLICY_PATH.read_bytes()
            current_hash = hashlib.sha256(current_bytes).hexdigest()
            if not hmac.compare_digest(current_hash, request.expected_file_hash.lower()):
                raise HTTPException(status_code=409, detail="Policy changed since it was loaded; reload before saving")
            file_mode = stat.S_IMODE(POLICY_PATH.stat().st_mode)
            backup_path = POLICY_PATH.with_name(f"{POLICY_PATH.name}.{time.time_ns()}.bak")
            shutil.copy2(POLICY_PATH, backup_path)
            write_policy_atomically(content_bytes, file_mode)
            candidate = PolicyEngine(str(POLICY_PATH))
            candidate_hash = candidate.policy_hash_full
            record_policy_event(admin, "SAVE_AND_ACTIVATE", "SUCCEEDED", current_hash, candidate_hash)
        except HTTPException:
            raise
        except Exception as exc:
            try:
                if "current_bytes" in locals():
                    write_policy_atomically(current_bytes, file_mode)
            except OSError:
                raise HTTPException(status_code=503, detail="Policy activation failed and automatic rollback failed") from None
            raise HTTPException(status_code=503, detail="Policy could not be saved and activated") from exc

        candidate.policy_path = str(POLICY_PATH)
        policy_engine = candidate
        return {
            "status": "RELOADED",
            "policy_hash": candidate.policy_hash,
            "policy_hash_full": candidate_hash,
            "backup_file": backup_path.name,
        }


@app.post("/admin/v1/policy/reload")
def reload_policy(admin: str = Depends(require_admin)) -> dict[str, str]:
    global policy_engine
    with POLICY_LOCK:
        previous_hash = policy_engine.policy_hash_full if policy_engine else None
        try:
            content = POLICY_PATH.read_text(encoding="utf-8")
            _, issues, is_valid = validate_policy_content(content)
            if not is_valid:
                record_policy_event(admin, "RELOAD", "VALIDATION_FAILED", previous_hash, None)
                raise HTTPException(status_code=422, detail={"message": "Configured policy is invalid", "issues": issues})
            candidate = PolicyEngine(str(POLICY_PATH))
            record_policy_event(admin, "RELOAD", "SUCCEEDED", previous_hash, candidate.policy_hash_full)
        except HTTPException:
            raise
        except Exception as exc:
            try:
                record_policy_event(admin, "RELOAD", "FAILED", previous_hash, None)
            except sqlite3.Error:
                pass
            connection.execute("CREATE INDEX IF NOT EXISTS missions_lease_idx ON missions(status, lease_expires_at)")
            raise HTTPException(status_code=503, detail="Configured policy could not be reloaded") from exc
        policy_engine = candidate
        return {"status": "RELOADED", "policy_hash": candidate.policy_hash, "policy_hash_full": candidate.policy_hash_full}


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


def serialize_adapter(row: sqlite3.Row) -> dict[str, Any]:
    config = json.loads(row["config"] or "{}")
    adapter_type = row["adapter_type"]
    requires_verification = adapter_type in notifications.EMAIL_ADAPTER_TYPES
    return {
        "adapter_id": row["adapter_id"],
        "adapter_type": adapter_type,
        "name": row["name"],
        "config": config,
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "requires_verification": requires_verification,
        "verified": adapter_is_verified(adapter_type, config, row["verified_fingerprint"]),
        "verified_at": row["verified_at"],
        "secrets_configured": notifications.secrets_status(adapter_type, config),
    }


ADAPTER_COLUMNS = "adapter_id, adapter_type, name, config, enabled, created_at, updated_at, verified_at, verified_fingerprint"


def load_adapter_row(connection: sqlite3.Connection, adapter_id: str) -> sqlite3.Row:
    row = connection.execute(f"SELECT {ADAPTER_COLUMNS} FROM notification_adapters WHERE adapter_id = ?", (adapter_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Notification adapter not found")
    return row


@app.post("/admin/v1/notification-adapters", status_code=status.HTTP_201_CREATED)
def create_notification_adapter(body: CreateNotificationAdapterRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    try:
        config = notifications.validate_adapter_config(body.adapter_type, body.config)
    except notifications.ConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    now = time.time()
    with transaction() as connection:
        existing = connection.execute("SELECT adapter_type, config FROM notification_adapters WHERE adapter_id = ?", (body.adapter_id,)).fetchone()
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
            (body.adapter_id, body.adapter_type, body.name, json.dumps(config), 1 if body.enabled else 0, now, now),
        )
        if existing is not None and (existing["adapter_type"] != body.adapter_type or json.loads(existing["config"] or "{}") != config):
            connection.execute("UPDATE notification_adapters SET verified_at = NULL, verified_fingerprint = NULL WHERE adapter_id = ?", (body.adapter_id,))
            connection.execute("DELETE FROM notification_adapter_verifications WHERE adapter_id = ?", (body.adapter_id,))
        row = load_adapter_row(connection, body.adapter_id)
    return serialize_adapter(row)


@app.get("/admin/v1/notification-adapters")
def list_notification_adapters(_admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(f"SELECT {ADAPTER_COLUMNS} FROM notification_adapters ORDER BY created_at DESC").fetchall()
    return [serialize_adapter(row) for row in rows]


@app.patch("/admin/v1/notification-adapters/{adapter_id}")
def update_notification_adapter(adapter_id: str, body: UpdateNotificationAdapterRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    with transaction() as connection:
        load_adapter_row(connection, adapter_id)
        connection.execute(
            "UPDATE notification_adapters SET enabled = ?, updated_at = ? WHERE adapter_id = ?",
            (1 if body.enabled else 0, time.time(), adapter_id),
        )
        row = load_adapter_row(connection, adapter_id)
    return serialize_adapter(row)


@app.delete("/admin/v1/notification-adapters/{adapter_id}")
def delete_notification_adapter(adapter_id: str, _admin: str = Depends(require_admin)) -> dict[str, str]:
    with transaction() as connection:
        load_adapter_row(connection, adapter_id)
        in_use = connection.execute("SELECT COUNT(*) FROM notification_profiles WHERE adapter_id = ?", (adapter_id,)).fetchone()[0]
        if in_use:
            raise HTTPException(status_code=409, detail="Adapter is used by notification profiles")
        connection.execute("DELETE FROM notification_adapter_verifications WHERE adapter_id = ?", (adapter_id,))
        connection.execute("DELETE FROM notification_adapters WHERE adapter_id = ?", (adapter_id,))
    return {"adapter_id": adapter_id, "status": "DELETED"}


@app.post("/admin/v1/notification-adapters/{adapter_id}/verify")
def start_notification_adapter_verification(
    adapter_id: str,
    body: VerifyNotificationAdapterRequest,
    request: Request,
    _admin: str = Depends(require_admin),
) -> dict[str, Any]:
    if not notifications.is_valid_address(body.recipient):
        raise HTTPException(status_code=422, detail="A valid recipient email address is required")
    with connect() as connection:
        row = load_adapter_row(connection, adapter_id)
    adapter_type = row["adapter_type"]
    if adapter_type not in notifications.EMAIL_ADAPTER_TYPES:
        raise HTTPException(status_code=409, detail="Only email adapters require verification")
    config = json.loads(row["config"] or "{}")
    try:
        config = notifications.validate_adapter_config(adapter_type, config)
    except notifications.ConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    missing = [name for name, present in notifications.secrets_status(adapter_type, config).items() if not present]
    if missing:
        raise HTTPException(status_code=409, detail=f"Service secrets are not configured: {', '.join(missing)}")

    token = secrets.token_urlsafe(32)
    now = time.time()
    expires_at = now + NOTIFICATION_VERIFICATION_TTL_SECONDS
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO notification_adapter_verifications (adapter_id, token_hash, fingerprint, recipient, expires_at, used_at, created_at)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            ON CONFLICT(adapter_id) DO UPDATE SET
                token_hash = excluded.token_hash, fingerprint = excluded.fingerprint, recipient = excluded.recipient,
                expires_at = excluded.expires_at, used_at = NULL, created_at = excluded.created_at
            """,
            (adapter_id, _token_hash(token), notification_fingerprint(adapter_type, config), body.recipient, expires_at, now),
        )
    link = f"{public_base_url(request)}/notification-verify/{token}"
    message = (
        f"This is a SluiceGate test message for the email adapter '{row['name']}'.\n\n"
        f"Confirm that you received it by opening this link and pressing Confirm:\n{link}\n\n"
        f"The link expires in {NOTIFICATION_VERIFICATION_TTL_SECONDS // 60} minutes and can be used once."
    )
    try:
        notifications.send_email(adapter_type, config, [body.recipient], "[SluiceGate] Verify email adapter", message, f"verify-{uuid.uuid4().hex}")
    except notifications.NotificationError as exc:
        with transaction() as connection:
            connection.execute("DELETE FROM notification_adapter_verifications WHERE adapter_id = ?", (adapter_id,))
        raise HTTPException(status_code=502, detail=f"Test email was not sent: {exc}") from None
    return {"adapter_id": adapter_id, "status": "VERIFICATION_SENT", "recipient": body.recipient, "expires_at": expires_at}


def verification_page(title: str, message: str, token: str | None = None) -> str:
    form = (
        f'<form method="post" action="/notification-verify/{html.escape(token)}"><button type="submit">Confirm</button></form>'
        if token
        else ""
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>SluiceGate</title></head>"
        f"<body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto\"><h1>{html.escape(title)}</h1><p>{html.escape(message)}</p>{form}</body></html>"
    )


def find_adapter_verification(connection: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT v.adapter_id, v.fingerprint, v.expires_at, v.used_at, a.adapter_type, a.config, a.name
        FROM notification_adapter_verifications v
        JOIN notification_adapters a ON a.adapter_id = v.adapter_id
        WHERE v.token_hash = ?
        """,
        (_token_hash(token),),
    ).fetchone()


@app.get("/notification-verify/{token}", response_class=HTMLResponse, include_in_schema=False)
def show_adapter_verification(token: str) -> HTMLResponse:
    # Read-only: mail scanners that prefetch links must not complete verification.
    with connect() as connection:
        row = find_adapter_verification(connection, token)
    if row is None or row["used_at"] is not None or float(row["expires_at"]) <= time.time():
        return HTMLResponse(verification_page("Link not valid", "This verification link is invalid, expired, or already used."), status_code=410)
    return HTMLResponse(verification_page("Confirm email adapter", f"Confirm that you received the test message for '{row['name']}'.", token))


@app.post("/notification-verify/{token}", response_class=HTMLResponse, include_in_schema=False)
def confirm_adapter_verification(token: str) -> HTMLResponse:
    invalid = HTMLResponse(verification_page("Link not valid", "This verification link is invalid, expired, or already used."), status_code=410)
    now = time.time()
    with transaction() as connection:
        row = find_adapter_verification(connection, token)
        if row is None or row["used_at"] is not None or float(row["expires_at"]) <= now:
            return invalid
        config = json.loads(row["config"] or "{}")
        try:
            current = notification_fingerprint(row["adapter_type"], config)
        except HTTPException:
            return invalid
        if not hmac.compare_digest(current, row["fingerprint"]):
            return invalid
        connection.execute(
            "UPDATE notification_adapters SET verified_at = ?, verified_fingerprint = ? WHERE adapter_id = ?",
            (now, current, row["adapter_id"]),
        )
        connection.execute("UPDATE notification_adapter_verifications SET used_at = ? WHERE adapter_id = ?", (now, row["adapter_id"]))
    return HTMLResponse(verification_page("Adapter verified", "The email adapter is verified and can now deliver notifications."))


def validate_profile_target(connection: sqlite3.Connection, adapter_id: str, recipients: list[str]) -> None:
    adapter = connection.execute("SELECT adapter_type FROM notification_adapters WHERE adapter_id = ?", (adapter_id,)).fetchone()
    if adapter is None:
        raise HTTPException(status_code=422, detail=f"Notification adapter '{adapter_id}' does not exist")
    if adapter["adapter_type"] in notifications.EMAIL_ADAPTER_TYPES:
        if not recipients or len(recipients) > notifications.MAX_EMAIL_RECIPIENTS:
            raise HTTPException(status_code=422, detail=f"Email profiles need 1-{notifications.MAX_EMAIL_RECIPIENTS} recipients")
        invalid = [item for item in recipients if not notifications.is_valid_address(item)]
        if invalid:
            raise HTTPException(status_code=422, detail="Recipients must be valid email addresses")


@app.post("/admin/v1/notification-profiles", status_code=status.HTTP_201_CREATED)
def create_notification_profile(body: CreateNotificationProfileRequest, _admin: str = Depends(require_admin)) -> dict[str, Any]:
    now = time.time()
    with transaction() as connection:
        validate_profile_target(connection, body.adapter_id, body.recipients)
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

        validate_profile_target(
            connection,
            body.adapter_id if body.adapter_id is not None else row["adapter_id"],
            body.recipients if body.recipients is not None else json.loads(row["recipients"] or "[]"),
        )
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
                "SELECT delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at, attempts, next_attempt_at FROM notification_deliveries WHERE request_id = ? ORDER BY delivered_at DESC",
                (request_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT delivery_id, profile_id, adapter_id, request_id, event_type, status, detail, delivered_at, attempts, next_attempt_at FROM notification_deliveries ORDER BY delivered_at DESC LIMIT 100"
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
