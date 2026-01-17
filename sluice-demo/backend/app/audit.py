from pydantic import BaseModel
from typing import Any, Dict, Literal, Optional, List
from datetime import datetime, timezone
import uuid

ActorType = Literal["SYSTEM", "POLICY", "HUMAN"]
EventType = Literal[
    "REQUEST_CREATED",
    "GATE_DECIDED",
    "NOTIFICATION_ATTEMPTED",
    "APPROVED",
    "REJECTED",
    "EXECUTION_STARTED",
    "EXECUTION_COMPLETED",
    "EXECUTION_FAILED",
]

class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    request_id: str
    event_type: EventType
    actor_type: ActorType
    actor_id: Optional[str] = None
    summary: str
    details: Dict[str, Any] = {}

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def new_event_id() -> str:
    return str(uuid.uuid4())

# In-memory append-only audit log (resets on restart)
AUDIT_LOG: List[AuditEvent] = []

def log_event(
    *,
    request_id: str,
    event_type: EventType,
    actor_type: ActorType,
    actor_id: Optional[str],
    summary: str,
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    evt = AuditEvent(
        event_id=new_event_id(),
        timestamp=iso_now(),
        request_id=request_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        summary=summary,
        details=details or {},
    )
    AUDIT_LOG.append(evt)
    return evt
