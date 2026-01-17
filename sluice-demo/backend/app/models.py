from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict, Any
from datetime import datetime, timezone
import time
import uuid

Decision = Literal["ALLOW", "PAUSE", "BLOCK"]
RequestStatus = Literal["PENDING", "APPROVED", "REJECTED", "EXECUTED", "BLOCKED"]

class ActionRequest(BaseModel):
    action: str
    amount: int = Field(ge=0, description="Amount in cents")
    currency: str = "USD"
    metadata: Dict[str, Any] = {}

class CreateDecisionResponse(BaseModel):
    request_id: str
    decision: Decision
    status: RequestStatus
    message: str

class StoredRequest(BaseModel):
    request_id: str
    created_at: str
    status: RequestStatus
    decision: Decision
    payload: ActionRequest
    executed_result: Optional[Dict[str, Any]] = None

def new_request_id() -> str:
    return str(uuid.uuid4())

def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

