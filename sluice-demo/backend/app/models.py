from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "PAUSE", "BLOCK"]
Status = Literal["PENDING", "APPROVED", "REJECTED", "EXECUTED", "BLOCKED"]


def new_request_id() -> str:
    return uuid.uuid4().hex


def now_ts() -> float:
    return time.time()


class ActionRequest(BaseModel):
    action: str
    amount: int
    currency: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CreateDecisionResponse(BaseModel):
    request_id: str
    decision: Decision
    status: Status
    message: str
    resume_token: Optional[str] = None


class StoredRequest(BaseModel):
    request_id: str
    created_at: float
    payload: ActionRequest
    decision: Decision
    status: Status
    policy_hash: str
    resume_token: Optional[str] = None
    executed_result: Optional[Dict[str, Any]] = None
