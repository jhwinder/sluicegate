from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# NOTE: "BLOCK" is used instead of "DENY" to match the existing public API.
# The PAUSE primitive extends this by adding resumable "continuations".
Decision = Literal["ALLOW", "PAUSE", "BLOCK"]

PauseStatus = Literal["PENDING", "APPROVED", "DENIED", "EXPIRED"]

@dataclass
class GateRequest:
    actor: Dict[str, Any]
    action: Dict[str, Any]
    target: Dict[str, Any]
    context: Dict[str, Any]

@dataclass
class Obligation:
    type: str
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GateDecision:
    request_id: str
    decision: Decision
    policy_hash: str
    obligations: List[Obligation] = field(default_factory=list)
    message: str = ""

    # ---- PAUSE primitive extensions (optional) ----
    # If decision == "PAUSE", SluiceGate returns a resume_token that can be
    # resolved later (approve/deny). Agents should treat PAUSE as a non-error
    # waiting state.
    resume_token: Optional[str] = None
    pause_status: Optional[PauseStatus] = None
    pause_timeout_at: Optional[float] = None  # epoch seconds
    reason_code: Optional[str] = None


@dataclass
class PauseRecord:
    """Stored continuation for a paused action."""

    resume_token: str
    created_at: float
    timeout_at: Optional[float]
    status: PauseStatus
    request: GateRequest
    policy_hash: str
    obligations: List[Obligation] = field(default_factory=list)
    message: str = ""
    reason_code: Optional[str] = None
    approver: Optional[str] = None
    approver_comment: str = ""
    resolved_at: Optional[float] = None

# ---------- Explain / simulation models ----------

@dataclass
class ConditionTrace:
    """
    Trace of a single condition evaluation.
    """
    path: str
    operator: str
    expected: Any
    actual: Any
    passed: bool
    note: str = ""

@dataclass
class RuleTrace:
    """
    Trace of a rule evaluation (AND-only in Beta).
    """
    name: str
    matched: bool
    conditions: List[ConditionTrace] = field(default_factory=list)
    decision: Optional[Decision] = None
    obligations: List[Obligation] = field(default_factory=list)

@dataclass
class ExplainResult:
    """
    Detailed trace of a policy evaluation.
    """
    decision: Decision
    policy_hash: str
    matched_rule: Optional[str]
    used_default: bool
    obligations: List[Obligation] = field(default_factory=list)
    rules: List[RuleTrace] = field(default_factory=list)
