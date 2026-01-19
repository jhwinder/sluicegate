from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

Decision = Literal["ALLOW", "PAUSE", "BLOCK"]

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
