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
