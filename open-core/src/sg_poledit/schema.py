from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SUPPORTED_OPERATORS = ("exists", "eq", "in", "gt", "gte", "lt", "lte")
VALID_DECISIONS = ("ALLOW", "PAUSE", "BLOCK")


@dataclass
class Condition:
    path: str
    operator: str
    value: Any

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, self.operator: self.value}


@dataclass
class Rule:
    name: str
    when: List[Condition]
    decision: str
    obligations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "name": self.name,
            "when": [condition.to_dict() for condition in self.when],
            "decision": self.decision,
        }
        if self.obligations:
            data["obligations"] = self.obligations
        return data


@dataclass
class DefaultPolicy:
    decision: str
    obligations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"decision": self.decision}
        if self.obligations:
            data["obligations"] = self.obligations
        return data


@dataclass
class PolicyDocument:
    version: Optional[int]
    default: DefaultPolicy
    rules: List[Rule]

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        if self.version is not None:
            data["version"] = self.version
        data["default"] = self.default.to_dict()
        data["rules"] = [rule.to_dict() for rule in self.rules]
        return data
