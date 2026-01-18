from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple, Union
import hashlib
import yaml

from .models import Decision
from .obligations import parse_obligations
from .models import Obligation

def short_hash(full_hash: str, length: int = 8) -> str:
    if not full_hash:
        return ""
    return f"{full_hash[:length]}.."

class PolicyEngine:
    """
    Beta policy engine:
      - YAML policy
      - rule order matters (first match wins)
      - AND-only conditions per rule
      - path-based field selection (dot notation)
    """

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policy_hash_full: str = ""
        self.policy_hash: str = ""
        self.policy: Dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        with open(self.policy_path, "rb") as f:
            raw = f.read()
        self.policy_hash_full = hashlib.sha256(raw).hexdigest()
        self.policy_hash = short_hash(self.policy_hash_full)
        self.policy = yaml.safe_load(raw.decode("utf-8")) or {}

    def decide(self, request_ctx: Dict[str, Any]) -> Tuple[Decision, List[Obligation], str]:
        """
        Returns (decision, obligations, policy_hash).
        """
        default = self.policy.get("default", {}) or {}
        default_decision: Decision = (default.get("decision") or "PAUSE")
        default_obls = parse_obligations(default.get("obligations") or [])

        for rule in (self.policy.get("rules") or []):
            when = rule.get("when") or []
            if self._match_all(when, request_ctx):
                decision: Decision = rule.get("decision") or default_decision
                obls = parse_obligations(rule.get("obligations") or [])
                return decision, obls, self.policy_hash

        return default_decision, default_obls, self.policy_hash

    def _match_all(self, conditions: List[Dict[str, Any]], ctx: Dict[str, Any]) -> bool:
        # AND-only in Beta
        for cond in conditions:
            if not self._match_one(cond, ctx):
                return False
        return True

    def _match_one(self, cond: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        path = cond.get("path")
        if not path or not isinstance(path, str):
            return False

        exists = "exists" in cond
        value = _get_by_path(ctx, path)

        if exists:
            want = bool(cond.get("exists"))
            has = value is not None
            return has if want else (not has)

        # exactly one operator expected
        if "eq" in cond:
            return value == cond.get("eq")
        if "in" in cond:
            candidates = cond.get("in")
            return value in candidates if isinstance(candidates, list) else False

        # numeric comparisons
        for op in ("gt", "gte", "lt", "lte"):
            if op in cond:
                if value is None:
                    return False
                try:
                    v = float(value)
                    c = float(cond.get(op))
                except Exception:
                    return False
                if op == "gt" and not (v > c):
                    return False
                if op == "gte" and not (v >= c):
                    return False
                if op == "lt" and not (v < c):
                    return False
                if op == "lte" and not (v <= c):
                    return False
                return True

        return False

def _get_by_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur
