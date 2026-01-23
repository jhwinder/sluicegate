from __future__ import annotations
from typing import Any, Dict, List, Tuple
import hashlib
import yaml

from .models import Decision, ExplainResult, RuleTrace, ConditionTrace, Obligation
from .obligations import parse_obligations

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
      - explain() returns an evaluation trace (pure; no side effects)
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

    # ---- Core decision (no trace) ----

    def decide(self, request_ctx: Dict[str, Any]) -> Tuple[Decision, List[Obligation], str]:
        default = self.policy.get("default", None)
        if isinstance(default, str):
            default_decision = default
            default_obligations = []
        elif isinstance(default, dict):
            default_decision = default.get("decision") or "PAUSE"
            default_obligations = default.get("obligations") or []
        else:
            default_decision = "PAUSE"
            default_obligations = []

        for rule in (self.policy.get("rules") or []):
            when = rule.get("when") or []
            if self._match_all(when, request_ctx):
                decision: Decision = rule.get("decision") or default_decision
                obls = parse_obligations(rule.get("obligations") or [])
                return decision, obls, self.policy_hash

        return default_decision, default_obligations, self.policy_hash

    # ---- Explain mode (with trace) ----

    def explain(self, request_ctx: Dict[str, Any]) -> ExplainResult:
        default = self.policy.get("default", {}) or {}
        default_decision: Decision = (default.get("decision") or "PAUSE")
        default_obligations = parse_obligations(default.get("obligations") or [])

        rules_trace: List[RuleTrace] = []
        matched_rule_name: str | None = None
        final_decision: Decision | None = None
        final_obls: List[Obligation] = []

        for rule in (self.policy.get("rules") or []):
            name = str(rule.get("name") or "Unnamed rule")
            when = rule.get("when") or []
            cond_traces, matched = self._trace_match_all(when, request_ctx)

            # If it matches, compute final decision/obligations from this rule
            if matched and matched_rule_name is None:
                matched_rule_name = name
                final_decision = (rule.get("decision") or default_decision)
                final_obls = parse_obligations(rule.get("obligations") or [])

                rules_trace.append(
                    RuleTrace(
                        name=name,
                        matched=True,
                        conditions=cond_traces,
                        decision=final_decision,
                        obligations=final_obls,
                    )
                )
                # First match wins: stop evaluating further rules (Beta semantics)
                break

            rules_trace.append(
                RuleTrace(
                    name=name,
                    matched=False,
                    conditions=cond_traces,
                    decision=None,
                    obligations=[],
                )
            )

        if matched_rule_name is None:
            # No rule matched; default applies
            return ExplainResult(
                decision=default_decision,
                policy_hash=self.policy_hash,
                matched_rule=None,
                used_default=True,
                obligations=default_obligations,
                rules=rules_trace,
            )

        return ExplainResult(
            decision=final_decision or default_decision,
            policy_hash=self.policy_hash,
            matched_rule=matched_rule_name,
            used_default=False,
            obligations=final_obls,
            rules=rules_trace,
        )

    # ---- Matching helpers ----

    def _match_all(self, conditions: List[Dict[str, Any]], ctx: Dict[str, Any]) -> bool:
        # AND-only in Beta
        for cond in conditions:
            if not self._match_one(cond, ctx):
                return False
        return True

    def _trace_match_all(self, conditions: List[Dict[str, Any]], ctx: Dict[str, Any]) -> Tuple[List[ConditionTrace], bool]:
        traces: List[ConditionTrace] = []
        all_ok = True
        for cond in conditions:
            trace = self._trace_one(cond, ctx)
            traces.append(trace)
            if not trace.passed:
                all_ok = False
        return traces, all_ok

    def _match_one(self, cond: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        return self._trace_one(cond, ctx).passed

    def _trace_one(self, cond: Dict[str, Any], ctx: Dict[str, Any]) -> ConditionTrace:
        path = cond.get("path")
        if not path or not isinstance(path, str):
            return ConditionTrace(
                path=str(path),
                operator="invalid",
                expected=None,
                actual=None,
                passed=False,
                note="Missing or invalid 'path'",
            )

        actual = _get_by_path(ctx, path)

        # exists
        if "exists" in cond:
            want = bool(cond.get("exists"))
            has = actual is not None
            passed = has if want else (not has)
            return ConditionTrace(
                path=path,
                operator="exists",
                expected=want,
                actual=has,
                passed=passed,
            )

        # eq
        if "eq" in cond:
            expected = cond.get("eq")
            return ConditionTrace(
                path=path,
                operator="eq",
                expected=expected,
                actual=actual,
                passed=(actual == expected),
            )

        # in
        if "in" in cond:
            expected = cond.get("in")
            passed = isinstance(expected, list) and (actual in expected)
            return ConditionTrace(
                path=path,
                operator="in",
                expected=expected,
                actual=actual,
                passed=passed,
            )

        # numeric comparisons
        for op in ("gt", "gte", "lt", "lte"):
            if op in cond:
                expected = cond.get(op)
                if actual is None:
                    return ConditionTrace(
                        path=path,
                        operator=op,
                        expected=expected,
                        actual=None,
                        passed=False,
                        note="Actual value missing",
                    )
                try:
                    v = float(actual)
                    c = float(expected)
                except Exception:
                    return ConditionTrace(
                        path=path,
                        operator=op,
                        expected=expected,
                        actual=actual,
                        passed=False,
                        note="Non-numeric compare",
                    )

                if op == "gt":
                    passed = v > c
                elif op == "gte":
                    passed = v >= c
                elif op == "lt":
                    passed = v < c
                else:  # lte
                    passed = v <= c

                return ConditionTrace(
                    path=path,
                    operator=op,
                    expected=c,
                    actual=v,
                    passed=passed,
                )

        return ConditionTrace(
            path=path,
            operator="invalid",
            expected=None,
            actual=actual,
            passed=False,
            note="No supported operator found",
        )

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
