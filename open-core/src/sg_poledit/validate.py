from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from .errors import ValidationResult
from .schema import SUPPORTED_OPERATORS, VALID_DECISIONS


def validate_policy_dict(data: Dict[str, Any]) -> ValidationResult:
    result = ValidationResult()
    if not isinstance(data, dict):
        result.add_error("", "Policy document must be a YAML mapping/object.")
        return result

    version = data.get("version")
    if version is not None and not isinstance(version, int):
        result.add_error("version", "Version must be an integer.")

    default = data.get("default")
    if isinstance(default, str):
        if default not in VALID_DECISIONS:
            result.add_error("default", f"Default decision must be one of {', '.join(VALID_DECISIONS)}.")
    elif isinstance(default, dict):
        _validate_decision(result, "default.decision", default.get("decision"))
        _validate_obligations(result, "default.obligations", default.get("obligations"))
    else:
        result.add_error("default", "Default must be a mapping with a decision.")

    rules = data.get("rules")
    if not isinstance(rules, list):
        result.add_error("rules", "Rules must be a list.")
        return result

    seen_rule_names: set[str] = set()
    for idx, rule in enumerate(rules):
        path = f"rules[{idx}]"
        if not isinstance(rule, dict):
            result.add_error(path, "Each rule must be a mapping/object.")
            continue

        name = rule.get("name")
        if not isinstance(name, str) or not name.strip():
            result.add_error(f"{path}.name", "Rule name is required.")
        elif name in seen_rule_names:
            result.add_warning(f"{path}.name", f"Duplicate rule name '{name}'.")
        else:
            seen_rule_names.add(name)

        when = rule.get("when")
        if not isinstance(when, list) or len(when) == 0:
            result.add_error(f"{path}.when", "Rule must include at least one condition.")
        else:
            for cond_idx, condition in enumerate(when):
                _validate_condition(result, f"{path}.when[{cond_idx}]", condition)

        _validate_decision(result, f"{path}.decision", rule.get("decision"))
        _validate_obligations(result, f"{path}.obligations", rule.get("obligations"))

    return result


def _validate_decision(result: ValidationResult, path: str, value: Any) -> None:
    if not isinstance(value, str):
        result.add_error(path, "Decision is required.")
        return
    if value not in VALID_DECISIONS:
        result.add_error(path, f"Decision must be one of {', '.join(VALID_DECISIONS)}.")


def _validate_obligations(result: ValidationResult, path: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        result.add_error(path, "Obligations must be a list.")
        return
    for idx, obligation in enumerate(value):
        obligation_path = f"{path}[{idx}]"
        if not isinstance(obligation, dict):
            result.add_error(obligation_path, "Each obligation must be a mapping/object.")
            continue
        typ = obligation.get("type")
        if not isinstance(typ, str) or not typ.strip():
            result.add_error(f"{obligation_path}.type", "Obligation type is required.")


def _validate_condition(result: ValidationResult, path: str, value: Any) -> None:
    if not isinstance(value, dict):
        result.add_error(path, "Condition must be a mapping/object.")
        return

    cond_path = value.get("path")
    if not isinstance(cond_path, str) or not cond_path.strip():
        result.add_error(f"{path}.path", "Condition path is required.")

    operators = _operator_items(value)
    if len(operators) != 1:
        result.add_error(
            path,
            f"Condition must include exactly one supported operator: {', '.join(SUPPORTED_OPERATORS)}.",
        )
        return

    operator, operand = operators[0]
    if operator == "in" and not isinstance(operand, list):
        result.add_error(f"{path}.{operator}", "The 'in' operator expects a list.")
    if operator == "exists" and not isinstance(operand, bool):
        result.add_error(f"{path}.{operator}", "The 'exists' operator expects true or false.")
    if operator in {"gt", "gte", "lt", "lte"} and not isinstance(operand, (int, float)):
        result.add_error(f"{path}.{operator}", f"The '{operator}' operator expects a number.")


def _operator_items(condition: Dict[str, Any]) -> List[Tuple[str, Any]]:
    return [(key, value) for key, value in condition.items() if key in SUPPORTED_OPERATORS]
