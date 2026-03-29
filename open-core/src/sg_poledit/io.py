from __future__ import annotations

from typing import Any, Dict, List

import yaml

from .errors import ValidationResult
from .schema import Condition, DefaultPolicy, PolicyDocument, Rule, SUPPORTED_OPERATORS
from .validate import validate_policy_dict


def load_policy_text(yaml_text: str) -> PolicyDocument:
    data = yaml.safe_load(yaml_text) or {}
    validation = validate_policy_dict(data)
    if not validation.is_valid:
        raise ValueError(validation.render())
    return policy_from_dict(data)


def load_policy_file(path: str) -> PolicyDocument:
    with open(path, "r", encoding="utf-8") as handle:
        return load_policy_text(handle.read())


def dump_policy(policy: PolicyDocument) -> str:
    return yaml.safe_dump(policy.to_dict(), sort_keys=False, allow_unicode=False)


def save_policy(policy: PolicyDocument, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(dump_policy(policy))


def format_policy_text(yaml_text: str) -> str:
    policy = load_policy_text(yaml_text)
    return dump_policy(policy)


def parse_policy_text(yaml_text: str) -> Dict[str, Any]:
    return yaml.safe_load(yaml_text) or {}


def validate_policy_text(yaml_text: str) -> ValidationResult:
    try:
        data = parse_policy_text(yaml_text)
    except yaml.YAMLError as exc:
        result = ValidationResult()
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        result.add_error("", f"Invalid YAML: {exc}", line=None if line is None else line + 1)
        return result
    return validate_policy_dict(data)


def policy_from_dict(data: Dict[str, Any]) -> PolicyDocument:
    default_data = data["default"]
    if isinstance(default_data, str):
        default_policy = DefaultPolicy(decision=default_data, obligations=[])
    else:
        default_policy = DefaultPolicy(
            decision=default_data["decision"],
            obligations=list(default_data.get("obligations") or []),
        )

    rules: List[Rule] = []
    for item in data.get("rules", []):
        conditions: List[Condition] = []
        for raw_condition in item.get("when", []):
            for operator in SUPPORTED_OPERATORS:
                if operator in raw_condition:
                    conditions.append(
                        Condition(
                            path=raw_condition["path"],
                            operator=operator,
                            value=raw_condition[operator],
                        )
                    )
                    break
        rules.append(
            Rule(
                name=item["name"],
                when=conditions,
                decision=item["decision"],
                obligations=list(item.get("obligations") or []),
            )
        )

    return PolicyDocument(
        version=data.get("version"),
        default=default_policy,
        rules=rules,
    )
