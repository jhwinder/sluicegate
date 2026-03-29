from __future__ import annotations

from .schema import Condition, DefaultPolicy, PolicyDocument, Rule
from .io import dump_policy


def starter_policy_template() -> PolicyDocument:
    return PolicyDocument(
        version=1,
        default=DefaultPolicy(decision="PAUSE"),
        rules=[
            Rule(
                name="Example allow rule",
                when=[
                    Condition(path="actor.role", operator="eq", value="trusted"),
                    Condition(path="context.risk_score", operator="lte", value=20),
                ],
                decision="ALLOW",
            ),
            Rule(
                name="Example pause rule",
                when=[
                    Condition(path="action.name", operator="eq", value="change.apply"),
                    Condition(path="context.env", operator="eq", value="prod"),
                ],
                decision="PAUSE",
                obligations=[
                    {
                        "type": "require_approval",
                        "approver_group": "Operators",
                        "reason": "Production changes require approval",
                    }
                ],
            ),
            Rule(
                name="Example block rule",
                when=[
                    Condition(path="action.name", operator="eq", value="data.export"),
                    Condition(path="context.sensitivity", operator="in", value=["PHI", "PII", "CONFIDENTIAL"]),
                ],
                decision="BLOCK",
            ),
        ],
    )


def get_starter_policy() -> PolicyDocument:
    return starter_policy_template()


def render_starter_policy_with_comments() -> str:
    policy_yaml = dump_policy(starter_policy_template()).strip()
    comment_lines = [
        "# SluiceGate starter policy",
        "# Replace these example rules with rules that match your own actors, actions, targets, and context.",
        "# Rules are evaluated top-to-bottom. The first matching rule wins.",
        "# Each rule below shows one possible decision: ALLOW, PAUSE, or BLOCK.",
        "",
        "# Example ALLOW rule: edit or replace to permit low-risk requests.",
        "# Example PAUSE rule: edit or replace to require approval for sensitive requests.",
        "# Example BLOCK rule: edit or replace to deny disallowed requests.",
        "",
    ]
    return "\n".join(comment_lines) + policy_yaml + "\n"
