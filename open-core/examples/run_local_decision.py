from __future__ import annotations

import os
from pathlib import Path

from sluicegate_core import Gate, PolicyEngine, GateRequest

def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    policy_path = os.environ.get("POLICY_PATH", str(repo_root / "policies" / "example-policy.yml"))

    engine = PolicyEngine(policy_path)
    gate = Gate(policy_engine=engine, audit_sink=lambda e: print(f"AUDIT {e['event']} {e.get('summary','')}"))

    req = GateRequest(
        actor={"type": "agent", "id": "agent-123"},
        action={"name": "data.write", "params": {"rows": 1000}},
        target={"type": "database", "id": "prod-main"},
        context={"env": "prod", "risk_score": 75, "sensitivity": "PII"},
    )

    decision = gate.evaluate(req)
    print("\nDecision:")
    print(decision)

if __name__ == "__main__":
    main()
