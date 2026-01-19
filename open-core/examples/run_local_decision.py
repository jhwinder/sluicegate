from __future__ import annotations

import os
from pathlib import Path
from sluicegate_core import Gate, PolicyEngine, GateRequest


def main() -> None:
    # --------------------------------------------------
    # Setup (one-time)
    # --------------------------------------------------
    repo_root = Path(__file__).resolve().parents[1]
    policy_path = os.environ.get(
        "POLICY_PATH",
        str(repo_root / "policies" / "example-policy.yml"),
    )

    engine = PolicyEngine(policy_path)
    gate = Gate(
        policy_engine=engine,
        audit_sink=lambda e: print(f"AUDIT {e['event']} {e.get('summary','')}")
    )

    print("\n=== SluiceGate Open Core – Policy Test Harness ===")

    # --------------------------------------------------
    # Test 1: High-risk write to prod 
    # --------------------------------------------------
    high_risk_write = GateRequest(
        actor={"type": "agent", "id": "agent-123"},
        action={"name": "data.write", "params": {"rows": 1000}},
        target={"type": "database", "id": "prod-main", "env": "prod"},
        context={"env": "prod", "risk_score": 75, "sensitivity": "PII"},
    )

    decision_1 = gate.evaluate(high_risk_write)
    print("\n[TEST] High-risk write decision:")
    print(decision_1)

    assert decision_1.decision == "PAUSE"

    # --------------------------------------------------
    # Test 2: Production code deploy
    # --------------------------------------------------
    deploy_req = GateRequest(
        actor={"type": "agent", "id": "ci-cd-bot", "role": "automation"},
        action={"name": "code.deploy", "params": {"service": "api", "version": "1.7.3"}},
        target={"type": "service", "id": "api", "env": "prod"},
        context={"env": "prod", "risk_score": 55},
    )

    decision_2 = gate.evaluate(deploy_req)
    print("\n[TEST] Production deploy decision:")
    print(decision_2)

    assert decision_2.decision == "PAUSE"
    assert any(
        o.type == "require_approval" and o.data.get("approver_group") == "ReleaseManagers"
        for o in decision_2.obligations
    )

    # --------------------------------------------------
    # Test 3: Small refund (ALLOW)
    # --------------------------------------------------
    refund_small = GateRequest(
        actor={"type": "service", "id": "support-tool", "role": "customer_support"},
        action={
            "name": "payments.refund",
            "params": {"amount": 50, "currency": "USD", "customer_id": "cus_001"},
        },
        target={"type": "customer", "id": "cus_001"},
        context={"env": "prod", "risk_score": 20},
    )

    decision_3 = gate.evaluate(refund_small)
    print("\n[TEST] Small refund decision:")
    print(decision_3)

    assert decision_3.decision == "ALLOW"
    assert len(decision_3.obligations) == 0

    # --------------------------------------------------
    # Test 4: Large refund (PAUSE)
    # --------------------------------------------------
    refund_large = GateRequest(
        actor={"type": "service", "id": "support-tool", "role": "customer_support"},
        action={
            "name": "payments.refund",
            "params": {"amount": 250, "currency": "USD", "customer_id": "cus_001"},
        },
        target={"type": "customer", "id": "cus_001"},
        context={"env": "prod", "risk_score": 40},
    )

    decision_4 = gate.evaluate(refund_large)
    print("\n[TEST] Large refund decision:")
    print(decision_4)

    assert decision_4.decision == "PAUSE"
    assert any(
        o.type == "require_approval" and o.data.get("approver_group") == "Finance"
        for o in decision_4.obligations
    )

    print("\nAll policy tests passed ✔️")


if __name__ == "__main__":
    main()
