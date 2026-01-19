from __future__ import annotations

import os
from pathlib import Path
from sg_core import Gate, PolicyEngine, GateRequest


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

    def show_explain(label: str, req: GateRequest, decision_obj) -> None:
        """
        Explain is pure: no audit emission, no side effects.
        It returns a trace of rule/condition evaluation.

        This helper also asserts that evaluate() and explain() agree.
        """
        exp = gate.explain(req)
        print(f"\n[EXPLAIN] {label}")
        print(f"  decision:     {exp.decision}")
        print(f"  policy_hash:  {exp.policy_hash}")
        print(f"  matched_rule: {exp.matched_rule}")
        print(f"  used_default: {exp.used_default}")
        print(f"  obligations:  {[{'type': o.type, **o.data} for o in exp.obligations]}")

        # ---- Regression assertions: evaluate() and explain() must agree ----
        assert exp.decision == decision_obj.decision
        assert exp.policy_hash == decision_obj.policy_hash

        exp_obls = [(o.type, tuple(sorted(o.data.items()))) for o in exp.obligations]
        eval_obls = [(o.type, tuple(sorted(o.data.items()))) for o in decision_obj.obligations]
        assert exp_obls == eval_obls

        # Print per-condition results for the matched rule (keeps output readable)
        if exp.rules:
            matched = next((r for r in exp.rules if r.matched), None)
            if matched:
                print(f"  matched rule conditions ({matched.name}):")
                for c in matched.conditions:
                    print(f"    - {c.path} {c.operator} {c.expected} | actual={c.actual} | passed={c.passed}")


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
    show_explain("High-risk write", high_risk_write, decision_1)

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
    show_explain("Production deploy", deploy_req, decision_2)


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
    show_explain("Small refund", refund_small, decision_3)


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
    show_explain("Large refund", refund_large, decision_4)

    
    # --------------------------------------------------
    # Test 5: Default path (no rule matches -> use default)
    # --------------------------------------------------
    unknown_req = GateRequest(
        actor={"type": "agent", "id": "unknown-agent"},
        action={"name": "system.reboot", "params": {"scope": "single-node"}},
        target={"type": "host", "id": "host-77", "env": "prod"},
        context={"env": "prod", "risk_score": 10},
    )

    decision_5 = gate.evaluate(unknown_req)
    print("\n[TEST] Default-path decision:")
    print(decision_5)

    # This should match your policy default.
    # If your default is PAUSE (as in example-policy.yml), this assertion should hold.
    assert decision_5.decision == "PAUSE"

    exp5 = gate.explain(unknown_req)
    assert exp5.used_default is True
    assert exp5.matched_rule is None

    show_explain("Default path (no rule match)", unknown_req, decision_5)

    print("\nAll policy tests passed ✔️")


if __name__ == "__main__":
    main()
