from typing import Dict, Any
import os

# For Day 1 we do a stubbed connector so the flow is proven end-to-end.
# Swap this for real Stripe test mode later.
def stripe_charge_stub(amount: int, currency: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "connector": "stripe_stub",
        "ok": True,
        "amount": amount,
        "currency": currency,
        "metadata": metadata,
        "charge_id": "ch_test_stub_123",
    }

def execute_action(action: str, amount: int, currency: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    if action == "stripe.charge":
        # future: if STRIPE_SECRET_KEY exists, use real stripe sdk
        return stripe_charge_stub(amount, currency, metadata)
    return {"ok": False, "error": f"Unknown action '{action}'"}
