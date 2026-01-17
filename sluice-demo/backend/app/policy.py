from typing import Any, Dict, Literal, Optional
import yaml
import os

Decision = Literal["ALLOW", "PAUSE", "BLOCK"]

class PolicyEngine:
    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policy = self._load()

    def _load(self) -> Dict[str, Any]:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def reload(self) -> None:
        self.policy = self._load()

    def decide(self, ctx: Dict[str, Any]) -> Decision:
        # ctx includes: action, amount, currency, metadata
        rules = self.policy.get("rules", [])
        for rule in rules:
            when = rule.get("when", {})
            if self._match(when, ctx):
                return rule.get("decision", "PAUSE")
        return self.policy.get("default", "PAUSE")

    def _match(self, when: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        if "action" in when and when["action"] != ctx.get("action"):
            return False
        if "currency" in when and str(when["currency"]).lower() != str(ctx.get("currency", "")).lower():
            return False

        amount = int(ctx.get("amount", 0))
        if "amount_lte" in when and amount > int(when["amount_lte"]):
            return False
        if "amount_gte" in when and amount < int(when["amount_gte"]):
            return False
        if "amount_gt" in when and amount <= int(when["amount_gt"]):
            return False
        if "amount_lt" in when and amount >= int(when["amount_lt"]):
            return False

        return True

def default_policy_path() -> str:
    # in docker-compose we mount /policies/policy.yml
    return os.environ.get("POLICY_PATH", "/policies/policy.yml")
