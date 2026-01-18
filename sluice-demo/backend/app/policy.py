from typing import Any, Dict, Literal
import yaml
import os
import hashlib

Decision = Literal["ALLOW", "PAUSE", "BLOCK"]


class PolicyEngine:


    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policy: Dict[str, Any] = {}
        self.policy_hash: str = ""
        self.reload()

    def _load(self) -> Dict[str, Any]:
        # Read bytes so the hash matches the actual on-disk policy
        with open(self.policy_path, "rb") as f:
            raw = f.read()
        self.policy_hash = hashlib.sha256(raw).hexdigest()
        return yaml.safe_load(raw.decode("utf-8"))

    def reload(self) -> None:
        self.policy = self._load()

    def decide(self, ctx: Dict[str, Any]) -> Decision:
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
    return os.environ.get("POLICY_PATH", "/policies/policy.yml")


def short_hash(full_hash: str, length: int = 8) -> str:
    if not full_hash:
        return ""
    return f"{full_hash[:length]}.."