from __future__ import annotations
from typing import Any, Dict, List

from .models import Obligation

def parse_obligations(raw: Any) -> List[Obligation]:
    if not raw:
        return []
    out: List[Obligation] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        typ = item.get("type")
        if not typ:
            continue
        data = {k: v for k, v in item.items() if k != "type"}
        out.append(Obligation(type=str(typ), data=data))
    return out
