from __future__ import annotations

import json
import math
import os
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_FILES = {
    "envelope": "mission-envelope.schema.json",
    "status": "mission-status-event.schema.json",
    "result": "mission-result.schema.json",
}


def protocol_dir() -> Path:
    configured = os.environ.get("SG_PROTOCOL_DIR", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "minion-registry" / "protocol"


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((protocol_dir() / SCHEMA_FILES[name]).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def schema_errors(name: str, instance: Any) -> list[str]:
    """Return sorted 'path: message' strings; an empty list means the instance conforms."""
    errors = sorted(_validator(name).iter_errors(instance), key=lambda error: [str(part) for part in error.absolute_path])
    return [f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}" for error in errors]


def _canonical_string(value: str) -> str:
    # ASCII-only output with lowercase \u escapes; PowerShell must produce byte-identical text.
    return json.dumps(value, ensure_ascii=True)


def _canonical_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("NaN and infinity cannot be signed")
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    text = repr(value)
    # Shortest round-trip digits, always positional so that no exponent form has to be matched.
    return format(Decimal(text), "f") if "e" in text or "E" in text else text


def canonical_json(value: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, ASCII strings, integral numbers without a fraction."""
    parts: list[str] = []

    def encode(item: Any) -> None:
        if item is None:
            parts.append("null")
        elif item is True:
            parts.append("true")
        elif item is False:
            parts.append("false")
        elif isinstance(item, int):
            parts.append(str(item))
        elif isinstance(item, float):
            parts.append(_canonical_float(item))
        elif isinstance(item, str):
            parts.append(_canonical_string(item))
        elif isinstance(item, (list, tuple)):
            parts.append("[")
            for index, element in enumerate(item):
                if index:
                    parts.append(",")
                encode(element)
            parts.append("]")
        elif isinstance(item, dict):
            parts.append("{")
            for index, key in enumerate(sorted(item)):
                if not isinstance(key, str):
                    raise TypeError("Object keys must be strings")
                if index:
                    parts.append(",")
                parts.append(_canonical_string(key))
                parts.append(":")
                encode(item[key])
            parts.append("}")
        else:
            raise TypeError(f"Cannot canonicalize {type(item).__name__}")

    encode(value)
    return "".join(parts).encode("utf-8")
