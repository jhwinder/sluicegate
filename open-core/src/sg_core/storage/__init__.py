"""
Experimental: storage interfaces (no implementations).

Storage covers persistence for:
- stored requests
- pause/resume tokens
- state transitions (PENDING -> EXECUTED/REJECTED/BLOCKED)
"""

from .store import RequestStore, StoreError

__all__ = [
    "RequestStore",
    "StoreError",
]
