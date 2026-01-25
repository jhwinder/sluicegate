"""
Experimental: request storage contracts.

The demo can use in-memory storage, but real deployments will want
SQLite/Postgres/Redis/etc. This interface creates that seam cleanly.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class StoreError(RuntimeError):
    pass


@runtime_checkable
class RequestStore(Protocol):
    """
    Contract for storing and retrieving requests.

    This intentionally uses `Dict[str, Any]` payloads to avoid coupling
    the storage layer to a specific model library (pydantic/dataclasses).
    """

    def put(self, request: Dict[str, Any]) -> None:
        """Insert a new request (must include request_id)."""
        ...

    def get(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a request by id."""
        ...

    def update(self, request_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a partial update and return the updated request.
        Should raise StoreError if missing.
        """
        ...

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List most recent requests (implementation-defined ordering)."""
        ...

    def find_by_resume_token(self, resume_token: str) -> Optional[Dict[str, Any]]:
        """Lookup request by resume token (used for PAUSE resume)."""
        ...
