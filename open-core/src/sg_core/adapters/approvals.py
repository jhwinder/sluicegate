"""
Experimental: approval adapter contracts.

This is the interface seam for PAUSE + human approval workflows.
Keep this module interface-only in open-core.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Protocol, runtime_checkable


class ApprovalDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


@dataclass(frozen=True)
class ApprovalRequest:
    """
    A structured request for human approval.

    Minimal, generic fields so the same adapter can be used across:
      - Stripe refunds
      - infrastructure changes
      - data exports
      - destructive tool calls
    """
    request_id: str
    action_name: str
    summary: str
    details: Dict[str, Any]
    approve_url: str
    reject_url: str
    reason: Optional[str] = None
    approver_group: Optional[str] = None


@runtime_checkable
class ApprovalAdapter(Protocol):
    """
    Adapter that can notify humans and deliver approve/reject links.

    Implementations can be in:
      - demo (email)
      - separate OSS packages (slack)
      - paid SDK packages
      - enterprise deployments
    """

    name: str

    def send(self, approval: ApprovalRequest) -> None:
        """Send an approval request to the appropriate channel."""
        ...
