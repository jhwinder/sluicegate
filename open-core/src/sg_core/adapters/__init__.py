"""
Experimental: adapter interfaces.

Adapters translate obligations into real-world side effects, e.g.:
- send approval emails
- post to Slack
- open a ticket

Core emits obligations; adapters fulfill them.
"""

from .approvals import ApprovalAdapter, ApprovalRequest, ApprovalDecision

__all__ = [
    "ApprovalAdapter",
    "ApprovalRequest",
    "ApprovalDecision",
]
