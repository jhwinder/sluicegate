"""
Experimental: audit interfaces.

Audit sinks are where decisions and outcomes are emitted.
Implementations can write to memory, stdout, files, SIEM, etc.
"""

from .sink import AuditSink, CompositeAuditSink

__all__ = [
    "AuditSink",
    "CompositeAuditSink",
]
