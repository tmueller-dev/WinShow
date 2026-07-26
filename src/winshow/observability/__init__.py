"""Structured logging, metrics and the audit trail.

Grouped together because they answer three versions of one operational question — what
is happening now, what has been happening, and what was asked for and by whom — and
because they share the correlation identifiers that make any of them useful.
"""

from __future__ import annotations

from winshow.observability.audit import AuditLog
from winshow.observability.logging import bind_context, configure_logging, get_logger
from winshow.observability.metrics import (
    REGISTRY,
    metrics_app,
    record_bytes,
    record_denial,
    record_reconnect,
    record_request,
    record_rtt,
    record_truncation,
    set_agent_connected,
    set_exec_running,
    set_inflight,
)

__all__ = [
    "REGISTRY",
    "AuditLog",
    "bind_context",
    "configure_logging",
    "get_logger",
    "metrics_app",
    "record_bytes",
    "record_denial",
    "record_reconnect",
    "record_request",
    "record_rtt",
    "record_truncation",
    "set_agent_connected",
    "set_exec_running",
    "set_inflight",
]
