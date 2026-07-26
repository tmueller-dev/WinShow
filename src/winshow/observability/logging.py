"""Structured logging, with the correlation property that makes it worth having.

``docs/02-architecture.md`` §9.1: the MCP request identifier, WinShow's internal request
identifier and the agent's session identifier appear together on every line touching a
call, so a **single search reconstructs it end to end** across two protocols and two
machines. That is the whole point of the format; the JSON is incidental.

Correlation values are carried in context variables rather than threaded through every
signature, because the call path crosses an ASGI handler, a tool function, the bridge and
a WebSocket receive loop, and threading an identifier through all of that reliably is not
realistic.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "JsonFormatter",
    "RedactingFilter",
    "bind_context",
    "configure_logging",
    "current_context",
    "get_logger",
]

# -- correlation context -----------------------------------------------------

# The default is None rather than {} so the one dict is not shared across every context
# that never binds anything.
_context: ContextVar[dict[str, Any] | None] = ContextVar("winshow_log_context", default=None)


@contextmanager
def bind_context(**fields: Any) -> Iterator[None]:
    """Add correlation fields to every log line emitted inside the block.

    Nested binds merge rather than replace, so an outer `mcp_request_id` survives an
    inner bind that only knows the WSAP `request_id`.
    """
    merged = {**(_context.get() or {}), **{k: v for k, v in fields.items() if v is not None}}
    token: Token[dict[str, Any] | None] = _context.set(merged)
    try:
        yield
    finally:
        _context.reset(token)


def current_context() -> dict[str, Any]:
    return dict(_context.get() or {})


# -- redaction ---------------------------------------------------------------

#: Keys whose values never appear in a log at any level (NFR-12). The agent's bearer
#: token is the specific thing the specification names, but anything shaped like a
#: credential is treated the same way — a leak is permanent and a redaction is cheap.
_SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|authorization|credential|_key$|apikey)", re.I
)

#: `Authorization: Bearer <token>` embedded in a free-text message.
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+/=]{8,}")

REDACTED = "[redacted]"


def _redact_value(key: str, value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return value
    if isinstance(value, dict):
        return {k: _redact_value(k, v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, v, depth + 1) for v in value]
    if _SECRET_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return _BEARER.sub(rf"\1{REDACTED}", value)
    return value


class RedactingFilter(logging.Filter):
    """Strips credentials from both the message and the structured fields.

    Implemented as a filter rather than inside the formatter so it applies whatever
    handler or formatter a deployment substitutes.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _BEARER.sub(rf"\1{REDACTED}", record.msg)
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED:
                continue
            record.__dict__[key] = _redact_value(key, value)
        return True


# Attributes the stdlib puts on every record. Everything else is a structured field the
# call site supplied via `extra=`.
_RESERVED = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs", "msg", "message", "name",
        "pathname", "process", "processName", "relativeCreated", "stack_info",
        "stacklevel", "thread", "threadName", "taskName",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, sharing its schema with the agent's own log."""

    def format(self, record: logging.LogRecord) -> str:
        moment = datetime.fromtimestamp(record.created, UTC)
        payload: dict[str, Any] = {
            "ts": f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
        }
        message = record.getMessage()
        if message != payload["event"]:
            payload["msg"] = message

        payload.update(current_context())
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key != "event":
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable output for an operator watching a console."""

    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record)} {record.levelname:<7} {record.name} " \
               f"{getattr(record, 'event', record.getMessage())}"
        fields = {**current_context()}
        fields.update(
            {k: v for k, v in record.__dict__.items() if k not in _RESERVED and k != "event"}
        )
        if fields:
            base += " " + " ".join(f"{k}={v}" for k, v in fields.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Install the formatter and the redaction filter on the root logger."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn installs its own handlers; letting them through would produce two formats
    # in one stream, which defeats machine parsing.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(noisy)
        logger.handlers.clear()
        logger.propagate = True


def get_logger(name: str) -> logging.Logger:
    """Return a standard logger.

    Call sites pass structured fields through ``extra=``; the formatter merges them with
    the correlation context. Field names must avoid the stdlib's reserved record
    attributes — notably ``message``, ``module`` and ``name``.
    """
    return logging.getLogger(name)
