"""The WSAP/1 error taxonomy, and its projection onto the MCP tool surface.

Normative sources:

* wire codes, classes and retryability — ``docs/03-agent-protocol.md`` §7.2
* server-originated codes — ``docs/05-mcp-tool-surface.md`` §1.5
* how a class maps onto MCP — ``docs/02-architecture.md`` §8.4

Two rules from those documents are load-bearing enough to restate here, because every
call site depends on them:

* ``POLICY_DENIED`` is **never** retryable. It will not become an allow by trying again,
  and marking it retryable invites a model to churn through variants of a path.
* A command exiting non-zero is **not** an error at all. It is a successful tool call
  carrying a non-zero ``exit_code``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ErrorClass",
    "WireErrorCode",
    "ServerErrorCode",
    "WireError",
    "WinShowError",
    "AgentUnavailable",
    "AgentDisconnected",
    "AgentSuperseded",
    "AgentTimeout",
    "AgentProtocolError",
    "classify",
    "is_retryable",
]


class ErrorClass(StrEnum):
    """The `class` member of a wire error object (§7.1)."""

    TRANSPORT = "transport"
    AUTH = "auth"
    POLICY = "policy"
    OS = "os"
    LIMIT = "limit"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INTERNAL = "internal"
    ARGUMENT = "argument"


class WireErrorCode(StrEnum):
    """Codes that can appear on the WSAP wire (§7.2).

    The enumeration is **append-only**: a published code never changes meaning and is
    never removed.
    """

    UNAUTHENTICATED = "UNAUTHENTICATED"
    INCOMPATIBLE_VERSION = "INCOMPATIBLE_VERSION"
    SUPERSEDED = "SUPERSEDED"
    MALFORMED_MESSAGE = "MALFORMED_MESSAGE"
    FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    IS_A_DIRECTORY = "IS_A_DIRECTORY"
    NOT_A_DIRECTORY = "NOT_A_DIRECTORY"
    INVALID_PATH = "INVALID_PATH"
    PATH_TOO_LONG = "PATH_TOO_LONG"
    SHARING_VIOLATION = "SHARING_VIOLATION"
    DISK_FULL = "DISK_FULL"
    IO_ERROR = "IO_ERROR"
    EXEC_NOT_FOUND = "EXEC_NOT_FOUND"
    SPAWN_FAILED = "SPAWN_FAILED"
    ENCODING_ERROR = "ENCODING_ERROR"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    AGENT_BUSY = "AGENT_BUSY"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ServerErrorCode(StrEnum):
    """Codes the server surfaces to MCP clients that never appear on the wire.

    They describe the state of the *link to the agent*, which is a thing only the server
    can observe.
    """

    AGENT_UNAVAILABLE = "AGENT_UNAVAILABLE"
    AGENT_DISCONNECTED = "AGENT_DISCONNECTED"
    AGENT_SUPERSEDED = "AGENT_SUPERSEDED"
    AGENT_TIMEOUT = "AGENT_TIMEOUT"
    AGENT_PROTOCOL_ERROR = "AGENT_PROTOCOL_ERROR"


# (class, retryable) for every code. Kept as one table so the two properties cannot
# drift apart, and so an unknown code has exactly one documented fallback.
_TAXONOMY: Final[dict[str, tuple[ErrorClass, bool]]] = {
    WireErrorCode.UNAUTHENTICATED: (ErrorClass.AUTH, False),
    WireErrorCode.INCOMPATIBLE_VERSION: (ErrorClass.AUTH, False),
    WireErrorCode.SUPERSEDED: (ErrorClass.TRANSPORT, False),
    WireErrorCode.MALFORMED_MESSAGE: (ErrorClass.TRANSPORT, False),
    WireErrorCode.FRAME_TOO_LARGE: (ErrorClass.TRANSPORT, False),
    WireErrorCode.UNSUPPORTED_OPERATION: (ErrorClass.ARGUMENT, False),
    WireErrorCode.NOT_IMPLEMENTED: (ErrorClass.ARGUMENT, False),
    WireErrorCode.INVALID_ARGUMENT: (ErrorClass.ARGUMENT, False),
    WireErrorCode.POLICY_DENIED: (ErrorClass.POLICY, False),
    WireErrorCode.POLICY_UNAVAILABLE: (ErrorClass.POLICY, False),
    WireErrorCode.NOT_FOUND: (ErrorClass.OS, False),
    WireErrorCode.ACCESS_DENIED: (ErrorClass.OS, False),
    WireErrorCode.IS_A_DIRECTORY: (ErrorClass.OS, False),
    WireErrorCode.NOT_A_DIRECTORY: (ErrorClass.OS, False),
    WireErrorCode.INVALID_PATH: (ErrorClass.OS, False),
    WireErrorCode.PATH_TOO_LONG: (ErrorClass.OS, False),
    WireErrorCode.SHARING_VIOLATION: (ErrorClass.OS, True),
    WireErrorCode.DISK_FULL: (ErrorClass.OS, False),
    WireErrorCode.IO_ERROR: (ErrorClass.OS, True),
    WireErrorCode.EXEC_NOT_FOUND: (ErrorClass.OS, False),
    WireErrorCode.SPAWN_FAILED: (ErrorClass.OS, False),
    WireErrorCode.ENCODING_ERROR: (ErrorClass.ARGUMENT, False),
    WireErrorCode.RESOURCE_EXHAUSTED: (ErrorClass.LIMIT, True),
    WireErrorCode.AGENT_BUSY: (ErrorClass.LIMIT, True),
    WireErrorCode.TIMEOUT: (ErrorClass.TIMEOUT, True),
    WireErrorCode.CANCELLED: (ErrorClass.CANCELLED, False),
    WireErrorCode.INTERNAL_ERROR: (ErrorClass.INTERNAL, False),
    # Server-originated. All but the protocol error are transient link conditions.
    ServerErrorCode.AGENT_UNAVAILABLE: (ErrorClass.TRANSPORT, True),
    ServerErrorCode.AGENT_DISCONNECTED: (ErrorClass.TRANSPORT, True),
    ServerErrorCode.AGENT_SUPERSEDED: (ErrorClass.TRANSPORT, True),
    ServerErrorCode.AGENT_TIMEOUT: (ErrorClass.TRANSPORT, True),
    ServerErrorCode.AGENT_PROTOCOL_ERROR: (ErrorClass.TRANSPORT, False),
}


def classify(code: str) -> ErrorClass:
    """Return the class of `code`.

    §7.4: a receiver encountering an unknown code MUST treat it as ``internal``. That is
    a forward-compatibility rule — a newer agent may send a code this build predates —
    so an unknown code is deliberately not an error.
    """
    known = _TAXONOMY.get(code)
    return known[0] if known else ErrorClass.INTERNAL


def is_retryable(code: str) -> bool:
    """Return whether an identical retry of `code` could plausibly succeed.

    Unknown codes are **not** retryable (§7.4). Guessing the other way would have the
    server retry something it does not understand.
    """
    known = _TAXONOMY.get(code)
    return known[1] if known else False


class WireError(BaseModel):
    """The `e` member of an ``err`` message (§7.1)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    code: str
    cls: ErrorClass = Field(alias="class")
    retryable: bool
    message: str
    rule: str | None = None
    win_error: int | None = Field(default=None, alias="winError")
    win_error_name: str | None = Field(default=None, alias="winErrorName")
    # Left as None rather than {} so an error with nothing to add does not put an empty
    # object on the wire that a peer has to distinguish from "no details".
    details: dict[str, Any] | None = None

    @classmethod
    def of(
        cls,
        code: WireErrorCode | ServerErrorCode | str,
        message: str,
        **extra: Any,
    ) -> WireError:
        """Build an error whose class and retryability come from the one table."""
        code = str(code)
        return cls.model_validate(
            {
                "code": code,
                "class": classify(code),
                "retryable": is_retryable(code),
                "message": message,
                **extra,
            }
        )


class WinShowError(Exception):
    """An error carrying a wire-shaped payload.

    Raised anywhere in the server that wants to fail a tool call with a specific code.
    The tool layer turns it into the ``{"ok": false, "error": {...}}`` envelope.
    """

    def __init__(
        self,
        code: WireErrorCode | ServerErrorCode | str,
        message: str,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.error = WireError.of(code, message, **extra)

    @property
    def code(self) -> str:
        return self.error.code

    @property
    def retryable(self) -> bool:
        return self.error.retryable


class AgentUnavailable(WinShowError):
    """No agent is connected — the Windows host has not dialled in."""

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(ServerErrorCode.AGENT_UNAVAILABLE, message, **extra)


class AgentDisconnected(WinShowError):
    """The agent went away while this request was in flight."""

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(ServerErrorCode.AGENT_DISCONNECTED, message, **extra)


class AgentSuperseded(WinShowError):
    """A newer agent connection replaced the one carrying this request."""

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(ServerErrorCode.AGENT_SUPERSEDED, message, **extra)


class AgentTimeout(WinShowError):
    """The agent did not answer within its own advertised timeout plus a margin.

    Distinct from wire ``TIMEOUT``: this one means the *agent* is misbehaving, and
    §8.6 requires the server to log it at WARN rather than paper over it.
    """

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(ServerErrorCode.AGENT_TIMEOUT, message, **extra)


class AgentProtocolError(WinShowError):
    """The agent sent something malformed or violated an ordering rule.

    The canonical trigger is a gap in an event `seq` (§8.2): output was lost, and a
    result with a hole in it is worse than an error.
    """

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(ServerErrorCode.AGENT_PROTOCOL_ERROR, message, **extra)
