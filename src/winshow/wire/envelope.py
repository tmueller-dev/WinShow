"""The WSAP/1 message envelope and its frame codec.

Normative source: ``docs/03-agent-protocol.md`` §2, with the machine-readable companion
in ``docs/schemas/wsap-v1-envelope.schema.json``.

One JSON object per WebSocket text frame, UTF-8. WebSocket already provides message
framing, so there is deliberately no second framing layer inside a frame: a conforming
receiver's entire parsing logic is a single ``json.loads``.

Forward compatibility is a hard requirement here (§11.1). Unknown fields at any nesting
depth are ignored rather than rejected, so a v1 receiver keeps working against a newer
v1 peer that has added optional fields. The sole exceptions are ``t`` and ``w``, which
are structural: an unknown value there is fatal for that message and nothing else.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from winshow.errors import WinShowError, WireError, WireErrorCode

__all__ = [
    "WIRE_VERSION",
    "MessageType",
    "Envelope",
    "ID_PATTERN",
    "decode_frame",
    "encode_frame",
    "now_rfc3339",
    "FrameTooLarge",
]

WIRE_VERSION: Final[int] = 1

#: Correlation identifiers are 1–64 characters of `[A-Za-z0-9._-]` (§2.2). The
#: constraint exists so an identifier is always safe to put in a log line or a metric
#: label without escaping.
ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class MessageType(StrEnum):
    REQ = "req"
    RES = "res"
    ERR = "err"
    EVT = "evt"


def now_rfc3339() -> str:
    """An RFC 3339 UTC timestamp with milliseconds, as every `ts` field must be.

    NFR-13: timestamps cross the wire as strings, never as raw 64-bit tick values,
    which a JSON number cannot carry safely.
    """
    # One clock read, not two: sampling twice can straddle a millisecond boundary and
    # emit a timestamp whose fractional part belongs to a different second.
    moment = datetime.now(UTC)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


class FrameTooLarge(WinShowError):
    """A frame exceeded the negotiated maximum (§1.7).

    The peer must be closed with WebSocket code 1009. Sending ``err FRAME_TOO_LARGE``
    first is a SHOULD rather than a MUST, because most WebSocket stacks abort an
    oversized message at the frame layer and never deliver any application bytes — so
    the correlation identifier is simply not available to name.
    """

    def __init__(self, size: int, limit: int, message_id: str | None = None) -> None:
        super().__init__(
            WireErrorCode.FRAME_TOO_LARGE,
            f"Frame of {size} bytes exceeds the negotiated maximum of {limit} bytes.",
            details={"size": size, "limit": limit},
        )
        self.size = size
        self.limit = limit
        self.message_id = message_id


class Envelope(BaseModel):
    """One WSAP/1 message.

    ``extra="allow"`` is not laxness; it is §11.1 rule 1 expressed in the type system.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    w: int = WIRE_VERSION
    t: MessageType
    id: str | None = None
    corr: str | None = None
    seq: int | None = None
    op: str | None = None
    ts: str | None = None
    trace: str | None = None
    p: dict[str, Any] | None = None
    e: WireError | None = None

    @field_validator("w")
    @classmethod
    def _known_wire_version(cls, v: int) -> int:
        # §2.2: a receiver MUST reject an unknown `w`. Structural, so fatal.
        if v != WIRE_VERSION:
            raise ValueError(f"unsupported wire version {v!r}; this build speaks {WIRE_VERSION}")
        return v

    @field_validator("id", "corr")
    @classmethod
    def _well_formed_id(cls, v: str | None) -> str | None:
        if v is not None and not ID_PATTERN.match(v):
            raise ValueError(f"identifier {v!r} is not 1-64 chars of [A-Za-z0-9._-]")
        return v

    @field_validator("seq")
    @classmethod
    def _non_negative_seq(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("seq must be zero or positive")
        return v

    def model_post_init(self, _context: Any, /) -> None:
        # Per-type structural requirements from the §2.2 presence column. These are
        # checked here rather than as separate models because the four message types
        # share one envelope on the wire and a receiver must decide the type first.
        if self.t in (MessageType.REQ, MessageType.RES, MessageType.ERR):
            if self.id is None:
                raise ValueError(f"{self.t} message requires an 'id'")
        if self.t is MessageType.EVT:
            if self.corr is None:
                raise ValueError("evt message requires a 'corr'")
            if self.seq is None:
                raise ValueError("evt message requires a 'seq'")
        if self.t in (MessageType.REQ, MessageType.EVT) and not self.op:
            raise ValueError(f"{self.t} message requires an 'op'")
        if self.t is MessageType.ERR:
            if self.e is None:
                raise ValueError("err message requires an 'e'")
        elif self.p is None:
            # §2.2: `p` MAY be {} but MUST be present and MUST be an object.
            raise ValueError(f"{self.t} message requires a 'p' object")

    # -- constructors ------------------------------------------------------------

    @classmethod
    def request(
        cls, id: str, op: str, payload: dict[str, Any] | None = None, *, trace: str | None = None
    ) -> Envelope:
        return cls(t=MessageType.REQ, id=id, op=op, p=payload or {}, ts=now_rfc3339(), trace=trace)

    @classmethod
    def response(cls, id: str, op: str | None, payload: dict[str, Any]) -> Envelope:
        return cls(t=MessageType.RES, id=id, op=op, p=payload, ts=now_rfc3339())

    @classmethod
    def error(cls, id: str, op: str | None, error: WireError) -> Envelope:
        return cls(t=MessageType.ERR, id=id, op=op, e=error, ts=now_rfc3339())

    @classmethod
    def event(cls, corr: str, seq: int, op: str, payload: dict[str, Any]) -> Envelope:
        return cls(t=MessageType.EVT, corr=corr, seq=seq, op=op, p=payload, ts=now_rfc3339())

    def to_json(self) -> str:
        # `by_alias` matters: WireError carries `class`, which is a Python keyword and
        # therefore aliased. `exclude_none` keeps absent optional fields off the wire
        # rather than sending explicit nulls a peer would have to ignore.
        return self.model_dump_json(by_alias=True, exclude_none=True)


def encode_frame(envelope: Envelope, max_frame_bytes: int | None = None) -> str:
    """Serialise `envelope`, refusing to emit a frame the peer has said it will not accept.

    Checked on the sending side as well as the receiving side because the alternative is
    discovering the violation as a 1009 close, which loses the connection and every
    other request multiplexed onto it.
    """
    text = envelope.to_json()
    if max_frame_bytes is not None:
        size = len(text.encode("utf-8"))
        if size > max_frame_bytes:
            raise FrameTooLarge(size, max_frame_bytes, envelope.id or envelope.corr)
    return text


def decode_frame(raw: str | bytes, max_frame_bytes: int | None = None) -> Envelope:
    """Parse one frame into an `Envelope`.

    Raises `FrameTooLarge` when the frame is over the negotiated cap, and
    `WinShowError(MALFORMED_MESSAGE)` when the bytes are not a well-formed WSAP/1
    message. Binary frames are rejected by the caller: §1.7 reserves them for a future
    wire version, and a v1 receiver MUST NOT accept them.
    """
    if isinstance(raw, bytes):
        # Reached only if a caller hands us bytes deliberately; the endpoint rejects
        # binary frames before this point.
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WinShowError(
                WireErrorCode.MALFORMED_MESSAGE, "Frame is not valid UTF-8."
            ) from exc

    if max_frame_bytes is not None:
        size = len(raw.encode("utf-8"))
        if size > max_frame_bytes:
            raise FrameTooLarge(size, max_frame_bytes)

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WinShowError(
            WireErrorCode.MALFORMED_MESSAGE, f"Frame is not valid JSON: {exc.msg}."
        ) from exc

    if not isinstance(obj, dict):
        raise WinShowError(
            WireErrorCode.MALFORMED_MESSAGE,
            f"Frame must be a JSON object, got {type(obj).__name__}.",
        )

    try:
        return Envelope.model_validate(obj)
    except ValidationError as exc:
        # Surface the first problem only. The whole message is being rejected either
        # way, and a wall of validation detail in a log line helps nobody.
        first = exc.errors()[0]
        location = ".".join(str(p) for p in first["loc"]) or "<root>"
        raise WinShowError(
            WireErrorCode.MALFORMED_MESSAGE,
            f"Malformed envelope at {location}: {first['msg']}.",
            details={"field": location},
        ) from exc
