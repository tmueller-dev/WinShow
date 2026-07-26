"""WSAP/1 — the wire protocol between the WinShow server and the Windows agent.

WSAP is deliberately not MCP. MCP governs the link between an MCP client and this
server; WSAP governs the link between this server and the agent. They are separate
protocols with separate versions, and an agent implementer needs to know nothing about
MCP. See ``docs/adr/0001-reverse-websocket-transport.md``.
"""

from __future__ import annotations

from winshow.wire.envelope import (
    ID_PATTERN,
    WIRE_VERSION,
    Envelope,
    FrameTooLarge,
    MessageType,
    decode_frame,
    encode_frame,
    now_rfc3339,
)
from winshow.wire.messages import IMPLICIT_OPS, REQUESTABLE_OPS, Op

__all__ = [
    "ID_PATTERN",
    "IMPLICIT_OPS",
    "REQUESTABLE_OPS",
    "WIRE_VERSION",
    "Envelope",
    "FrameTooLarge",
    "MessageType",
    "Op",
    "decode_frame",
    "encode_frame",
    "now_rfc3339",
]
