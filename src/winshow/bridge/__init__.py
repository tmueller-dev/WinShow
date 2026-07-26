"""The agent link: one slot, one socket, and the routing between them."""

from __future__ import annotations

from winshow.bridge.bridge import AgentBridge
from winshow.bridge.inflight import InflightRequest, TruncatingBuffer
from winshow.bridge.session import AgentSession, Negotiated, WebSocketLike

__all__ = [
    "AgentBridge",
    "AgentSession",
    "InflightRequest",
    "Negotiated",
    "TruncatingBuffer",
    "WebSocketLike",
]
