"""The `/agent` endpoint — where the Windows host dials in.

Normative source: ``docs/03-agent-protocol.md`` §1 (transport, authentication) and §3.1
(the handshake).

The order of operations here is a security property rather than a style choice.
Authentication happens **before** the WebSocket upgrade, so a request with a bad token
costs one HTTP round trip and never reaches the message layer or occupies the agent slot.
Authenticating after the upgrade — as a challenge-response would require — hands an
unauthenticated peer a socket, which is a free denial of service
(`docs/adr/0004-bearer-token-over-hmac-challenge.md`).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import time
from collections import defaultdict, deque
from typing import Any

from starlette.responses import PlainTextResponse, Response
from starlette.websockets import WebSocket, WebSocketDisconnect

from winshow import SERVER_NAME, __version__
from winshow.bridge.bridge import AgentBridge
from winshow.bridge.session import AgentSession, Negotiated
from winshow.config import Settings
from winshow.errors import WinShowError, WireError, WireErrorCode
from winshow.observability.logging import bind_context, get_logger
from winshow.wire.envelope import WIRE_VERSION, Envelope, MessageType, decode_frame, now_rfc3339
from winshow.wire.messages import REQUESTABLE_OPS, HelloRequest, HelloResponse, Op

__all__ = ["SUBPROTOCOL", "HandshakeRateLimiter", "make_agent_endpoint"]

#: §1.2. The agent MUST offer this and the server MUST echo it; anything else means the
#: agent is not talking to a WinShow server.
SUBPROTOCOL = "winshow.v1"

#: §1.3. A stable identifier, 1-64 characters, safe to put in a log line or metric label.
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

SUPPORTED_WIRE_VERSIONS = (WIRE_VERSION,)

log = get_logger(__name__)


class HandshakeRateLimiter:
    """§1.4: after five failures from one source within 60 seconds, answer 429.

    Kept in memory deliberately. The server is a single process by design
    (`docs/07-operations.md` §1), so a shared store would add a dependency to defend a
    single-host deployment against an attacker who already has to guess a 32-byte token.
    """

    def __init__(self, limit: int = 5, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def record_failure(self, source: str) -> None:
        now = time.monotonic()
        bucket = self._failures[source]
        bucket.append(now)
        self._prune(bucket, now)

    def is_limited(self, source: str) -> bool:
        bucket = self._failures.get(source)
        if not bucket:
            return False
        self._prune(bucket, time.monotonic())
        return len(bucket) >= self.limit

    def retry_after(self, source: str) -> int:
        bucket = self._failures.get(source)
        if not bucket:
            return 1
        return max(1, int(self.window - (time.monotonic() - bucket[0])) + 1)

    def clear(self, source: str) -> None:
        self._failures.pop(source, None)

    def _prune(self, bucket: deque[float], now: float) -> None:
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()


def _client_key(websocket: WebSocket) -> str:
    client = websocket.client
    return client.host if client else "unknown"


async def _deny(websocket: WebSocket, response: Response) -> None:
    """Answer the handshake with an HTTP response instead of upgrading.

    Uses the ASGI websocket-denial-response extension. Servers that lack it get a plain
    close instead — the peer then sees a failed upgrade rather than a specific status,
    which is less informative but still unambiguous.
    """
    try:
        await websocket.send_denial_response(response)
    except RuntimeError:
        with contextlib.suppress(Exception):
            await websocket.close(code=4001, reason="unauthenticated")


def _negotiate_version(offered: list[int]) -> int | None:
    """Intersection of the two lists, highest wins (§3.1)."""
    common = [v for v in SUPPORTED_WIRE_VERSIONS if v in offered]
    return max(common) if common else None


def make_agent_endpoint(
    bridge: AgentBridge,
    settings: Settings,
    limiter: HandshakeRateLimiter | None = None,
) -> Any:
    """Build the `/agent` WebSocket handler bound to one bridge."""
    limiter = limiter or HandshakeRateLimiter()

    async def agent_endpoint(websocket: WebSocket) -> None:
        source = _client_key(websocket)

        if limiter.is_limited(source):
            await _deny(
                websocket,
                PlainTextResponse(
                    "Too many failed handshakes.",
                    status_code=429,
                    headers={"Retry-After": str(limiter.retry_after(source))},
                ),
            )
            return

        # -- subprotocol (§1.2) --------------------------------------------------
        offered = [
            value.strip()
            for value in websocket.headers.get("sec-websocket-protocol", "").split(",")
            if value.strip()
        ]
        if SUBPROTOCOL not in offered:
            await _deny(
                websocket,
                PlainTextResponse(
                    f"This endpoint speaks {SUBPROTOCOL!r}.",
                    status_code=400,
                ),
            )
            return

        # -- authentication (§1.4), before the upgrade ---------------------------
        authorization = websocket.headers.get("authorization", "")
        scheme, _, presented = authorization.partition(" ")
        if scheme.lower() != "bearer" or not presented or not settings.token_is_valid(presented):
            limiter.record_failure(source)
            log.warning(
                "agent.unauthenticated",
                extra={"event": "agent.unauthenticated", "source": source},
            )
            await _deny(
                websocket,
                PlainTextResponse(
                    "Unauthenticated.",
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                ),
            )
            return

        agent_id = websocket.headers.get("x-winshow-agent-id", "")
        if not AGENT_ID_PATTERN.match(agent_id):
            await _deny(
                websocket,
                PlainTextResponse(
                    "X-WinShow-Agent-Id must be 1-64 characters of [A-Za-z0-9._-].",
                    status_code=400,
                ),
            )
            return
        if not settings.agent_id_is_allowed(agent_id):
            limiter.record_failure(source)
            log.warning(
                "agent.id_not_allowed",
                extra={"event": "agent.id_not_allowed", "agent_id": agent_id, "source": source},
            )
            await _deny(websocket, PlainTextResponse("Agent id not permitted.", status_code=403))
            return

        limiter.clear(source)
        await websocket.accept(subprotocol=SUBPROTOCOL)

        session_id = f"s-{secrets.token_hex(4)}"
        with bind_context(session_id=session_id, agent_id=agent_id):
            await _run_session(websocket, bridge, settings, session_id, agent_id)

    return agent_endpoint


async def _await_hello(websocket: WebSocket, settings: Settings) -> Envelope | None:
    """Read frames until `session.hello` arrives, or the 10-second window closes (§3.1)."""
    deadline = settings.hello_timeout_ms / 1000
    try:
        message = await asyncio.wait_for(websocket.receive(), timeout=deadline)
    except TimeoutError:
        return None
    if message.get("type") != "websocket.receive":
        return None
    raw = message.get("text")
    if raw is None:
        return None
    return decode_frame(raw, settings.max_frame_bytes)


async def _run_session(
    websocket: WebSocket,
    bridge: AgentBridge,
    settings: Settings,
    session_id: str,
    agent_id: str,
) -> None:
    try:
        envelope = await _await_hello(websocket, settings)
    except WinShowError as exc:
        await websocket.close(code=1002, reason=exc.code)
        return

    if envelope is None:
        # §1.8, code 4008: no hello within the window.
        log.warning("agent.hello_timeout", extra={"event": "agent.hello_timeout"})
        await websocket.close(code=4008, reason="hello timeout")
        return

    if envelope.t is not MessageType.REQ or envelope.op != Op.SESSION_HELLO:
        await websocket.close(code=4008, reason="first message must be session.hello")
        return

    try:
        hello = HelloRequest.model_validate(envelope.p or {})
    except Exception as exc:
        await _send_error(
            websocket,
            envelope.id or "h-1",
            Op.SESSION_HELLO,
            WireErrorCode.INVALID_ARGUMENT,
            f"Malformed session.hello payload: {exc}",
        )
        await websocket.close(code=1002, reason="malformed hello")
        return

    # §3.1: the handshake `agentId` MUST equal the header. They are two statements of
    # the same fact, and a mismatch means one of them is not to be trusted.
    if hello.agent_id != agent_id:
        await _send_error(
            websocket,
            envelope.id or "h-1",
            Op.SESSION_HELLO,
            WireErrorCode.INVALID_ARGUMENT,
            "agentId in session.hello does not match the X-WinShow-Agent-Id header.",
        )
        await websocket.close(code=1002, reason="agent id mismatch")
        return

    wire_version = _negotiate_version(hello.wire_versions)
    if wire_version is None:
        await _send_error(
            websocket,
            envelope.id or "h-1",
            Op.SESSION_HELLO,
            WireErrorCode.INCOMPATIBLE_VERSION,
            f"No common wire version. This server speaks {list(SUPPORTED_WIRE_VERSIONS)}, "
            f"the agent offered {hello.wire_versions}.",
        )
        await websocket.close(code=4004, reason="incompatible version")
        return

    # Each negotiated limit is the minimum of the two offers: a cap either side cannot
    # honour is not a cap.
    negotiated = Negotiated(
        wire_version=wire_version,
        max_frame_bytes=min(hello.limits.max_frame_bytes, settings.max_frame_bytes),
        ack_window_chunks=min(hello.limits.ack_window_chunks, settings.ack_window_chunks),
        ack_window_bytes=min(hello.limits.ack_window_bytes, settings.ack_window_bytes),
        heartbeat_interval_ms=settings.heartbeat_interval_ms,
        # §11.2 rule 5: never send an op the agent did not advertise. Intersecting here
        # means a capability the server does not know about is simply unused rather than
        # producing a runtime surprise.
        enabled_ops=sorted(set(hello.capabilities) & REQUESTABLE_OPS),
    )

    response = HelloResponse(
        wireVersion=wire_version,
        sessionId=session_id,
        server={"name": SERVER_NAME, "version": __version__},
        serverTime=now_rfc3339(),
        heartbeatIntervalMs=negotiated.heartbeat_interval_ms,
        maxFrameBytes=negotiated.max_frame_bytes,
        ackWindowChunks=negotiated.ack_window_chunks,
        ackWindowBytes=negotiated.ack_window_bytes,
        enabledOps=negotiated.enabled_ops,
    )
    await websocket.send_text(
        Envelope.response(envelope.id or "h-1", Op.SESSION_HELLO, response.wire()).to_json()
    )

    session = AgentSession(
        websocket,
        session_id=session_id,
        agent_id=agent_id,
        hello=hello,
        negotiated=negotiated,
        settings=settings,
    )
    await bridge.attach(session)
    try:
        await session.serve()
    except WebSocketDisconnect:
        pass
    finally:
        await bridge.detach(session)


async def _send_error(
    websocket: WebSocket,
    message_id: str,
    op: str,
    code: WireErrorCode,
    message: str,
) -> None:
    with contextlib.suppress(Exception):
        await websocket.send_text(
            Envelope.error(message_id, op, WireError.of(code, message)).to_json()
        )
