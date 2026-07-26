"""An in-process WSAP/1 agent, for driving the server without a Windows host.

This is the test harness the conformance vectors run against. It speaks the protocol
rather than mocking the bridge, so a test exercises the real codec, the real correlation
table, the real sequence checking and the real acknowledgement pump.

It is deliberately *not* a reference agent: it fakes the filesystem and the process
layer entirely. What it implements faithfully is the wire contract.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections.abc import Awaitable, Callable
from typing import Any

from winshow.bridge.session import AgentSession, Negotiated
from winshow.config import Settings
from winshow.errors import WireError
from winshow.wire.envelope import Envelope, MessageType, decode_frame
from winshow.wire.messages import HelloRequest, Op

__all__ = ["FakeAgent", "FakeWebSocket", "connected_session", "make_hello"]

Handler = Callable[[str, dict[str, Any]], Awaitable[Any] | Any]

#: Distinct session ids, so a test that attaches two agents can tell them apart.
_session_counter = itertools.count(1)


class FakeWebSocket:
    """A duplex pair with the same surface as Starlette's `WebSocket`.

    `send_text` is what the *server* writes; the agent reads it from `outbound`. The
    agent's own frames go in through `deliver`, which the server sees from `receive`.
    """

    def __init__(self) -> None:
        self.outbound: asyncio.Queue[str] = asyncio.Queue()
        self._inbound: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.close_code: int | None = None
        self.close_reason: str | None = None

    async def send_text(self, data: str) -> None:
        await self.outbound.put(data)

    async def receive(self) -> dict[str, Any]:
        return await self._inbound.get()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.close_code = code
        self.close_reason = reason
        await self._inbound.put({"type": "websocket.disconnect", "code": code})

    async def deliver(self, text: str) -> None:
        """Push one frame from the agent to the server."""
        await self._inbound.put({"type": "websocket.receive", "text": text})

    async def deliver_bytes(self, payload: bytes) -> None:
        """Push a binary frame, which a v1 receiver must reject (§1.7)."""
        await self._inbound.put({"type": "websocket.receive", "bytes": payload})

    async def disconnect(self, code: int = 1006) -> None:
        await self._inbound.put({"type": "websocket.disconnect", "code": code})

    async def next_frame(self, timeout: float = 2.0) -> Envelope:
        raw = await asyncio.wait_for(self.outbound.get(), timeout=timeout)
        return decode_frame(raw)


def make_hello(
    *,
    agent_id: str = "WS-TEST-01",
    capabilities: list[str] | None = None,
    wire_versions: list[int] | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    """A `session.hello` payload matching the example in §3.1."""
    payload: dict[str, Any] = {
        "wireVersions": wire_versions or [1],
        "agentId": agent_id,
        "agent": {"name": "fake-agent", "version": "0.0.1", "implementation": "pytest"},
        "os": {
            "platform": "windows",
            "version": "10.0.19045",
            "build": 19045,
            "edition": "Windows 10 Pro",
            "arch": "x64",
            "is64Bit": True,
            "hostname": agent_id,
            "uptimeSeconds": 1000,
        },
        "identity": {
            "user": "NT SERVICE\\WinShowAgent",
            "sid": "S-1-5-80-1",
            "isService": True,
            "sessionId": 0,
            "isElevated": False,
            "integrityLevel": "medium",
            "privileges": ["SeChangeNotifyPrivilege"],
        },
        "capabilities": capabilities
        if capabilities is not None
        else ["fs.list", "fs.stat", "fs.read", "fs.glob", "fs.grep", "exec.start"],
        "features": ["longPaths"],
        "limits": {
            "maxFrameBytes": 1048576,
            "maxConcurrentRequests": 16,
            "maxConcurrentProcesses": 4,
            "maxOutputBytesPerExec": 4194304,
            "maxExecMillis": 300000,
            "maxReadBytes": 1048576,
            "maxGlobResults": 5000,
            "ackWindowChunks": 64,
            "ackWindowBytes": 4194304,
        },
        "policy": {
            "policyVersion": "2026-07-20T09:00:00Z",
            "policyHash": "sha256:" + "0" * 64,
            "state": "ok",
            "readRoots": ["C:\\src", "D:\\Logs"],
            "denyGlobCount": 2,
            "execMode": "allowlist",
            "allowedCommandCount": 2,
            "allowedCommandIds": ["svc-query", "tasklist"],
            "shellsAllowed": ["powershell"],
            "writeEnabled": False,
            "maxOutputBytes": 4194304,
            "maxExecMillis": 300000,
            "denialDisclosure": "explicit",
        },
        "clock": {"now": "2026-07-26T18:13:59.004Z", "tzOffsetMinutes": 0, "tzName": "UTC"},
    }
    payload.update(overrides)
    return payload


class FakeAgent:
    """Reads server frames and answers them from programmable handlers."""

    def __init__(self, ws: FakeWebSocket) -> None:
        self.ws = ws
        self.handlers: dict[str, Handler] = {}
        self.received: list[Envelope] = []
        self.acks: list[dict[str, Any]] = []
        self.cancelled: list[str] = []
        self._seq: dict[str, int] = {}
        self._task: asyncio.Task[None] | None = None
        self._pending: set[asyncio.Task[None]] = set()
        #: Set to skip a sequence number, which must make the server fail the request.
        self.inject_seq_gap_after: int | None = None

    # -- lifecycle ---------------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        for task in list(self._pending):
            task.cancel()
        if self._pending:
            await asyncio.gather(*self._pending, return_exceptions=True)
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def wait_for(self, predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
        """Poll until `predicate` holds. Frames are delivered asynchronously, so a test
        that asserts immediately after triggering one is asserting on a race."""
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.005)
        return predicate()

    async def _run(self) -> None:
        while True:
            raw = await self.ws.outbound.get()
            envelope = decode_frame(raw)
            self.received.append(envelope)
            # §8.1: an agent MUST NOT serialise requests. Handling each on its own task
            # keeps the harness reading the socket while a long exec is still streaming,
            # which is what lets a cancellation arrive mid-run at all.
            task = asyncio.create_task(self._dispatch(envelope))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def _dispatch(self, envelope: Envelope) -> None:
        if envelope.t is MessageType.EVT and envelope.op == Op.EXEC_ACK:
            self.acks.append(envelope.p or {})
            return
        if envelope.t is not MessageType.REQ:
            return

        op = envelope.op or ""
        payload = envelope.p or {}

        if op == Op.SESSION_PING:
            await self.respond(envelope.id or "", op, {"nonce": payload.get("nonce", "")})
            return

        if op == Op.SESSION_CANCEL:
            target = payload.get("targetId", "")
            self.cancelled.append(target)
            await self.respond(envelope.id or "", op, {"targetId": target, "cancelled": True})
            return

        handler = self.handlers.get(op)
        if handler is None:
            await self.fail(
                envelope.id or "",
                op,
                WireError.of("UNSUPPORTED_OPERATION", f"fake agent has no handler for {op}"),
            )
            return

        result = handler(envelope.id or "", payload)
        if asyncio.iscoroutine(result):
            result = await result
        if isinstance(result, WireError):
            await self.fail(envelope.id or "", op, result)
        elif isinstance(result, dict):
            await self.respond(envelope.id or "", op, result)
        # A handler returning None has taken responsibility for answering itself.

    # -- sending -----------------------------------------------------------------

    async def respond(self, message_id: str, op: str, payload: dict[str, Any]) -> None:
        await self.ws.deliver(Envelope.response(message_id, op, payload).to_json())

    async def fail(self, message_id: str, op: str, error: WireError) -> None:
        await self.ws.deliver(Envelope.error(message_id, op, error).to_json())

    async def event(self, corr: str, op: str, payload: dict[str, Any]) -> None:
        seq = self._seq.get(corr, 0)
        if self.inject_seq_gap_after is not None and seq == self.inject_seq_gap_after + 1:
            seq += 1  # skip one, which must trip the gap check
        self._seq[corr] = seq + 1
        await self.ws.deliver(Envelope.event(corr, seq, op, payload).to_json())

    # -- canned behaviours -------------------------------------------------------

    def on(self, op: str, handler: Handler) -> None:
        self.handlers[op] = handler

    def serve_exec(
        self,
        *,
        chunks: list[tuple[str, str]] | None = None,
        exit_code: int = 0,
        exit_reason: str = "exited",
        pid: int = 4242,
        truncated: bool = False,
        delay: float = 0.0,
    ) -> None:
        """Answer `exec.start` with a pid, then stream chunks, then exit."""
        chunks = chunks if chunks is not None else [("stdout", "hello\r\n")]

        async def handler(message_id: str, payload: dict[str, Any]) -> None:
            await self.respond(
                message_id,
                Op.EXEC_START,
                {
                    "pid": pid,
                    "startedAt": "2026-07-26T18:14:03.688Z",
                    "resolvedExecutable": (payload.get("argv") or ["?"])[0],
                    "resolvedCwd": payload.get("cwd") or "C:\\",
                    "commandLineUsed": " ".join(payload.get("argv") or []),
                },
            )
            totals = {"stdout": 0, "stderr": 0}
            for stream, data in chunks:
                if delay:
                    await asyncio.sleep(delay)
                totals[stream] += len(data)
                await self.event(
                    message_id,
                    Op.EXEC_OUTPUT,
                    {
                        "stream": stream,
                        "data": data,
                        "encoding": "utf-8",
                        "bytes": len(data),
                        "totalBytes": totals[stream],
                        "dropped": False,
                    },
                )
            await self.event(
                message_id,
                Op.EXEC_EXIT,
                {
                    "exitCode": exit_code,
                    "exitCodeSigned": exit_code,
                    "exitReason": exit_reason,
                    "startedAt": "2026-07-26T18:14:03.688Z",
                    "endedAt": "2026-07-26T18:14:04.000Z",
                    "durationMs": 312,
                    "stdoutBytes": totals["stdout"],
                    "stderrBytes": totals["stderr"],
                    "truncated": truncated,
                    "truncationReason": "maxOutputBytes" if truncated else None,
                },
            )

        self.on(Op.EXEC_START, handler)


async def connected_session(
    settings: Settings,
    *,
    hello: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> tuple[AgentSession, FakeAgent, FakeWebSocket, asyncio.Task[None]]:
    """Build a session that is already past the handshake.

    The handshake itself is covered separately against the real HTTP endpoint; tests
    that care about behaviour *after* it should not have to replay it.
    """
    ws = FakeWebSocket()
    payload = hello or make_hello()
    hello_model = HelloRequest.model_validate(payload)
    negotiated = Negotiated(
        wire_version=1,
        max_frame_bytes=min(hello_model.limits.max_frame_bytes, settings.max_frame_bytes),
        ack_window_chunks=settings.ack_window_chunks,
        ack_window_bytes=settings.ack_window_bytes,
        heartbeat_interval_ms=settings.heartbeat_interval_ms,
        enabled_ops=sorted(hello_model.capabilities),
    )
    session = AgentSession(
        ws,
        session_id=session_id or f"s-{next(_session_counter):04x}",
        agent_id=hello_model.agent_id,
        hello=hello_model,
        negotiated=negotiated,
        settings=settings,
    )
    agent = FakeAgent(ws)
    agent.start()
    serving = asyncio.create_task(session.serve())
    return session, agent, ws, serving
