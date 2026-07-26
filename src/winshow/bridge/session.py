"""One live WSAP/1 connection to a Windows agent.

An `AgentSession` owns a WebSocket, multiplexes requests over it, and enforces the
ordering, flow-control and timeout rules from ``docs/03-agent-protocol.md`` §8 and §9.

The session is deliberately ignorant of MCP. It speaks WSAP and nothing else, which is
what keeps the two protocols separable (`docs/adr/0001-reverse-websocket-transport.md`).
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from winshow.bridge.inflight import InflightRequest, TruncatingBuffer
from winshow.config import Settings
from winshow.errors import (
    AgentDisconnected,
    AgentProtocolError,
    AgentTimeout,
    WinShowError,
    WireError,
    WireErrorCode,
)
from winshow.observability.logging import get_logger
from winshow.observability.metrics import (
    record_bytes,
    record_denial,
    record_rtt,
    set_exec_running,
    set_inflight,
)
from winshow.wire.envelope import Envelope, MessageType, decode_frame, encode_frame
from winshow.wire.messages import (
    CancelReason,
    ExecAckEvent,
    ExecExitEvent,
    ExecOutputEvent,
    ExecStartResponse,
    ExitReason,
    HelloRequest,
    Op,
    PingResponse,
)

__all__ = ["AgentSession", "Negotiated", "OutputCallback", "ReviewCallback", "WebSocketLike"]

log = get_logger(__name__)

#: Called with each `exec.output` event as it is consumed, for progress streaming.
OutputCallback = Callable[[ExecOutputEvent], Awaitable[None]]
#: Called when the agent reports that a stage-2 policy review is running (§5.5).
ReviewCallback = Callable[[int], Awaitable[None]]


class WebSocketLike(Protocol):
    """The slice of Starlette's `WebSocket` this module uses.

    Narrowed to a protocol so tests can drive a session over an in-memory pair without
    an HTTP server, which is what makes the conformance transcripts replayable.
    """

    async def send_text(self, data: str) -> None: ...

    async def receive(self) -> MutableMapping[str, Any]: ...

    async def close(self, code: int = 1000, reason: str = "") -> None: ...


@dataclass
class Negotiated:
    """The effective parameters after the handshake (§3.1).

    Each is the minimum of what the two sides offered, because a limit either side
    cannot honour is not a limit.
    """

    wire_version: int
    max_frame_bytes: int
    ack_window_chunks: int
    ack_window_bytes: int
    heartbeat_interval_ms: int
    enabled_ops: list[str] = field(default_factory=list)


class AgentSession:
    """A connected agent, from the moment `session.hello` succeeds until the socket dies."""

    def __init__(
        self,
        ws: WebSocketLike,
        *,
        session_id: str,
        agent_id: str,
        hello: HelloRequest,
        negotiated: Negotiated,
        settings: Settings,
    ) -> None:
        self.ws = ws
        self.session_id = session_id
        self.agent_id = agent_id
        self.hello = hello
        self.negotiated = negotiated
        self.settings = settings

        self.connected_since = time.time()
        self.last_message_at = time.monotonic()
        self.rtt_seconds: float | None = None
        self.close_error: WinShowError | None = None

        self._inflight: dict[str, InflightRequest] = {}
        self._output_callbacks: dict[str, OutputCallback] = {}
        self._review_callbacks: dict[str, ReviewCallback] = {}
        self._send_lock = asyncio.Lock()
        self._pings: dict[str, tuple[str, float]] = {}
        self._seen_ids: set[str] = set()
        self._exec_running = 0
        self._background: set[asyncio.Task[None]] = set()

        # §8.3: the server MUST respect the agent's advertised concurrency and queue
        # locally rather than overshooting. Overshooting would earn AGENT_BUSY, which is
        # a worse outcome than waiting a moment for a slot.
        self._slots = asyncio.Semaphore(max(hello.limits.max_concurrent_requests, 1))

    # -- identity ----------------------------------------------------------------

    @property
    def clock_skew_seconds(self) -> float | None:
        """The agent's clock relative to ours at handshake (NFR-17).

        Reported rather than corrected for: a skew is a fact about the deployment the
        operator needs to see, not something to paper over.
        """
        raw = self.hello.clock.get("now")
        if not isinstance(raw, str):
            return None
        from datetime import datetime

        try:
            agent_now = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return agent_now.timestamp() - self.connected_since

    def supports(self, op: str) -> bool:
        """§11.2 rule 5: the server MUST NOT send an op the agent did not advertise."""
        return op in self.negotiated.enabled_ops

    # -- sending -----------------------------------------------------------------

    async def send(self, envelope: Envelope) -> None:
        """Serialise and write one frame.

        The lock matters: several tasks send concurrently — request dispatch, heartbeat,
        and the acknowledgement pump — and interleaved writes would corrupt the stream.
        """
        text = encode_frame(envelope, self.negotiated.max_frame_bytes)
        async with self._send_lock:
            await self.ws.send_text(text)
        record_bytes("out", len(text))

    # -- requests ----------------------------------------------------------------

    def _new_request_id(self) -> str:
        # Identifiers are scoped to a connection (§8.5) and must match [A-Za-z0-9._-].
        while True:
            candidate = f"r-{secrets.token_hex(6)}"
            if candidate not in self._seen_ids:
                self._seen_ids.add(candidate)
                return candidate

    async def request(
        self,
        op: str,
        payload: dict[str, Any],
        *,
        timeout_ms: int | None = None,
        on_output: OutputCallback | None = None,
        on_review: ReviewCallback | None = None,
        trace: str | None = None,
    ) -> dict[str, Any]:
        """Send a request and await its terminal message.

        For `exec.start` the terminal message is the `exec.exit` **event**, not the
        response: the response only reports the pid, and the outcome arrives later. For
        every other operation the response is terminal.
        """
        if not self.supports(op):
            raise WinShowError(
                WireErrorCode.UNSUPPORTED_OPERATION,
                f"The connected agent does not implement {op!r}.",
                details={"enabledOps": sorted(self.negotiated.enabled_ops)},
            )

        budget_ms = timeout_ms or self.settings.default_request_timeout_ms
        # §8.6: the agent's timeout is authoritative because it owns the process. The
        # server keeps a net set a few seconds later; if that fires, the agent is
        # misbehaving and we say so rather than papering over it.
        deadline_ms = budget_ms + self.settings.server_timeout_margin_ms

        await self._slots.acquire()
        request_id = self._new_request_id()
        loop = asyncio.get_running_loop()
        entry = InflightRequest(
            id=request_id,
            op=op,
            future=loop.create_future(),
            deadline=time.monotonic() + deadline_ms / 1000,
        )
        if op == Op.EXEC_START:
            cap = self.settings.max_buffered_output_bytes
            entry.stdout = TruncatingBuffer(cap)
            entry.stderr = TruncatingBuffer(cap)
        self._inflight[request_id] = entry
        if on_output is not None:
            self._output_callbacks[request_id] = on_output
        if on_review is not None:
            self._review_callbacks[request_id] = on_review
        set_inflight(len(self._inflight))

        try:
            await self.send(Envelope.request(request_id, op, payload, trace=trace))
            return await asyncio.wait_for(entry.future, timeout=deadline_ms / 1000)
        except TimeoutError:
            log.warning(
                "agent.timeout",
                extra={
                    "event": "agent.timeout",
                    "request_id": request_id,
                    "op": op,
                    "budget_ms": budget_ms,
                },
            )
            # Best effort: tell the agent to stop working on something nobody is waiting
            # for any more. The result is ignored — we are already failing the call.
            with contextlib.suppress(Exception):
                await self.cancel(request_id, CancelReason.TIMEOUT)
            raise AgentTimeout(
                f"The agent did not answer {op!r} within {deadline_ms} ms.",
                details={"requestId": request_id, "op": op},
            ) from None
        except asyncio.CancelledError:
            # The MCP client withdrew the call, or its stream died. §8.4: all three
            # cancellation triggers feed the one `session.cancel` mechanism, so the agent
            # terminates the process tree here exactly as it would on a timeout.
            #
            # Dispatched as a detached task rather than awaited: this coroutine is being
            # cancelled, so any await here would raise CancelledError again before the
            # frame reached the agent.
            self._spawn(self._cancel_quietly(request_id, CancelReason.CLIENT_CANCELLED))
            raise
        finally:
            self._inflight.pop(request_id, None)
            self._output_callbacks.pop(request_id, None)
            self._review_callbacks.pop(request_id, None)
            set_inflight(len(self._inflight))
            self._slots.release()

    def _spawn(self, coro: Any) -> None:
        """Run `coro` detached, holding a reference so it is not garbage collected.

        asyncio keeps only a weak reference to a task, so a fire-and-forget task can be
        collected mid-flight and simply never run.
        """
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _cancel_quietly(self, target_id: str, reason: CancelReason | str) -> None:
        with contextlib.suppress(Exception):
            await self.cancel(target_id, reason)

    async def cancel(self, target_id: str, reason: CancelReason | str) -> bool:
        """Ask the agent to abandon `target_id` (§3.3).

        Idempotent and racy by nature: cancelling an unknown or already-terminal
        identifier returns false and is not an error.
        """
        request_id = self._new_request_id()
        loop = asyncio.get_running_loop()
        pending = InflightRequest(
            id=request_id,
            op=Op.SESSION_CANCEL,
            future=loop.create_future(),
            deadline=time.monotonic() + 5,
        )
        self._inflight[request_id] = pending
        try:
            await self.send(
                Envelope.request(
                    request_id,
                    Op.SESSION_CANCEL,
                    {"targetId": target_id, "reason": str(reason)},
                )
            )
            result = await asyncio.wait_for(pending.future, timeout=5)
            return bool(result.get("cancelled", False))
        except (TimeoutError, WinShowError):
            return False
        finally:
            self._inflight.pop(request_id, None)

    # -- receive loop ------------------------------------------------------------

    async def serve(self) -> None:
        """Run until the socket closes, then fail everything still outstanding."""
        heartbeat = asyncio.create_task(self._heartbeat_loop(), name=f"hb-{self.session_id}")
        try:
            await self._receive_loop()
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            self._fail_all(
                self.close_error
                or AgentDisconnected(
                    "The WinShow agent disconnected while this request was in flight.",
                    details={"sessionId": self.session_id, "agentId": self.agent_id},
                )
            )

    async def _receive_loop(self) -> None:
        while True:
            message = await self.ws.receive()
            kind = message.get("type")
            if kind == "websocket.disconnect":
                log.info(
                    "agent.disconnected",
                    extra={
                        "event": "agent.disconnected",
                        "session_id": self.session_id,
                        "agent_id": self.agent_id,
                        "code": message.get("code"),
                    },
                )
                return
            if kind != "websocket.receive":
                continue

            if message.get("bytes") is not None:
                # §1.7: binary frames are reserved for a future wire version and MUST be
                # rejected by a v1 receiver.
                self.close_error = AgentProtocolError(
                    "Binary frames are not permitted in WSAP/1."
                )
                await self.close(1003, "binary frames not permitted")
                return

            raw = message.get("text") or ""
            self.last_message_at = time.monotonic()
            record_bytes("in", len(raw))

            try:
                envelope = decode_frame(raw, self.negotiated.max_frame_bytes)
            except WinShowError as exc:
                # NFR-14: a malformed message must not take the server down. Answering
                # and continuing is the documented behaviour; only an oversized frame
                # forces a close, because the stream position is then unrecoverable.
                if exc.code == WireErrorCode.FRAME_TOO_LARGE:
                    self.close_error = exc
                    await self.close(1009, "frame too large")
                    return
                log.warning(
                    "agent.malformed_message",
                    extra={"event": "agent.malformed_message", "reason": str(exc)},
                )
                continue

            try:
                await self._dispatch(envelope)
            except AgentProtocolError as exc:
                # A violated ordering rule taints only the request it belongs to.
                log.warning(
                    "agent.protocol_error",
                    extra={"event": "agent.protocol_error", "reason": str(exc)},
                )

    async def _dispatch(self, env: Envelope) -> None:
        if env.t is MessageType.RES:
            self._on_response(env)
        elif env.t is MessageType.ERR:
            self._on_error(env)
        elif env.t is MessageType.EVT:
            await self._on_event(env)
        elif env.t is MessageType.REQ:
            await self._on_request(env)

    def _on_response(self, env: Envelope) -> None:
        assert env.id is not None
        entry = self._inflight.get(env.id)
        payload = env.p or {}

        if entry is None:
            # A response to something we already gave up on. Not an error: a timeout and
            # a slow answer race by nature.
            if env.id in self._pings:
                self._settle_ping(env.id, payload)
            return

        if entry.op == Op.SESSION_PING:
            self._settle_ping(env.id, payload)
            entry.resolve(payload)
            return

        if entry.op == Op.EXEC_START:
            # §5.1: the response reports the pid only. The outcome arrives as exec.exit,
            # so the caller keeps waiting.
            entry.start_info = ExecStartResponse.model_validate(payload)
            self._exec_running += 1
            set_exec_running(self._exec_running)
            return

        if entry.op == Op.FS_READ and payload.get("chunked"):
            # §4.3: a read too large for one frame arrives as `fs.read.chunk` events
            # followed by a response carrying the metadata with `data` omitted. The
            # chunks share the correlation's gapless sequence space, and the response is
            # sent after them on the same ordered connection, so they are all present by
            # the time we get here and joining in arrival order *is* joining in seq order.
            payload = {**payload, "data": "".join(entry.read_chunks)}

        entry.resolve(payload)

    def _on_error(self, env: Envelope) -> None:
        assert env.id is not None
        entry = self._inflight.get(env.id)
        if entry is None:
            return
        wire = env.e or WireError.of(WireErrorCode.INTERNAL_ERROR, "Agent sent an empty error.")
        if wire.code == WireErrorCode.POLICY_DENIED:
            record_denial(entry.op, wire.rule or "unknown")
        # An err on exec.start means no process was ever created (§5.1), so there will
        # be no exec.exit and this is the terminal message.
        if entry.op == Op.EXEC_START and entry.start_info is not None:
            self._exec_running = max(self._exec_running - 1, 0)
            set_exec_running(self._exec_running)
        entry.fail(
            WinShowError(
                wire.code,
                wire.message,
                rule=wire.rule,
                winError=wire.win_error,
                winErrorName=wire.win_error_name,
                details=wire.details,
            )
        )

    async def _on_event(self, env: Envelope) -> None:
        assert env.corr is not None and env.seq is not None
        op = env.op or ""
        payload = env.p or {}

        if op == Op.SESSION_BYE:
            log.info(
                "agent.bye",
                extra={
                    "event": "agent.bye",
                    "session_id": self.session_id,
                    "reason": payload.get("reason"),
                    # Not "message": the stdlib reserves that attribute on a LogRecord.
                    "bye_message": payload.get("message"),
                },
            )
            return

        entry = self._inflight.get(env.corr)
        if entry is None:
            # §11.1 rule 2: an event we cannot place is ignored, not fatal. It normally
            # means the request already completed or timed out.
            return

        try:
            entry.note_event_seq(env.seq)
        except AgentProtocolError as exc:
            entry.fail(exc)
            raise

        if op == Op.EXEC_OUTPUT:
            await self._on_exec_output(entry, payload)
        elif op == Op.EXEC_EXIT:
            self._on_exec_exit(entry, payload)
        elif op == Op.FS_READ_CHUNK:
            entry.read_chunks.append(str(payload.get("data", "")))
        elif op == Op.POLICY_REVIEWING:
            # §5.5: this carries no authorization meaning and MUST NOT be treated as an
            # approval. Its only purpose is to let the server tell the caller the request
            # is under review rather than merely slow.
            review = self._review_callbacks.get(entry.id)
            if review is not None:
                elapsed = int(payload.get("elapsedMs", 0) or 0)
                with contextlib.suppress(Exception):
                    await review(elapsed)
        else:
            log.debug("agent.unknown_event", extra={"event": "agent.unknown_event", "op": op})

    async def _on_exec_output(self, entry: InflightRequest, payload: dict[str, Any]) -> None:
        chunk = ExecOutputEvent.model_validate(payload)
        buffer = entry.stdout if chunk.stream == "stdout" else entry.stderr
        overflowed_before = bool(
            (entry.stdout and entry.stdout.truncated) or (entry.stderr and entry.stderr.truncated)
        )
        if buffer is not None:
            buffer.append(chunk.data)
        if chunk.stream == "stdout":
            entry.stdout_bytes = chunk.total_bytes
        else:
            entry.stderr_bytes = chunk.total_bytes

        entry.acked_seq = entry.expected_seq - 1
        entry.acked_bytes += chunk.bytes

        # §9.3: acknowledge eagerly on consuming a chunk. The window exists to bound
        # memory, not to pace the sender, so batching acks only risks stalling it.
        await self._send_ack(entry)

        # §7.3 of the architecture: on server-side buffer overflow the server cancels the
        # request and returns what it has, flagged as truncated. `buffer_limit` is the
        # cancellation reason the protocol reserves for exactly this. Without it the
        # process keeps running and producing output nobody will ever see, which wastes
        # the Windows host's CPU on a result already known to be incomplete.
        if not overflowed_before and not entry.buffer_limit_hit:
            now_overflowed = bool(
                (entry.stdout and entry.stdout.truncated)
                or (entry.stderr and entry.stderr.truncated)
            )
            if now_overflowed:
                entry.buffer_limit_hit = True
                log.warning(
                    "exec.buffer_limit",
                    extra={
                        "event": "exec.buffer_limit",
                        "request_id": entry.id,
                        "cap_bytes": self.settings.max_buffered_output_bytes,
                    },
                )
                self._spawn(self._cancel_quietly(entry.id, CancelReason.BUFFER_LIMIT))

        callback = self._output_callbacks.get(entry.id)
        if callback is not None:
            # A misbehaving progress consumer must not break the run it is reporting on.
            try:
                await callback(chunk)
            except Exception:
                log.warning(
                    "progress.callback_failed",
                    extra={"event": "progress.callback_failed", "request_id": entry.id},
                    exc_info=True,
                )

    async def _send_ack(self, entry: InflightRequest) -> None:
        payload = ExecAckEvent(ackSeq=entry.acked_seq, ackBytes=entry.acked_bytes).wire()
        envelope = Envelope.event(entry.id, entry.ack_seq_out, Op.EXEC_ACK, payload)
        entry.ack_seq_out += 1
        with contextlib.suppress(Exception):
            await self.send(envelope)

    def _on_exec_exit(self, entry: InflightRequest, payload: dict[str, Any]) -> None:
        exit_event = ExecExitEvent.model_validate(payload)
        entry.exit_info = exit_event
        self._exec_running = max(self._exec_running - 1, 0)
        set_exec_running(self._exec_running)
        entry.resolve(self._exec_result(entry))

    def _exec_result(self, entry: InflightRequest, *, partial: bool = False) -> dict[str, Any]:
        """Fold the start response, the buffered output and the exit event into one result."""
        exit_event = entry.exit_info or ExecExitEvent(exitReason=ExitReason.DISCONNECTED)
        start = entry.start_info
        stdout = entry.stdout.value() if entry.stdout else ""
        stderr = entry.stderr.value() if entry.stderr else ""
        truncated = bool(exit_event.truncated) or bool(
            (entry.stdout and entry.stdout.truncated) or (entry.stderr and entry.stderr.truncated)
        )
        reason = exit_event.truncation_reason
        if truncated and reason is None:
            reason = "serverBufferLimit"
        return {
            "exitCode": exit_event.exit_code,
            "exitCodeSigned": exit_event.exit_code_signed,
            "exitReason": str(exit_event.exit_reason),
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
            "truncationReason": reason,
            "partial": partial,
            "durationMs": exit_event.duration_ms,
            "stdoutBytes": exit_event.stdout_bytes or entry.stdout_bytes,
            "stderrBytes": exit_event.stderr_bytes or entry.stderr_bytes,
            "pid": start.pid if start else None,
            "commandLineUsed": start.command_line_used if start else "",
            "resolvedExecutable": start.resolved_executable if start else "",
            "startedAt": exit_event.started_at or (start.started_at if start else None),
            "endedAt": exit_event.ended_at,
            "cpuTimeMs": exit_event.cpu_time_ms,
            "peakWorkingSetBytes": exit_event.peak_working_set_bytes,
            "killedProcesses": exit_event.killed_processes,
        }

    async def _on_request(self, env: Envelope) -> None:
        """Answer a request the agent originated.

        Only `session.ping` is legitimate here after the handshake (§2.3). Anything else
        is answered with `UNSUPPORTED_OPERATION` rather than closing the connection,
        which is §11.1 rule 3 applied symmetrically.
        """
        assert env.id is not None
        if env.op == Op.SESSION_PING:
            payload = env.p or {}
            await self.send(
                Envelope.response(
                    env.id,
                    Op.SESSION_PING,
                    {"nonce": payload.get("nonce", "")},
                )
            )
            return
        await self.send(
            Envelope.error(
                env.id,
                env.op,
                WireError.of(
                    WireErrorCode.UNSUPPORTED_OPERATION,
                    f"The WinShow server does not accept {env.op!r} from an agent.",
                ),
            )
        )

    # -- heartbeat ---------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Ping on a cadence and declare the peer dead after prolonged silence (NFR-8).

        This is an application-level ping, deliberately not a WebSocket control ping.
        Control pings are frequently answered transparently by libraries and middleboxes,
        which proves the socket is alive but says nothing about whether the agent's event
        loop is (§3.2).
        """
        interval = self.negotiated.heartbeat_interval_ms / 1000
        dead_after = self.settings.agent_dead_after_ms / 1000
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - self.last_message_at > dead_after:
                log.warning(
                    "agent.dead_peer",
                    extra={
                        "event": "agent.dead_peer",
                        "session_id": self.session_id,
                        "silent_for_s": round(time.monotonic() - self.last_message_at, 1),
                    },
                )
                self.close_error = AgentDisconnected(
                    "The agent stopped answering heartbeats and was declared dead."
                )
                await self.close(1011, "dead peer")
                return

            ping_id = self._new_request_id()
            nonce = secrets.token_hex(4)
            self._pings[ping_id] = (nonce, time.monotonic())
            try:
                await self.send(
                    Envelope.request(ping_id, Op.SESSION_PING, {"nonce": nonce})
                )
            except Exception:
                self._pings.pop(ping_id, None)
                return

    def _settle_ping(self, ping_id: str, payload: dict[str, Any]) -> None:
        sent = self._pings.pop(ping_id, None)
        if sent is None:
            return
        expected_nonce, sent_at = sent
        echoed = PingResponse.model_validate(payload).nonce
        if echoed != expected_nonce:
            # §3.2 requires a verbatim echo. A mismatch means the peer is not tracking
            # correlation properly, which is worth surfacing but not worth a disconnect.
            log.warning(
                "agent.ping_nonce_mismatch",
                extra={"event": "agent.ping_nonce_mismatch", "session_id": self.session_id},
            )
            return
        self.rtt_seconds = time.monotonic() - sent_at
        record_rtt(self.rtt_seconds)

    # -- teardown ----------------------------------------------------------------

    async def close(self, code: int, reason: str) -> None:
        """Close the socket, tolerating a peer that has already vanished."""
        with contextlib.suppress(Exception):
            await self.ws.close(code=code, reason=reason)

    async def say_goodbye(
        self, reason: str, message: str, by_session_id: str | None = None
    ) -> None:
        """Send `session.bye` before closing (§3.4). Best effort by definition."""
        payload: dict[str, Any] = {"reason": reason, "message": message}
        if by_session_id is not None:
            payload["bySessionId"] = by_session_id
        with contextlib.suppress(Exception):
            # §3.4: bye is the one event with no originating request; its corr is the
            # sessionId of the connection being closed and its seq starts at 0.
            await self.send(Envelope.event(self.session_id, 0, Op.SESSION_BYE, payload))

    def _fail_all(self, error: WinShowError) -> None:
        """Complete every outstanding request immediately (NFR-16).

        A hang is the worst available outcome: it gives the user neither a result nor a
        reason, and it looks identical to a bug in the client. So nothing is left waiting
        for the caller's own timeout.

        Partial results are handled asymmetrically on purpose (§8.2 of the architecture):
        an execution returns the output captured so far, because a truncated build log is
        useful, whereas a partial file read is discarded, because a partial file is a lie
        rather than a partial truth.
        """
        for entry in list(self._inflight.values()):
            if entry.future.done():
                continue
            if entry.op == Op.EXEC_START and entry.start_info is not None:
                entry.exit_info = ExecExitEvent(exitReason=ExitReason.DISCONNECTED)
                entry.resolve(self._exec_result(entry, partial=True))
            else:
                entry.fail(error)
        self._inflight.clear()
        set_inflight(0)
        set_exec_running(0)
