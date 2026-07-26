"""Per-request state held by the server while an operation is in flight.

The server keeps deliberately little: an identifier, the operation, a deadline, the MCP
progress token when the client supplied one, an output buffer with its byte count, and a
future to resolve (``docs/02-architecture.md`` §6). Everything else lives on the agent,
which is the side that owns the process and the filesystem.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from winshow.errors import AgentProtocolError, WinShowError
from winshow.wire.messages import ExecExitEvent, ExecStartResponse, Op

__all__ = ["OMISSION_MARKER", "InflightRequest", "TruncatingBuffer"]

#: The marker written between the kept head and the kept tail of truncated output.
OMISSION_MARKER = "\n[… {omitted} bytes omitted …]\n"


class TruncatingBuffer:
    """Accumulates output, keeping the head and the tail once the cap is exceeded.

    §7.4 of the architecture: on overflow the result keeps the **first quarter** and the
    **last three quarters** of the budget, with an explicit omitted-bytes marker between
    them.

    The split is empirical rather than arbitrary. The interesting part of a failing build
    is at the end, and the invocation banner naming what actually ran is at the start.
    Keeping only the head gives you the command and none of the error; keeping only the
    tail gives you an error with no context.
    """

    def __init__(self, cap_bytes: int) -> None:
        self._cap = max(cap_bytes, 0)
        self._head_cap = self._cap // 4
        self._tail_cap = self._cap - self._head_cap
        self._head: list[str] = []
        self._head_len = 0
        self._tail: list[str] = []
        self._tail_len = 0
        #: Raw characters seen, including those dropped. Distinct from what is retained.
        self.received = 0
        self.truncated = False

    def append(self, text: str) -> None:
        if not text:
            return
        self.received += len(text)

        if self._cap == 0:
            self.truncated = True
            return

        if self._head_len < self._head_cap:
            room = self._head_cap - self._head_len
            take, text = text[:room], text[room:]
            self._head.append(take)
            self._head_len += len(take)
            if not text:
                return

        self._tail.append(text)
        self._tail_len += len(text)

        # Drop from the front of the tail until it fits. Whole fragments go first, then
        # the oldest surviving fragment is sliced, so the cost is bounded by the number
        # of chunks rather than by the total bytes.
        while self._tail_len > self._tail_cap:
            self.truncated = True
            oldest = self._tail[0]
            excess = self._tail_len - self._tail_cap
            if len(oldest) <= excess:
                self._tail.pop(0)
                self._tail_len -= len(oldest)
            else:
                self._tail[0] = oldest[excess:]
                self._tail_len -= excess

    def value(self) -> str:
        head = "".join(self._head)
        tail = "".join(self._tail)
        if not self.truncated:
            return head + tail
        omitted = self.received - self._head_len - self._tail_len
        return head + OMISSION_MARKER.format(omitted=max(omitted, 0)) + tail

    @property
    def retained(self) -> int:
        return self._head_len + self._tail_len


@dataclass
class InflightRequest:
    """One outstanding WSAP request.

    ``future`` resolves with the response payload, or is failed with a `WinShowError`.
    Events belonging to the request accumulate here until the terminal message arrives.
    """

    id: str
    op: str
    future: asyncio.Future[dict[str, Any]]
    #: Absolute deadline for the server's safety net (§8.6). The agent's own timeout is
    #: authoritative; this one only fires when the agent is misbehaving.
    deadline: float
    started: float = field(default_factory=time.monotonic)

    #: MCP progress token, when the client supplied one. Absent means the client does not
    #: want progress notifications, and nothing may depend on them either way (A-4).
    progress_token: str | int | None = None

    #: Next event `seq` expected from the agent. Events for one correlation must arrive
    #: gapless starting at 0 (§8.2).
    expected_seq: int = 0
    #: Independent server-side sequence space for `exec.ack`, which travels the other way.
    ack_seq_out: int = 0

    #: Execution state, populated as the agent reports it.
    start_info: ExecStartResponse | None = None
    exit_info: ExecExitEvent | None = None
    stdout: TruncatingBuffer | None = None
    stderr: TruncatingBuffer | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    #: Highest contiguous seq consumed, and cumulative bytes, for the credit window (§9.3).
    acked_seq: int = -1
    acked_bytes: int = 0
    #: Chunks of a `fs.read` too large for one frame, reassembled in seq order (§4.3).
    read_chunks: list[str] = field(default_factory=list)
    #: Set when the agent reported a slow stage-2 policy review (§5.5).
    under_review: bool = False
    cancelling: bool = False
    #: Set once the server-side buffer overflowed and a `buffer_limit` cancellation was
    #: dispatched, so the cancel is sent once rather than on every subsequent chunk.
    buffer_limit_hit: bool = False

    def note_event_seq(self, seq: int) -> None:
        """Enforce the gapless-ordering rule for the agent's event stream (§8.2).

        A gap means output was lost, and a result with a hole in it is worse than an
        error, so the request is failed rather than completed.

        This rule applies only to the agent's stream. It deliberately does not apply to
        ``exec.ack``, which travels the other way and is cumulative: a lost or reordered
        acknowledgement is superseded by the next one.
        """
        if seq != self.expected_seq:
            raise AgentProtocolError(
                f"Event sequence gap on request {self.id}: expected seq {self.expected_seq}, "
                f"received {seq}. Output was lost.",
                details={
                    "requestId": self.id,
                    "expectedSeq": self.expected_seq,
                    "receivedSeq": seq,
                },
            )
        self.expected_seq = seq + 1

    def is_exec(self) -> bool:
        return self.op == Op.EXEC_START

    def resolve(self, payload: dict[str, Any]) -> None:
        if not self.future.done():
            self.future.set_result(payload)

    def fail(self, error: WinShowError) -> None:
        if not self.future.done():
            self.future.set_exception(error)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started
