"""The single agent slot, and everything the tool layer talks to.

`AgentBridge` holds one optional `AgentSession`. When a second connection authenticates
successfully, **the incumbent is evicted** rather than the newcomer rejected
(`docs/adr/0007-newest-agent-wins.md`).

The reasoning is that the dominant real-world case is a half-open TCP connection after a
network partition: the server still believes an agent is attached while the agent has
already noticed and reconnected. Rejecting the newcomer leaves the system broken until
the 60-second dead-peer timer fires; evicting the incumbent self-heals in one round trip.
The cost — that someone holding the token can boot the incumbent — is acceptable, because
someone holding the token can already run whatever the policy permits.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

from winshow.bridge.session import AgentSession, OutputCallback
from winshow.config import Settings
from winshow.errors import AgentUnavailable, WinShowError, WireErrorCode
from winshow.observability.logging import get_logger
from winshow.observability.metrics import (
    record_reconnect,
    record_request,
    set_agent_connected,
)

__all__ = ["AgentBridge"]

log = get_logger(__name__)

#: §8.3: AGENT_BUSY is retryable and the server SHOULD retry "after a short delay, with a
#: bounded number of attempts". Bounded is the operative word — unbounded retries turn a
#: saturated host into a busier one.
AGENT_BUSY_ATTEMPTS = 3
AGENT_BUSY_BACKOFF_SECONDS = 0.25


class AgentBridge:
    """Owns the agent slot and routes every operation across it."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._session: AgentSession | None = None
        self._arrived = asyncio.Event()
        self._last_seen_at: float | None = None
        self._lock = asyncio.Lock()

    # -- slot management ---------------------------------------------------------

    @property
    def session(self) -> AgentSession | None:
        return self._session

    @property
    def is_ready(self) -> bool:
        """What `/readyz` reports.

        Deliberately does **not** consider policy state (`docs/07-operations.md` §1.1).
        An agent whose policy file is broken still connects, still completes the
        handshake, and refuses each operation with a legible `POLICY_UNAVAILABLE`. That
        is a working connection carrying an error, which is far more useful than a red
        probe indistinguishable from a dead machine.
        """
        return self._session is not None

    async def attach(self, session: AgentSession) -> None:
        """Install `session`, evicting whatever held the slot."""
        async with self._lock:
            incumbent = self._session
            self._session = session
            self._arrived.set()

        if incumbent is not None:
            log.warning(
                "agent.superseded",
                extra={
                    "event": "agent.superseded",
                    "evicted_session_id": incumbent.session_id,
                    "session_id": session.session_id,
                    "agent_id": session.agent_id,
                },
            )
            await incumbent.say_goodbye(
                "superseded",
                "A newer agent connection replaced this one.",
                by_session_id=session.session_id,
            )
            # 4009 — superseded. The eviction happens after the newcomer is installed so
            # there is no window in which the slot is empty.
            await incumbent.close(4009, "superseded")

        set_agent_connected(True)
        record_reconnect()
        log.info(
            "agent.connected",
            extra={
                "event": "agent.connected",
                "session_id": session.session_id,
                "agent_id": session.agent_id,
                "hostname": session.hello.os.get("hostname"),
                "wire_version": session.negotiated.wire_version,
            },
        )

    async def detach(self, session: AgentSession) -> None:
        """Release the slot, but only if `session` still holds it.

        The guard matters under eviction: the incumbent's `serve()` finishes *after* the
        newcomer has been installed, and an unguarded detach would then clear a slot that
        belongs to somebody else.
        """
        async with self._lock:
            if self._session is not session:
                return
            self._session = None
            self._arrived.clear()
            self._last_seen_at = time.time()
        set_agent_connected(False)
        log.info(
            "agent.slot_released",
            extra={"event": "agent.slot_released", "session_id": session.session_id},
        )

    async def shutdown(self) -> None:
        session = self._session
        if session is None:
            return
        await session.say_goodbye("shutdown", "The WinShow server is shutting down.")
        await session.close(1001, "server shutdown")

    # -- dispatch ----------------------------------------------------------------

    async def require_session(self) -> AgentSession:
        """Return the connected agent, waiting out a brief reconnection blip.

        `wait_for_agent_ms` defaults to 0 — fail fast — because a clear error beats a
        hanging call. Setting it to a few seconds lets a request that arrives during a
        two-second reconnect succeed instead of failing (§8.1 of the architecture).
        """
        session = self._session
        if session is not None:
            return session

        grace = self.settings.wait_for_agent_ms / 1000
        if grace > 0:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._arrived.wait(), timeout=grace)
            session = self._session
            if session is not None:
                return session

        disconnected_for = (
            int(time.time() - self._last_seen_at) if self._last_seen_at is not None else None
        )
        raise AgentUnavailable(
            "No WinShow agent is connected. The Windows host has not dialed in.",
            details={
                "lastSeenAt": self._last_seen_at,
                "disconnectedForSeconds": disconnected_for,
            },
        )

    async def call(
        self,
        op: str,
        payload: dict[str, Any],
        *,
        timeout_ms: int | None = None,
        on_output: OutputCallback | None = None,
        progress_token: str | int | None = None,
        trace: str | None = None,
    ) -> dict[str, Any]:
        """Run one operation against the connected agent, recording the outcome.

        `AGENT_BUSY` is retried a bounded number of times (§8.3). That is safe even for
        `exec.start`, which §8.7 forbids anyone to retry: `AGENT_BUSY` is the agent
        stating that it *rejected* the request rather than ran it, so there is no
        ambiguity about whether the command already executed — which is the entire reason
        that rule exists.
        """
        started = time.monotonic()
        outcome = "ok"
        try:
            for attempt in range(AGENT_BUSY_ATTEMPTS):
                session = await self.require_session()
                try:
                    return await session.request(
                        op,
                        payload,
                        timeout_ms=timeout_ms,
                        on_output=on_output,
                        progress_token=progress_token,
                        trace=trace,
                    )
                except WinShowError as exc:
                    last = attempt == AGENT_BUSY_ATTEMPTS - 1
                    if exc.code != WireErrorCode.AGENT_BUSY or last:
                        outcome = exc.code
                        raise
                    delay = AGENT_BUSY_BACKOFF_SECONDS * (2**attempt)
                    log.info(
                        "agent.busy_retry",
                        extra={
                            "event": "agent.busy_retry",
                            "op": op,
                            "attempt": attempt + 1,
                            "delay_s": delay,
                        },
                    )
                    await asyncio.sleep(delay)
            # Unreachable: the loop either returns or raises on its final attempt.
            raise AssertionError("retry loop fell through")
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        finally:
            record_request(op, outcome, time.monotonic() - started)

    # -- introspection -----------------------------------------------------------

    def host_info(self) -> dict[str, Any]:
        """The payload behind `winshow_host_info`.

        When no agent is connected this is still a **successful** result carrying
        `connected: false`. The absence of a host is information, not an error
        (`docs/05-mcp-tool-surface.md` §2).
        """
        session = self._session
        if session is None:
            return {
                "connected": False,
                "connected_since": None,
                "last_seen_at": _iso(self._last_seen_at),
                "agent": None,
                "host": None,
                "identity": None,
                "capabilities": [],
                "limits": None,
                "policy": None,
                "clock_skew_seconds": None,
            }

        hello = session.hello
        return {
            "connected": True,
            "connected_since": _iso(session.connected_since),
            "last_seen_at": None,
            "agent": hello.agent,
            "host": hello.os,
            "identity": hello.identity,
            "capabilities": list(session.negotiated.enabled_ops),
            "limits": hello.limits.model_dump(by_alias=True),
            "policy": hello.policy.model_dump(by_alias=True, exclude_none=True),
            "clock_skew_seconds": session.clock_skew_seconds,
        }


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    from datetime import UTC, datetime

    moment = datetime.fromtimestamp(epoch, UTC)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"
