"""Behaviour of the agent session and the single slot.

Each test names the rule it is defending, because these are the behaviours that are
cheap to break silently and expensive to notice later.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tests.fake_agent import connected_session, make_hello
from winshow.bridge.bridge import AgentBridge
from winshow.bridge.inflight import TruncatingBuffer
from winshow.config import Settings
from winshow.errors import (
    AgentDisconnected,
    AgentProtocolError,
    AgentUnavailable,
    WinShowError,
    WireError,
    WireErrorCode,
)
from winshow.wire.messages import ExitReason, Op


class TestTruncatingBuffer:
    def test_keeps_everything_below_the_cap(self) -> None:
        buffer = TruncatingBuffer(100)
        buffer.append("hello")
        assert buffer.value() == "hello"
        assert buffer.truncated is False

    def test_keeps_head_and_tail_with_a_marker(self) -> None:
        # §7.4 of the architecture: the first quarter and the last three quarters of the
        # budget survive. The head carries the invocation banner, the tail the error.
        buffer = TruncatingBuffer(100)
        buffer.append("H" * 40 + "M" * 200 + "T" * 40)
        value = buffer.value()
        assert buffer.truncated is True
        assert value.startswith("H" * 25)
        assert value.endswith("T" * 40)
        assert "bytes omitted" in value

    def test_counts_what_was_dropped(self) -> None:
        buffer = TruncatingBuffer(40)
        buffer.append("x" * 200)
        assert buffer.received == 200
        assert buffer.retained == 40
        assert "160 bytes omitted" in buffer.value()

    def test_zero_cap_retains_nothing_but_records_truncation(self) -> None:
        buffer = TruncatingBuffer(0)
        buffer.append("anything")
        assert buffer.truncated is True
        assert "bytes omitted" in buffer.value()


class TestRequestRouting:
    async def test_simple_response_resolves(self, linked: Any) -> None:
        bridge, agent, _ = linked
        agent.on(Op.FS_LIST, lambda _id, p: {"path": p["path"], "entries": [], "total": 0})
        result = await bridge.call(Op.FS_LIST, {"path": "C:\\src"})
        assert result["path"] == "C:\\src"

    async def test_error_response_raises_with_the_wire_code(self, linked: Any) -> None:
        bridge, agent, _ = linked
        agent.on(
            Op.FS_LIST,
            lambda _id, _p: WireError.of(
                WireErrorCode.POLICY_DENIED, "outside every root", rule="fs.readRoots"
            ),
        )
        with pytest.raises(WinShowError) as caught:
            await bridge.call(Op.FS_LIST, {"path": "C:\\Windows"})
        assert caught.value.code == WireErrorCode.POLICY_DENIED
        assert caught.value.error.rule == "fs.readRoots"
        assert caught.value.retryable is False

    async def test_responses_may_arrive_out_of_order(self, linked: Any) -> None:
        # §8.2: receivers MUST NOT assume FIFO. A slow directory listing must not hold up
        # a fast stat issued after it.
        bridge, agent, _ = linked

        async def slow(message_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
            await asyncio.sleep(0.05)
            return {"path": "slow", "entries": [], "total": 0}

        agent.on(Op.FS_LIST, slow)
        agent.on(Op.FS_STAT, lambda _id, _p: {"path": "fast", "exists": True})

        listing = asyncio.create_task(bridge.call(Op.FS_LIST, {"path": "C:\\"}))
        await asyncio.sleep(0)
        stat = await bridge.call(Op.FS_STAT, {"path": "C:\\x"})
        assert stat["path"] == "fast"
        assert (await listing)["path"] == "slow"

    async def test_unadvertised_operation_is_refused_locally(self, settings: Settings) -> None:
        # §11.2 rule 5: the server MUST NOT send an op the agent did not advertise. It is
        # caught here rather than on the wire, so no frame is wasted.
        session, agent, _ws, serving = await connected_session(
            settings, hello=make_hello(capabilities=["fs.list"])
        )
        bridge = AgentBridge(settings)
        await bridge.attach(session)
        try:
            with pytest.raises(WinShowError) as caught:
                await bridge.call(Op.EXEC_START, {"argv": ["x"]})
            assert caught.value.code == WireErrorCode.UNSUPPORTED_OPERATION
        finally:
            await agent.stop()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)


class TestExecution:
    async def test_exit_event_is_terminal_not_the_response(self, linked: Any) -> None:
        # §5.1: the response only reports a pid. Resolving on it would return before the
        # command had produced anything.
        bridge, agent, _ = linked
        agent.serve_exec(chunks=[("stdout", "one\r\n"), ("stdout", "two\r\n")], exit_code=0)
        result = await bridge.call(Op.EXEC_START, {"argv": ["tasklist.exe"]})
        assert result["exitCode"] == 0
        assert result["stdout"] == "one\r\ntwo\r\n"
        assert result["pid"] == 4242

    async def test_non_zero_exit_is_a_successful_call(self, linked: Any) -> None:
        bridge, agent, _ = linked
        agent.serve_exec(chunks=[("stderr", "error CS0103\r\n")], exit_code=1)
        result = await bridge.call(Op.EXEC_START, {"argv": ["dotnet"]})
        assert result["exitCode"] == 1
        assert result["exitReason"] == "exited"
        assert result["stderr"] == "error CS0103\r\n"

    async def test_output_is_acknowledged_eagerly(self, linked: Any) -> None:
        # §9.3: the window bounds memory, it does not pace the sender, so acks go out on
        # consuming a chunk rather than in batches.
        bridge, agent, _ = linked
        agent.serve_exec(chunks=[("stdout", "a"), ("stdout", "b"), ("stdout", "c")])
        await bridge.call(Op.EXEC_START, {"argv": ["x"]})
        assert len(agent.acks) == 3
        assert [a["ackSeq"] for a in agent.acks] == [0, 1, 2]
        # Cumulative, not per-chunk.
        assert [a["ackBytes"] for a in agent.acks] == [1, 2, 3]

    async def test_sequence_gap_fails_the_request(self, linked: Any) -> None:
        # §8.2: a gap means output was lost. A result with a hole in it is worse than an
        # error, so the request fails rather than completing.
        bridge, agent, _ = linked
        agent.inject_seq_gap_after = 0
        agent.serve_exec(chunks=[("stdout", "a"), ("stdout", "b"), ("stdout", "c")])
        with pytest.raises(AgentProtocolError):
            await bridge.call(Op.EXEC_START, {"argv": ["x"]})

    async def test_cancellation_reaches_the_agent(self, linked: Any) -> None:
        bridge, agent, _ = linked
        agent.serve_exec(chunks=[("stdout", "x")] * 50, delay=0.02)
        call = asyncio.create_task(bridge.call(Op.EXEC_START, {"argv": ["slow"]}))
        await asyncio.sleep(0.05)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        # The cancel is dispatched as a detached task, so wait for it to land rather
        # than asserting on a race.
        assert await agent.wait_for(lambda: bool(agent.cancelled)), (
            "session.cancel never reached the agent"
        )

    async def test_server_timeout_yields_agent_timeout(self, linked: Any) -> None:
        # §8.6: the agent's timeout is authoritative. If the server's net fires, the agent
        # is misbehaving and the failure says so specifically.
        bridge, agent, _ = linked

        async def never_answers(_id: str, _p: dict[str, Any]) -> None:
            await asyncio.sleep(30)

        agent.on(Op.FS_LIST, never_answers)
        with pytest.raises(WinShowError) as caught:
            await bridge.call(Op.FS_LIST, {"path": "C:\\"}, timeout_ms=100)
        assert caught.value.code == "AGENT_TIMEOUT"


class TestDisconnect:
    async def test_execution_returns_partial_output(self, settings: Settings) -> None:
        # §8.2 of the architecture: a truncated build log is useful, so what arrived is
        # returned with partial: true.
        session, agent, ws, serving = await connected_session(settings)
        bridge = AgentBridge(settings)
        await bridge.attach(session)

        async def start_then_vanish(message_id: str, _payload: dict[str, Any]) -> None:
            await agent.respond(
                message_id,
                Op.EXEC_START,
                {
                    "pid": 1,
                    "startedAt": "2026-07-26T18:00:00.000Z",
                    "resolvedExecutable": "x",
                    "resolvedCwd": "C:\\",
                    "commandLineUsed": "x",
                },
            )
            await agent.event(
                message_id,
                Op.EXEC_OUTPUT,
                {
                    "stream": "stdout",
                    "data": "partial output\r\n",
                    "encoding": "utf-8",
                    "bytes": 16,
                    "totalBytes": 16,
                    "dropped": False,
                },
            )
            await asyncio.sleep(0.02)
            await ws.disconnect()

        agent.on(Op.EXEC_START, start_then_vanish)
        result = await bridge.call(Op.EXEC_START, {"argv": ["build"]})
        assert result["partial"] is True
        assert result["exitReason"] == ExitReason.DISCONNECTED
        assert "partial output" in result["stdout"]

        await agent.stop()
        await asyncio.gather(serving, return_exceptions=True)

    async def test_file_read_is_failed_rather_than_returned_partial(
        self, settings: Settings
    ) -> None:
        # The asymmetry is deliberate: a partial file is a lie rather than a partial truth.
        session, agent, ws, serving = await connected_session(settings)
        bridge = AgentBridge(settings)
        await bridge.attach(session)

        async def vanish(_id: str, _p: dict[str, Any]) -> None:
            await asyncio.sleep(0.02)
            await ws.disconnect()

        agent.on(Op.FS_READ, vanish)
        with pytest.raises(AgentDisconnected):
            await bridge.call(Op.FS_READ, {"path": "C:\\x", "tailLines": 5})

        await agent.stop()
        await asyncio.gather(serving, return_exceptions=True)

    async def test_nothing_is_left_hanging(self, settings: Settings) -> None:
        # NFR-16 stated as a test: a hang gives the user neither a result nor a reason and
        # looks identical to a client bug.
        session, agent, ws, serving = await connected_session(settings)
        bridge = AgentBridge(settings)
        await bridge.attach(session)
        agent.on(Op.FS_LIST, lambda _id, _p: None)  # answers nothing at all

        calls = [asyncio.create_task(bridge.call(Op.FS_LIST, {"path": "C:\\"})) for _ in range(5)]
        await asyncio.sleep(0.02)
        await ws.disconnect()

        results = await asyncio.wait_for(
            asyncio.gather(*calls, return_exceptions=True), timeout=2.0
        )
        assert all(isinstance(r, AgentDisconnected) for r in results)

        await agent.stop()
        await asyncio.gather(serving, return_exceptions=True)


class TestSlot:
    async def test_no_agent_is_an_actionable_error(self, bridge: AgentBridge) -> None:
        with pytest.raises(AgentUnavailable) as caught:
            await bridge.call(Op.FS_LIST, {"path": "C:\\"})
        assert caught.value.retryable is True

    async def test_host_info_without_an_agent_is_not_an_error(self, bridge: AgentBridge) -> None:
        # The absence of a host is information, not a failure.
        info = bridge.host_info()
        assert info["connected"] is False
        assert info["policy"] is None

    async def test_host_info_exposes_the_policy_summary(self, linked: Any) -> None:
        # FR-3: this is what lets a model propose something that will work instead of
        # spending three turns guessing.
        bridge, _agent, _ws = linked
        info = bridge.host_info()
        assert info["connected"] is True
        assert info["policy"]["readRoots"] == ["C:\\src", "D:\\Logs"]
        assert info["policy"]["allowedCommandIds"] == ["svc-query", "tasklist"]

    async def test_newest_agent_evicts_the_incumbent(self, settings: Settings) -> None:
        # ADR 0007. The dominant real case is a half-open connection after a partition:
        # rejecting the newcomer leaves the system broken until the dead-peer timer fires.
        bridge = AgentBridge(settings)
        first, agent_a, ws_a, serve_a = await connected_session(settings)
        await bridge.attach(first)
        assert bridge.session is first

        second, agent_b, _ws_b, serve_b = await connected_session(settings)
        await bridge.attach(second)

        assert bridge.session is second
        assert ws_a.close_code == 4009
        # The incumbent is told why, and by whom, so two sessions can be stitched
        # together in a log.
        assert await agent_a.wait_for(
            lambda: any(e.op == Op.SESSION_BYE for e in agent_a.received)
        ), "the evicted agent was never sent session.bye"
        byes = [e for e in agent_a.received if e.op == Op.SESSION_BYE]
        assert byes[-1].p is not None
        assert byes[-1].p["reason"] == "superseded"
        assert byes[-1].p["bySessionId"] == second.session_id

        for agent, task in ((agent_a, serve_a), (agent_b, serve_b)):
            await agent.stop()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_late_detach_does_not_clear_a_newer_slot(self, settings: Settings) -> None:
        # The evicted session's serve() finishes after the newcomer is installed; an
        # unguarded detach would then release a slot belonging to somebody else.
        bridge = AgentBridge(settings)
        first, agent_a, _ws_a, serve_a = await connected_session(settings)
        second, agent_b, _ws_b, serve_b = await connected_session(settings)
        await bridge.attach(first)
        await bridge.attach(second)
        await bridge.detach(first)
        assert bridge.session is second

        for agent, task in ((agent_a, serve_a), (agent_b, serve_b)):
            await agent.stop()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class TestFrameHandling:
    async def test_binary_frame_closes_the_connection(self, settings: Settings) -> None:
        # §1.7: binary frames are reserved for a future wire version and MUST be rejected.
        _session, agent, ws, serving = await connected_session(settings)
        await ws.deliver_bytes(b"\x00\x01\x02")
        await asyncio.wait_for(serving, timeout=2.0)
        assert ws.close_code == 1003
        await agent.stop()

    async def test_malformed_frame_does_not_kill_the_connection(
        self, settings: Settings
    ) -> None:
        # NFR-14: no single malformed message may take the server down.
        session, agent, ws, serving = await connected_session(settings)
        bridge = AgentBridge(settings)
        await bridge.attach(session)
        agent.on(Op.FS_LIST, lambda _id, _p: {"path": "ok", "entries": [], "total": 0})

        await ws.deliver("{ this is not json")
        await asyncio.sleep(0.02)
        assert not serving.done()

        result = await bridge.call(Op.FS_LIST, {"path": "C:\\"})
        assert result["path"] == "ok"

        await agent.stop()
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)


class TestHeartbeat:
    async def test_ping_is_answered_and_measured(self, settings: Settings) -> None:
        fast = settings.model_copy(update={"heartbeat_interval_ms": 20, "agent_dead_after_ms": 5000})
        session, agent, _ws, serving = await connected_session(fast)
        try:
            assert await agent.wait_for(lambda: session.rtt_seconds is not None), (
                "the heartbeat round-trip was never measured"
            )
            pings = [e for e in agent.received if e.op == Op.SESSION_PING]
            assert pings, "no application-level ping was sent"
        finally:
            await agent.stop()
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)

    async def test_silent_peer_is_declared_dead(self, settings: Settings) -> None:
        # NFR-8. The fake agent is stopped so nothing answers, which is exactly the
        # half-open socket the timer exists for.
        deadly = settings.model_copy(
            update={"heartbeat_interval_ms": 20, "agent_dead_after_ms": 60}
        )
        _session, agent, ws, serving = await connected_session(deadly)
        await agent.stop()
        await asyncio.wait_for(serving, timeout=3.0)
        assert ws.close_code == 1011
