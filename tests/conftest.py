"""Shared fixtures."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest

from tests.fake_agent import FakeAgent, FakeWebSocket, connected_session
from winshow.bridge.bridge import AgentBridge
from winshow.config import Settings
from winshow.observability.audit import AuditLog

AGENT_TOKEN = secrets.token_urlsafe(32)


@pytest.fixture
def settings() -> Settings:
    """Settings with the heartbeat pushed out of the way.

    Tests that care about the heartbeat set their own interval; everything else would
    otherwise race a 20-second timer for no reason.
    """
    return Settings(
        agent_tokens=[AGENT_TOKEN],
        allowed_origins=["https://client.example"],
        heartbeat_interval_ms=60_000,
        agent_dead_after_ms=120_000,
        default_request_timeout_ms=2_000,
        server_timeout_margin_ms=500,
        log_format="text",
        metrics_enabled=False,
    )


@pytest.fixture
def bridge(settings: Settings) -> AgentBridge:
    return AgentBridge(settings)


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog(None)


@pytest.fixture
async def linked(
    settings: Settings, bridge: AgentBridge
) -> AsyncIterator[tuple[AgentBridge, FakeAgent, FakeWebSocket]]:
    """A bridge with a fake agent already attached and serving."""
    session, agent, ws, serving = await connected_session(settings)
    await bridge.attach(session)
    try:
        yield bridge, agent, ws
    finally:
        await agent.stop()
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        await bridge.detach(session)


@pytest.fixture(autouse=True)
def _quiet_metrics() -> Iterator[None]:
    """Metrics are global counters; tests assert on behaviour, not on their values."""
    yield


def payload_of(result: Any) -> dict[str, Any]:
    """Pull the structured envelope out of a `CallToolResult`."""
    assert result.structuredContent is not None
    return dict(result.structuredContent)
