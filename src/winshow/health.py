"""Liveness and readiness probes.

The distinction between the two earns its keep here (``docs/07-operations.md`` §1.1).
Liveness answers "should this process be restarted", and restarting the server because
the *Windows host* rebooted would be exactly wrong. Readiness answers "can this server
currently do its job", which is false — correctly — from the moment the agent drops until
it completes a new handshake.

Wire a load balancer to `/readyz` and a process supervisor to `/healthz`, never the other
way round.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse

from winshow import __version__
from winshow.bridge.bridge import AgentBridge

__all__ = ["make_health_routes"]

Endpoint = Callable[[Request], Awaitable[JSONResponse]]


def make_health_routes(bridge: AgentBridge) -> tuple[Endpoint, Endpoint]:
    """Return the `/healthz` and `/readyz` handlers bound to `bridge`."""

    async def healthz(request: Request) -> JSONResponse:
        # Green whenever the process is alive and its event loop is responsive. It says
        # nothing about the agent, deliberately.
        return JSONResponse({"status": "ok", "version": __version__})

    async def readyz(request: Request) -> JSONResponse:
        session = bridge.session
        ready = bridge.is_ready
        body = {
            "status": "ready" if ready else "no-agent",
            "agent_connected": ready,
            "agent_id": session.agent_id if session else None,
            "session_id": session.session_id if session else None,
        }
        # 503 rather than 200-with-a-flag: a load balancer reads the status code, and a
        # server with no agent cannot serve a single useful tool call.
        return JSONResponse(body, status_code=200 if ready else 503)

    return healthz, readyz
