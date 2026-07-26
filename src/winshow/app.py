"""The ASGI application: `/mcp`, `/agent` and the health probes in one process.

Normative source: ``docs/02-architecture.md`` §2 and ``docs/07-operations.md`` §1.1.

`/mcp` and `/agent` share one listener deliberately. Port 443 is the one port that
reliably survives corporate egress filtering, and colocating them means one certificate,
one DNS name, and one firewall rule to explain to whoever administers the network.

`/metrics` is the exception and binds a **separate** admin address, because the metric
set names the agent, the host and the denial counts.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.types import Receive, Scope, Send

from winshow.bridge.bridge import AgentBridge
from winshow.config import Settings, get_settings
from winshow.health import make_health_routes
from winshow.mcp.tools import build_mcp_server
from winshow.observability.audit import AuditLog
from winshow.observability.logging import configure_logging, get_logger
from winshow.observability.metrics import metrics_app
from winshow.transport.agent_ws import make_agent_endpoint

# "app" is resolved by the module-level __getattr__ below, so it is deliberately
# absent here: listing a name ruff cannot see statically is a false signal.
__all__ = ["create_admin_app", "create_app"]

log = get_logger(__name__)


def _transport_security(settings: Settings) -> TransportSecuritySettings:
    """DNS-rebinding protection for `/mcp`.

    Keyed on `allowed_hosts` alone, deliberately. The SDK's middleware rejects **every**
    Host when protection is on and the host list is empty — there is no allow-all — so
    enabling it merely because origins were configured would take `/mcp` off the air with
    a 421 that looks nothing like a configuration mistake.

    The Origin check is therefore performed separately, by `_OriginGuard` below, which is
    also what `docs/07-operations.md` §1.2 asks for: a **403** on mismatch.
    """
    enabled = bool(settings.allowed_hosts)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=enabled,
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )


class _OriginGuard:
    """Rejects an `/mcp` request whose `Origin` is not on the configured list.

    `docs/06-security.md` §6: the header exists to stop a *browser* being used as a
    confused deputy against a server the user's machine can reach. A request with no
    `Origin` at all is accepted, because non-browser MCP clients do not send one and
    refusing them would break every legitimate caller to defend against none.

    An empty allow-list disables the check. That is correct behind an authenticating
    reverse proxy doing it instead, and wrong if nothing is — hence the warning at
    startup.
    """

    def __init__(self, app: Any, settings: Settings) -> None:
        self._app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            origin = None
            for name, value in scope.get("headers", []):
                if name == b"origin":
                    origin = value.decode("latin-1")
                    break
            if not self._settings.origin_is_allowed(origin):
                log.warning(
                    "mcp.origin_rejected",
                    extra={"event": "mcp.origin_rejected", "origin": origin},
                )
                response = PlainTextResponse("Origin not allowed.", status_code=403)
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


def create_app(settings: Settings | None = None) -> Starlette:
    """Build the public application."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    bridge = AgentBridge(settings)
    audit = AuditLog(settings.audit_file)
    mcp_server = build_mcp_server(bridge, audit)

    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        # No event store: resumability would mean replaying an agent's output after a
        # reconnect, and §4 of the architecture is explicit that a reconnection
        # resurrects nothing.
        event_store=None,
        json_response=False,
        security_settings=_transport_security(settings),
    )

    async def handle_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    guarded_mcp = _OriginGuard(handle_mcp, settings)
    if not settings.allowed_origins:
        log.warning(
            "mcp.origin_check_disabled",
            extra={
                "event": "mcp.origin_check_disabled",
                "hint": "Set WINSHOW_ALLOWED_ORIGINS unless a proxy validates Origin for you.",
            },
        )

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        # This is the mounting detail that is easy to get wrong and silent when wrong:
        # the SDK's session manager MUST be run from the PARENT application's lifespan.
        # A nested lifespan on a mounted sub-application is not executed, and the symptom
        # is a server that accepts connections and then never initialises
        # (docs/adr/0005-python-mcp-sdk-selection.md).
        async with session_manager.run():
            log.info(
                "server.started",
                extra={
                    "event": "server.started",
                    "mcp_path": settings.mcp_path,
                    "agent_path": settings.agent_path,
                    "tokens_configured": len(settings.agent_tokens),
                },
            )
            try:
                yield
            finally:
                await bridge.shutdown()
                log.info("server.stopped", extra={"event": "server.stopped"})

    healthz, readyz = make_health_routes(bridge)

    application = Starlette(
        routes=[
            Mount(settings.mcp_path, app=guarded_mcp),
            WebSocketRoute(settings.agent_path, endpoint=make_agent_endpoint(bridge, settings)),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
            # Deliberately not the metrics endpoint: a request for /metrics on the public
            # listener is answered with a pointer rather than the data.
            Route("/metrics", _metrics_moved, methods=["GET"]),
        ],
        lifespan=lifespan,
    )
    # Kept on the app so tests and embedders can reach them without rebuilding anything.
    application.state.bridge = bridge
    application.state.settings = settings
    application.state.audit = audit
    return application


async def _metrics_moved(request: Any) -> PlainTextResponse:
    return PlainTextResponse(
        "Metrics are served on the admin listener, not here. See docs/07-operations.md §1.1.",
        status_code=404,
    )


def create_admin_app(settings: Settings | None = None) -> Any:
    """The admin listener, serving only the Prometheus exposition."""
    settings = settings or get_settings()
    if not settings.metrics_enabled:
        return None
    return metrics_app()


_default_app: Starlette | None = None


def __getattr__(name: str) -> Any:
    """Construct the default application on first access to `winshow.app:app`.

    `docs/07-operations.md` §2 documents `uvicorn winshow.app:app`, with no `--factory`,
    so the attribute has to exist. Building it lazily rather than at import time keeps a
    plain `import winshow.app` — in a test, or to read a constant — from reconfiguring
    logging and instantiating a bridge as a side effect.
    """
    if name == "app":
        global _default_app
        if _default_app is None:
            _default_app = create_app()
        return _default_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
