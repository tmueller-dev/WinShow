"""Command-line entry point: `winshow` or `python -m winshow`.

Runs the public listener and, unless disabled, the admin listener that carries
`/metrics`. They are separate servers on separate addresses because the metric set names
the agent, the host and the denial counts, and none of that belongs on a public port.

Exactly **one** worker, always. The agent holds a single WebSocket, and with two workers
that socket lands in one of them while an MCP request may arrive in the other — where the
bridge has no agent to route to (``docs/07-operations.md`` §1).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import secrets
import sys

import uvicorn

from winshow import __version__
from winshow.app import create_admin_app, create_app
from winshow.config import get_settings, set_settings
from winshow.observability.logging import get_logger

__all__ = ["main"]

log = get_logger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="winshow",
        description="WinShow MCP server — brokers a remote Windows host that dials out.",
    )
    parser.add_argument("--version", action="version", version=f"winshow {__version__}")
    parser.add_argument("--host", default=None, help="Public bind address")
    parser.add_argument("--port", type=int, default=None, help="Public port")
    parser.add_argument(
        "--generate-token",
        action="store_true",
        help="Print a fresh agent token and exit. Transfer it out of band.",
    )
    return parser.parse_args(argv)


async def _serve() -> None:
    settings = get_settings()
    public = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host=settings.host,
            port=settings.port,
            # WinShow installs its own JSON formatter; letting uvicorn configure logging
            # would produce two formats in one stream and defeat machine parsing.
            log_config=None,
            access_log=False,
            # Raised well above the heartbeat so an idle-but-healthy agent connection is
            # not closed between two pings.
            timeout_keep_alive=75,
        )
    )

    servers = [public.serve()]
    admin_app = create_admin_app(settings)
    if admin_app is not None and settings.admin_host:
        admin = uvicorn.Server(
            uvicorn.Config(
                admin_app,
                host=settings.admin_host,
                port=settings.admin_port,
                log_config=None,
                access_log=False,
            )
        )
        servers.append(admin.serve())
        log.info(
            "admin.listening",
            extra={
                "event": "admin.listening",
                "host": settings.admin_host,
                "port": settings.admin_port,
            },
        )

    await asyncio.gather(*servers)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.generate_token:
        # The same command the operations document tells operators to run, so the token
        # is generated where it is going into the valid set anyway.
        print(secrets.token_urlsafe(32))
        return 0

    if args.host is not None or args.port is not None:
        overrides = {}
        if args.host is not None:
            overrides["host"] = args.host
        if args.port is not None:
            overrides["port"] = args.port
        set_settings(get_settings(**overrides))

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
