"""WinShow — an MCP server for a Windows host that cannot accept inbound connections.

The Windows host dials out to this server and holds the connection open; the server
brokers MCP tool calls across it. Authorization lives entirely on the Windows agent, and
this server performs no filtering of paths or commands (NFR-4).

See ``docs/00-overview.md`` for orientation and ``docs/03-agent-protocol.md`` for the
normative wire contract.
"""

from __future__ import annotations

__all__ = ["SERVER_NAME", "__version__"]

__version__ = "0.1.0"
SERVER_NAME = "winshow-server"
