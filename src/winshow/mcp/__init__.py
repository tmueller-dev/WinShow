"""The MCP side: the seven tools an assistant sees, and how results are shaped.

Named `mcp` for symmetry with `wire`, which holds the other protocol. Imports of the
upstream SDK inside this package use absolute `mcp.` paths, which resolve to the
installed distribution rather than to this package because the project uses a src layout
and absolute imports.
"""

from __future__ import annotations

from winshow.mcp.tools import TOOL_NAMES, build_mcp_server

__all__ = ["TOOL_NAMES", "build_mcp_server"]
