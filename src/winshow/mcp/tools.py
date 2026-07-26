"""The seven MCP tools.

Normative source: ``docs/05-mcp-tool-surface.md``.

Seven is a design decision rather than an accident: every tool costs context in the
client and adds a choice the model can get wrong, so each one has to earn its place by
covering a use case no other tool covers.

Two rules from ``docs/02-architecture.md`` §8.4 govern everything here:

* Anything the model or the user could act on becomes a **tool execution error** —
  ``isError: true`` with a structured payload — and only malformed protocol usage becomes
  a JSON-RPC error. MCP clients feed execution errors back to the model, which is exactly
  what should happen to "no agent is connected" or "the policy forbids that path".
* **A command exiting non-zero is a successful tool call.** Conflating "the build failed"
  with "the tool failed" pushes a model to discard the output it needs to explain the
  failure.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from pydantic import BaseModel, ValidationError

from winshow import __version__
from winshow.bridge.bridge import AgentBridge
from winshow.errors import WinShowError, WireErrorCode
from winshow.mcp import rendering
from winshow.mcp.models import (
    FindFilesInput,
    HostInfoInput,
    ListDirectoryInput,
    ReadFileInput,
    RunCommandInput,
    SearchFilesInput,
    StatPathInput,
    envelope_schema,
    human_size,
)
from winshow.observability.audit import AuditLog
from winshow.observability.logging import bind_context, get_logger
from winshow.observability.metrics import record_truncation
from winshow.wire.messages import ExecOutputEvent, Op

__all__ = ["TOOL_NAMES", "build_mcp_server"]

log = get_logger(__name__)

TOOL_NAMES = (
    "winshow_host_info",
    "winshow_list_directory",
    "winshow_stat_path",
    "winshow_read_file",
    "winshow_find_files",
    "winshow_search_files",
    "winshow_run_command",
)

SERVER_INSTRUCTIONS = """\
WinShow brokers file inspection and command execution on ONE remote Windows host. The \
host dials out to this server, so it is reachable only while its agent is connected.

Call winshow_host_info first when you do not know whether the host is up, or before \
proposing a command: it reports the readable roots and the permitted command identifiers, \
which lets you propose something that will work instead of guessing.

Authorization lives on the Windows host, in a policy file a human wrote. A POLICY_DENIED \
result will not become an allow by retrying; tell the user what the policy would have to \
permit instead.
"""

#: §7.3 rate-limiting for progress notifications: roughly four per second with
#: intermediate chunks coalesced, per the MCP specification's guidance on flooding.
PROGRESS_INTERVAL_SECONDS = 0.25
#: The tail of recent output carried on a progress notification.
PROGRESS_MESSAGE_CHARS = 300


class _ProgressPump:
    """Coalesces output chunks into rate-limited progress notifications.

    Nothing may depend on these (A-4): the MCP specification makes progress advisory, a
    server may send none and a client may ignore them. The final buffered result is
    always complete, so a client that ignores progress entirely still sees everything.
    """

    def __init__(self, session: Any, token: str | int, related_request_id: str | None) -> None:
        self._session = session
        self._token = token
        self._related = related_request_id
        self._last_sent = 0.0
        self._pending = ""
        self._bytes = 0

    async def feed(self, chunk: ExecOutputEvent) -> None:
        self._bytes += chunk.bytes
        self._pending = (self._pending + chunk.data)[-PROGRESS_MESSAGE_CHARS:]
        now = time.monotonic()
        if now - self._last_sent < PROGRESS_INTERVAL_SECONDS:
            return
        await self._flush(now)

    async def note_review(self, elapsed_ms: int) -> None:
        """Report that the host's stage-2 policy review is running (§5.5).

        Carries no authorization meaning. Its purpose is to distinguish "under review"
        from "merely slow", which is otherwise indistinguishable from a hung command.
        """
        await self._send(
            f"Waiting on the host's policy review ({elapsed_ms} ms so far)…", self._bytes
        )

    async def _flush(self, now: float) -> None:
        self._last_sent = now
        message = self._pending.strip()
        self._pending = ""
        await self._send(message or None, self._bytes)

    async def _send(self, message: str | None, progress: int) -> None:
        try:
            await self._session.send_progress_notification(
                progress_token=self._token,
                progress=float(progress),
                message=message,
                related_request_id=self._related,
            )
        except Exception:
            # A client that has gone away must not fail the command it was watching.
            log.debug("progress.send_failed", extra={"event": "progress.send_failed"})


def _traceparent(context: Any) -> str | None:
    """Extract the W3C Trace Context header from the originating HTTP request.

    `docs/02-architecture.md` §9.1: the `traceparent` value is propagated from `/mcp`
    into the wire envelope's `trace` field, so one call can be followed from the client
    through this server to the agent's decision and the process it started. The MCP
    revision publishing 2026-07-28 formalises Trace Context, so carrying it now costs
    nothing and saves a change later.
    """
    request = getattr(context, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    value = headers.get("traceparent")
    return str(value) if value else None


def _ok(data: dict[str, Any], text: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structuredContent={"ok": True, "data": data},
        isError=False,
    )


def _hint_for(code: str, details: dict[str, Any]) -> str | None:
    """Compose the sentence written for the model rather than for the log.

    A denial that only says "no" costs a turn. A denial that says what *is* permitted
    lets the model either propose a valid alternative or tell the user precisely what the
    operator would have to change.
    """
    summary = details.get("allowedSummary") or {}
    if code == WireErrorCode.POLICY_DENIED:
        commands = summary.get("allowedCommandIds") or []
        roots = summary.get("readRoots") or []
        if commands:
            return (
                f"Permitted commands on this host are: {', '.join(commands)}. "
                "Ask the operator to extend policy.toml if this one is genuinely needed."
            )
        if roots:
            return (
                f"Readable roots on this host are: {', '.join(roots)}. "
                "A path outside every root is refused before it reaches the filesystem."
            )
        return "Call winshow_host_info to see what this host permits."
    if code == WireErrorCode.POLICY_UNAVAILABLE:
        return (
            "The host's policy file is missing or invalid, so the agent is refusing "
            "everything. The operator needs to fix policy.toml; the agent reloads it "
            "without a restart."
        )
    if code in ("AGENT_UNAVAILABLE", "AGENT_DISCONNECTED"):
        return (
            "The Windows host is not currently connected. Nothing can run until its "
            "agent dials back in; this is worth reporting to the user rather than retrying "
            "in a loop."
        )
    if code == WireErrorCode.AGENT_BUSY:
        return "The host is at its concurrency limit. Retrying shortly should succeed."
    return None


def _fail(exc: WinShowError, request_id: str | None = None) -> types.CallToolResult:
    wire = exc.error
    details = wire.details or {}
    error: dict[str, Any] = {
        "code": wire.code,
        "class": str(wire.cls),
        "message": wire.message,
        "retryable": wire.retryable,
        "rule": wire.rule,
        "reason": details.get("reason"),
        "reason_source": details.get("reasonSource"),
        "hint": _hint_for(wire.code, details),
        "request_id": request_id,
        "win_error": wire.win_error,
        "win_error_name": wire.win_error_name,
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=rendering.render_error(error))],
        structuredContent={"ok": False, "error": error},
        isError=True,
    )


def _entry_out(entry: dict[str, Any]) -> dict[str, Any]:
    """Wire `FileEntry` to the snake_case shape the tool surface documents."""
    return {
        "name": entry.get("name"),
        "path": entry.get("path"),
        "kind": entry.get("kind"),
        "size": entry.get("size", 0),
        "size_human": human_size(int(entry.get("size", 0) or 0)),
        "mtime": entry.get("mtime"),
        "ctime": entry.get("ctime"),
        "atime": entry.get("atime"),
        "attrs": entry.get("attrs", []),
        "link_target": entry.get("linkTarget"),
    }


def _parse(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "<arguments>"
        raise WinShowError(
            WireErrorCode.INVALID_ARGUMENT,
            f"Invalid argument {where}: {first['msg']}.",
        ) from exc


def build_mcp_server(bridge: AgentBridge, audit: AuditLog) -> Server[Any, Any]:
    """Construct the MCP server and register the seven tools against `bridge`."""
    server: Server[Any, Any] = Server(
        name="winshow", version=__version__, instructions=SERVER_INSTRUCTIONS
    )

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return _tool_definitions()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        handler = _HANDLERS.get(name)
        if handler is None:
            # An unknown tool name is protocol misuse rather than something the model can
            # act on, so it is the one case that becomes a plain exception and therefore
            # a JSON-RPC error.
            raise ValueError(f"Unknown tool {name!r}")

        request_id: str | None = None
        try:
            context = server.request_context
            request_id = str(context.request_id)
        except LookupError:
            context = None

        with bind_context(
            mcp_request_id=request_id, tool=name, traceparent=_traceparent(context)
        ):
            try:
                return await handler(bridge, audit, arguments, context)
            except WinShowError as exc:
                log.info(
                    "tool.failed",
                    extra={"event": "tool.failed", "tool": name, "code": exc.code},
                )
                return _fail(exc, request_id)

    return server


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


async def _host_info(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    _parse(HostInfoInput, arguments)
    # Never fails while the server is up: the absence of a host is information, not an
    # error, so a disconnected agent is `ok: true` with `connected: false`.
    data = bridge.host_info()
    return _ok(data, rendering.render_host_info(data))


async def _list_directory(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: ListDirectoryInput = _parse(ListDirectoryInput, arguments)
    payload: dict[str, Any] = {
        "path": args.path,
        "offset": args.offset,
        "limit": args.limit,
        "pattern": args.pattern,
        "includeHidden": args.include_hidden,
        "sort": args.sort,
        "descending": args.descending,
    }
    if args.kinds:
        payload["kinds"] = args.kinds

    result = await bridge.call(Op.FS_LIST, payload, trace=_traceparent(context))
    data = {
        "path": result.get("path", args.path),
        "entries": [_entry_out(e) for e in result.get("entries", [])],
        "total": result.get("total", 0),
        "truncated": result.get("truncated", False),
        "truncation_reason": result.get("truncationReason"),
    }
    if data["truncated"]:
        record_truncation(str(data["truncation_reason"] or "unknown"))
    return _ok(data, rendering.render_listing(data))


async def _stat_path(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: StatPathInput = _parse(StatPathInput, arguments)
    result = await bridge.call(
        Op.FS_STAT,
        {
            "path": args.path,
            "resolveLinks": args.resolve_links,
            "sniff": args.sniff,
            "hash": args.hash,
        },
        trace=_traceparent(context),
    )
    sniff = result.get("sniff")
    data = {
        "path": result.get("path", args.path),
        # A missing path is a successful result with exists: false, not an error. That
        # lets a model check for something without triggering an error-handling path.
        "exists": result.get("exists", False),
        "entry": _entry_out(result["entry"]) if result.get("entry") else None,
        "real_path": result.get("realPath"),
        "sniff": None
        if not sniff
        else {
            "is_probably_text": sniff.get("isProbablyText"),
            "encoding": sniff.get("encoding"),
            "has_bom": sniff.get("hasBom"),
            "line_ending": sniff.get("lineEnding"),
            "sampled_bytes": sniff.get("sampledBytes"),
        },
        "sha256": result.get("sha256"),
        "volume": result.get("volume"),
    }
    return _ok(data, rendering.render_stat(data))


async def _read_file(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: ReadFileInput = _parse(ReadFileInput, arguments)

    # §4.3: exactly one of three addressing modes. Checked here rather than on the wire
    # so the message can name all three and the model can correct itself in one turn.
    modes = {
        "tail_lines": args.tail_lines is not None,
        "from_line": args.from_line is not None,
        "offset": args.offset is not None,
    }
    chosen = [name for name, given in modes.items() if given]
    if len(chosen) > 1:
        raise WinShowError(
            WireErrorCode.INVALID_ARGUMENT,
            f"Choose exactly one addressing mode; got {', '.join(chosen)}. Use tail_lines "
            "for the end of a log, from_line with line_count for a known region, or "
            "offset with length for a byte range.",
        )
    if not chosen:
        raise WinShowError(
            WireErrorCode.INVALID_ARGUMENT,
            "Choose an addressing mode: tail_lines for the end of a log (the usual "
            "choice), from_line with line_count for a known region, or offset with "
            "length for a byte range.",
        )

    payload: dict[str, Any] = {
        "path": args.path,
        "encoding": args.encoding,
        "force": args.force_text,
    }
    if args.tail_lines is not None:
        payload["tailLines"] = args.tail_lines
    elif args.from_line is not None:
        payload["fromLine"] = args.from_line
        payload["lineCount"] = args.line_count or 200
    else:
        payload["offset"] = args.offset
        if args.length is not None:
            payload["length"] = args.length
    if args.max_bytes is not None:
        payload["maxBytes"] = args.max_bytes

    result = await bridge.call(Op.FS_READ, payload, trace=_traceparent(context))
    encoding = result.get("encoding", "utf-8")
    data = {
        "content": result.get("data") or "",
        "encoding": encoding,
        "is_binary": encoding == "binary",
        "had_bom": result.get("hadBom", False),
        "byte_offset": result.get("byteOffset", 0),
        "byte_length": result.get("byteLength", 0),
        "file_size": result.get("fileSize", 0),
        "eof": result.get("eof", False),
        "first_line": result.get("firstLine"),
        "line_count": result.get("lineCount"),
        "total_lines": result.get("totalLines"),
        "truncated": result.get("truncated", False),
        "line_ending": result.get("lineEnding", "none"),
        "decode_errors": result.get("decodeErrors", 0),
    }
    if data["truncated"]:
        record_truncation("read_cap")
    return _ok(data, rendering.render_read(data))


async def _find_files(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: FindFilesInput = _parse(FindFilesInput, arguments)
    result = await bridge.call(
        Op.FS_GLOB,
        {
            "root": args.root,
            "patterns": args.patterns,
            "excludes": args.excludes,
            "maxDepth": args.max_depth,
            "maxResults": args.max_results,
            "timeBudgetMs": args.time_budget_ms,
            "kinds": args.kinds,
            "includeHidden": args.include_hidden,
            "stat": args.with_stat,
        },
        timeout_ms=args.time_budget_ms + 5_000,
        trace=_traceparent(context),
    )
    raw_matches = result.get("matches", [])
    data = {
        "matches": [_entry_out(m) if isinstance(m, dict) else m for m in raw_matches],
        "count": result.get("count", len(raw_matches)),
        "truncated": result.get("truncated", False),
        "truncation_reason": result.get("truncationReason"),
        "scanned_dirs": result.get("scannedDirs", 0),
        "elapsed_ms": result.get("elapsedMs", 0),
    }
    if data["truncated"]:
        record_truncation(str(data["truncation_reason"] or "unknown"))
    return _ok(data, rendering.render_find(data))


async def _search_files(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: SearchFilesInput = _parse(SearchFilesInput, arguments)
    result = await bridge.call(
        Op.FS_GREP,
        {
            "root": args.root,
            "query": args.query,
            "isRegex": args.is_regex,
            "caseSensitive": args.case_sensitive,
            "patterns": args.patterns,
            "excludes": args.excludes,
            "contextBefore": args.context_before,
            "contextAfter": args.context_after,
            "maxMatches": args.max_matches,
            "maxMatchesPerFile": args.max_matches_per_file,
            "maxFileBytes": args.max_file_bytes,
            "skipBinary": args.skip_binary,
            "timeBudgetMs": args.time_budget_ms,
        },
        timeout_ms=args.time_budget_ms + 5_000,
        trace=_traceparent(context),
    )
    data = {
        "matches": result.get("matches", []),
        "count": result.get("count", 0),
        "files_scanned": result.get("filesScanned", 0),
        "files_skipped": result.get("filesSkipped", 0),
        "truncated": result.get("truncated", False),
        "truncation_reason": result.get("truncationReason"),
        "elapsed_ms": result.get("elapsedMs", 0),
    }
    if data["truncated"]:
        record_truncation(str(data["truncation_reason"] or "unknown"))
    return _ok(data, rendering.render_search(data))


async def _run_command(
    bridge: AgentBridge, audit: AuditLog, arguments: dict[str, Any], context: Any
) -> types.CallToolResult:
    args: RunCommandInput = _parse(RunCommandInput, arguments)

    if (args.argv is None) == (args.command_line is None):
        raise WinShowError(
            WireErrorCode.INVALID_ARGUMENT,
            "Supply exactly one of argv or command_line. argv is the normal choice: the "
            "arguments are passed to the process directly and are not parsed by a shell.",
        )
    if args.command_line is not None and args.shell == "none":
        raise WinShowError(
            WireErrorCode.INVALID_ARGUMENT,
            "command_line requires a shell. Set shell to cmd, powershell or pwsh, or pass "
            "argv instead — with shell 'none' there is nothing to parse a command line.",
        )

    payload: dict[str, Any] = {
        "shell": args.shell,
        "envMode": args.env_mode,
        "mergeStderr": args.merge_stderr,
    }
    if args.argv is not None:
        payload["argv"] = args.argv
    else:
        payload["commandLine"] = args.command_line
    if args.cwd is not None:
        payload["cwd"] = args.cwd
    if args.env:
        payload["env"] = args.env
    if args.timeout_ms is not None:
        payload["timeoutMs"] = args.timeout_ms
    if args.max_output_bytes is not None:
        payload["maxOutputBytes"] = args.max_output_bytes
    if args.stdin is not None:
        payload["stdin"] = args.stdin

    session = bridge.session
    mcp_request_id = str(context.request_id) if context is not None else None
    audit.exec_dispatch(
        request_id=mcp_request_id or "unknown",
        agent_id=session.agent_id if session else "none",
        hostname=(session.hello.os.get("hostname") if session else None),
        mcp_client=_client_identity(context),
        principal=None,
        argv=args.argv,
        shell=args.shell,
        cwd=args.cwd,
        # The names only, never the values: an overlay is exactly where a caller would
        # put a credential.
        env_overlay_keys=sorted(args.env.keys()),
        timeout_ms=args.timeout_ms,
    )

    pump: _ProgressPump | None = None
    if context is not None and context.meta is not None and context.meta.progressToken is not None:
        pump = _ProgressPump(
            context.session, context.meta.progressToken, str(context.request_id)
        )

    try:
        result = await bridge.call(
            Op.EXEC_START,
            payload,
            timeout_ms=args.timeout_ms,
            on_output=pump.feed if pump else None,
            on_review=pump.note_review if pump else None,
            trace=_traceparent(context),
        )
    except WinShowError as exc:
        wire_details = exc.error.details or {}
        if exc.code == WireErrorCode.POLICY_DENIED:
            audit.exec_denied(
                request_id=mcp_request_id or "unknown",
                agent_id=session.agent_id if session else "none",
                argv=args.argv,
                shell=args.shell,
                rule=exc.error.rule,
                reason=wire_details.get("reason"),
                reason_source=wire_details.get("reasonSource"),
            )
        raise
    except asyncio.CancelledError:
        # The client withdrew the call. The agent has already been told to terminate the
        # process tree by AgentSession; nothing useful can be returned to a caller that
        # is no longer listening, so the cancellation propagates.
        log.info("tool.cancelled", extra={"event": "tool.cancelled", "tool": "winshow_run_command"})
        raise

    data = {
        "exit_code": result.get("exitCode"),
        "exit_code_signed": result.get("exitCodeSigned"),
        "exit_reason": result.get("exitReason", "exited"),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "truncated": result.get("truncated", False),
        "truncation_reason": result.get("truncationReason"),
        "partial": result.get("partial", False),
        "duration_ms": result.get("durationMs", 0),
        "pid": result.get("pid"),
        "command_line_used": result.get("commandLineUsed", ""),
        "resolved_executable": result.get("resolvedExecutable", ""),
    }
    if data["truncated"]:
        record_truncation(str(data["truncation_reason"] or "maxOutputBytes"))

    audit.exec_complete(
        request_id=mcp_request_id or "unknown",
        pid=data["pid"],
        exit_code=data["exit_code"],
        exit_reason=str(data["exit_reason"]),
        duration_ms=int(data["duration_ms"] or 0),
        stdout_bytes=int(result.get("stdoutBytes", 0) or 0),
        stderr_bytes=int(result.get("stderrBytes", 0) or 0),
        truncated=bool(data["truncated"]),
    )
    return _ok(data, rendering.render_command(data))


def _client_identity(context: Any) -> dict[str, Any] | None:
    """Best-effort identification of the calling MCP client, for the audit record."""
    if context is None:
        return None
    session = getattr(context, "session", None)
    params = getattr(session, "client_params", None)
    info = getattr(params, "clientInfo", None) if params else None
    if info is None:
        return None
    return {"name": getattr(info, "name", None), "version": getattr(info, "version", None)}


_HANDLERS = {
    "winshow_host_info": _host_info,
    "winshow_list_directory": _list_directory,
    "winshow_stat_path": _stat_path,
    "winshow_read_file": _read_file,
    "winshow_find_files": _find_files,
    "winshow_search_files": _search_files,
    "winshow_run_command": _run_command,
}


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------

_ENTRY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "path": {"type": "string"},
        "kind": {"type": "string"},
        "size": {"type": "integer"},
        "size_human": {"type": "string"},
        "mtime": {"type": ["string", "null"]},
        "ctime": {"type": ["string", "null"]},
        "atime": {"type": ["string", "null"]},
        "attrs": {"type": "array", "items": {"type": "string"}},
        "link_target": {"type": ["string", "null"]},
    },
}


def _obj(**properties: Any) -> dict[str, Any]:
    return {"type": "object", "properties": properties}


def _tool_definitions() -> list[types.Tool]:
    """The tool list, with the descriptions the model actually reads.

    Each description is doing work. `winshow_run_command`'s, in particular, exists to
    prevent four specific observed failures: passing a shell string into `argv`,
    expecting `|` to work without a shell, guessing at commands that will be denied, and
    treating a failed build as a broken tool.
    """
    return [
        types.Tool(
            name="winshow_host_info",
            title="Windows host status and policy",
            description=(
                "Report the status of the connection to the remote Windows host, and what "
                "that host permits. Call this first when you do not know whether the host "
                "is reachable, or before proposing a command, so you can see which "
                "commands and paths are allowed rather than guessing."
            ),
            inputSchema=HostInfoInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    connected={"type": "boolean"},
                    connected_since={"type": ["string", "null"]},
                    last_seen_at={"type": ["string", "null"]},
                    agent={"type": ["object", "null"]},
                    host={"type": ["object", "null"]},
                    identity={"type": ["object", "null"]},
                    capabilities={"type": "array", "items": {"type": "string"}},
                    limits={"type": ["object", "null"]},
                    policy={"type": ["object", "null"]},
                    clock_skew_seconds={"type": ["number", "null"]},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_list_directory",
            title="List a directory on the Windows host",
            description=(
                "List the contents of a directory on the remote Windows host. Returns "
                "name, size, timestamps and attributes for each entry. Use sort and "
                "descending to find the newest or largest files without reading them."
            ),
            inputSchema=ListDirectoryInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    path={"type": "string"},
                    entries={"type": "array", "items": _ENTRY_SCHEMA},
                    total={"type": "integer"},
                    truncated={"type": "boolean"},
                    truncation_reason={"type": ["string", "null"]},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_stat_path",
            title="Inspect one path on the Windows host",
            description=(
                "Get details about a single file or directory on the remote Windows host, "
                "including whether it exists at all, its size and timestamps, and — for "
                "text files — the detected encoding and line ending. Use this to check for "
                "a file before reading it. A missing path is a normal result with "
                "exists: false, not an error."
            ),
            inputSchema=StatPathInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    path={"type": "string"},
                    exists={"type": "boolean"},
                    entry={"anyOf": [_ENTRY_SCHEMA, {"type": "null"}]},
                    real_path={"type": ["string", "null"]},
                    sniff={"type": ["object", "null"]},
                    sha256={"type": ["string", "null"]},
                    volume={"type": ["object", "null"]},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_read_file",
            title="Read part of a file on the Windows host",
            description=(
                "Read a file from the remote Windows host. Choose exactly one addressing "
                "mode: tail_lines for the end of a log (the usual choice), from_line with "
                "line_count for a known region, or offset with length for a byte range. "
                "Large files are never transferred whole; ask for the part you need."
            ),
            inputSchema=ReadFileInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    content={"type": "string"},
                    encoding={"type": "string"},
                    is_binary={"type": "boolean"},
                    had_bom={"type": "boolean"},
                    byte_offset={"type": "integer"},
                    byte_length={"type": "integer"},
                    file_size={"type": "integer"},
                    eof={"type": "boolean"},
                    first_line={"type": ["integer", "null"]},
                    line_count={"type": ["integer", "null"]},
                    total_lines={"type": ["integer", "null"]},
                    truncated={"type": "boolean"},
                    line_ending={"type": "string"},
                    decode_errors={"type": "integer"},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_find_files",
            title="Find files by glob on the Windows host",
            description=(
                "Find files on the remote Windows host by glob pattern. Supports *, ?, ** "
                "for any number of directories, character classes and {a,b} alternation. "
                "Matching is case-insensitive. Searching happens on the Windows host; only "
                "the matching paths are returned."
            ),
            inputSchema=FindFilesInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    matches={"type": "array"},
                    count={"type": "integer"},
                    truncated={"type": "boolean"},
                    truncation_reason={"type": ["string", "null"]},
                    scanned_dirs={"type": "integer"},
                    elapsed_ms={"type": "integer"},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_search_files",
            title="Search file contents on the Windows host",
            description=(
                "Search the contents of files on the remote Windows host for a string or a "
                "regular expression, returning matching lines with optional surrounding "
                "context. The search runs on the Windows host, so only the matches cross "
                "the network. Backreferences and lookaround are not supported, so that "
                "matching is guaranteed linear-time; an unsupported construct is rejected "
                "by name."
            ),
            inputSchema=SearchFilesInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    matches={"type": "array"},
                    count={"type": "integer"},
                    files_scanned={"type": "integer"},
                    files_skipped={"type": "integer"},
                    truncated={"type": "boolean"},
                    truncation_reason={"type": ["string", "null"]},
                    elapsed_ms={"type": "integer"},
                )
            ),
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
        ),
        types.Tool(
            name="winshow_run_command",
            title="Run a command on the Windows host",
            description=(
                "Run a command on the remote Windows host and return its output and exit "
                "code. Pass the program and its arguments as a list (argv) — the arguments "
                "are NOT parsed by a shell, so pipes, redirection and wildcards do not work "
                "unless you explicitly set shell. Only commands permitted by the host's "
                "policy will run; call winshow_host_info to see which ones. A non-zero exit "
                "code is a normal result, not an error."
            ),
            inputSchema=RunCommandInput.model_json_schema(),
            outputSchema=envelope_schema(
                _obj(
                    exit_code={"type": ["integer", "null"]},
                    exit_code_signed={"type": ["integer", "null"]},
                    exit_reason={"type": "string"},
                    stdout={"type": "string"},
                    stderr={"type": "string"},
                    truncated={"type": "boolean"},
                    truncation_reason={"type": ["string", "null"]},
                    partial={"type": "boolean"},
                    duration_ms={"type": "integer"},
                    pid={"type": ["integer", "null"]},
                    command_line_used={"type": "string"},
                    resolved_executable={"type": "string"},
                )
            ),
            annotations=types.ToolAnnotations(
                # Not read-only and not idempotent: exec.start is the one operation with
                # real consequences, and §8.7 forbids anyone retrying it automatically.
                readOnlyHint=False,
                idempotentHint=False,
                destructiveHint=True,
                openWorldHint=True,
            ),
        ),
    ]
