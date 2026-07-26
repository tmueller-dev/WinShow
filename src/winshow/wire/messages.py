"""Typed payloads for every WSAP/1 operation.

Normative source: ``docs/03-agent-protocol.md`` §3–§5, with the machine-readable
companion in ``docs/schemas/wsap-v1-messages.schema.json``.

Every model sets ``extra="allow"``. That is §11.1 rule 1 — receivers MUST ignore unknown
fields at any nesting depth — and it is what lets a v1 server keep working against an
agent built against a later minor revision of this same wire version.

The wire is camelCase and the Python is snake_case, so each field carries an alias.
Serialisation always goes through ``by_alias=True``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AgentLimits",
    "ByeEvent",
    "ByeReason",
    "CancelReason",
    "CancelRequest",
    "CancelResponse",
    "Encoding",
    "ExecAckEvent",
    "ExecExitEvent",
    "ExecOutputEvent",
    "ExecStartRequest",
    "ExecStartResponse",
    "ExitReason",
    "FileEntry",
    "FsGlobRequest",
    "FsGlobResponse",
    "FsGrepRequest",
    "FsGrepResponse",
    "FsListRequest",
    "FsListResponse",
    "FsReadChunkEvent",
    "FsReadRequest",
    "FsReadResponse",
    "FsStatRequest",
    "FsStatResponse",
    "GrepMatch",
    "HelloRequest",
    "HelloResponse",
    "Op",
    "PingRequest",
    "PingResponse",
    "PolicyReviewingEvent",
    "PolicySummary",
]


class _Wire(BaseModel):
    """Base for every payload: camelCase on the wire, tolerant of unknown fields."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    def wire(self) -> dict[str, Any]:
        """The payload as it goes onto the wire.

        ``exclude_none`` keeps absent optionals off the wire entirely rather than
        sending explicit nulls the peer would have to distinguish from "not set".
        """
        return self.model_dump(by_alias=True, exclude_none=True)


class Op(StrEnum):
    """Operation names (§6.1).

    Those marked *implicit* in the specification are part of the base protocol and
    MUST NOT be advertised in ``capabilities``; every agent implements them.
    """

    SESSION_HELLO = "session.hello"
    SESSION_PING = "session.ping"
    SESSION_CANCEL = "session.cancel"
    SESSION_BYE = "session.bye"
    FS_LIST = "fs.list"
    FS_STAT = "fs.stat"
    FS_READ = "fs.read"
    FS_READ_CHUNK = "fs.read.chunk"
    FS_GLOB = "fs.glob"
    FS_GREP = "fs.grep"
    EXEC_START = "exec.start"
    EXEC_OUTPUT = "exec.output"
    EXEC_ACK = "exec.ack"
    EXEC_EXIT = "exec.exit"
    POLICY_REVIEWING = "policy.reviewing"


#: §6.1: implicit operations are never listed in `capabilities`.
IMPLICIT_OPS: frozenset[str] = frozenset(
    {Op.SESSION_HELLO, Op.SESSION_PING, Op.SESSION_CANCEL, Op.SESSION_BYE, Op.EXEC_ACK}
)

#: Operations the server may send to an agent that advertised them.
REQUESTABLE_OPS: frozenset[str] = frozenset(
    {Op.FS_LIST, Op.FS_STAT, Op.FS_READ, Op.FS_GLOB, Op.FS_GREP, Op.EXEC_START}
)

# `Encoding` is an open string enum on the wire (§4.0). Modelled as a Literal for the
# values this build knows, but every field typed with it accepts a plain str as well,
# because §11.1 rule 4 requires tolerating new enum values rather than failing.
Encoding = str

KNOWN_ENCODINGS: frozenset[str] = frozenset(
    {
        "utf-8",
        "utf-16le",
        "utf-16be",
        "utf-32le",
        "cp1252",
        "cp850",
        "oem",
        "ansi",
        "binary",
        "auto",
    }
)


class ExitReason(StrEnum):
    """§5.4. Authoritative — consumers MUST prefer it over inferring from `exitCode`."""

    EXITED = "exited"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    KILLED = "killed"
    BACKPRESSURE = "backpressure"
    AGENT_SHUTDOWN = "agentShutdown"
    #: Server-side only: the agent vanished mid-run. Never sent by an agent.
    DISCONNECTED = "disconnected"


class CancelReason(StrEnum):
    """§3.3. Three triggers, one mechanism."""

    CLIENT_CANCELLED = "client_cancelled"
    TIMEOUT = "timeout"
    SERVER_SHUTDOWN = "server_shutdown"
    BUFFER_LIMIT = "buffer_limit"


class ByeReason(StrEnum):
    SHUTDOWN = "shutdown"
    SUPERSEDED = "superseded"
    POLICY_RELOAD_FAILED = "policy_reload_failed"
    FATAL = "fatal"


# ---------------------------------------------------------------------------
# Shared types (§4.0)
# ---------------------------------------------------------------------------


class FileEntry(_Wire):
    name: str
    path: str
    kind: Literal["file", "dir", "symlink", "junction", "other"] | str
    size: int = 0
    mtime: str | None = None
    ctime: str | None = None
    atime: str | None = None
    attrs: list[str] = Field(default_factory=list)
    link_target: str | None = Field(default=None, alias="linkTarget")


# ---------------------------------------------------------------------------
# Session operations (§3)
# ---------------------------------------------------------------------------


class AgentLimits(_Wire):
    """The agent's advertised limits (§3.1). Defaults match the specification."""

    max_frame_bytes: int = Field(default=1_048_576, alias="maxFrameBytes")
    max_concurrent_requests: int = Field(default=16, alias="maxConcurrentRequests")
    max_concurrent_processes: int = Field(default=4, alias="maxConcurrentProcesses")
    max_output_bytes_per_exec: int = Field(default=4_194_304, alias="maxOutputBytesPerExec")
    max_exec_millis: int = Field(default=300_000, alias="maxExecMillis")
    max_read_bytes: int = Field(default=1_048_576, alias="maxReadBytes")
    max_glob_results: int = Field(default=5_000, alias="maxGlobResults")
    ack_window_chunks: int = Field(default=64, alias="ackWindowChunks")
    ack_window_bytes: int = Field(default=4_194_304, alias="ackWindowBytes")


class PolicySummary(_Wire):
    """The policy **summary** reported at handshake — never the full policy.

    FR-3 exists because of this block: an assistant that knows the read roots and the
    permitted command identifiers proposes something that works, instead of spending
    three turns guessing. See ``docs/04-agent-policy.md`` §7.
    """

    policy_version: str | None = Field(default=None, alias="policyVersion")
    policy_hash: str | None = Field(default=None, alias="policyHash")
    state: str = "ok"
    read_roots: list[str] = Field(default_factory=list, alias="readRoots")
    deny_glob_count: int | None = Field(default=None, alias="denyGlobCount")
    exec_mode: str | None = Field(default=None, alias="execMode")
    allowed_command_count: int | None = Field(default=None, alias="allowedCommandCount")
    allowed_command_ids: list[str] = Field(default_factory=list, alias="allowedCommandIds")
    shells_allowed: list[str] = Field(default_factory=list, alias="shellsAllowed")
    write_enabled: bool = Field(default=False, alias="writeEnabled")
    model_review: dict[str, Any] | None = Field(default=None, alias="modelReview")
    max_output_bytes: int | None = Field(default=None, alias="maxOutputBytes")
    max_exec_millis: int | None = Field(default=None, alias="maxExecMillis")
    denial_disclosure: str | None = Field(default=None, alias="denialDisclosure")


class HelloRequest(_Wire):
    """`session.hello` request — the only request an agent originates besides a ping."""

    wire_versions: list[int] = Field(alias="wireVersions")
    agent_id: str = Field(alias="agentId")
    agent: dict[str, Any]
    os: dict[str, Any]
    identity: dict[str, Any]
    capabilities: list[str]
    features: list[str] = Field(default_factory=list)
    limits: AgentLimits = Field(default_factory=AgentLimits)
    policy: PolicySummary = Field(default_factory=PolicySummary)
    clock: dict[str, Any] = Field(default_factory=dict)
    resume_of: str | None = Field(default=None, alias="resumeOf")


class HelloResponse(_Wire):
    wire_version: int = Field(alias="wireVersion")
    session_id: str = Field(alias="sessionId")
    server: dict[str, Any]
    server_time: str = Field(alias="serverTime")
    heartbeat_interval_ms: int = Field(alias="heartbeatIntervalMs")
    max_frame_bytes: int = Field(alias="maxFrameBytes")
    ack_window_chunks: int = Field(alias="ackWindowChunks")
    ack_window_bytes: int = Field(alias="ackWindowBytes")
    enabled_ops: list[str] = Field(alias="enabledOps")


class PingRequest(_Wire):
    nonce: str


class PingResponse(_Wire):
    nonce: str
    agent_time: str | None = Field(default=None, alias="agentTime")
    load: dict[str, Any] = Field(default_factory=dict)


class CancelRequest(_Wire):
    target_id: str = Field(alias="targetId")
    reason: CancelReason | str


class CancelResponse(_Wire):
    target_id: str = Field(alias="targetId")
    cancelled: bool


class ByeEvent(_Wire):
    reason: ByeReason | str
    message: str = ""
    by_session_id: str | None = Field(default=None, alias="bySessionId")


# ---------------------------------------------------------------------------
# Filesystem operations (§4)
# ---------------------------------------------------------------------------


class FsListRequest(_Wire):
    path: str
    offset: int = 0
    limit: int = 500
    pattern: str = "*"
    kinds: list[str] | None = None
    include_hidden: bool = Field(default=False, alias="includeHidden")
    sort: Literal["name", "size", "mtime"] = "name"
    descending: bool = False
    follow_links: bool = Field(default=False, alias="followLinks")


class FsListResponse(_Wire):
    path: str
    entries: list[FileEntry] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False
    truncation_reason: str | None = Field(default=None, alias="truncationReason")


class FsStatRequest(_Wire):
    path: str
    resolve_links: bool = Field(default=False, alias="resolveLinks")
    sniff: bool = True
    hash: Literal["none", "sha256"] = "none"


class FsStatResponse(_Wire):
    path: str
    exists: bool
    entry: FileEntry | None = None
    real_path: str | None = Field(default=None, alias="realPath")
    sniff: dict[str, Any] | None = None
    sha256: str | None = None
    volume: dict[str, Any] | None = None


class FsReadRequest(_Wire):
    """§4.3. Exactly one of three addressing modes; more than one is INVALID_ARGUMENT.

    The mutual exclusion is enforced in the tool layer, where a violation can be
    reported to the model with a description of the three modes, rather than here where
    it would surface as an opaque validation failure.
    """

    path: str
    offset: int | None = None
    length: int | None = None
    from_line: int | None = Field(default=None, alias="fromLine")
    line_count: int | None = Field(default=None, alias="lineCount")
    tail_lines: int | None = Field(default=None, alias="tailLines")
    encoding: Encoding = "auto"
    strip_bom: bool = Field(default=True, alias="stripBom")
    force: bool = False
    max_bytes: int | None = Field(default=None, alias="maxBytes")


class FsReadResponse(_Wire):
    path: str
    data: str | None = None
    encoding: Encoding = "utf-8"
    had_bom: bool = Field(default=False, alias="hadBom")
    byte_offset: int = Field(default=0, alias="byteOffset")
    byte_length: int = Field(default=0, alias="byteLength")
    file_size: int = Field(default=0, alias="fileSize")
    eof: bool = False
    first_line: int | None = Field(default=None, alias="firstLine")
    line_count: int | None = Field(default=None, alias="lineCount")
    total_lines: int | None = Field(default=None, alias="totalLines")
    truncated: bool = False
    line_ending: str = Field(default="none", alias="lineEnding")
    decode_errors: int = Field(default=0, alias="decodeErrors")
    chunked: bool = False


class FsReadChunkEvent(_Wire):
    """A slice of a `fs.read` too large for one frame (§4.3).

    ``seq`` lives on the envelope, not here; it shares the gapless sequence space of
    every other event for that correlation.
    """

    seq: int
    data: str
    encoding: Encoding = "utf-8"


class FsGlobRequest(_Wire):
    root: str
    patterns: list[str]
    excludes: list[str] = Field(default_factory=list)
    max_depth: int = Field(default=16, alias="maxDepth")
    max_results: int = Field(default=1000, alias="maxResults")
    time_budget_ms: int = Field(default=10_000, alias="timeBudgetMs")
    kinds: list[str] = Field(default_factory=lambda: ["file"])
    include_hidden: bool = Field(default=False, alias="includeHidden")
    follow_links: bool = Field(default=False, alias="followLinks")
    stat: bool = False


class FsGlobResponse(_Wire):
    root: str
    #: Plain canonical paths, or `FileEntry` objects when `stat` was requested.
    matches: list[Any] = Field(default_factory=list)
    count: int = 0
    truncated: bool = False
    truncation_reason: str | None = Field(default=None, alias="truncationReason")
    scanned_dirs: int = Field(default=0, alias="scannedDirs")
    elapsed_ms: int = Field(default=0, alias="elapsedMs")


class FsGrepRequest(_Wire):
    root: str
    query: str
    is_regex: bool = Field(default=False, alias="isRegex")
    case_sensitive: bool = Field(default=False, alias="caseSensitive")
    patterns: list[str] = Field(default_factory=lambda: ["**/*"])
    excludes: list[str] = Field(default_factory=list)
    context_before: int = Field(default=0, alias="contextBefore")
    context_after: int = Field(default=0, alias="contextAfter")
    max_matches: int = Field(default=200, alias="maxMatches")
    max_matches_per_file: int = Field(default=20, alias="maxMatchesPerFile")
    max_file_bytes: int = Field(default=8_388_608, alias="maxFileBytes")
    skip_binary: bool = Field(default=True, alias="skipBinary")
    time_budget_ms: int = Field(default=15_000, alias="timeBudgetMs")
    encoding: Encoding = "auto"


class GrepMatch(_Wire):
    path: str
    line: int
    column: int = 1
    text: str = ""
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)


class FsGrepResponse(_Wire):
    matches: list[GrepMatch] = Field(default_factory=list)
    count: int = 0
    files_scanned: int = Field(default=0, alias="filesScanned")
    files_skipped: int = Field(default=0, alias="filesSkipped")
    truncated: bool = False
    truncation_reason: str | None = Field(default=None, alias="truncationReason")
    elapsed_ms: int = Field(default=0, alias="elapsedMs")


# ---------------------------------------------------------------------------
# Execution operations (§5)
# ---------------------------------------------------------------------------


class ExecStartRequest(_Wire):
    argv: list[str] | None = None
    command_line: str | None = Field(default=None, alias="commandLine")
    shell: Literal["none", "cmd", "powershell", "pwsh"] = "none"
    cwd: str | None = None
    env: dict[str, str | None] | None = None
    env_mode: Literal["overlay", "clean"] = Field(default="overlay", alias="envMode")
    timeout_ms: int | None = Field(default=None, alias="timeoutMs")
    max_output_bytes: int | None = Field(default=None, alias="maxOutputBytes")
    output_encoding: Encoding = Field(default="utf-8", alias="outputEncoding")
    merge_stderr: bool = Field(default=False, alias="mergeStderr")
    stdin: str | None = None
    stdin_encoding: Encoding = Field(default="utf-8", alias="stdinEncoding")
    priority: Literal["idle", "belowNormal", "normal"] = "normal"


class ExecStartResponse(_Wire):
    pid: int
    started_at: str = Field(alias="startedAt")
    resolved_executable: str = Field(default="", alias="resolvedExecutable")
    resolved_cwd: str = Field(default="", alias="resolvedCwd")
    command_line_used: str = Field(default="", alias="commandLineUsed")


class ExecOutputEvent(_Wire):
    stream: Literal["stdout", "stderr"] | str
    data: str = ""
    encoding: Encoding = "utf-8"
    bytes: int = 0
    total_bytes: int = Field(default=0, alias="totalBytes")
    dropped: bool = False


class ExecAckEvent(_Wire):
    """The one event travelling server → agent (§5.3).

    Cumulative by design: it carries the highest contiguous `seq` and the running byte
    total, so a lost acknowledgement is superseded by the next one and MUST NOT cause
    the agent to fail anything.

    The correlation travels on the envelope's `corr`, not in this payload; `ackSeq` and
    `ackBytes` are the only members the schema requires. ``ackSeq`` starts at -1, meaning
    nothing has been consumed yet.
    """

    ack_seq: int = Field(alias="ackSeq")
    ack_bytes: int = Field(alias="ackBytes")


class ExecExitEvent(_Wire):
    exit_code: int | None = Field(default=None, alias="exitCode")
    exit_code_signed: int | None = Field(default=None, alias="exitCodeSigned")
    exit_reason: ExitReason | str = Field(default=ExitReason.EXITED, alias="exitReason")
    started_at: str | None = Field(default=None, alias="startedAt")
    ended_at: str | None = Field(default=None, alias="endedAt")
    duration_ms: int = Field(default=0, alias="durationMs")
    stdout_bytes: int = Field(default=0, alias="stdoutBytes")
    stderr_bytes: int = Field(default=0, alias="stderrBytes")
    truncated: bool = False
    truncation_reason: str | None = Field(default=None, alias="truncationReason")
    cpu_time_ms: int | None = Field(default=None, alias="cpuTimeMs")
    peak_working_set_bytes: int | None = Field(default=None, alias="peakWorkingSetBytes")
    killed_processes: int | None = Field(default=None, alias="killedProcesses")


class PolicyReviewingEvent(_Wire):
    """Emitted when a stage-2 model review runs long (§5.5).

    It carries no authorization meaning and MUST NOT be treated as an approval — it
    exists so the server can say "under review" rather than "slow".
    """

    stage: str = "modelReview"
    elapsed_ms: int = Field(default=0, alias="elapsedMs")
