# MCP tool surface

**Status:** Draft · **Revision:** 2026-07-26

This document specifies what an MCP client sees: the tools WinShow exposes, their inputs and
outputs, and how failures are presented. It is the counterpart to
[`03-agent-protocol.md`](03-agent-protocol.md), which specifies what the Windows agent sees.

The MVP exposes **seven tools**. That number is a design decision rather than an accident:
every tool costs context in the client and adds a choice the model can get wrong, so each one
has to earn its place by covering a use case from
[`01-requirements.md` §3](01-requirements.md#3-use-cases) that no other tool covers.

---

## 1. Conventions

### 1.1 Naming

All tools are prefixed `winshow_`. The prefix disambiguates them from a client's local
filesystem tools, which matters a great deal here: a model that confuses
`winshow_read_file` with a local `read_file` will read the wrong machine and be confused by
the result. Every tool description states plainly that it operates on **a remote Windows
host**.

### 1.2 Structured output

Every tool declares an `outputSchema` and returns `structuredContent`, generated from a
Pydantic model. Every tool additionally returns a compact human-readable rendering as a text
content block, because clients differ in what they surface to the user and a table of file
names reads better than a JSON blob.

### 1.3 The result envelope

Every result — success or failure — has the same top-level shape, so the model learns one
pattern instead of seven:

```json
{ "ok": true,  "data": { … } }
{ "ok": false, "error": { "code": "…", "message": "…", "retryable": false, … } }
```

### 1.4 Paths

Every path parameter is an **absolute Windows path**. Both `C:\src\file.txt` and
`C:/src/file.txt` are accepted; results always come back canonicalised with backslashes and
an uppercase drive letter. Relative paths are rejected — see
[`03-agent-protocol.md` §10.1](03-agent-protocol.md#101-path-handling) for why.

### 1.5 Errors

The rule is stated in [`02-architecture.md` §8.4](02-architecture.md#84-error-taxonomy-and-how-it-maps-to-mcp):
anything the model or the user could act on is a **tool execution error** (`isError: true`
with the envelope above), and only malformed protocol usage is a JSON-RPC error.

Two consequences that surprise people:

- **A command exiting non-zero is a successful tool call.** `winshow_run_command` returns
  `ok: true` with `exit_code: 1`. The tool did its job; the command reported an outcome. Any
  other choice pushes the model to discard the output it needs to explain the failure.
- **A policy denial is never retryable.** It will not become an allow by trying again. The
  right response is to tell the user what the policy would have to permit.

Error codes visible to MCP clients are the wire codes from
[`03-agent-protocol.md` §7.2](03-agent-protocol.md#72-code-table), plus five that are
server-originated and never appear on the wire:

| Code | Meaning | Retryable |
|---|---|---|
| `AGENT_UNAVAILABLE` | No agent is connected; the Windows host has not dialled in | yes |
| `AGENT_DISCONNECTED` | The agent went away while this request was in flight | yes |
| `AGENT_SUPERSEDED` | The agent connection was replaced by a newer one mid-request | yes |
| `AGENT_TIMEOUT` | The agent did not answer within its own advertised timeout plus a margin | yes |
| `AGENT_PROTOCOL_ERROR` | The agent sent something malformed or violated an ordering rule | no |

---

## 2. `winshow_host_info`

**Description shown to the model.** *Report the status of the connection to the remote Windows
host, and what that host permits. Call this first when you do not know whether the host is
reachable, or before proposing a command, so you can see which commands and paths are allowed
rather than guessing.*

That second sentence is doing real work. The policy summary is what turns a blind
trial-and-error loop into a single correct proposal.

### Input

No parameters.

### Output

| Field | Type | Notes |
|---|---|---|
| `connected` | boolean | |
| `connected_since` | string \| null | RFC 3339 |
| `last_seen_at` | string \| null | Set when disconnected |
| `agent` | object \| null | Name, version, implementation |
| `host` | object \| null | Hostname, Windows version, build, edition, architecture, uptime |
| `identity` | object \| null | The account the agent runs as, whether it is a service, its integrity level |
| `capabilities` | string[] | Which operations this agent implements |
| `limits` | object \| null | Maximum execution time, output size, read size, concurrency |
| `policy` | object \| null | The policy summary: read roots, permitted command identifiers, permitted shells, whether writes are enabled, whether stage-2 review is on |
| `clock_skew_seconds` | number \| null | Agent clock relative to the server |

### Errors

Never fails when the server is up. When no agent is connected it returns `ok: true` with
`connected: false` — the absence of a host is information, not an error.

---

## 3. `winshow_list_directory`

**Description.** *List the contents of a directory on the remote Windows host. Returns name,
size, timestamps and attributes for each entry. Use `sort` and `descending` to find the
newest or largest files without reading them.*

### Input

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `path` | string | required | Absolute Windows path |
| `pattern` | string | `*` | Wildcard filter on the entry name |
| `limit` | integer | 200 | |
| `offset` | integer | 0 | For paging |
| `sort` | `name` \| `size` \| `mtime` | `name` | |
| `descending` | boolean | false | |
| `kinds` | string[] | all | `file`, `dir`, `symlink`, `junction`, `other` |
| `include_hidden` | boolean | false | |

### Output

`entries` (name, path, kind, size, `size_human`, mtime, ctime, attrs, link_target), plus
`total`, `truncated`, and `truncation_reason`.

`size_human` is added by the server for the text rendering. The raw byte count remains
authoritative in `size`; a model that needs to compare sizes should use that.

Maps to [`fs.list`](03-agent-protocol.md#41-fslist).

---

## 4. `winshow_stat_path`

**Description.** *Get details about a single file or directory on the remote Windows host,
including whether it exists at all, its size and timestamps, and — for text files — the
detected encoding and line ending. Use this to check for a file before reading it.*

### Input

| Parameter | Type | Default |
|---|---|---|
| `path` | string | required |
| `resolve_links` | boolean | false |
| `sniff` | boolean | true |
| `hash` | `none` \| `sha256` | `none` |

### Output

`exists`, `entry`, `real_path`, `sniff` (`is_probably_text`, `encoding`, `has_bom`,
`line_ending`), `sha256`, and `volume` (drive type, filesystem, free and total bytes).

**A missing path returns `ok: true` with `exists: false`**, not an error. This lets a model
check for something without triggering an error-handling path, which in practice is the
difference between one clean turn and two confused ones.

Maps to [`fs.stat`](03-agent-protocol.md#42-fsstat).

---

## 5. `winshow_read_file`

**Description.** *Read a file from the remote Windows host. Choose exactly one addressing
mode: `tail_lines` for the end of a log (the usual choice), `from_line` with `line_count` for
a known region, or `offset` with `length` for a byte range. Large files are never transferred
whole; ask for the part you need.*

### Input

| Parameter | Type | Default | Mode |
|---|---|---|---|
| `path` | string | required | all |
| `tail_lines` | integer | — | tail |
| `from_line` | integer | — | line range (1-based) |
| `line_count` | integer | 200 | line range |
| `offset` | integer | — | byte range |
| `length` | integer | agent limit | byte range |
| `encoding` | string | `auto` | all |
| `max_bytes` | integer | agent limit | all |
| `force_text` | boolean | false | Decode content that sniffs as binary |

Supplying more than one addressing mode is `INVALID_ARGUMENT`. The tool description names
`tail_lines` first because log inspection is the dominant use, and because a model that
reaches for `offset: 0, length: 1000000` on a 17 GiB log has chosen badly.

### Output

`content`, `encoding`, `is_binary`, `had_bom`, `byte_offset`, `byte_length`, `file_size`,
`eof`, `first_line`, `line_count`, `total_lines`, `truncated`, `line_ending`, and
`decode_errors`.

`decode_errors` above zero is worth surfacing: it means the encoding sniff produced
replacement characters, and the content should be treated with suspicion rather than quoted
back to the user as fact.

Maps to [`fs.read`](03-agent-protocol.md#43-fsread).

---

## 6. `winshow_find_files`

**Description.** *Find files on the remote Windows host by glob pattern. Supports `*`, `?`,
`**` for any number of directories, character classes and `{a,b}` alternation. Matching is
case-insensitive. Searching happens on the Windows host; only the matching paths are
returned.*

### Input

| Parameter | Type | Default |
|---|---|---|
| `root` | string | required |
| `patterns` | string[] | required |
| `excludes` | string[] | `[]` |
| `max_results` | integer | 200 |
| `max_depth` | integer | 16 |
| `time_budget_ms` | integer | 10000 |
| `kinds` | string[] | `["file"]` |
| `include_hidden` | boolean | false |
| `with_stat` | boolean | false |

### Output

`matches`, `count`, `truncated`, `truncation_reason`, `scanned_dirs`, `elapsed_ms`.

The three separate bounds — result count, depth, and wall clock — exist because a glob over a
large tree can be slow in three unrelated ways, and a caller should be able to tell which one
it hit. `truncation_reason` says which.

Maps to [`fs.glob`](03-agent-protocol.md#44-fsglob).

---

## 7. `winshow_search_files`

**Description.** *Search the contents of files on the remote Windows host for a string or a
regular expression, returning matching lines with optional surrounding context. The search
runs on the Windows host, so only the matches cross the network.*

### Input

| Parameter | Type | Default |
|---|---|---|
| `root` | string | required |
| `query` | string | required |
| `is_regex` | boolean | false |
| `case_sensitive` | boolean | false |
| `patterns` | string[] | `["**/*"]` |
| `excludes` | string[] | `[]` |
| `context_before` | integer | 0 |
| `context_after` | integer | 0 |
| `max_matches` | integer | 100 |
| `max_matches_per_file` | integer | 10 |
| `max_file_bytes` | integer | 8388608 |
| `skip_binary` | boolean | true |
| `time_budget_ms` | integer | 15000 |

The description **must** state the regex limitation, because a silently rejected pattern
wastes a turn: *backreferences and lookaround are not supported, so that matching is
guaranteed linear-time.* An unsupported construct returns `INVALID_ARGUMENT` naming the
construct.

### Output

`matches` (path, line, column, text, before, after), `count`, `files_scanned`,
`files_skipped`, `truncated`, `elapsed_ms`.

Maps to [`fs.grep`](03-agent-protocol.md#45-fsgrep).

---

## 8. `winshow_run_command`

The tool with real consequences, and therefore the one whose description matters most.

**Description.** *Run a command on the remote Windows host and return its output and exit
code. Pass the program and its arguments as a list (`argv`) — the arguments are NOT parsed by
a shell, so pipes, redirection and wildcards do not work unless you explicitly set `shell`.
Only commands permitted by the host's policy will run; call `winshow_host_info` to see which
ones. A non-zero exit code is a normal result, not an error.*

Every clause of that description prevents a specific, observed failure: passing a shell string
into `argv`, expecting `|` to work, guessing at commands that will be denied, and treating a
failed build as a broken tool.

### Input

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `argv` | string[] | one of ¹ | Program and arguments, already split |
| `command_line` | string | one of ¹ | Raw command line; **only** valid with a `shell` |
| `shell` | `none` \| `cmd` \| `powershell` \| `pwsh` | `none` | Each shell is separately permitted by policy |
| `cwd` | string | policy default | Absolute path |
| `env` | object | `{}` | Overlay; a null value removes a variable |
| `env_mode` | `overlay` \| `clean` | `overlay` | |
| `timeout_ms` | integer | policy default | Capped by the agent |
| `max_output_bytes` | integer | policy default | |
| `merge_stderr` | boolean | false | |
| `stdin` | string \| null | null | Written once, then the pipe is closed |

¹ Exactly one of `argv` and `command_line`.

### Output

| Field | Type | Notes |
|---|---|---|
| `exit_code` | integer \| null | Unsigned 32-bit |
| `exit_code_signed` | integer \| null | The same bits read as signed int32 |
| `exit_reason` | string | `exited`, `timeout`, `cancelled`, `killed`, `backpressure`, `disconnected` |
| `stdout` | string | |
| `stderr` | string | |
| `truncated` | boolean | |
| `truncation_reason` | string \| null | |
| `partial` | boolean | True when the agent disconnected mid-run |
| `duration_ms` | integer | |
| `pid` | integer \| null | |
| `command_line_used` | string | The exact command line the OS received, after quoting |
| `resolved_executable` | string | |

`command_line_used` is surfaced to the client rather than kept internal because it is the only
unambiguous answer to "what actually ran". Windows quoting has enough corner cases —
`msiexec`, `robocopy` and Go-built binaries all parse their own command line — that
reconstructing it from `argv` is a guess.

**`exit_reason` is authoritative.** When the agent kills a process on timeout or cancellation
the exit code is whatever `TerminateProcess` was handed and means nothing. A client that
infers the outcome from the exit code will report a cancelled build as a failed one.

### Streaming

When the client supplies a progress token, the server emits `notifications/progress` as output
arrives: `progress` counts bytes emitted so far and `message` carries the most recent output
lines, truncated to roughly 300 characters. Notifications are rate-limited to about four per
second with intermediate chunks coalesced.

The final result is **authoritative**, and complete up to the caps: it carries everything the
agent captured, which is everything the command produced unless `max_output_bytes` was
reached, in which case `truncated` says so and the truncation keeps the head and the tail with
an explicit omitted-bytes marker between them. The specification makes progress notifications
advisory, so a client that ignores them entirely must still get the whole result — it must
never be the case that streaming saw something the final result did not. See
[ADR 0009](adr/0009-progress-now-tasks-later.md).

### Cancellation

An MCP `notifications/cancelled` for this call, or the client disconnecting, propagates to
`session.cancel` on the wire. The agent delivers a break signal to the process group, waits a
grace period, then closes the job object, which terminates the entire process tree. The result
comes back with `exit_reason: "cancelled"` and the output captured so far.

Maps to [`exec.start`](03-agent-protocol.md#51-execstart--server--agent-reqres).

---

## 9. Worked error examples

A policy denial, showing what makes it useful rather than merely correct:

```json
{
  "ok": false,
  "error": {
    "code": "POLICY_DENIED",
    "class": "policy",
    "retryable": false,
    "message": "Command denied: matches deny rule 'no-destructive'.",
    "rule": "exec.deny[no-destructive]",
    "reason": "Destructive disk and boot operations are never permitted.",
    "reason_source": "rule",
    "hint": "Permitted commands on this host are: svc-query, tasklist, dotnet-build, ps-diagnostics. Ask the operator to extend policy.toml if this one is genuinely needed.",
    "request_id": "r-7f3a91c2"
  }
}
```

The `hint` field is written **for the model**: it says what is possible and what the human
would have to do. That turns a dead end into a useful sentence for the user, instead of five
more attempts.

When `reason_source` is `"model"`, the reason came from the host's stage-2 review. The server
**MUST** label it as untrusted generated content when relaying it, and the client **MUST NOT**
treat it as instructions — see
[`04-agent-policy.md` §6.6](04-agent-policy.md#66-the-verdict-is-untrusted-text).

A command that ran and failed — note `ok: true`:

```json
{
  "ok": true,
  "data": {
    "exit_code": 1, "exit_code_signed": 1, "exit_reason": "exited",
    "stdout": "Determining projects to restore...\r\n…\r\nBuild FAILED.\r\n",
    "stderr": "Program.cs(42,13): error CS0103: The name 'foo' does not exist\r\n",
    "truncated": false, "partial": false, "duration_ms": 34513, "pid": 8812,
    "command_line_used": "\"C:\\Program Files\\dotnet\\dotnet.exe\" build -c Release",
    "resolved_executable": "C:\\Program Files\\dotnet\\dotnet.exe"
  }
}
```

---

## 10. What is deliberately not exposed

| Not exposed | Why |
|---|---|
| Write, delete, move, upload | Deferred to a later phase; they need a separate write policy. See [`01-requirements.md` §4.5](01-requirements.md#45-what-the-mvp-is-and-why). |
| Process list and kill | `tasklist` and `taskkill` through the execution allowlist cover these until structured output is worth the protocol surface. |
| Registry, services, event log as tools | Same reasoning — reachable through an allowlisted command today. |
| A "raw wire operation" escape hatch | It would let a caller bypass the tool layer's validation and would make the audit record meaningless. |
| MCP resources for files | Considered and deferred; see [`01-requirements.md` §9](01-requirements.md#9-open-questions) question Q-4. |
| A host selection parameter | One host. The extension point is described in [`02-architecture.md` §5.1](02-architecture.md#51-extension-points-for-multiple-hosts). |
