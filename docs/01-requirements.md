# Requirements

**Status:** Draft · **Revision:** 2026-07-26

This document states what WinShow must do and what it must be, in a form the rest of the
design can be checked against. Every functional requirement carries an identifier of the form
`FR-n` and every non-functional one `NFR-n`, and §8 traces each of them to the MCP tool and
the wire operation that realises it. A requirement with no trace is a requirement nobody
built; an operation with no requirement is scope creep.

---

## 1. The problem

Someone runs a Windows machine they cannot easily reach — a build server in an office, a
machine at a customer site, a VM behind a corporate firewall — and wants to use an AI
assistant to look at it and act on it. The obstacles are concrete:

- **There is no inbound path.** The host sits behind NAT or a corporate firewall. Creating an
  inbound path is precisely the change most likely to be refused by whoever runs the network,
  and most likely to be regretted later.
- **The assistant needs structure, not a terminal.** Feeding a language model raw terminal
  output and hoping is not a design. It needs typed results it can reason over and errors
  that tell it how to correct itself.
- **Nobody wants to hand an assistant a shell.** The interesting question is not "can it run
  commands" but "who decides which commands, and where does that decision live".

WinShow answers these by having the Windows host **dial out** to a broker, and by putting the
authorization decision **on the Windows host**, in a file a human wrote.

---

## 2. Stakeholders

| Stakeholder | What they need from WinShow |
|---|---|
| **Operator** — owns the Windows machine, runs the server, writes the policy | To let an assistant see a machine they cannot easily reach, while being certain it can do nothing they did not permit. They need denials that name the rule, because most of the denials they will hit are their own policy being stricter than they meant. |
| **MCP client and the model driving it** | Tool descriptions and structured results it can reason over, and errors that are actionable rather than opaque. It needs to know what is permitted *before* it tries, or it wastes turns guessing. |
| **Third-party agent implementer** | A contract precise enough to build a Go, C#, or Rust agent without reading the Python server. This stakeholder is why [`03-agent-protocol.md`](03-agent-protocol.md) exists as a separate normative document. |
| **Auditor, or the operator six months later** | A durable, tamper-evident record of every command that ran, who asked for it, and whether the policy allowed or denied it. |
| **The Windows host itself** | Not to be destabilised: bounded CPU, bounded memory, bounded output, and no orphaned processes after a network blip. |

---

## 3. Use cases

These are the concrete things someone would actually ask, and they are what the MVP scope in
§4 is cut to satisfy.

1. **Orientation.** "What is on `D:\`? Show me the largest files in `D:\Logs`."
2. **Log inspection.** "Read the last 200 lines of `C:\Program Files\App\logs\service.log` —
   is there a stack trace?" The file is 17 GiB, so this must not mean transferring it.
3. **Search.** "Find every `*.config` under `C:\inetpub` that contains `Debug=true`." The
   search runs on the Windows host; only the matches cross the wire.
4. **Diagnosis.** "Is the print spooler running?" — an allowlisted `sc.exe query`.
5. **A long job.** "Run `dotnet build` on `C:\src\proj` and tell me if it fails." Minutes of
   output, a timeout, and the ability to give up partway.
6. **Introspection.** "Is the agent even connected? What Windows build is it?"
7. **A denial.** "Read `C:\Users\me\.ssh\id_rsa`." This **must** be refused by the agent's
   policy, and the refusal must be legible enough that the assistant tells the user what the
   policy would have to say instead of trying six variants of the path.

Use case 7 is not an edge case. It is the one that decides whether the design is sound.

---

## 4. Functional requirements

Phase markers: **M** is the MVP, delivered in Phases 2 and 3. **P2** and **P3** are later,
with the reasoning for deferral given in §4.5.

### 4.1 Connectivity and introspection

| ID | Requirement | Phase |
|---|---|---|
| FR-1 | The server SHALL accept exactly one agent connection at a time and expose its state — connected or not, and since when — to MCP clients through a tool. | M |
| FR-2 | The agent SHALL report at handshake: its name and version, the wire versions it supports, the operations it implements, the hostname, the Windows version, build and architecture, the security context it runs as, its clock and timezone, its resource limits, and a summary of its policy. | M |
| FR-3 | The server SHALL expose that handshake information as structured content, so the model can reason about what the host is and what is permitted before attempting anything. | M |

FR-3 exists because of use case 7. An assistant that knows the read roots and the four
permitted command identifiers proposes something that works; one that does not spends three
turns guessing and irritates the user.

### 4.2 Filesystem, read side

| ID | Requirement | Phase |
|---|---|---|
| FR-4 | List a directory, returning per entry: name, canonical path, kind, size, modification, creation and access times in UTC, and Windows file attributes. Paged by offset and limit, with a deterministic total order so paging neither skips nor duplicates. | M |
| FR-5 | Stat a single path, returning the same fields plus existence, the reparse target when there is one, and — for files — a cheap content sniff giving the probable encoding and line ending. | M |
| FR-6 | Read a byte range of a file, returning the slice, the total file size, whether the end was reached, and the encoding actually used. | M |
| FR-7 | Read a **line range** and read a **tail** of *n* lines. These are the two accesses that logs actually require, and performing them on the host is what stops use case 2 from meaning a 17 GiB transfer. | M |
| FR-8 | Return binary content as Base64 with an explicit marker, never as mangled text, and refuse to text-decode content that sniffs as binary unless the caller explicitly forces it. | M |
| FR-9 | Find paths by glob, bounded by a maximum result count, a traversal depth, and a wall-clock budget, returning partial results flagged as truncated with the reason. | M |
| FR-10 | Search file contents, literal or regular expression, with case sensitivity, context lines, and caps on matches, per-file matches, and file size. | M |
| FR-11 | Compute a file hash, so a caller can verify identity or detect change without transferring content. | P2 |
| FR-22 | Write or create a file atomically, via a temporary file and a rename. | P2 |
| FR-23 | Append to a file. | P2 |
| FR-24 | Chunked upload for files larger than one frame. | P2 |
| FR-25 | Delete, move, and create directories. | P3 |

### 4.3 Execution

| ID | Requirement | Phase |
|---|---|---|
| FR-12 | Execute a command given an argument vector, a working directory, an environment overlay and a timeout, capturing both output streams and returning the exit code and timing. This is the workhorse. | M |
| FR-13 | Stream output while the command runs, so a build that takes four minutes is not four minutes of silence. | M |
| FR-14 | Enforce a timeout, terminating the whole process tree on expiry and returning the output captured so far. | M |
| FR-15 | Propagate cancellation from the MCP client through to termination of the process tree, and confirm it. | M |
| FR-16 | Support shell execution (`cmd`, `powershell`, `pwsh`) as a distinct, separately permitted mode — never the default. | M |
| FR-17 | Accept an explicit working directory and environment overlay per request, both subject to policy. | M |
| FR-18 | Feed a bounded, one-shot input to a process's standard input. | P2 |
| FR-19 | List processes with pid, parent, name, image path, user, CPU time, memory and start time. | P2 |
| FR-20 | Terminate a process by pid, optionally with its tree. | P2 |
| FR-21 | Query Windows services and slices of the event log as first-class operations rather than through a shell. | P3 |

### 4.4 Policy and audit

| ID | Requirement | Phase |
|---|---|---|
| FR-26 | The agent SHALL enforce an operator-authored policy governing which paths may be read and which commands may run, and SHALL be the only component that does so. | M |
| FR-27 | A policy denial SHALL be reported as a distinct, non-retryable error naming the deciding rule, and distinguishable from a denial by a Windows access control list. | M |
| FR-28 | A denial SHALL carry a summary of what *is* permitted, so a caller can propose a valid alternative rather than guessing. | M |
| FR-29 | The agent SHALL support an optional second review stage backed by a local model, which runs only after the deterministic rules have already allowed a request and which can only deny. | M |
| FR-30 | Every execution SHALL produce an audit record before dispatch and after completion, written on both the server and the agent. | M |
| FR-31 | The policy SHALL be reloadable without restarting the agent, atomically, keeping the previous policy if the new one fails to load. | M |

### 4.5 What the MVP is, and why

The MVP is **FR-1 through FR-10, FR-12 through FR-17, and FR-26 through FR-31**. That is
read plus execute plus the policy engine — the smallest set that satisfies use cases 1 to 7.

**Write operations are deferred deliberately**, and not because they are hard. They double
the policy surface, and a write allowlist is a substantially harder thing to get right than a
read allowlist: a read rule is wrong if it exposes something, whereas a write rule is wrong
if it exposes something *or* if it permits a path that some other program later trusts.
Meanwhile an allowlisted `exec` already covers the legitimate "change something" cases, under
rules a human wrote, with an audit record. Adding writes before the read-and-execute path has
been operated for a while would be adding risk before we have learned anything.

**Process listing and termination are deferred** because `tasklist` and `taskkill` through the
execution allowlist cover them at zero protocol cost until structured output is worth having.

---

## 5. Non-functional requirements

| ID | Requirement | Target or rule |
|---|---|---|
| NFR-1 | **Transport security.** All MCP client traffic and all agent traffic over TLS 1.2 or better, preferring 1.3. Plaintext only on loopback. The agent MUST verify the certificate chain and the hostname, and MUST refuse a non-loopback `ws://` unless explicitly configured otherwise, logging a warning on every attempt when it is. | Hard |
| NFR-2 | **Agent authentication.** A shared bearer token of at least 32 bytes of CSPRNG output, presented at the handshake, compared in constant time. Two tokens valid simultaneously so rotation needs no downtime. Optional mutual TLS profile. | Hard |
| NFR-3 | **MCP client authentication.** Phase 2: a static bearer token plus `Origin` validation. Phase 4: OAuth 2.1 resource server per the MCP authorization specification. | Phased |
| NFR-4 | **Authorization locus.** The server performs no path or command filtering. The agent is the sole enforcement point and MUST NOT accept authorization input from the server. | Architectural invariant |
| NFR-5 | **Latency.** Server-added overhead at or below 20 ms at the 95th percentile, excluding Windows I/O and network round trip. No polling in the request path. | Soft |
| NFR-6 | **Framing and chunking.** One frame at most 1 MiB by default, ceiling 8 MiB, negotiated at handshake. Large reads and command output chunked by the agent. Base64 expansion counted inside the cap, not against the raw byte count. | Hard |
| NFR-7 | **Backpressure.** A bounded credit window of unacknowledged output, defaulting to 64 chunks or 4 MiB. When the window is full the agent stops reading the child's pipes so the child blocks — ordinary operating-system backpressure, which loses nothing. A stall beyond 30 seconds terminates the process tree with an explicit reason. | Hard |
| NFR-8 | **Reliability and reconnection.** The agent reconnects automatically with exponential backoff and full jitter, from 1 s to a 60 s ceiling, indefinitely. Heartbeat every 20 s with death declared at 60 s. A reconnection resurrects nothing: all in-flight state is abandoned on both sides. | Hard |
| NFR-9 | **Concurrency limits.** The agent advertises `maxConcurrentRequests` (default 16) and `maxConcurrentProcesses` (default 4). Exceeding them yields `AGENT_BUSY` rather than unbounded queueing, because unbounded queueing turns a burst into memory exhaustion and hides the misbehaviour instead of surfacing it. | Hard |
| NFR-10 | **Resource limits.** Maximum execution wall time (default 300 s), maximum output per execution (default 4 MiB), maximum read slice (default 1 MiB). Exceeding a limit yields a structured result flagged as truncated, or a structured error — never a crash. | Hard |
| NFR-11 | **Observability.** Structured JSON logs on both sides sharing one schema, carrying the MCP request identifier, the internal request identifier and the agent session identifier on every line, so one search reconstructs a call end to end. Prometheus metrics on a separate admin bind address. | Hard |
| NFR-12 | **Audit.** Every execution produces an immutable record on the server, which knows the MCP client, and on the agent, which is the authority and survives a compromised server. The agent additionally writes to the Windows Event Log. The agent's token appears in no log at any level. | Hard |
| NFR-13 | **Portability of the contract.** The wire specification MUST NOT reference any language or runtime, and every type must be expressible in JSON. Timestamps are RFC 3339 strings, never raw 64-bit tick values, which a JSON number cannot carry safely. | Hard |
| NFR-14 | **Failure containment.** No single malformed message, oversized frame, or misbehaving agent may take down the server. Unknown message types, unknown operations, and unknown fields are ignored or answered, never fatal. | Hard |
| NFR-15 | **Startup independence.** The server starts and serves MCP with no agent connected; the agent starts and retries with no server reachable. Neither blocks on the other. | Hard |
| NFR-16 | **No hanging calls.** When the agent disconnects, every outstanding MCP request is completed with an error immediately. A tool call that hangs until the client's own timeout is the worst available outcome, because it gives the user neither a result nor a reason. | Hard |
| NFR-17 | **Clock discipline.** All timestamps RFC 3339 with `Z`. The agent reports its clock skew relative to the server at handshake, and a skew beyond five minutes is logged. | Soft |

---

## 6. Out of scope

Stated explicitly, because each of these is something a reader might reasonably assume is
included:

- **Multiple simultaneous Windows hosts.** One host, one agent slot. The extension points are
  noted in [`02-architecture.md`](02-architecture.md) but nothing is built for it.
- **Interactive sessions.** No pseudo-terminal, no console attach, no ANSI escape
  interpretation, no curses applications. Commands run non-interactively or they do not run.
- **Anything graphical.** No screenshots, no input injection, no desktop automation. The agent
  runs in session 0 and cannot see a desktop.
- **Impersonation.** Every operation runs as the agent's own identity. Launching a process as
  another user is a privilege-escalation primitive and is deliberately absent.
- **The Windows registry.**
- **Job scheduling that survives an agent restart.** Nothing is resumed across a reconnection.
- **Being a replacement for RDP, SMB, or SSH.** WinShow is a narrow, audited, policy-gated
  window, not a general remote access product.
- **MCP features beyond tools.** No prompts, no sampling, no elicitation in version 1.
  Resources are considered and deferred; see §7.
- **Per-user authorization on the Windows side.** The policy governs what the *agent* permits,
  not what a particular MCP client user permits. Multi-tenant scoping is a different design.
- **The agent's installer, code signing pipeline, and auto-update.** Real product concerns,
  not design-phase concerns.

---

## 7. Assumptions

| | Assumption |
|---|---|
| A-1 | The server host has a stable DNS name reachable from the Windows host, and a TLS certificate the agent can validate. |
| A-2 | The Windows host can make outbound TLS connections on port 443, possibly through an HTTP proxy. Inbound connections are impossible. |
| A-3 | One operator writes both the server configuration and the agent policy. There is no adversarial separation between them — but the *server process* is nonetheless treated as untrusted by the agent, as defence in depth against a compromised server. |
| A-4 | The MCP client supports the Streamable HTTP transport. It may or may not surface progress notifications to the user, so nothing may depend on them. |
| A-5 | Windows 10 version 1607 or Server 2016 and later: long-path support is available and Windows PowerShell 5.1 is present. |
| A-6 | Typical file reads are under 1 MiB, typical commands finish within 30 seconds, and occasional builds run for minutes. |

---

## 8. Traceability

Every functional requirement maps to at least one MCP tool and one wire operation. Tools are
specified in [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md); operations in
[`03-agent-protocol.md`](03-agent-protocol.md).

| Requirement | MCP tool | Wire operation |
|---|---|---|
| FR-1, FR-2, FR-3 | `winshow_host_info` | `session.hello` |
| FR-4 | `winshow_list_directory` | `fs.list` |
| FR-5 | `winshow_stat_path` | `fs.stat` |
| FR-6, FR-8 | `winshow_read_file` | `fs.read` |
| FR-7 | `winshow_read_file` (line and tail modes) | `fs.read` |
| FR-9 | `winshow_find_files` | `fs.glob` |
| FR-10 | `winshow_search_files` | `fs.grep` |
| FR-12, FR-16, FR-17 | `winshow_run_command` | `exec.start` |
| FR-13 | `winshow_run_command` (progress notifications) | `exec.output`, `exec.ack` |
| FR-14 | `winshow_run_command` (`timeout_ms`) | `exec.exit` with `exitReason: "timeout"` |
| FR-15 | `winshow_run_command` (MCP cancellation) | `session.cancel` |
| FR-26, FR-27, FR-28 | every tool (error path) | `POLICY_DENIED` |
| FR-29 | `winshow_run_command` | `policy.reviewing`, `POLICY_DENIED` with `reasonSource: "model"` |
| FR-30 | none — a server and agent responsibility | audit record, see [`02-architecture.md`](02-architecture.md) |
| FR-31 | surfaced through `winshow_host_info` (`policyHash`) | `session.hello` policy summary |
| FR-11, FR-18 to FR-25 | later phases | see [`03-agent-protocol.md` §6](03-agent-protocol.md#6-deferred-operations) |

---

## 9. Open questions

These are genuinely undecided. They are recorded here rather than papered over, and each
should be resolved before or during the phase named.

| | Question | Leaning | Resolve by |
|---|---|---|---|
| Q-1 | Target the 2025-11-25 MCP revision, or the 2026-07-28 one that removes the session model? | Implement against 2025-11-25 via the SDK's defaults while keying no state off `Mcp-Session-Id`, so the migration is a configuration change rather than a redesign. | Phase 2 start |
| Q-2 | Ship an OAuth 2.1 resource server in Phase 2, or run behind an authenticating reverse proxy until Phase 4? | Reverse proxy first. It is the same security posture with far less code, and the authorization specification is moving. | Phase 2 start |
| Q-3 | Should a denial for a path outside every root be explicit, or shaped as "not found" so the tool surface reveals nothing about the disk? | Explicit by default — the operator is the principal and needs to debug their own rules — with `denialDisclosure` as the switch. Already implemented as a policy setting; the question is what the documented default should be. | Phase 3 |
| Q-4 | Expose files as MCP resources in addition to tools? | No in the MVP. Resources are pull-by-URI and clients handle them inconsistently; `resource_link` content blocks returned from a listing are a cheaper route to the same affordance later. | Phase 4 |
| Q-5 | One shared agent token, or per-agent tokens with identifier pinning from the start? | Pin from the start. It costs nothing and it is the multi-host extension point. | Phase 2 |
| Q-6 | Are the concurrency, window and timeout defaults right? | They are considered defaults, not measurements. Phase 2 should confirm them against real behaviour and adjust before Phase 3 freezes them in an agent. | Phase 2 exit |
| Q-7 | Where does the stage-2 model run — in the agent process or a local inference server — which model, and what is its review prompt and output contract? | Deferred to Phase 3. The capability flag, the `policy.reviewing` event, and the `reasonSource` field are designed now so it drops in without a protocol change. | Phase 3 |
| Q-8 | Should the audit trail be forwarded off the host, and to what? | Append-only JSONL plus the Windows Event Log, with syslog forwarding as configuration. A database is over-engineering for one host. | Phase 3 |
