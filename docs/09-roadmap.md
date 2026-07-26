# Roadmap

**Status:** Draft · **Revision:** 2026-07-26

This document sets out how WinShow gets built, in what order, and — more importantly — why
that order and not another. Each phase has explicit exit criteria, because a phase without
them ends whenever somebody is tired of it rather than when it is finished.

The through-line of the ordering is that **the specification is the artefact**, and
everything else is built to test it. The wire protocol is written before any code exists; the
mock agent is written before the real one so that the protocol can be exercised end to end on
a machine that has no Windows API at all; the conformance harness is written before the
Windows agent so that the Windows agent has something to be measured against. By the time
anyone calls `CreateProcessW`, the question "what is this supposed to do?" has a written,
executable answer.

The second organising principle is that **capability comes last**. Writes, uploads, process
control, and multi-host all sit in the final phases. This is not because they are hard — most
of them are easy — but because each one widens the blast radius, and widening the blast radius
before the enforcement point has been proven is the wrong order to make mistakes in.

| Phase | Theme | Runs on | Gate to the next phase |
|---|---|---|---|
| 1 | Design | Paper and CI | A stranger can implement an agent from the docs |
| 2 | Server plus mock agent | Linux | The whole protocol validated in CI |
| 3 | The real Windows agent | Windows | Every conformance box ticked; escape suite fails to escape |
| 4 | Production hardening | Both | OAuth, mTLS, signed installer, rotation |
| 5 | Capability expansion | Both | Writes, uploads, process and system operations, Tasks |
| 6 | Multi-host (conditional) | Both | Only if actually needed |

---

## Phase 1 — Design *(current)*

**Deliverable:** the `docs/` tree — the overview, the requirements, the architecture, the
normative protocol and policy specifications, the MCP tool surface, the security model, the
operations guide, the conformance checklist, this roadmap, the four JSON Schemas, the four
annotated wire transcripts, the three example policies, and the ADRs recording every decision
that had a real alternative.

There is no code in this phase, which is a deliberate and slightly uncomfortable choice. The
argument for it is that WinShow's central design decision — authorization lives entirely on
the Windows agent, and the server is a dumb relay
([ADR 0003](adr/0003-authorization-on-agent-only.md)) — is the kind of decision that is
nearly impossible to retrofit. A server that started out doing "just a bit" of path filtering
acquires a second enforcement point, and two enforcement points that disagree is worse than
either alone. Deciding that on paper, writing it down normatively, and building against it
costs a few days now and saves a rewrite later.

The same reasoning applies to the wire protocol. WSAP/1 is versioned, has an append-only error
code table, and has explicit forward-compatibility rules
([`03-agent-protocol.md` §11](03-agent-protocol.md#11-versioning-and-forward-compatibility))
precisely so that later phases can add operations without breaking agents built in Phase 3.
Those rules are much cheaper to write before there is an installed base than after.

### Exit criteria

| # | Criterion | How it is checked |
|---|---|---|
| 1.1 | A developer who has never seen this repository can read [`03-agent-protocol.md`](03-agent-protocol.md) and [`04-agent-policy.md`](04-agent-policy.md) and begin writing a conforming agent without asking a question | Hand both documents to someone outside the project and have them describe the handshake, the cancellation contract, and the path canonicalisation order back |
| 1.2 | Every functional requirement in [`01-requirements.md`](01-requirements.md) traces to a named MCP tool in [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md) and to a WSAP operation in [`03-agent-protocol.md`](03-agent-protocol.md) | Traceability table in the requirements document, with no unmapped rows in either direction |
| 1.3 | Every decision that had a genuine alternative has an ADR recording the alternative and why it lost | [ADR 0001](adr/0001-reverse-websocket-transport.md) through [ADR 0009](adr/0009-progress-now-tasks-later.md) exist and are referenced from the documents whose content they explain |
| 1.4 | `tools/validate-docs.py` exits 0 | Schemas are valid; every transcript message validates; event sequences are gapless and `exec.exit` is last; every example policy validates; error codes and operation names agree between prose and schema; every relative Markdown link resolves |
| 1.5 | The conformance checklist covers the specification exhaustively | Every MUST in the two normative documents appears as an observable item in [`08-conformance.md`](08-conformance.md) |

Criterion 1.4 deserves a note. `validate-docs.py` is not documentation hygiene; it is the
mechanism that keeps the prose and the machine-readable contract from drifting apart. The
classic failure of a specification like this one is that the document says `POLICY_DENIED`,
the schema says `POLICY_REFUSED`, and the second implementer picks whichever they read last.
Checking that in CI from the first day means the drift never accumulates.

---

## Phase 2 — Server plus mock agent

**Deliverable:** the Python MCP server, and a Python mock agent that speaks WSAP/1 against a
temporary directory on Linux.

### The server

| Component | Scope |
|---|---|
| Transport | Streamable HTTP on `/mcp` for MCP clients, WebSocket on `/agent` for the agent, both on Starlette under uvicorn |
| MCP layer | The official `mcp` SDK v1.28.x with FastMCP; structured output on every tool; progress notifications for long operations ([ADR 0009](adr/0009-progress-now-tasks-later.md)) |
| Bridge | The single-slot agent registry, request multiplexing by `id`, correlation of events by `corr`, cancellation plumbing, and the credit-window backpressure logic from [`03-agent-protocol.md` §9](03-agent-protocol.md#9-streaming-and-backpressure) |
| Tools | The MVP surface in [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md): list, stat, read, glob, grep, exec |
| Auth | Static bearer token for MCP clients; the pre-shared bearer token for the agent ([ADR 0004](adr/0004-bearer-token-over-hmac-challenge.md)) |
| Observability | The structured audit log, `/metrics`, `/healthz`, and `/readyz` — the last of which stays red until a `session.hello` exchange has completed |

The single-slot registry with newest-wins eviction ([ADR 0007](adr/0007-newest-agent-wins.md))
is the piece most worth building carefully, because it is where half of the interesting
failure modes live: a half-open socket, two agents sharing a token, an eviction racing an
in-flight request.

### Why the mock agent comes first

The mock agent is a Python WSAP/1 implementation that serves a temporary directory on Linux
and executes a small allowlist of harmless commands. It is not a stepping stone toward the
real agent and shares no code with it. It exists for three reasons.

**It makes the entire server testable in CI on Linux.** Every path through the bridge —
multiplexing, cancellation, backpressure, eviction, timeout, malformed frames — can be
exercised on the same machines that run the unit tests, with no Windows host, no VM, and no
manual setup. A test suite that requires a Windows machine to run is a test suite that runs
rarely, and a bridge is exactly the kind of component whose bugs only appear under concurrency
and only get caught by tests that run on every commit.

**It turns the specification into executable truth before anyone touches a Windows API.**
Writing a second implementation of a protocol is the only reliable way to find out which parts
of it were actually specified and which parts were merely described. Every ambiguity the mock
author has to guess at is an ambiguity a third-party implementer would also have hit, and
fixing it in Phase 2 costs a documentation edit. Fixing it in Phase 3, when the Windows agent
has already made the opposite guess, costs a behavioural change on a shipped component.

**It separates protocol bugs from Windows bugs.** When the real agent misbehaves in Phase 3,
the first question is always whether the fault is in the wire handling or in the platform
code. With a mock that passes the same harness, that question has an immediate answer: run the
harness against both and see which one diverges. Without it, every Windows bug is also a
protocol suspicion.

The mock deliberately does *not* emulate Windows. It serves POSIX paths through the
canonicalisation layer where that is meaningful and returns `NOT_IMPLEMENTED` where it is not.
Pretending to be Windows would produce a mock that passes tests the real agent fails, which is
worse than no mock.

### The conformance harness

Phase 2 also produces the harness described in
[`08-conformance.md` §13](08-conformance.md#13-test-vector-index): a WebSocket client that
replays the four transcripts in [`examples/`](examples/) against any agent, playing the server
side and asserting the agent's replies match the recorded ones modulo timestamps, pids,
session identifiers, and live byte counts. It runs against the mock in Phase 2 and against the
real agent in Phase 3, and it is what makes WSAP/1 a standard rather than a description of
whatever the first implementation happened to do.

### Exit criteria

| # | Criterion |
|---|---|
| 2.1 | An MCP client — Claude, or the MCP Inspector — completes a full session against the server plus mock: connect, discover tools, list a directory, read a file, run a command with streamed output, receive structured output |
| 2.2 | The conformance harness passes against the mock agent, in CI, on Linux, with no Windows host anywhere in the pipeline |
| 2.3 | Cancellation works end to end: `notifications/cancelled` from the MCP client reaches the agent as `session.cancel` and produces exactly one terminal message for the request |
| 2.4 | Backpressure works end to end: a mock command emitting output faster than the server consumes it stalls at the credit window rather than growing the server's memory without bound, and a window held full past `sendStallTimeoutMs` produces `exitReason: "backpressure"` |
| 2.5 | **Killing the mock agent mid-request produces a clean error rather than a hang.** The in-flight MCP tool call completes promptly with `AGENT_DISCONNECTED`, carrying whatever partial output arrived, rather than waiting for the MCP client's own timeout |
| 2.6 | Evicting an incumbent agent with a newer connection fails the incumbent's in-flight requests with `AGENT_SUPERSEDED` and leaves the registry holding exactly one session |
| 2.7 | Concurrency is real: a four-minute mock command and a twenty-millisecond directory listing issued together both complete, with the listing returning first |
| 2.8 | The audit log contains a record for every tool call and every denial, and `/metrics` exposes in-flight counts, agent-connection state, and per-operation latency |
| 2.9 | A malformed frame, an oversized frame, a duplicate request id, and an unknown `op` each produce the documented error without closing the connection where the specification says it should stay open |

Criterion 2.5 is called out specifically because a hang is the worst possible failure for this
system. An error is something the model can report and the user can act on; a hang consumes
the user's attention, then their patience, and gives them nothing to report. Every path where
the agent can vanish — network partition, service stop, process kill, eviction — must
terminate the waiting MCP call promptly and with a code that says which of those happened.

---

## Phase 3 — The real Windows agent

**Deliverable:** the Python Windows agent, packaged as a Windows service running under a
virtual service account.

Python was chosen for the agent as well as the server for a specific reason: the operator
intends to run small local models on the Windows host for stage-2 policy review
([`04-agent-policy.md` §6](04-agent-policy.md#6-stage-2-model-assisted-review)), and the
tooling for that is Python-first. The protocol itself is language-agnostic and deliberately
so — [`03-agent-protocol.md`](03-agent-protocol.md) is written to be implementable in C#, Go,
or Rust by somebody who has never seen this repository, and the conformance harness is what
lets them prove they succeeded.

| Area | What gets built |
|---|---|
| Paths | Canonicalisation, `GetFinalPathNameByHandle` resolution, component-wise containment, reserved names, ADS rejection, long-path support, UNC |
| Encoding | The BOM-and-heuristic sniffing order, `decodeErrors` accounting, no line-ending translation, explicit decoding of child output |
| Execution | `CreateProcessW` with an explicit argv, MSVCRT quoting, Job Objects with kill-on-close, create-suspended-assign-resume, restricted handle inheritance, concurrent pipe reading |
| Policy | The TOML engine: schema validation, anchored allow patterns enforced at load, deny-beats-allow, atomic hot reload, per-root overrides |
| Stage 2 | The local reviewer wired in behind a loopback-only endpoint, with strict verdict parsing and `failMode` handling |
| Audit | Append-only file plus Windows Event Log, with redaction applied before write |
| Packaging | Service installation, virtual service account creation, `RequiredPrivileges` reduction, the `--console` debugging mode |

### Exit criteria

| # | Criterion |
|---|---|
| 3.1 | Every box in [`08-conformance.md`](08-conformance.md) is ticked, including the items verified by inspection rather than by the harness — handle inheritance, job membership, service account, file ACLs, log redaction |
| 3.2 | The conformance harness passes **identically** against the mock agent and the real Windows agent. Any divergence is either a specification ambiguity to be fixed in the documents or a bug in one of the two implementations; it is never accepted as a platform difference without a documented reason |
| 3.3 | The policy-escape suite fails to escape, in full |
| 3.4 | Hot reload is demonstrated: editing `policy.toml` narrows access within seconds without a restart, and introducing a syntax error keeps the previous policy live while logging the failure |
| 3.5 | A restart with a broken policy connects, reports `state: "invalid"`, and refuses every operation with `POLICY_UNAVAILABLE` naming the file and location |
| 3.6 | A fifteen-minute build streams output the whole way through without the connection being torn down by a heartbeat timeout, and its process tree is fully reaped on cancellation |

### The policy-escape suite

Criterion 3.3 is a standing adversarial test suite, run in CI against the Windows agent, drawn
from [`08-conformance.md` §15](08-conformance.md#15-self-test-suggestions). Every case must be
**denied**, and the denial must name a rule:

| Case | What it attacks |
|---|---|
| Junction escape — `mklink /J C:\src\shortcut C:\Users`, then read through it | Lexical-only path checking |
| 8.3 short name — `C:\PROGRA~1\...` for a path outside every root | Path checking that does not resolve short names |
| `..` traversal — `C:\src\..\Windows\win.ini` | Missing or misordered lexical canonicalisation |
| Alternate data stream — `C:\src\notes.txt:hidden` | A place data hides from every listing an operator will look at |
| `PATH` override — `env: {"PATH": "C:\\attacker"}`, and the `Path` and `pAtH` variants | Executable substitution, and case-sensitive environment handling |
| `cmd` metacharacter injection — `tasklist & whoami`, and the `\|`, `>`, `^`, `%`, unbalanced-quote variants | The unquotable-`cmd` problem |
| `.bat` under `shell: "none"` | Silent shell routing that bypasses the argv model |
| Sibling root — `C:\src2` against read root `C:\src` | `startsWith` containment |
| Argument injection — a placeholder value containing `"` and `&` | Incorrect MSVCRT quoting |
| Unanchored allow pattern in the policy file | Load-time anchoring enforcement |

This suite is not a one-time gate. It stays in CI for the life of the project, because these
are precisely the regressions that a well-meaning refactor of the path layer reintroduces
without any test noticing.

---

## Phase 4 — Production hardening

Phase 3 produces something correct. Phase 4 produces something that can be operated by a
person who did not write it, on a network they do not fully control.

| Work | Detail |
|---|---|
| OAuth 2.1 resource server | Replace the static bearer token for MCP clients with proper OAuth: RFC 9728 protected resource metadata at `/.well-known/oauth-protected-resource`, strict audience validation on every token, and RFC 8707 resource indicators so a token minted for another service cannot be replayed against WinShow |
| Stateless MCP | Migrate to the 2026-07-28 MCP revision's stateless model, which removes sessions from the client-facing protocol (see [known risks](#known-risks)) |
| mTLS profile | The optional hardening profile from [`03-agent-protocol.md` §1.4](03-agent-protocol.md#14-authentication): a client certificate whose subject CN or SAN equals the `agentId`, asserted at the upgrade |
| Signed installer | An MSI or equivalent, Authenticode-signed, that creates the service, the virtual account, the `%ProgramData%\WinShow` tree with correct ACLs, and an initial `policy.minimal.toml` |
| Token rotation without restart | The server already supports two simultaneously valid tokens; the agent gains the ability to pick up a new token file and reconnect on the next backoff cycle rather than on a service restart |
| Rate limiting | Per-client limits on the MCP side, and the handshake failure rate limiting from `03` §1.4 on the agent side |

The ordering within this phase matters less than the fact that it comes after Phase 3. OAuth
is a substantial piece of work and it protects the *server*; until the agent's enforcement is
proven, hardening the server is hardening the wrong end. The design is explicitly built so
that a fully compromised server still cannot obtain anything the operator did not write into
`policy.toml` ([ADR 0003](adr/0003-authorization-on-agent-only.md)), which is what makes it
safe to defer this.

### Exit criteria

| # | Criterion |
|---|---|
| 4.1 | An MCP client completes the full OAuth flow against the server, and a token with the wrong audience is rejected |
| 4.2 | Token rotation completes with no dropped requests and no service restart on either side |
| 4.3 | The installer produces a working agent on a clean Windows host with no manual ACL or account steps |
| 4.4 | The mTLS profile is demonstrated end to end, and an agent presenting a certificate whose CN does not match its `agentId` is rejected |
| 4.5 | The conformance harness still passes unchanged — hardening added no behavioural change to WSAP/1 |

---

## Phase 5 — Capability expansion

Everything catalogued in
[`03-agent-protocol.md` §6](03-agent-protocol.md#6-deferred-operations) becomes real. The
capability strings were fixed in Phase 1 precisely so that this phase needs no protocol
revision: an agent advertises `fs.write`, the server sees it in `capabilities`, and the tool
appears. Nothing about the wire version changes.

| Capability | What it needs |
|---|---|
| `fs.write`, `fs.append` | Atomic write via temp file plus rename, and — this is the substantive part — a **genuinely separate write policy**. Write roots are not read roots. Being able to read `C:\inetpub\wwwroot` is a diagnostic capability; being able to write it is a deployment capability, and conflating them means every read grant silently becomes a write grant |
| `fs.upload.begin`/`.chunk`/`.commit` | Chunked transfer for files larger than one frame, with the same commit-on-complete atomicity |
| `fs.mutate` | `fs.delete`, `fs.move`, `fs.mkdir`, under the write policy |
| `proc.list` | With `includeCommandLine` separately policy-gated, because command lines routinely contain credentials |
| `proc.kill` | With the hard refusals already specified: never the agent itself, `System`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, or any pid ≤ 4 |
| `sys.services`, `sys.eventlog` | Structured Windows operations, so that querying a service does not require an `exec` allow rule for `sc.exe` and parsing its output |

The structured Windows operations are worth more than they look. Every one of them replaces a
shell-out with a typed call, which means the policy engine gets to authorise "read the
application event log" rather than "run `wevtutil` with these arguments", and the model gets
structured data rather than text it has to parse. Each one that lands is an `exec` allow rule
the operator no longer needs.

### Long-running execution moves to MCP Tasks

The most significant item in this phase is migrating `exec` from a synchronous tool call with
progress notifications onto the MCP Tasks extension. This has been the intended destination
since Phase 1, and [ADR 0009](adr/0009-progress-now-tasks-later.md) records the decision to
ship progress notifications first and move later.

The reasoning is that a fifteen-minute build does not fit the request/response shape of a tool
call. Progress notifications make it survivable — the client sees output arriving and does not
time out — but the call is still bound to the client's connection, so a client that
disconnects loses the result of work that is still running. Tasks are the correct long-term
home: the call returns a task handle immediately, the work continues server-side, and the
client polls or reconnects to collect the result.

This is also the reason the wire protocol was split into `exec.start` / `exec.output` /
`exec.exit` in the first place, rather than a single blocking `exec` operation. WSAP/1 already
models an execution as a started thing that produces events and eventually terminates, which
is exactly the shape a task needs. Migrating to Tasks therefore changes the MCP tool surface
and changes nothing at all below the socket — the agent built in Phase 3 needs no
modification.

### Exit criteria

| # | Criterion |
|---|---|
| 5.1 | Write operations are governed by a write policy with its own roots, and a read-only policy grants no write capability under any configuration |
| 5.2 | An interrupted upload leaves no partial file visible at the destination |
| 5.3 | `proc.kill` refuses every protected process, verified as a test rather than asserted in a comment |
| 5.4 | A fifteen-minute build runs as an MCP task, survives an MCP client disconnect and reconnect, and delivers its full result |
| 5.5 | The conformance harness passes unchanged against a Phase 3 agent that advertises none of the new capabilities — expansion is additive, and an old agent stays conformant |

---

## Phase 6 (conditional) — Multi-host

**This phase happens only if it is actually needed.** WinShow is designed for one Windows
host, that design is load-bearing in several places, and building multi-host speculatively
would trade a system that is simple and correct for one that is general and half-tested. The
single-agent constraint is what makes the registry a single slot, the eviction policy a single
rule, and the authorization story a single file on a single machine.

What follows is not a plan. It is a record of the extension points that exist so that if the
requirement does arrive, it is additive work rather than a rewrite.

| Extension point | Why it is already additive |
|---|---|
| `agentId` exists end to end | It is a required handshake field and a required header, it is carried in every audit record, and it is the natural key. `Optional[Session]` becomes `Dict[agentId, Session]` and the registry's shape barely changes |
| An optional `host` parameter on every tool | Adding an optional parameter to an MCP tool is backwards compatible. Omitted, it means "the only host", which is exactly what today's callers mean |
| The wire protocol needs no host field | Routing is a server concern that lives *above* the socket. Each agent has its own connection, and the server already knows which connection it is writing to. No WSAP change, no wire version bump, and Phase 3 agents work unmodified in a multi-host deployment |
| The audit record already carries `agentId` and the hostname | Multi-host audit is already searchable by host, because the single-host records were never written as if there were only one |
| Eviction is already per-`agentId` | Newest-wins ([ADR 0007](adr/0007-newest-agent-wins.md)) is defined in terms of the identity, not in terms of the slot |

The parts that would need real work are not in the plumbing:

**A host-selection affordance for the model.** With one host, "read the log" is unambiguous.
With five, the model has to choose, and it needs enough information to choose correctly — what
each host is for, what each one's policy permits, which one the user meant. That is a tool
surface and prompt design problem, and it is genuinely harder than the routing.

**Per-host authorization on the client side.** Today the entire authorization story is one
policy file on one machine, and the MCP client's bearer token is a binary in-or-out. With many
hosts, "this client may reach the build server but not the domain controller" becomes a real
requirement, and it has to live on the server — which is precisely the thing this design has
been careful to keep out of the authorization business. Resolving that tension honestly is the
substance of Phase 6, and it is not resolved here.

---

## Known risks

These are the things most likely to force unplanned work. None of them is a reason to change
the plan; all of them are reasons to keep the layering clean.

**The MCP specification is moving.** A revision publishes on 2026-07-28 that removes sessions
from the client-facing protocol in favour of a stateless model. WinShow is being designed
against the current revision, and the migration is scheduled explicitly in Phase 4 rather than
left to be discovered. The mitigation that matters is structural: MCP concerns are confined to
the server's tool layer, and WSAP/1 is a separate protocol with a separate version that owes
MCP nothing ([ADR 0001](adr/0001-reverse-websocket-transport.md)). An MCP revision changes how
the server talks to Claude; it changes nothing about how the server talks to the agent, and it
cannot invalidate a Windows agent already deployed in the field.

**The Python SDK v2 line will eventually supersede v1.x.** WinShow targets `mcp` v1.28.x with
FastMCP ([ADR 0005](adr/0005-python-mcp-sdk-selection.md)). A v2 line will arrive, will
eventually stop receiving fixes on v1, and will require a migration. The same containment
applies: the SDK is a dependency of the tool layer only, and the bridge, the registry, and the
WSAP implementation do not import it. The migration should be a rewrite of the thin layer that
declares tools, not of anything that understands the protocol.

**The server as designed is not horizontally scalable.** Two replicas behind a load balancer
would each want the single agent slot, and the agent — which dials out to one URL — would land
on whichever replica the balancer chose, leaving the other replica with no agent and no way to
serve a request. This is an inherent consequence of the reverse-connection design and the
single-slot registry, both of which are the right choices for one host.

The fix, if it is ever needed, is a shared agent-affinity layer: a coordination store that
records which replica holds which `agentId`, and either a proxy hop that forwards a request to
the replica holding the connection or a sticky routing rule at the balancer. That is real
distributed-systems work — leases, failover, split-brain when a replica is partitioned from the
store but not from the agent — and it is **out of scope for a system serving one Windows
host**. A single replica serving one host has no availability story worth the complexity, and
the honest mitigation is to run one replica and restart it quickly. Note that this risk and
Phase 6 are independent: multi-host with one server replica needs no affinity layer at all.

---

## Related documents

| Document | Purpose |
|---|---|
| [`00-overview.md`](00-overview.md) | What WinShow is and who it is for |
| [`01-requirements.md`](01-requirements.md) | The functional requirements each phase delivers against |
| [`02-architecture.md`](02-architecture.md) | The component structure the phases build out |
| [`03-agent-protocol.md`](03-agent-protocol.md) | The normative wire protocol, fixed in Phase 1 |
| [`04-agent-policy.md`](04-agent-policy.md) | The normative policy engine, implemented in Phase 3 |
| [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md) | The MCP tools built in Phase 2 and extended in Phase 5 |
| [`06-security.md`](06-security.md) | The threat model behind the ordering of Phases 3 and 4 |
| [`07-operations.md`](07-operations.md) | Deployment and monitoring, delivered across Phases 2 to 4 |
| [`08-conformance.md`](08-conformance.md) | The checklist that gates Phase 3 |
