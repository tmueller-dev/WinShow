# ADR 0005: Python 3.12 with the official `mcp` SDK v1.x, and a Python reference agent

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

WinShow is an MCP server that MCP clients reach over HTTP, and it is also a WebSocket server
that the Windows agent dials into ([ADR 0001](0001-reverse-websocket-transport.md)). Both
live in one ASGI application: `/mcp` speaks the MCP Streamable HTTP transport, `/agent`
speaks WSAP/1. That shape — a hand-written ASGI application with an MCP implementation
mounted into it — constrains what a framework needs to give us, and it turns out to constrain
it quite a lot.

There are two separable decisions here and this record covers both, because the second is
frequently misread as following from the first when in fact it has an entirely different
justification. The first is what the **server** is built on. The second is what language the
**reference agent** is written in.

At the time of writing, the current stable MCP specification revision is **2025-11-25**, with
revision **2026-07-28** in release candidate. The upcoming revision removes the session model
(`Mcp-Session-Id` is no longer required), adds `Mcp-Method` and `Mcp-Name` routing headers,
adopts W3C Trace Context, and graduates the Tasks utility from experimental to an extension.
It adds no new transports. Whatever we build on has to absorb that revision without a
rewrite.

## Decision

**The server is Python 3.12, using the official `mcp` SDK pinned `>=1.28.1,<2`, with
Starlette, uvicorn, Pydantic v2, and anyio.**

**The Windows agent reference implementation is also Python**, chosen by the operator for
reasons unrelated to the server stack — see below.

The specification remains language-agnostic. Python is the reference implementation and never
a protocol requirement.

## Alternatives considered — the server stack

| Option | Assessment | Verdict |
|---|---|---|
| Official `mcp` SDK, v1.x line, with FastMCP | The stable line the maintainers recommend for production, currently 1.28.1. Includes FastMCP, which handles tool registration, schema generation from type hints, and the Streamable HTTP session manager. Mounts into a Starlette application we own. | **Chosen** |
| Official `mcp` SDK, v2.x (`mcp==2.0.0b1`, class `MCPServer`) | Pre-release. Its own README says not to use it in production, which settles the matter for a system whose job is to run commands on somebody's Windows box. Worth tracking, not worth adopting. | Rejected |
| Community `fastmcp` (PrefectHQ) 3.x | A genuinely capable separate project with more batteries: server composition, generated clients, auth helpers, deployment conveniences. But it is a different project on a faster release cadence, and the main thing it would have done for us — own the web application — is the one thing we are deliberately doing ourselves, because the agent WebSocket has to live in the same app. We would take the churn and use the smaller half. | Rejected |
| Hand-rolled JSON-RPC over Starlette, no MCP SDK | Total control and total maintenance. We would own protocol version negotiation, capability advertisement, structured output, progress notifications, and the transport's session semantics — all of which change with the specification, as the 2026-07-28 revision demonstrates. | Rejected |

To be fair to the community `fastmcp` package: for a project whose deliverable is *only* an
MCP server, its extra machinery is a real advantage and the faster cadence is a feature
rather than a risk. Our situation is unusual in that the MCP server is one of two protocols
in one process, and the second one is the one with the interesting requirements. Under those
circumstances the smaller, slower-moving, officially-maintained dependency is the better
trade. This is a judgement about our shape, not a criticism of theirs.

Pinning `>=1.28.1,<2` is deliberate on both ends. The lower bound is the current stable
release; the upper bound stops a `pip install` from silently pulling in the 2.x line, whose
entry point is a differently-named class and whose README asks us not to.

## The lifespan gotcha, recorded because it is silent

Mounting FastMCP into a Starlette application has one failure mode that is worth writing down
in an architecture record rather than leaving in a comment, because it produces no error.

FastMCP's Streamable HTTP transport needs `session_manager.run()` to be running for the
duration of the server's life. That is normally driven by the sub-application's lifespan. But
**nested lifespans are silently not run**: mounting the app does not cause Starlette to
execute the mounted app's lifespan, so the session manager never starts and requests to
`/mcp` fail in ways that look like a transport bug rather than a wiring bug.

The parent application's lifespan must therefore drive `session_manager.run()` explicitly.
The same lifespan is the natural place to start and stop the agent connection registry, which
means the two halves of the process — the MCP side and the WSAP side — have a single,
explicit startup and shutdown ordering rather than two implicit ones.

## The second decision: a Python reference agent

The Windows agent could have been written in anything. The protocol was designed so that it
could be ([ADR 0001](0001-reverse-websocket-transport.md),
[ADR 0002](0002-json-envelope-base64-payloads.md)), and nothing in
[`../03-agent-protocol.md`](../03-agent-protocol.md) presumes a language.

The reference agent targets **Python 3.11 or later**, a lower floor than the server's 3.12
because the agent has to install on whatever Windows hosts already exist rather than on a
machine we provision. The two are independent processes with independent version floors, which
is why the handshake examples in the protocol document report
`"implementation": "python-3.11"` while the server is 3.12 — that field describes the agent
that sent it, and any value is conforming.

The operator chose Python for one concrete reason: **the stage-2 model review runs on the
Windows side**, and that tooling lives in Python. The design in
[`../04-agent-policy.md` §6](../04-agent-policy.md#6-stage-2-model-assisted-review) has a
small local model reviewing `exec.start` requests that the deterministic rules have already
allowed, over a loopback endpoint, with a hard timeout and a fail-closed default. Keeping the
agent and the reviewer in the same runtime removes a process boundary, a serialisation step,
and a deployment artefact from the part of the system that has the tightest latency budget
and the strictest failure semantics.

That choice is not free, and the tradeoff should be stated plainly rather than discovered
during a rollout: **a Python runtime on a locked-down Windows host is a heavier deployment
story than a self-contained single-file binary.** A .NET AOT or Go agent would ship as one
executable, with no interpreter to install, no site-packages to keep consistent, no
antivirus exclusions for a directory full of scripts, and a much smaller software bill of
materials for whoever has to approve it. On a hardened server, that difference is not
cosmetic. We accept it in exchange for having the local model integration in-process, and we
accept it knowing that a second implementation in a compiled language is a perfectly
reasonable thing for someone to build.

Which is the point of insisting on the distinction: **Python is the reference implementation,
never a protocol requirement.** Everything a conforming agent must do is in the protocol
document and the schemas, and the handshake reports the implementation as a string in
`agent.implementation` precisely so that it is descriptive metadata rather than something the
server branches on. The Phase 2 conformance harness
([`../08-conformance.md`](../08-conformance.md)) must therefore run against **any** agent
over a WebSocket, driven by the transcripts in [`../examples/`](../examples/README.md) — it
must not import the reference agent, call into it, or assume anything about its internals. A
harness that can only test the Python agent would quietly convert the reference
implementation into the specification, which is exactly the outcome the whole documentation
effort exists to prevent.

## Consequences

### What this buys us

One language and one async runtime across both halves of the system, with anyio underneath
both the MCP SDK and our WebSocket handling, so there is a single concurrency model to reason
about. A stable, officially-maintained MCP implementation that will track specification
revisions — including the removal of the session model in 2026-07-28 — without us having to.
Pydantic v2 models that are shared between the tool surface and the WSAP payload validation.
And, on the Windows side, an in-process path to the local reviewer.

### What it costs us

The server carries a dependency whose release cadence we do not control, and a pin that will
need a deliberate review when 2.x stabilises. The agent carries a Python runtime onto a
Windows host where a single binary would have been easier to approve and easier to install.
And the lifespan wiring is a piece of non-obvious integration knowledge that has to survive
in documentation, because nothing in the code will complain if it is removed.

### What we would have to change to reverse it

Replacing the MCP SDK means rewriting the tool surface and the transport wiring, but nothing
below it: WSAP, the policy engine, and the schemas are independent of how MCP is served.
Replacing the reference agent with a compiled implementation means rewriting the agent and
re-hosting the stage-2 reviewer as a separate local service behind the loopback endpoint the
policy already specifies — which is why that endpoint is defined as an address rather than an
in-process call. Neither reversal touches
[`../03-agent-protocol.md`](../03-agent-protocol.md), and that is the property worth
protecting.
