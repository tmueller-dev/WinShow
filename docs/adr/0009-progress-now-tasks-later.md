# ADR 0009: Progress notifications now, the Tasks extension later

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

A `dotnet build` takes four minutes and produces output the whole time. On the WSAP side that
is already handled well: the agent streams `exec.output` events as the child writes, under a
credit window advanced by `exec.ack`, and finishes with exactly one `exec.exit`
([`../03-agent-protocol.md` §9](../03-agent-protocol.md#9-streaming-and-backpressure)). The
server sees the build happening.

The question this record answers is what the *MCP client* sees. MCP is a request/response
protocol at heart: the client calls a tool and eventually receives a `CallToolResult`. There
are three mechanisms that could carry the middle of a long-running command to the caller, and
they are at very different stages of maturity.

**Progress notifications** are available today and well supported. A client that wants them
includes a `progressToken` in the request's `_meta`, and the server sends notifications
carrying a monotonically increasing `progress` value and an optional human-readable `message`.
The critical property, and the one that shapes this decision, is that the specification makes
them **advisory**: a receiver may send none at all, and a client may ignore every one it
receives. Nothing may depend on them.

**Structured tool output** is also available today: a tool declares an `outputSchema` and
returns `structuredContent` alongside its human-readable content. This is a contract, not a
hint.

**Tasks** is the utility designed for exactly our problem — durable, long-running requests
that the client can poll, cancel, and retrieve results from independently of the connection
that started them. It was **experimental** in specification revision 2025-11-25 and
**graduates to an extension** in revision 2026-07-28, which is currently a release candidate.

## Decision

**Long-running command output surfaces to MCP clients as progress notifications now, with the
buffered final result always authoritative. The design migrates to the Tasks extension later.**

Concretely:

- The tool that runs a command — see [`../05-mcp-tool-surface.md`](../05-mcp-tool-surface.md)
  — returns a `CallToolResult` containing the complete captured
  output and a `structuredContent` object carrying the exit code, exit reason, timings, and
  byte counts. **That result is the contract.**
- While the command runs, if the caller supplied a `progressToken`, the server emits progress
  notifications summarising output as it arrives. These are a convenience and nothing more.
- A command that fails is not a protocol error. It is a normal result with `isError: true`, so
  the client can feed it back to the model for self-correction, which is what the
  specification intends that flag for. A protocol-level JSON-RPC error is reserved for the
  cases where the call itself was malformed or could not be dispatched.

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| Progress notifications now, buffered authoritative result | Works with every client today. Nothing depends on the advisory channel. Costs the caller a wait for the final result if their client ignores progress. | **Chosen** |
| Build on the Tasks utility now | Exactly the right abstraction, and experimental in the current stable revision. Adopting it now means building against a moving target and excluding every client that has not implemented it — for a system with one agent and one host. | Deferred, not rejected |
| Stream output as the sole delivery mechanism | Would make correctness depend on an explicitly advisory channel. A client that ignores progress notifications, which the specification permits, would receive a successful tool call with no output at all. | Rejected |
| Chunk the command into several tool calls the model drives | Pushes protocol mechanics into the model's reasoning, multiplies round trips, and makes the audit trail a set of unrelated executions. | Rejected |

## Why the final result has to be authoritative

This follows directly from the specification making progress advisory, and it is worth
spelling out because it is easy to design past.

If output were delivered *only* through notifications, then a client that ignores them —
behaviour the specification explicitly permits — would see a tool call that succeeded and
returned nothing. The failure would be silent, intermittent across clients, and would look
like a bug in WinShow. So the buffered result is not a fallback for when streaming fails; it
is the delivery mechanism, and streaming is a preview of something that is coming anyway.

The same reasoning explains why `structuredContent` carries the outcome rather than leaving it
to be parsed out of the text. `exitReason` is authoritative over `exitCode` on the WSAP side —
when the agent terminates a process on timeout or cancellation, the exit code is whatever
`TerminateProcess` was given and carries no meaning
([`../03-agent-protocol.md` §10.5](../03-agent-protocol.md#105-exit-codes)) — and that
distinction has to survive the trip to the MCP client as a field, not as a sentence in a
transcript that a model might misread.

## Rate limiting and truncation

Two practical constraints shape what the progress channel actually carries.

**Roughly four notifications per second**, following the specification's guidance about
flooding. The agent's flush rules are tuned for the WSAP link and can produce chunks
considerably faster than that — 64 KiB accumulated, or 250 ms elapsed, or a newline boundary
with at least 4 KiB pending
([`../03-agent-protocol.md` §9.2](../03-agent-protocol.md#92-flush-rules-for-execoutput)).
The server coalesces intermediate chunks into a single notification per interval rather than
relaying each one. A model consuming progress at conversational speed gains nothing from ten
updates per second, and a client that renders each notification would be doing meaningful work
to display text nobody reads.

**Head-plus-tail truncation, with an explicit omitted-bytes marker**, in the case where the
captured output still exceeds what a single tool result should carry. This is not a routine
occurrence: the agent has already bounded the capture at the policy's `maxOutputBytes`, so a
normal result carries everything the agent captured. Truncating from the end is the intuitive
choice for the case that remains, and the wrong
one: the interesting part of a failing build is the error at the end, and the invocation
banner — the command line, the tool version, the target framework — is at the start. Both ends
carry signal and the middle usually does not. The marker is required, and states how many
bytes were dropped, because a model reading a truncated transcript with no indication of the
gap will happily reason about a build log as though it were complete.

WSAP already reports the raw facts needed to make this honest: `truncated`,
`truncationReason`, `stdoutBytes`, and `stderrBytes` on `exec.exit`, alongside the `dropped`
flag on individual `exec.output` events. The MCP-facing truncation is the server's own layer
on top, and both are visible in the structured result.

## Why the migration will not be a redesign

The WSAP execution operation was deliberately split into three messages — `exec.start`,
`exec.output`, `exec.exit` — rather than being a single request that returns everything when
the process finishes. That split does no work for the buffered design; the server could just
as well have received one large response at the end.

It exists because it maps directly onto what Tasks needs. `exec.start` is the point at which a
task would be created and a handle returned, `exec.output` is the incremental state a poll
would report, and `exec.exit` is the terminal state that makes the result retrievable. The
correlation identifier that ties the three together is already the natural task identifier,
and the cancellation path already exists in a form that fits: one mechanism, `session.cancel`,
fed by three triggers, one of which is the MCP client's `notifications/cancelled`
([`../03-agent-protocol.md` §8.4](../03-agent-protocol.md#84-cancellation)).

So the migration is a change to how the server presents an execution to its MCP clients, not a
change to how executions work. Nothing in the agent moves, no transcript in
[`../examples/`](../examples/README.md) is invalidated, and no conforming agent needs to be
updated. That property was bought deliberately, at the cost of a slightly more elaborate wire
protocol than the buffered design strictly required.

## Consequences

### What this buys us

Every MCP client works today, including clients that implement no optional utilities at all.
Correctness never depends on an advisory channel. A client that does support progress
notifications gets a genuinely better experience — the user sees a build progressing rather
than a spinner — without that experience being load-bearing. And the code path that matters
most, the one that produces the final authoritative result, is exercised on every single call
rather than only when streaming is unavailable.

### What it costs us

A caller whose client ignores progress waits for the whole command with no feedback, bounded
by the agent's `maxExecMillis` — five minutes by default. There is no way to retrieve results
after a disconnection: if the MCP client goes away, the tool call is gone, and under WSAP's
cancellation rules the process is terminated with it. That is precisely the gap Tasks exists
to close, and until we adopt it, it stays open.

The server also buffers a whole execution's output in memory before responding, bounded by the
policy's `maxOutputBytes` (4 MiB by default). That is a deliberate ceiling rather than an
oversight, but it is a ceiling, and a command that would legitimately produce more must be
made narrower rather than being allowed to stream past it.

### What we would have to change to reverse it

Adopting Tasks means adding a task-shaped presentation of `exec.start` on the MCP side:
returning a handle, servicing polls from the accumulating state the server already keeps, and
mapping task cancellation onto the `session.cancel` path that already exists. Progress
notifications would remain, since they stay useful for the interactive case and cost nothing
to keep. The WSAP protocol, the policy engine, the agent, and the conformance vectors are
untouched. The trigger for doing it is the 2026-07-28 revision reaching stable and clients
implementing the extension — at which point this is a feature addition rather than a
reversal, which is the outcome the three-message split was designed to produce.
