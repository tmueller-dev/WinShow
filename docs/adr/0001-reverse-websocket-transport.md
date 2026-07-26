# ADR 0001: The agent dials out over WebSocket on port 443

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

WinShow brokers file inspection and command execution on exactly one Windows host. The
server is reachable on the internet, because MCP clients need to reach it. The Windows host
is not: it sits behind NAT and a corporate firewall, it has no stable address, and the
operator is not willing — and in most organisations not permitted — to open an inbound port
to it. Any design that requires the server to initiate a connection to the Windows machine
is therefore not merely inconvenient, it is unavailable.

That inverts the usual arrangement. The party that issues requests cannot be the party that
opens the socket. Whatever we choose has to give us a long-lived channel that the Windows
side establishes and the server side then drives, carrying many concurrent request/response
exchanges plus a stream of unsolicited events flowing back from the agent as a command
produces output.

There is a second force. The agent is meant to be re-implementable. The reference
implementation is Python (see
[ADR 0005](0005-python-mcp-sdk-selection.md)), but the specification in
[`../03-agent-protocol.md`](../03-agent-protocol.md) is written so that someone with no
access to the server source can build a conforming agent in whatever language their
environment already trusts. That makes the implementation burden on a third-party agent
author a first-class selection criterion, not an afterthought.

## Decision

The agent dials out to the server over **WebSocket on TLS**, `wss://`, on port 443 by
default, and the WinShow Agent Protocol (WSAP/1) runs over that link as one JSON object per
text frame. The server never initiates a connection to the Windows host, and the Windows
host never requires an inbound firewall rule.

The same ASGI application serves the MCP Streamable HTTP transport at `/mcp` and the agent
WebSocket at `/agent`. They are separate protocols on separate paths that happen to share a
process, as described in [`../02-architecture.md`](../02-architecture.md).

## Alternatives considered

Each option was judged on whether it is genuinely bidirectional, whether it multiplexes
concurrent exchanges over one connection, how well it survives corporate proxies and a
443-only egress policy, and how much work it imposes on somebody writing a third-party agent
in an arbitrary language.

| Option | Assessment | Verdict |
|---|---|---|
| WebSocket over TLS | Bidirectional by construction. Multiplexing must be built by us on top of the message stream, which is the one real cost. Traverses proxies via `CONNECT`, indistinguishable from HTTPS at the network edge, and standard on 443. A client library ships with, or is one small dependency away from, every language an operator would plausibly use. | **Chosen** |
| HTTP long-poll, or SSE downstream with POST-back upstream | Bidirectional only in the sense that two half-duplex channels glued together are. Requires correlating two independent HTTP conversations, handling the case where one dies and the other does not, and re-establishing the downstream leg on every proxy idle timeout. Proxy-friendly, but the agent author now writes a state machine instead of using one. | Rejected |
| gRPC bidirectional streaming | Genuinely bidirectional and multiplexed, and HTTP/2 would give us flow control for free. But it needs HTTP/2 end to end, which many intercepting corporate proxies will not carry, and it obliges every agent implementer to adopt protobuf, a code generator, and a gRPC runtime. That is a heavy tax on the goal of "conforming agent in any language". | Rejected |
| SSH reverse tunnel (`ssh -R`) | Solves reachability well and is battle-tested. But it makes an SSH daemon on the server and an SSH client on the Windows host part of the security perimeter, moves authentication out of the application and into `authorized_keys`, and produces a tunnel that forwards a port rather than a protocol — we would still have to define what runs inside it. It also fails the "any language" test differently: the agent author now depends on an external binary and its configuration. | Rejected |
| Raw TCP plus TLS with custom framing | Maximum control and minimum overhead, and we would still have to invent framing, ping/pong, and close semantics — all of which WebSocket already specifies. Worse, a bare TLS stream on 443 that is not HTTP is exactly what a `CONNECT` proxy will refuse or an inspecting middlebox will drop. | Rejected |
| MQTT or AMQP broker | Bidirectional, multiplexed by topic, and the broker absorbs reconnection. But it introduces a third piece of infrastructure to deploy, secure, and monitor for a system that has exactly one agent, and request/response correlation over a pub/sub fabric is something we would build anyway. The operational weight is disproportionate to one Windows host. | Rejected |

## Why not run MCP itself over the reverse link

The obvious-looking simplification is to carry MCP end to end: let the Windows agent be an
MCP server that dials out, and let the WinShow server be a proxy. We rejected it for three
reasons.

First, **MCP has no dial-out transport**. The specification defines exactly two standard
transports, stdio and Streamable HTTP, and both have the client connecting to the server.
Custom transports are permitted, but nobody else implements one, so "run MCP over the reverse
link" really means "invent a custom MCP transport and be its only user". We would be doing
the same design work with none of the ecosystem benefit.

Second, it would **push MCP into the agent**. Today an agent implementer reads one document
and handles a twelve-field envelope. Under the alternative they would have to implement
JSON-RPC 2.0, the MCP initialization handshake, capability negotiation, the lifecycle rules,
and whatever the specification adds next — including revision churn such as the session model
being removed in the 2026-07-28 revision. That is a large, moving surface to impose on
somebody whose actual job is to list a directory and start a process.

Third, and most important, **the agent's operations are deliberately at a different level
than MCP tools**. WSAP exposes `fs.read` with byte offsets, line ranges, encodings, chunking,
and an acknowledgement window; MCP exposes a tool that a model can call. The seam between
them is where the server translates low-level, precisely-specified primitives into a small
number of model-facing tools, where it applies truncation and summarisation, and where it
decides what a progress notification looks like (see
[ADR 0009](0009-progress-now-tasks-later.md)). Collapsing the two layers would mean the
Windows agent's wire format changes whenever the tool surface changes. Keeping them separate
means the agent specification can stay stable while the MCP-facing side evolves. The seam is
a feature, not an accident.

## Consequences

### What this buys us

The Windows host needs no inbound firewall rule, no port forward, and no stable address; it
needs only outbound 443, which it already has. The connection is indistinguishable from
HTTPS to a network appliance, and the proxy support described in
[`../03-agent-protocol.md` §1.6](../03-agent-protocol.md#16-proxy-support) works because
`CONNECT` tunnelling is a solved problem for WebSocket clients. Authentication happens at the
HTTP handshake, before any upgrade, which is what makes the bearer-token design in
[ADR 0004](0004-bearer-token-over-hmac-challenge.md) work. And the agent contract stays small
enough that a third party can implement it.

### What it costs us

We hand-roll what HTTP/2 would have given us for free. Multiplexing is our own correlation-id
scheme (`id`, `corr`, `seq`) with its own ordering rules, and flow control is our own credit
window advanced by `exec.ack`, with its own stall timeout. Both are specified normatively in
[`../03-agent-protocol.md` §8](../03-agent-protocol.md#8-concurrency-and-ordering) and
[§9](../03-agent-protocol.md#9-streaming-and-backpressure) precisely because they are ours to
get right, and both are places where an agent implementation can be subtly wrong. We also
own reconnection, liveness detection, and the single-agent eviction rule of
[ADR 0007](0007-newest-agent-wins.md), none of which a transport gives us.

### What we would have to change to reverse it

Reversing the direction — server dials agent — would change only §1 of the protocol document
and the agent's connection loop; the envelope, the operations, and the policy engine are
direction-agnostic. Reversing the *protocol* choice is the expensive one: moving WSAP onto
gRPC or onto a broker would replace §§1, 2, 8 and 9, invalidate every transcript in
[`../examples/`](../examples/), and require every agent implementation to be rewritten.
Nothing above the envelope would need to change, which is the main reason those layers are
specified separately.
