# ADR 0007: When a second agent connects, the newest one wins

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

WinShow brokers access to exactly one Windows host, and the server holds exactly one agent
session at a time. That constraint is deliberate: it keeps request routing trivial, it makes
the handshake's policy summary unambiguous, and it means the operator never has to reason
about which of several agents answered.

It also forces a decision that only becomes obvious in production. When a second connection
authenticates successfully while a session already exists, one of the two has to go. Either
the newcomer is rejected and the incumbent keeps the slot, or the incumbent is evicted and
the newcomer takes it.

Stated abstractly, reject-new sounds safer — it protects an established, working session from
being disturbed. Stated concretely, it is the wrong answer, because of what actually produces
a second connection in practice.

**The dominant real-world case is a half-open TCP connection.** The Windows host's network
drops: a laptop lid closes, a VPN reconnects, a NAT table entry is evicted, a wireless
access point hands over. The agent's side of the connection is torn down immediately and it
begins reconnecting. The server's side is not torn down, because nothing told it anything
happened. TCP will not notice until a write fails or a keepalive times out. So the server
sits there believing it has a healthy agent, holding a socket that will never carry another
byte, while the real agent is knocking on the door.

Under reject-new, that state persists until the server's dead-peer detection fires. WSAP's
liveness mechanism is an application-level heartbeat
([`../03-agent-protocol.md` §3.2](../03-agent-protocol.md#32-sessionping--either-direction-reqres)),
and the dead-peer timer is 60 seconds. For that whole minute the system is broken in the most
frustrating possible way: the agent is up, the server is up, the network is fine, and every
request fails. The agent, meanwhile, is retrying into a closed door and being refused, so
nothing it does can shorten the outage.

Under newest-wins, the same failure self-heals in one round trip. The new connection
authenticates, the server evicts the stale one, and the system is working again before anyone
notices.

## Decision

**When a second agent authenticates and completes `session.hello`, the incumbent is evicted
and the newcomer takes the session.** The newcomer is never rejected on the grounds that a
session already exists.

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| Newest wins — evict the incumbent | Self-heals the half-open case in one round trip. Requires the evicted agent to back off so a genuine two-agent misconfiguration does not become a reconnection storm. | **Chosen** |
| Reject the newcomer | Protects an established session, including one that is already dead. Leaves the system broken for up to 60 seconds in the most common failure, with nothing the agent can do to recover faster. | Rejected |
| Accept both, route by `agentId` | Removes the conflict by removing the single-agent model, and with it the guarantee that one host answers. Two agents would report two policy summaries, and the server would have to choose between them per request. That is a different product. | Rejected |
| Probe the incumbent before deciding | Sounds principled: ping the existing session, and evict only if it fails. But a half-open socket absorbs the ping silently, so the probe has to time out before the decision can be made — reintroducing the delay newest-wins exists to avoid, on every legitimate reconnection. | Rejected |

## The eviction sequence

The order matters, and it is fixed. The server evicts the incumbent **before** installing the
newcomer, so there is never a moment where two sessions are simultaneously live. A worked
example is in
[`transcript-reconnect.jsonl`](../examples/transcript-reconnect.jsonl).

1. The newcomer's `session.hello` arrives and is validated. It may carry `resumeOf` naming
   the previous `sessionId`; that field is informational only, and **no state is ever
   resumed**.
2. The server sends `session.bye` on the incumbent connection with
   `reason: "superseded"` and `bySessionId` naming the successor session. Because
   `session.bye` is the one event with no originating request, its `corr` is the `sessionId`
   of the connection being closed. Naming the successor is what lets an operator stitch the
   two sessions together in a log and see that one replaced the other, rather than seeing two
   unexplained disconnections.
3. Every in-flight request on the incumbent connection is failed. The server surfaces these
   to its own MCP clients as `AGENT_SUPERSEDED`, one of the server-originated codes that never
   appears on the WSAP wire.
4. The incumbent connection is closed with WebSocket close code **4009**.
5. The server responds to the newcomer's `session.hello` and the new session becomes ready.

Note what step 3 implies and the protocol states plainly: a running `exec.start` on the
evicted connection does not survive. `exec.start` is not idempotent and **must not** be
retried by anyone — not the server, not the agent — because nobody can know whether the
command already ran. Retrying is a decision for a human or a model, made with the audit log
in hand.

## The obligation on the evicted agent

An agent that receives `session.bye` with `reason: "superseded"`, or is closed with code
4009, **must apply an elevated reconnection backoff of at least 5 seconds, and must log the
eviction prominently.**

Both halves matter, for the same reason. Eviction has exactly two causes. One is the
half-open case, where the evicted connection is this same agent's own stale socket — harmless,
already resolved, and nothing to report. The other is that **two agents are sharing one
token**: a forgotten instance on another machine, a service that was supposed to be
decommissioned, a test agent someone left running. That second case is a genuine
misconfiguration, and it has a nasty dynamic. Two agents that both reconnect immediately will
evict each other in a tight loop, producing a system that appears to work intermittently,
fails unpredictably, and floods both hosts with connection churn. The backoff breaks the loop;
the prominent log entry is what lets an operator find the cause instead of chasing a
phantom network fault.

The log line is not a nicety. From the outside, the two-agent case and the half-open case look
identical, and the only place the distinction can be observed is in the agents' own logs.

## Consequences

### What this buys us

The overwhelmingly common failure — a network blip leaving a half-open socket — recovers in a
single round trip instead of waiting out a 60-second timer, and it recovers by the agent
doing the thing it was already going to do. The recovery path and the normal connection path
are the same code, which means the recovery path is exercised constantly rather than only
during incidents. There is no special "force takeover" operation to design, secure, or abuse.

### What it costs us

**Anyone holding the token can boot the incumbent.** That is a real capability and it should
be named rather than glossed over. We accept it because it grants nothing new: a token holder
can already open a session and issue requests, and every one of those requests is judged by
the policy on the Windows host ([ADR 0003](0003-authorization-on-agent-only.md)). The
incremental power gained by also being able to displace the legitimate agent is the ability
to cause a disruption, not the ability to do anything the policy forbids. Since the token is
a long-lived bearer credential ([ADR 0004](0004-bearer-token-over-hmac-challenge.md)),
protecting it is already the load-bearing control, and eviction does not change that
calculation.

The second cost is the misconfiguration dynamic described above, which is why the backoff and
the log requirement are normative rather than advisory. Without them, newest-wins converts a
duplicate-agent mistake into a self-sustaining outage.

### What we would have to change to reverse it

Switching to reject-new is a small change on the server — refuse the handshake and close —
and would want a distinct error code and close code so the newcomer can tell "a session
already exists" apart from "your token is wrong". It would also need shorter dead-peer
detection to be tolerable at all, which means a faster heartbeat and more traffic on a link
that may be metered. Supporting multiple simultaneous agents is not a reversal but a redesign:
it would change routing, the meaning of the policy summary, and the server's tool surface,
since a caller would then have to say which host they meant.
