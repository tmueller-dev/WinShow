# ADR 0004: A pre-shared bearer token at the handshake, not an HMAC challenge-response

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

The agent dials out to the server ([ADR 0001](0001-reverse-websocket-transport.md)), so the
server has to decide whether the peer that just connected is the agent it was expecting. This
is the only authentication event in WSAP/1: once a connection is established and the
handshake completes, every subsequent message on that socket inherits its identity.

Two designs are conventional. The first sends a shared secret as an HTTP header on the
upgrade request, over TLS. The second accepts the connection, then runs a challenge-response
exchange over the established WebSocket in which the server sends a nonce and the agent
returns an HMAC of it under the shared key.

The second design has an appealing property that is worth stating fairly, because it is the
reason anyone proposes it: the secret never travels. If the transport were compromised — a
proxy terminating TLS with a certificate the agent wrongly trusted, say — a bearer token
would be captured and replayable, whereas an HMAC response is bound to a nonce and useless
afterwards.

The question is whether that property is worth what it costs, and whether it is the right way
to close the risk it addresses.

## Decision

**A pre-shared bearer token, presented in the `Authorization` header of the HTTP handshake
request, over TLS with mandatory certificate chain and hostname verification.** The
normative requirements are in
[`../03-agent-protocol.md` §1.4](../03-agent-protocol.md#14-authentication): at least 32
bytes of CSPRNG output, header only and never a query string, constant-time comparison, two
simultaneously valid tokens so rotation needs no downtime, and never written to a log at any
level.

Rejection happens **before** the WebSocket upgrade. A missing or invalid token gets
`HTTP 401` with `WWW-Authenticate: Bearer` and no upgrade at all.

## Why, specifically

**It is rejectable before the upgrade, so an unauthenticated peer never reaches the message
layer.** This is the decisive reason. A challenge-response scheme must accept the socket
first: complete the upgrade, allocate connection state, start a read loop, and only then
discover the peer cannot answer. That is a free denial-of-service primitive — anyone who can
reach the endpoint can make the server allocate a connection, and in a system whose single
agent occupies a single session slot, an attacker who can open sockets can crowd out the real
agent without holding any secret at all. Rejecting at the HTTP layer means an unauthenticated
peer consumes a request and a 401, and nothing else. The rate limiting in §1.4 — five
failures from one source address within 60 seconds, then `429` with `Retry-After` — is
possible for the same reason.

**It works through reverse proxies and gateways, which can enforce it independently.** A
bearer token in a standard header is something an operator's existing edge already knows how
to check, log the absence of, and rate-limit. A challenge-response exchange conducted in
application messages after the upgrade is invisible to every layer in front of the
application, so the edge can only pass everything through and hope.

**Every WebSocket client library supports custom handshake headers.** That is not true of
every library for the pieces challenge-response needs. It adds a mandatory round trip before
the connection is usable, a nonce state machine on both sides, a constant-time HMAC
comparison, and a cryptographic dependency — for an implementer whose actual job is to list
a directory and start a process. Given that the protocol is written so a third party can
build a conforming agent in any language
([`../03-agent-protocol.md`](../03-agent-protocol.md)), that tax is charged to exactly the
people we most want to keep.

**TLS with mandatory hostname verification already provides what challenge-response would
buy.** The property being purchased is confidentiality of the secret in transit against an
active network attacker. TLS provides that, and the agent's obligations in
[§1.5](../03-agent-protocol.md#15-certificate-validation) — full chain validation, hostname
verification against the certificate's SAN entries, no silent disabling of revocation
checking — are what make it hold.

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| Bearer token in the handshake header, over validated TLS | Rejectable pre-upgrade, enforceable by intermediaries, trivially implementable everywhere, and adequately protected by the transport. | **Chosen** |
| HMAC challenge-response after the upgrade | The secret never crosses the wire, which matters only if TLS has already failed. Costs a pre-upgrade rejection path, a round trip, a state machine, and a crypto dependency for every implementer — and hands anyone who can open a socket a way to consume connection state. | Rejected |
| Mutual TLS | Strong, and it authenticates at the transport rather than above it. But it makes certificate issuance, distribution, and renewal a prerequisite for the simplest deployment, which is a lot to ask of an operator connecting one Windows box. | Kept as an **optional hardening profile** |
| Token in a query string | Works with libraries that cannot set headers, and lands the secret in every proxy and server access log on the path. | Rejected outright |

## The residual risk, and how it is actually closed

The honest residual risk is a man-in-the-middle holding a certificate the agent will accept
— a forged or mis-issued certificate, or a corporate interception proxy whose CA is in the
trust store — who harvests a reusable secret and can then impersonate the agent indefinitely.

The right response is not to make the secret non-replayable, because an attacker in that
position can relay a challenge-response exchange in real time anyway and owns the connection
regardless. The right response is to **prevent the man in the middle from existing**, and
that is what the transport requirements do. Mandatory hostname verification means the
attacker needs a certificate valid for the server's actual name from a CA the agent trusts,
not merely any valid certificate. The optional `pin` trust mode narrows it further: chain
validation still applies, and in addition the server's SPKI SHA-256 must match one of the
configured pins, which defeats even a trusted-but-mis-issuing CA. The specification asks for
at least two pins so that a certificate rotation does not brick the agent.

Note the difference in kind. Challenge-response would *limit the damage* from a successful
interception; hostname verification plus pinning *prevents the interception*. Preventing it
is strictly better, and it is why the interception case is handled by requiring a
deliberately configured trust bundle
([`../03-agent-protocol.md` §1.6](../03-agent-protocol.md#16-proxy-support)) rather than by
complicating the authentication exchange.

For deployments that want transport-level mutual authentication anyway, the **mTLS hardening
profile** is available: the server requires a client certificate and asserts that its subject
CN or a SAN entry equals the `agentId`. Support is optional for conformance, so it hardens a
deployment without raising the floor for implementers.

## Consequences

### What this buys us

Unauthenticated peers are turned away at the HTTP layer, before any connection state exists,
which makes the single-agent session slot much harder to attack. Authentication is one header
that any client library can set and any reverse proxy can inspect. Token rotation is a
configuration change with no downtime, because the server accepts two valid tokens at once.
And a conforming agent needs no cryptographic code of its own beyond a TLS client it was
going to need anyway.

### What it costs us

The secret is a long-lived bearer credential. Anyone who obtains it can connect as the agent,
and — under the eviction rule in [ADR 0007](0007-newest-agent-wins.md) — can displace the
real one. That is why the token must live in a file or an OS secret store rather than in
source or a world-readable location, why it must never appear in a log, and why the policy's
`envRedact` defaults must keep it out of every child process
([`../04-agent-policy.md` §5.6](../04-agent-policy.md#56-environment-handling)). It is also
why the risk is bounded rather than eliminated: holding the token buys the ability to make
requests, and every request is still judged by the policy on the Windows host
([ADR 0003](0003-authorization-on-agent-only.md)).

There is no per-message authentication. Once the socket is established, every frame on it is
trusted as coming from the authenticated peer. That is a deliberate consequence of putting
the authentication event at the handshake, and it is sound precisely because the connection
is a single TLS session that cannot be joined midway.

### What we would have to change to reverse it

Adding a challenge-response exchange would mean defining two new session operations, an
ordering rule placing them before `session.hello`, and a close code for a failed challenge —
and it would still be additive rather than a replacement, because the pre-upgrade rejection
is worth keeping regardless. Making mTLS mandatory instead is a smaller change to the
specification and a much larger change to every deployment, which is exactly why it is
offered as a profile rather than a requirement.
