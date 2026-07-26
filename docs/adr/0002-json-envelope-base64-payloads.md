# ADR 0002: One JSON object per frame, with Base64 for binary payloads

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

Having chosen a WebSocket link between the server and the Windows agent
([ADR 0001](0001-reverse-websocket-transport.md)), we still had to decide what travels
inside it. WSAP/1 carries four kinds of message — requests, responses, errors, and events —
which are described in [`../03-agent-protocol.md` §2](../03-agent-protocol.md#2-message-envelope)
and share a small common envelope. Some of what they carry is unavoidably binary: the
contents of a file read with `encoding: "binary"`, and the output of a command whose
`outputEncoding` is `"binary"`.

The choice matters more than it usually would, because of a constraint stated in the first
paragraph of the protocol document: an implementer with no access to the server source must
be able to build a conforming agent in any language. Every byte of format complexity is paid
for once by us and then again by every agent author. The question we actually asked was not
"which encoding is most efficient" but "which encoding makes the agent's parsing layer
smallest and hardest to get wrong".

WebSocket is also not a byte stream. It already delivers discrete, ordered, length-delimited
messages, and it already distinguishes text frames (which are UTF-8 by definition) from
binary frames. Any framing we add sits on top of framing that already exists.

## Decision

**One JSON object per WebSocket text frame, UTF-8 encoded.** There is no newline framing
inside a frame, and no frame carries a fragment of an object or more than one object.

**Binary payloads are Base64** (RFC 4648 §4, with padding) inside ordinary JSON string
fields. The field that would have carried text carries Base64 instead, and a sibling
`encoding` field says which it is.

Binary WebSocket frames are **reserved** in WSAP/1 and a v1 receiver must reject them. A
future wire version may introduce them behind a `binaryFrames` capability negotiated in
`session.hello`; reserving the frame type now means that introduction will not have to
contend with implementations that already used binary frames for something else.

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| One JSON object per text frame, Base64 for binary | The agent's entire parsing layer is one `parse` call on the frame payload. No boundary logic, no reassembly, no interleaving rules. Costs roughly 33 % on bulk binary. | **Chosen** |
| Newline-delimited JSON inside frames | Framing inside framing: two independent places where a boundary can be wrong, and the receiver must handle a frame ending mid-line. Buys nothing, because WebSocket frames are already cheap and already delimited. | Rejected |
| A JSON header frame followed by a binary payload frame | Removes the Base64 overhead, and immediately creates a stateful protocol. The receiver must remember which header the next binary frame belongs to, which means defining what happens when two large payloads interleave, when a header arrives with no payload, or when a payload arrives with no header. Every one of those is a new conformance requirement and a new class of bug. | Rejected |
| Protocol Buffers | Compact and strongly typed, and it obliges every agent author to adopt a code generator and keep generated code in step with a `.proto` file. It also makes the wire unreadable without tooling, which costs us the annotated transcripts in [`../examples/`](../examples/) that currently serve as both documentation and conformance vectors. | Rejected |
| MessagePack | Binary JSON: keeps the data model, removes the Base64 overhead, and is a single dependency in most languages. But it is a dependency, whereas JSON is in the standard library everywhere, and it costs the same human readability. The bandwidth saved is not worth the readability and portability lost for a system whose dominant payloads are text. | Rejected |

## Consequences

### What this buys us

The receive path of a conforming agent is: take the frame, parse it as JSON, dispatch on
`t` and `op`. There is no buffering across frames, no partial-object state, and no case where
a receiver holds one message while waiting for another. That is the property we were actually
buying, and it is why the protocol document can claim that everything an agent implementer
needs fits in one document.

Because frames are text and the content is JSON, every message on the wire is directly
readable. The transcripts in [`../examples/`](../examples/) are literally what goes over the
socket, which means the conformance vectors, the documentation, and the debugging output are
the same artefact. A capture from a misbehaving deployment can be diffed against a transcript
without a decoder.

Base64 also removes a whole category of encoding bug. A file that turns out to be binary, a
command that emits raw bytes, and a text file whose declared encoding is wrong all flow
through the same string-shaped field, and the frame remains valid JSON regardless — which is
what makes the rule in
[`../03-agent-protocol.md` §10.2](../03-agent-protocol.md#102-encoding) about escaping or
replacing lone surrogates enforceable at all.

### What it costs us

Roughly 33 % bandwidth overhead on bulk binary payloads, plus a small encode and decode cost
at each end. This is the deliberate price of not having a header-frame-then-payload-frame
protocol with interleaving rules, and we consider it well spent: the dominant traffic in this
system is log text, directory listings, and build output, all of which are text and none of
which pay the penalty.

The overhead is not free of second-order effects, and the protocol accounts for them
explicitly. Base64 expansion is counted **inside** the frame cap rather than against the raw
byte count, so a 1 MiB frame carries at most about 768 KiB of binary payload
([`../03-agent-protocol.md` §9.4](../03-agent-protocol.md#94-caps)). An agent that budgets
against raw bytes will overshoot the negotiated `maxFrameBytes` and be told
`FRAME_TOO_LARGE`. That is a real sharp edge, and it is the reason the accounting rule is
stated normatively rather than left to be discovered.

The other cost is that large payloads must be split at the application layer rather than by
the transport. That is what the `fs.read.chunk` event exists for: when a response would
exceed the negotiated frame size, the agent emits chunk events and then a metadata-only
response with `chunked: true`. A binary-frame design would have gotten this from the
transport; we get it from a specified event sequence instead.

### What we would have to change to reverse it

Moving to binary frames is the anticipated change and is already accommodated. It needs a new
wire version, a `binaryFrames` capability negotiated in `session.hello`, and a defined
correlation between a header object and the frame that follows it. Because v1 receivers are
required to reject binary frames outright, a v2 agent talking to a v1 server degrades
predictably rather than ambiguously.

Moving to a different serialisation entirely — protobuf or MessagePack — is a larger change
than it looks. The envelope and the payload schemas would survive, since they are defined in
[`../schemas/`](../schemas/) in terms of a data model rather than a byte format, but every
transcript in [`../examples/`](../examples/) would have to be regenerated, and the
conformance harness would lose the property that its inputs are human-readable. We would want
a demonstrated bandwidth problem, not an anticipated one, before paying that.
