# WSAP/1 conformance checklist

**Status:** Draft · **Revision:** 2026-07-26

This document is a worked checklist for somebody building a WinShow agent. It is derived
mechanically from [`03-agent-protocol.md`](03-agent-protocol.md) and
[`04-agent-policy.md`](04-agent-policy.md), and it adds no rules of its own: where this
document and those two disagree, they win and this one has a bug. Every item here traces
back to a **MUST**, a **MUST NOT**, or a **SHALL** in one of them, with the section number
given in the trailing reference so that you can read the reasoning rather than only the
requirement.

**Conformant means every MUST satisfied.** There is no partial credit and no scoring. An
agent that satisfies every applicable MUST is conformant; an agent that misses one is not,
even if the miss looks cosmetic — several of the requirements below are load-bearing for
security in ways that are not obvious from the requirement text alone, which is why
[§14](#14-the-security-critical-subset) calls the worst of them out separately.

Items marked **SHOULD** are included where the specification states a strong recommendation
and where a reviewer would reasonably want to see a deliberate decision rather than an
oversight. They are prefixed `(SHOULD)` and do not affect conformance. Items that are
requirements on the *server* rather than the agent are prefixed `(server)`; they are listed
because an agent implementer benefits from knowing what the other end owes them, and because
the WinShow server is itself an implementation that has to be checked.

The intended way to use this document is to copy it into your own repository, work through
it top to bottom with a test for each box, and keep it in the tree as a living record. The
Phase 2 conformance harness described in [§13](#13-test-vector-index) automates a large
fraction of it, but not all of it: items about file permissions, service accounts, log
contents, and handle inheritance are checked by inspection, not by replaying a transcript.

---

## Table of contents

1. [Conformance levels](#1-conformance-levels)
2. [Transport](#2-transport)
3. [Envelope](#3-envelope)
4. [Session](#4-session)
5. [Filesystem](#5-filesystem)
6. [Execution](#6-execution)
7. [Windows semantics](#7-windows-semantics)
8. [Policy](#8-policy)
9. [Streaming and backpressure](#9-streaming-and-backpressure)
10. [Concurrency and ordering](#10-concurrency-and-ordering)
11. [Versioning and forward compatibility](#11-versioning-and-forward-compatibility)
12. [Operations](#12-operations)
13. [Test vector index](#13-test-vector-index)
14. [The security-critical subset](#14-the-security-critical-subset)
15. [Self-test suggestions](#15-self-test-suggestions)

---

## 1. Conformance levels

WSAP/1 has a mandatory core and an opt-in periphery. The distinction matters because it is
what allows a minimal read-only agent, a full-featured developer agent, and some future
agent written for an embedded Windows appliance to all be correct implementations of the
same protocol.

### 1.1 The base protocol — mandatory for every agent

Everything in the following table is part of the base protocol. There is no way to decline
it, and none of it appears in the `capabilities` array — an agent that lists any of these in
`capabilities` is wrong, because the array exists to describe what is optional
([`03` §6.1](03-agent-protocol.md#61-operation-summary)).

| Area | What is mandatory |
|---|---|
| Transport | TLS validation, the `winshow.v1` subprotocol, bearer authentication, text frames, frame size negotiation |
| Envelope | The full envelope grammar, correlation, sequencing, direction rules |
| Operations | `session.hello`, `session.ping`, `session.cancel`, `session.bye`, and receipt of `exec.ack` |
| Errors | The error object shape, the error class enumeration, unknown-code handling |
| Policy | The whole of [`04-agent-policy.md`](04-agent-policy.md) that applies to the operations the agent does implement, including fail-closed behaviour and the handshake summary |
| Concurrency | Multiplexing, gapless sequencing, duplicate-id rejection, `AGENT_BUSY` |
| Windows semantics | Path canonicalisation, final-path resolution, containment testing, and encoding rules, for whichever operations the agent implements |

An agent that implements *nothing but* the base protocol is a conformant WSAP/1 agent. It
advertises `capabilities: []`, answers pings, reports its policy summary, and returns
`NOT_IMPLEMENTED` for every request the server sends it. That is a useless agent, but it is
a correct one, and being able to write it is a good first milestone.

### 1.2 Optional capabilities — opt-in, advertised at handshake

Each of the following is independently optional. An agent that does not advertise one is
still fully conformant; an agent that *does* advertise one takes on every requirement in the
corresponding section below.

| Capability string | Operation | Checklist section |
|---|---|---|
| `fs.list` | `fs.list` | [§5.1](#51-fslist) |
| `fs.stat` | `fs.stat` | [§5.2](#52-fsstat) |
| `fs.read` | `fs.read`, `fs.read.chunk` | [§5.3](#53-fsread) |
| `fs.glob` | `fs.glob` | [§5.4](#54-fsglob) |
| `fs.grep` | `fs.grep` | [§5.5](#55-fsgrep) |
| `exec.start` | `exec.start`, `exec.output`, `exec.exit` | [§6](#6-execution) |

The `policy.modelReview` **feature** flag is likewise optional, and gates the
`policy.reviewing` event and the whole of stage 2. Everything catalogued in
[`03` §6](03-agent-protocol.md#6-deferred-operations) — `fs.write`, `fs.upload`,
`fs.mutate`, `proc.list`, `proc.kill`, `sys.services`, `sys.eventlog` — is outside WSAP/1's
MVP entirely and is not required of anyone.

### 1.3 Declining an operation: `NOT_IMPLEMENTED`, not `UNSUPPORTED_OPERATION`

These two codes are not interchangeable, and picking the wrong one gives the operator a
misleading diagnosis.

| Code | Use it when | What it tells the operator |
|---|---|---|
| `NOT_IMPLEMENTED` | The `op` is defined in WSAP/1 but this build did not implement it | "This is a real operation. Your agent build does not have it. Get a build that does." |
| `UNSUPPORTED_OPERATION` | The `op` is not a name this agent recognises at all | "Either the server is speaking a later minor revision, or something is confused." |

`NOT_IMPLEMENTED` is therefore the correct and expected way to decline an operation you
know about and chose not to build. It is not a failure and it is not an embarrassment — it
is the mechanism. Do not return `UNSUPPORTED_OPERATION` for `fs.grep` just because you did
not write a grep; `fs.grep` is a name you are required to recognise.

In practice a well-behaved server never sends you an operation you did not advertise
([`03` §11.1](03-agent-protocol.md#111-receiver-rules)), so these paths should be dead code.
Implement them anyway: they are what turns a server bug into a legible error instead of a
silent hang.

---

## 2. Transport

### 2.1 Connection and endpoint

- [ ] **T-01** Dials out to the configured `wss://` URL and never listens for an inbound
      connection; the Windows host needs no inbound firewall rule. `03` §1.1
- [ ] **T-02** Accepts a `ws://` URL only when the host is `localhost`, `127.0.0.1`, or
      `::1`, or when configuration sets `insecure = true`. `03` §1.1
- [ ] **T-03** With `insecure = true`, emits a WARN log line containing the literal string
      `INSECURE TRANSPORT` on **every** connection attempt, not only the first. `03` §1.1
- [ ] **T-04** Sends `Sec-WebSocket-Protocol: winshow.v1` on the upgrade request. `03` §1.2
- [ ] **T-05** Closes the connection and reports a version failure when the `101` response
      omits the subprotocol header or echoes a different value. `03` §1.2
- [ ] **T-06** Sends `Authorization`, `X-WinShow-Agent-Id`, and `X-WinShow-Agent-Version` on
      every upgrade request. `03` §1.3
- [ ] **T-07** The `X-WinShow-Agent-Id` value is 1–64 characters drawn from
      `[A-Za-z0-9._-]`, and is stable across restarts. `03` §1.3

### 2.2 Authentication

- [ ] **T-08** The configured token is at least 32 bytes of CSPRNG output rendered as
      printable ASCII; the agent refuses, or at minimum warns loudly, on a shorter one.
      `03` §1.4
- [ ] **T-09** Transmits the token only in the `Authorization` header — never in a query
      string, never in a subprotocol value, never in a first frame. `03` §1.4
- [ ] **T-10** Loads the token from a file or an OS secret store, not from its own source and
      not from a world-readable location. `03` §1.4
- [ ] **T-11** The token appears in no log line at any level, including debug and crash
      dumps, and including the redacted-URL form of the connection target. `03` §1.4,
      `04` §9
- [ ] **T-12** (server) Compares the presented token in constant time. `03` §1.4
- [ ] **T-13** (server) Accepts two simultaneously valid tokens so that rotation needs no
      downtime. `03` §1.4
- [ ] **T-14** (server) Rejects a bad token with `HTTP 401` and `WWW-Authenticate: Bearer`
      **before** the WebSocket upgrade, never after it. `03` §1.4
- [ ] **T-15** (SHOULD, server) Rate-limits: five failures from one source address within
      60 seconds produces `429` with `Retry-After`. `03` §1.4

### 2.3 TLS

- [ ] **T-16** Verifies the full certificate chain to a trusted root. `03` §1.5
- [ ] **T-17** Verifies the hostname against the certificate's SAN entries — chain validity
      alone is not accepted. `03` §1.5
- [ ] **T-18** Supports all three trust modes: `system`, `ca-bundle`, and `pin`. `03` §1.5
- [ ] **T-19** In `pin` mode, still performs chain validation **in addition to** matching the
      server SPKI SHA-256 against a configured pin. `03` §1.5
- [ ] **T-20** Negotiates TLS 1.2 as a minimum and prefers TLS 1.3. `03` §1.5
- [ ] **T-21** Does not silently disable revocation checking. `03` §1.5
- [ ] **T-22** If an `insecureSkipVerify`-style option exists at all, it logs at WARN on
      every use. `03` §1.5
- [ ] **T-23** (SHOULD) Documents that at least two SPKI pins should be configured, so that a
      certificate rotation does not brick the fleet. `03` §1.5

### 2.4 Proxies

- [ ] **T-24** Supports an explicitly configured HTTP proxy using `CONNECT` tunnelling.
      `03` §1.6
- [ ] **T-25** Supports a `noProxy` list containing both hostnames and CIDR ranges. `03` §1.6
- [ ] **T-26** Keeps the TLS session end-to-end with the server; a TLS-terminating
      interception proxy is accepted only when that proxy's CA is explicitly present in the
      configured trust bundle. `03` §1.6
- [ ] **T-27** (SHOULD) Supports Basic and Negotiate/NTLM proxy authentication, and honours
      the Windows system proxy configuration when no explicit proxy is set. `03` §1.6

### 2.5 Frames and closure

- [ ] **T-28** Sends only WebSocket **text** frames. `03` §1.7
- [ ] **T-29** Rejects an inbound **binary** frame rather than attempting to parse it — binary
      is reserved for a future wire version. `03` §1.7
- [ ] **T-30** Sends exactly one JSON object per frame, with no newline framing inside the
      frame. `03` §1.7
- [ ] **T-31** Reassembles fragmented inbound frames correctly. `03` §1.7
- [ ] **T-32** Honours the negotiated `maxFrameBytes` (default 1 MiB, hard ceiling 8 MiB) on
      both send and receive. `03` §1.7
- [ ] **T-33** On receiving an oversized frame, replies `err FRAME_TOO_LARGE` when the frame
      was parseable enough to correlate, and then closes with code `1009`. `03` §1.7
- [ ] **T-34** Uses the documented close codes with their documented meanings: `1000`,
      `1001`, `1009`, `1011`, `4004`, `4008`, `4009`, `4013`. `03` §1.8
- [ ] **T-35** Closes with `1001` — not `1011` — when the Windows service is stopping
      normally. `03` §1.8

---

## 3. Envelope

### 3.1 Structure

- [ ] **E-01** Every frame is a single UTF-8 JSON object. `03` §2.1
- [ ] **E-02** Binary payloads are Base64 per RFC 4648 §4 **with padding**, carried inside
      JSON string fields. `03` §2.1
- [ ] **E-03** Emits `w: 1` on every message, and rejects any inbound message whose `w` is
      not a value it understands. `03` §2.2
- [ ] **E-04** Emits `t` as exactly one of `"req"`, `"res"`, `"err"`, `"evt"`, and treats an
      unrecognised `t` as fatal for that message rather than as a tolerable unknown enum
      value. `03` §2.2, §11.1
- [ ] **E-05** Echoes `id` unchanged on every `res` and `err`. `03` §2.2
- [ ] **E-06** Echoes `op` on every `res` and `err`, so a response is self-describing.
      `03` §2.2
- [ ] **E-07** Sets `corr` on every `evt` to the `id` of the originating request. `03` §2.2
- [ ] **E-08** Sets `seq` on every `evt`: zero-based, strictly incrementing per `corr`, and
      gapless. `03` §2.2
- [ ] **E-09** Always includes `p` on `req`, `res`, and `evt`; it may be `{}` but it is never
      absent and never a non-object. `03` §2.2
- [ ] **E-10** Always includes `e` on `err`, containing the full error object. `03` §2.2, §7.1
- [ ] **E-11** (SHOULD) Includes `ts` as an RFC 3339 UTC timestamp with milliseconds, and
      treats an inbound `ts` as advisory only — never as a source of truth for ordering or
      expiry. `03` §2.2
- [ ] **E-12** Propagates `trace` unchanged when present. `03` §2.2
- [ ] **E-13** Rejects an unparseable frame, or one missing a structural field, with
      `MALFORMED_MESSAGE`. `03` §7.2

### 3.2 Direction rules

- [ ] **E-14** Originates only `session.hello` and `session.ping` as requests; every other
      `req` on the wire flows server to agent. `03` §2.3
- [ ] **E-15** Answers a `session.ping` originated by the server. `03` §2.3
- [ ] **E-16** Emits `exec.output`, `exec.exit`, `fs.read.chunk`, and `policy.reviewing` as
      agent-to-server events only. `03` §2.3
- [ ] **E-17** Accepts `exec.ack` as the one server-to-agent event, and does not treat its
      server-side `seq` numbering as part of the agent's own sequence space. `03` §2.3, §5.3
- [ ] **E-18** Tolerates any well-formed `id` string from the peer, including one that
      happens to look like an identifier the agent itself would have generated. `03` §2.3

### 3.3 The error object

- [ ] **E-19** Every `err` carries `code`, `class`, `retryable`, and `message`; none is
      omitted. `03` §7.1
- [ ] **E-20** `class` is one of `transport`, `auth`, `policy`, `os`, `limit`, `timeout`,
      `cancelled`, `internal`, `argument`, and matches the class the code table assigns to
      that code. `03` §7.1, §7.2
- [ ] **E-21** `retryable` matches the code table — in particular `POLICY_DENIED` is always
      `false` and `AGENT_BUSY`, `TIMEOUT`, `SHARING_VIOLATION`, `IO_ERROR`, and
      `RESOURCE_EXHAUSTED` are `true`. `03` §7.2
- [ ] **E-22** `message` is human-readable and safe to display to an end user. `03` §7.1
- [ ] **E-23** Sets `winError` and `winErrorName` whenever a Win32 failure caused the error,
      so the operator has the code to search for. `03` §7.1
- [ ] **E-24** Treats an error code it does not recognise as `class: "internal"`,
      `retryable: false`, rather than failing to parse it. `03` §7.4
- [ ] **E-25** Never reuses a published error code for a new meaning and never removes one:
      the code set is append-only. `03` §7.4

---

## 4. Session

### 4.1 `session.hello`

- [ ] **S-01** Sends `session.hello` as the first message after the upgrade, within 10
      seconds. `03` §3.1
- [ ] **S-02** (server) Closes with code `4008` when no `session.hello` arrives within 10
      seconds of the upgrade. `03` §3.1
- [ ] **S-03** The `agentId` in the payload is byte-identical to the `X-WinShow-Agent-Id`
      header value. `03` §3.1
- [ ] **S-04** Includes every REQUIRED payload field: `wireVersions`, `agentId`, `agent`,
      `os`, `identity`, `capabilities`, `limits`, `policy`, `clock`. `03` §3.1
- [ ] **S-05** `wireVersions` is ordered by descending preference. `03` §3.1
- [ ] **S-06** `capabilities` lists only the opt-in operations
      ([§1.2](#12-optional-capabilities--opt-in-advertised-at-handshake)), and omits the
      implicit base-protocol operations. `03` §6.1
- [ ] **S-07** `limits` carries all nine integer fields, and the agent actually enforces each
      of the values it advertised. `03` §3.1
- [ ] **S-08** Rejects a `session.hello` response whose `wireVersion` is not one the agent
      offered. `03` §3.1
- [ ] **S-09** (server) Replies `err INCOMPATIBLE_VERSION` and closes with `4004` when the
      version intersection is empty. `03` §3.1
- [ ] **S-10** (server) Does not report ready — `/readyz` stays red — until a `session.hello`
      exchange has completed successfully. `03` §3.1
- [ ] **S-11** The `identity` block reports the true security context: `user`, `sid`,
      `isService`, `sessionId`, `isElevated`, `integrityLevel`, `privileges`. `03` §3.1,
      §10.8
- [ ] **S-12** `resumeOf`, when sent, is treated as informational by both sides: no state,
      no buffer, and no process survives a reconnection. `03` §3.1
- [ ] **S-13** Sends only the policy **summary**, never the full rule set.
      `04` §7

### 4.2 `session.ping`

- [ ] **S-14** Echoes `nonce` verbatim in the response. `03` §3.2
- [ ] **S-15** Responds within 5 seconds. `03` §3.2
- [ ] **S-16** Keeps answering pings while other requests are being processed, including
      while an `exec.start` is streaming megabytes of output. `03` §3.2
- [ ] **S-17** Keeps answering pings while a stage-2 model review is running — the review
      does not block the event loop. `03` §3.2, `04` §6.5
- [ ] **S-18** Answers a ping the agent itself did not originate, and can also originate one
      of its own; the operation is symmetric. `03` §2.3, §3.2

### 4.3 `session.cancel`

- [ ] **S-19** Returns `{"cancelled": false}` — a **successful response, not an error** — for
      an unknown or already-terminal `targetId`. `03` §3.3
- [ ] **S-20** Is idempotent: a second cancel for the same `targetId` is harmless. `03` §3.3,
      §8.4
- [ ] **S-21** After acknowledging a cancel, still emits exactly one terminal message for
      `targetId` — an `err CANCELLED`, or an `evt exec.exit` with `exitReason: "cancelled"`
      for an execution. `03` §3.3
- [ ] **S-22** Cancelling an execution terminates the entire job object, meaning the whole
      process tree and not merely the direct child. `03` §3.3
- [ ] **S-23** (SHOULD) Attempts graceful termination first by delivering `CTRL_BREAK_EVENT`
      to the process group and waiting `gracePeriodMs` (default 2000) before the hard kill.
      `03` §3.3
- [ ] **S-24** Does not implement, accept, or emit an `exec.cancel` operation; the name is
      reserved. `03` §5.6

### 4.4 `session.bye`

- [ ] **S-25** Sends `session.bye` immediately before closing, on both graceful shutdown and
      known-fatal paths. `03` §3.4
- [ ] **S-26** Copes with the peer closing **without** a `session.bye` — the event is best
      effort. `03` §3.4
- [ ] **S-27** Sets `corr` on `session.bye` to the `sessionId` of the connection being
      closed, with `seq` starting at 0 for that value. `03` §3.4
- [ ] **S-28** Sets `bySessionId` to the successor session when `reason` is `"superseded"`.
      `03` §3.4
- [ ] **S-29** Uses only the defined reasons: `shutdown`, `superseded`,
      `policy_reload_failed`, `fatal`. `03` §3.4

---

## 5. Filesystem

Every item in this section applies only to the capabilities the agent advertised. All of
them are additionally subject to the path rules in [§7.1](#71-path-handling) and the policy
rules in [§8](#8-policy) — a filesystem operation is not correct merely because its payload
is well shaped.

### 5.0 Shared types

- [ ] **F-01** `FileEntry.path` is canonical: backslash separators, uppercase drive letter,
      no `\\?\` prefix. `03` §4.0
- [ ] **F-02** `FileEntry.name` preserves the on-disk casing rather than a normalised form.
      `03` §4.0, §10.1
- [ ] **F-03** `mtime`, `ctime`, and `atime` are RFC 3339 UTC strings, never raw 64-bit
      FILETIME ticks. `03` §4.0
- [ ] **F-04** `ctime` reports the Windows **creation** time, not a POSIX-style status-change
      time. `03` §4.0
- [ ] **F-05** `kind` distinguishes `symlink` and `junction` from `file`, `dir`, and `other`,
      and `linkTarget` is populated for both reparse kinds. `03` §4.0
- [ ] **F-06** `attrs` uses only the ten defined attribute names. `03` §4.0
- [ ] **F-07** Never reports `encoding: "auto"` in any response — `"auto"` is request-only.
      `03` §4.0
- [ ] **F-08** Resolves `"oem"` and `"ansi"` at runtime from `GetOEMCP` and `GetACP` rather
      than hard-coding a code page. `03` §4.0

### 5.1 `fs.list`

- [ ] **F-09** Sorts by a **total order**: the requested key, then ordinal-ignore-case leaf
      name, then ordinal leaf name — so that paging by `offset` never skips or duplicates an
      entry. `03` §4.1
- [ ] **F-10** `total` counts all matching entries **before** `offset` and `limit` are
      applied. `03` §4.1
- [ ] **F-11** Sets `truncated` exactly when `total > offset + entries.length`, with a
      matching `truncationReason` of `"limit"`, `"agent_cap"`, or `"time_budget"`. `03` §4.1
- [ ] **F-12** Caps `limit` at the advertised `maxGlobResults` and reports
      `truncationReason: "agent_cap"` when it does. `03` §4.1
- [ ] **F-13** Matches `pattern` against the leaf name case-insensitively. `03` §4.1
- [ ] **F-14** Omits `hidden` and `system` entries unless `includeHidden` is true. `03` §4.1
- [ ] **F-15** With `followLinks: false` (the default) reports reparse points as entries but
      does not traverse them. `03` §4.1

### 5.2 `fs.stat`

- [ ] **F-16** Returns a **successful** response with `exists: false` for a path that does not
      exist, rather than `NOT_FOUND`. `03` §4.2
- [ ] **F-17** Still evaluates policy for a non-existent path: a path outside every read root
      is `POLICY_DENIED`, or `exists: false` under `denialDisclosure = "notfound"` — never
      silently statted. `03` §4.2, `04` §8
- [ ] **F-18** Populates `realPath` when `resolveLinks` was set and a reparse point was
      actually traversed. `03` §4.2
- [ ] **F-19** Computes `sha256` only when requested and only within the policy's
      `maxHashBytes`. `03` §4.2

### 5.3 `fs.read`

- [ ] **F-20** Requires **exactly one** addressing mode; a request combining byte range, line
      range, or tail is `INVALID_ARGUMENT`. `03` §4.3
- [ ] **F-21** Treats `fromLine` as 1-based. `03` §4.3
- [ ] **F-22** Includes the line terminator in the returned `data`, so the slice round-trips
      and the byte accounting is exact. `03` §4.3
- [ ] **F-23** Recognises `\r\n`, `\n`, and `\r` as terminators, and counts a final
      unterminated line as a line. `03` §4.3
- [ ] **F-24** Implements `tailLines` by reading **backwards from EOF in blocks**; a 20 GiB
      log tailed for 50 lines does not read 20 GiB. `03` §4.3
- [ ] **F-25** Emits `evt fs.read.chunk` events and then a `res` with `data` omitted and
      `chunked: true` whenever the response would exceed the negotiated `maxFrameBytes`.
      `03` §4.3
- [ ] **F-26** `fs.read.chunk` `seq` values share the single gapless event sequence space for
      that `corr`. `03` §4.3
- [ ] **F-27** Reports the encoding **actually used** in `encoding`, and reports
      `decodeErrors` above zero whenever replacement characters were substituted. `03` §4.3,
      §10.2
- [ ] **F-28** With `stripBom: true`, removes the BOM from `data` while `byteOffset` and
      `byteLength` still describe raw file bytes including the BOM, and `hadBom` is set.
      `03` §10.2
- [ ] **F-29** Sets `eof` exactly when `byteOffset + byteLength >= fileSize`. `03` §4.3
- [ ] **F-30** With `encoding: "binary"`, returns Base64 in `data` and performs no decoding.
      `03` §4.3
- [ ] **F-31** Returns `ENCODING_ERROR` when content cannot be decoded and `force` was false.
      `03` §7.2
- [ ] **F-32** Returns `NOT_FOUND` — not `exists: false` — for a missing path, because
      `fs.read` requires existence. `03` §4.2

### 5.4 `fs.glob`

- [ ] **F-33** Implements exactly the documented pattern tokens: `*`, `?`, `**`, character
      classes with negation, and `{a,b}` alternation. `03` §4.4
- [ ] **F-34** Accepts both `\` and `/` as separators inside a pattern. `03` §4.4
- [ ] **F-35** Matches case-insensitively. `03` §4.4
- [ ] **F-36** Interprets patterns as relative to `root`. `03` §4.4
- [ ] **F-37** Returns `FileEntry` objects when `stat` is true and canonical path strings
      otherwise. `03` §4.4
- [ ] **F-38** With `followLinks: true`, performs cycle detection on **resolved** paths, so a
      junction pointing at its own ancestor terminates instead of looping. `03` §4.4,
      `04` §4.4
- [ ] **F-39** Honours `maxDepth`, `maxResults`, and `timeBudgetMs`, and reports which one
      truncated the result in `truncationReason`. `03` §4.4

### 5.5 `fs.grep`

- [ ] **F-40** Supports only the normative regex subset: literals, `.`, character classes,
      `^`, `$`, `*`, `+`, `?`, `{n,m}`, `|`, `()` and `(?:)`, and `\d \w \s \b` with their
      negations. `03` §4.5
- [ ] **F-41** Rejects a pattern containing a backreference or any lookaround construct with
      `INVALID_ARGUMENT`, up front, rather than accepting it and risking catastrophic
      backtracking. `03` §4.5
- [ ] **F-42** Reports `line` and `column` as 1-based. `03` §4.5
- [ ] **F-43** Honours `maxMatches`, `maxMatchesPerFile`, `maxFileBytes`, `skipBinary`, and
      `timeBudgetMs`, reporting `truncated` with a reason when any bites. `03` §4.5

---

## 6. Execution

Everything in this section applies only if the agent advertises `exec.start`.

### 6.1 `exec.start` request handling

- [ ] **X-01** Requires exactly one of `argv` and `commandLine`; supplying both or neither is
      `INVALID_ARGUMENT`. `03` §5.1
- [ ] **X-02** Rejects `commandLine` when `shell` is `"none"` — a raw command line is valid
      only in a shell mode. `03` §5.1
- [ ] **X-03** Caps `timeoutMs` at the advertised `maxExecMillis` rather than honouring a
      larger request. `03` §5.1
- [ ] **X-04** Caps `maxOutputBytes` at the policy value, counting stdout and stderr
      combined. `03` §5.1
- [ ] **X-05** Refuses to raise process priority above `normal`; only `idle`, `belowNormal`,
      and `normal` are accepted. `03` §5.1
- [ ] **X-06** Writes `stdin` to the child and then closes the pipe, so a child waiting on
      EOF is not left hanging. `03` §5.1
- [ ] **X-07** With `mergeStderr: true`, interleaves stderr into the stdout stream labelled
      `stream: "stdout"`. `03` §5.1

### 6.2 `exec.start` response

- [ ] **X-08** Returns the `res` as soon as the process exists, not when it finishes.
      `03` §5.1
- [ ] **X-09** Reports `pid`, `startedAt`, `resolvedExecutable`, `resolvedCwd`, and
      `commandLineUsed`. `03` §5.1
- [ ] **X-10** `commandLineUsed` is the exact string handed to the OS after all quoting — the
      ground truth for the audit log, not a reconstruction. `03` §5.1
- [ ] **X-11** A spawn failure is an `err` on `exec.start` (`EXEC_NOT_FOUND` or
      `SPAWN_FAILED`) and produces **no** `exec.exit` event, because no process ever existed.
      `03` §5.1, §10.5

### 6.3 `exec.output`

- [ ] **X-12** Labels each chunk `stdout` or `stderr` and reports `bytes` as the raw
      pre-decode byte count for that chunk. `03` §5.2
- [ ] **X-13** `totalBytes` is the cumulative raw byte count for that stream. `03` §5.2
- [ ] **X-14** Sets `dropped: true` on the first chunk emitted after output was discarded
      because a cap was hit. `03` §5.2
- [ ] **X-15** Reports `encoding: "binary"` with Base64 `data` when decoding was refused.
      `03` §5.2

### 6.4 `exec.exit`

- [ ] **X-16** `exec.exit` is the **last** event for its `corr`. `03` §5.4, §8.2
- [ ] **X-17** `exec.exit` is emitted **exactly once**, on every failure path after a
      successful spawn — timeout, cancellation, backpressure kill, and agent shutdown
      included. `03` §5.4
- [ ] **X-18** Reports `exitCode` as an unsigned 32-bit value in `0`–`4294967295` **and**
      `exitCodeSigned` as the same bits read as signed int32. `03` §5.4, §10.5
- [ ] **X-19** `exitReason` is one of `exited`, `timeout`, `cancelled`, `killed`,
      `backpressure`, `agentShutdown`, and is authoritative — consumers are told to prefer it
      over inferring an outcome from `exitCode`. `03` §5.4
- [ ] **X-20** Never reinterprets, normalises, or remaps an exit code. `03` §10.5
- [ ] **X-21** Reports `exitCode: null` when the process never completed. `03` §5.4
- [ ] **X-22** Sets `truncated` with `truncationReason` of `"maxOutputBytes"` or
      `"backpressure"` when output was clipped. `03` §5.4
- [ ] **X-23** Preserves and delivers the output captured so far on a timeout or a
      cancellation; a truncated build log is still delivered. `03` §8.6

### 6.5 `policy.reviewing`

- [ ] **X-24** (SHOULD) Emits `policy.reviewing` once a stage-2 review exceeds roughly
      1500 ms. `03` §5.5, `04` §6.5
- [ ] **X-25** Never treats `policy.reviewing` as carrying authorization meaning; it is a
      progress signal and nothing else. `03` §5.5, `04` §6.5

---

## 7. Windows semantics

This is the section where implementations diverge, and it is the section where divergence is
most likely to be a vulnerability rather than an inconvenience.

### 7.1 Path handling

- [ ] **W-01** Accepts both `\` and `/` on input, including mixed forms such as
      `D:/Logs\archive`, and normalises internally to `\`. `03` §10.1
- [ ] **W-02** Accepts drive-absolute, UNC, and `\\?\`-prefixed forms. `03` §10.1
- [ ] **W-03** Rejects a relative path such as `foo\bar` with `INVALID_PATH`. `03` §10.1
- [ ] **W-04** Rejects a drive-relative path such as `C:foo` with `INVALID_PATH`. `03` §10.1
- [ ] **W-05** Rejects a rooted-but-driveless path such as `\foo` with `INVALID_PATH`.
      `03` §10.1
- [ ] **W-06** Performs canonicalisation in the specified order: separator conversion,
      separator collapsing (preserving a leading UNC `\\`), lexical `.` and `..` resolution,
      drive-letter uppercasing, trailing-separator stripping except on a bare root, and
      `\\?\` removal from returned values. `03` §10.1
- [ ] **W-07** Obtains the **OS-final path** with `GetFinalPathNameByHandle` or an equivalent
      before evaluating any policy rule. `03` §10.1, `04` §1.4
- [ ] **W-08** Evaluates policy against that final path — resolving junctions, symlinks, and
      8.3 short names — and never against the lexical path. `03` §10.1, `04` §1.4
- [ ] **W-09** Supports paths beyond 260 characters, and never leaks a `\\?\` prefix into a
      returned path value. `03` §10.1
- [ ] **W-10** Uses **ordinal, culture-invariant, case-insensitive** comparison for every
      policy comparison — no culture-aware casing anywhere in an authorization decision.
      `03` §10.1
- [ ] **W-11** Rejects `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9` as a path
      component, with or without an extension. `03` §10.1
- [ ] **W-12** Rejects a path component with a trailing dot or a trailing space. `03` §10.1
- [ ] **W-13** Rejects an alternate data stream — a `:` after the drive specifier — unless
      the policy sets `allowAlternateDataStreams = true`. `03` §10.1, `04` §4.4
- [ ] **W-14** Never attempts to resolve a mapped drive letter; network locations are
      expressed in UNC form because mapped drives do not exist in session 0. `03` §10.1
- [ ] **W-15** `isWithin(root, path)` compares **whole path components**, not string
      prefixes: `C:\src2` does not match root `C:\src`, while `c:\SRC\file.txt` does.
      `03` §10.1, `04` §4.1

### 7.2 Encoding

- [ ] **W-16** Implements the `encoding: "auto"` sniffing order exactly: BOM detection first,
      checking UTF-32LE before UTF-16LE; then a NUL-pattern examination of the first 8 KiB;
      then a strict UTF-8 decode attempt; then the ≥1 % non-printable heuristic for binary;
      then the policy's `defaultAnsiEncoding`. `03` §10.2
- [ ] **W-17** Never translates line endings — `\r\n` in the file is `\r\n` in `data`.
      `03` §10.2
- [ ] **W-18** Reads raw bytes from the child's pipes and decodes explicitly, rather than
      attaching a text reader to the pipe. `03` §10.2
- [ ] **W-19** Prepends
      `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8;`
      to the script for `shell: "powershell"` and `shell: "pwsh"`. `03` §10.2
- [ ] **W-20** (SHOULD) Arranges UTF-8 output for `shell: "cmd"`, for example by prefixing
      `chcp 65001>nul & `. `03` §10.2
- [ ] **W-21** Substitutes U+FFFD on a decode failure and counts the substitutions into
      `decodeErrors`. `03` §10.2
- [ ] **W-22** Escapes or replaces control characters and lone surrogates so that every frame
      is valid JSON; an invalid UTF-16 surrogate pair becomes U+FFFD rather than being emitted
      raw. `03` §10.2

### 7.3 Process creation

- [ ] **W-23** Launches with `CreateProcessW` and an explicit argument vector by default —
      no shell, no `ShellExecute`. `03` §10.3
- [ ] **W-24** Invokes PowerShell with `-NoProfile -NonInteractive -NoLogo -ExecutionPolicy
      Bypass -Command`; `-NoProfile` and `-NonInteractive` are not optional. `03` §10.3
- [ ] **W-25** Invokes `cmd.exe` with `/d /s /c`. `03` §10.3
- [ ] **W-26** Under `shell: "cmd"`, rejects a `commandLine` containing any of
      `& | < > ^ %`, or containing an odd number of `"` characters, unless the policy sets
      `allowUnsafeCmdMetacharacters = true`. `03` §10.3
- [ ] **W-27** Resolves `argv[0]` either as an absolute path or against the **policy-defined
      search list**, and never against the ambient `PATH`. `03` §10.3, `04` §5.5
- [ ] **W-28** Returns `EXEC_NOT_FOUND` for an ambiguous or failed executable resolution.
      `03` §10.3, `04` §5.5
- [ ] **W-29** Evaluates policy against the **resolved absolute** executable path and reports
      that same path as `resolvedExecutable`. `03` §10.3
- [ ] **W-30** Refuses `.bat`, `.cmd`, and `.ps1` under `shell: "none"` with
      `EXEC_NOT_FOUND`, and the message hints at the corresponding shell mode. `03` §10.3
- [ ] **W-31** Creates every process inside a **Job Object** with
      `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. `03` §10.3
- [ ] **W-32** Uses creation flags `CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
      CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP`. `03` §10.3
- [ ] **W-33** Creates the process **suspended**, assigns it to the job, and only then
      resumes it — so a fast-starting child cannot spawn a grandchild outside the job.
      `03` §10.3
- [ ] **W-34** Inherits **only** the three standard pipe handles, passed explicitly via
      `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; blanket inheritance is not used anywhere.
      `03` §10.3
- [ ] **W-35** (SHOULD) Applies `JobMemoryLimit` and `ActiveProcessLimit` from policy.
      `03` §10.3

### 7.4 Quoting

- [ ] **W-36** Implements the MSVCRT quoting rules exactly: space-separated arguments; an
      argument quoted when it is empty or contains a space, tab, newline, vertical tab, or
      `"`. `03` §10.4
- [ ] **W-37** A run of *n* backslashes immediately preceding a `"` becomes *2n+1*
      backslashes followed by `\"`. `03` §10.4
- [ ] **W-38** A run of *n* backslashes at the very end of a quoted argument becomes *2n*
      backslashes. `03` §10.4
- [ ] **W-39** Backslashes not adjacent to a quote are emitted literally. `03` §10.4
- [ ] **W-40** `argv[0]` is an absolute path and is quoted when it contains a space.
      `03` §10.4
- [ ] **W-41** Reproduces every row of the worked-examples table, including `""` for the
      empty string, `"she said \"hi\""`, and `"C:\path\\"`. `03` §10.4
- [ ] **W-42** Documents rather than works around the known exceptions — `cmd.exe`, `.bat`
      and `.cmd` files, `msiexec`, `robocopy`, and Go binaries all parse their raw command
      line differently. `03` §10.4

### 7.5 Environment

- [ ] **W-43** `envMode: "overlay"` starts from the agent's own environment minus everything
      matching `envRedact`, then applies the request overlay filtered through `envAllow`.
      `03` §10.6, `04` §5.6
- [ ] **W-44** `envMode: "clean"` starts from `envBase` only, plus the filtered overlay, and
      nothing else. `03` §10.6
- [ ] **W-45** Deduplicates variable names case-insensitively; a request setting both `Path`
      and `PATH` is `INVALID_ARGUMENT`. `03` §10.6
- [ ] **W-46** Rejects an attempt to set `PATH`, `PATHEXT`, `ComSpec`, `SystemRoot`, or
      `windir` unless the policy sets `envAllowSensitive = true`. `03` §10.6, `04` §5.6
- [ ] **W-47** The agent's own token variable is redacted from every child environment under
      **every** configuration, including `envAllowSensitive = true`. `04` §5.6
- [ ] **W-48** Builds the environment block as Unicode, sorted case-insensitively by name,
      terminated with a double NUL. `03` §10.6
- [ ] **W-49** Never expands `%VAR%` inside `argv`; the agent is not a shell. `03` §10.6
- [ ] **W-50** Reports overlaid variable **names** to the audit log and never their values.
      `04` §9

### 7.6 Working directory and security context

- [ ] **W-51** Requires `cwd` to be absolute, to exist, and to be a directory. `03` §10.7
- [ ] **W-52** Requires `cwd` to satisfy the policy's `cwdRoots`, defaulting to the read
      roots. `03` §10.7
- [ ] **W-53** Does not run as `LocalSystem` by default; the default deployment is a virtual
      service account or a group-managed service account. `03` §10.8
- [ ] **W-54** Never impersonates: no `WTSQueryUserToken` plus `CreateProcessAsUser`, no
      launching into another session. `03` §10.8
- [ ] **W-55** An interactive `--console` mode exists, runs as the invoking user, and logs
      `RUNNING INTERACTIVELY AS <user>` at startup. `03` §10.8
- [ ] **W-56** (SHOULD) `RequiredPrivileges` is reduced to `SeChangeNotifyPrivilege`, with a
      write-restricted token where the platform permits. `03` §10.8

### 7.7 Standard streams

- [ ] **W-57** Marks only the child's pipe ends inheritable; the parent's ends are **not**
      inheritable. `03` §10.9
- [ ] **W-58** Reads stdout and stderr **concurrently**; neither is read to completion before
      the other is touched. `03` §10.9
- [ ] **W-59** (SHOULD) Raises the pipe buffer size to 1 MiB. `03` §10.9

---

## 8. Policy

Every item here is normative in [`04-agent-policy.md`](04-agent-policy.md). An agent that
implements the wire protocol perfectly and the policy engine loosely is not conforming; it
is a remote shell with extra steps.

### 8.1 Enforcement model

- [ ] **P-01** The agent is the sole enforcement point: no protocol field, header,
      capability, or flag from the server relaxes any rule. There is no "trusted request"
      path. `04` §1.1
- [ ] **P-02** Nothing is permitted unless a rule permits it — there is no implicit allow.
      `04` §1.3
- [ ] **P-03** Deny rules are evaluated after allow rules and override them unconditionally.
      `04` §1.3
- [ ] **P-04** There is no `mode = "any"` for execution; `mode` is `"allowlist"` or
      `"disabled"` and nothing else. `04` §1.3, §5.1
- [ ] **P-05** Every rule is evaluated against resolved values: the OS-final path for
      filesystem subjects and working directories, and the resolved absolute path for
      executables. `04` §1.4

### 8.2 Loading and fail-closed behaviour

- [ ] **P-06** With a missing, unparseable, or schema-invalid policy the agent **still
      connects** and completes the handshake, reporting `policy.state = "invalid"`.
      `04` §1.2
- [ ] **P-07** In that state it rejects **every** operation with `POLICY_UNAVAILABLE`.
      `04` §1.2
- [ ] **P-08** It logs the parse or validation failure at error level, naming the file and
      the location within it. `04` §1.2
- [ ] **P-09** It never falls back to a permissive default and never carries a policy forward
      from a previous process. `04` §1.2
- [ ] **P-10** An unknown key anywhere in the policy file is a **load failure**, not a
      warning. `04` §3
- [ ] **P-11** Read roots are canonicalised at load; a root that does not exist at load time
      is a warning, not an error. `04` §4.1
- [ ] **P-12** Watches the policy file and reloads on change. `04` §2.2
- [ ] **P-13** The reload is **atomic**: the new content is parsed and validated in full
      before it is swapped in, so a partially applied policy is never live. `04` §2.2
- [ ] **P-14** A failed reload keeps the previous policy, logs at error level, and continues
      serving. `04` §2.2
- [ ] **P-15** (SHOULD) A failed reload is reflected in the next handshake summary.
      `04` §2.2
- [ ] **P-16** (SHOULD) Checks the policy file's ACL at load and warns when it is writable by
      a non-administrative principal, including the agent's own account. `04` §2.1

### 8.3 Filesystem rules

- [ ] **P-17** A filesystem request is permitted only when its **final** path is contained
      within a configured read root. `04` §4.1
- [ ] **P-18** Containment is component-wise and ordinal case-insensitive, implemented by
      splitting on `\` rather than by `startsWith`. `04` §4.1
- [ ] **P-19** UNC read roots are supported. `04` §4.1
- [ ] **P-20** `denyGlobs` are applied to the final path, case-insensitively, **after**
      `readRoots` has allowed it; any match denies. `04` §4.2
- [ ] **P-21** `denyGlobs` use the same minimal glob dialect as `fs.glob`. `04` §4.2
- [ ] **P-22** `rootOverrides.allowedExtensions`, when present, restricts reads under that
      root to those extensions, as a case-insensitive allowlist. `04` §4.3
- [ ] **P-23** `followLinks` and `allowAlternateDataStreams` default to `false`. `04` §4.4

### 8.4 Execution rules

- [ ] **P-24** An allow rule is either an executable rule or a shell rule; the two shapes are
      mutually exclusive. `04` §5.2
- [ ] **P-25** An executable rule matches only when the request's **resolved** executable
      equals the rule's `executable` under ordinal case-insensitive comparison. `04` §5.2
- [ ] **P-26** `argv` pins the whole vector positionally; `argvPrefix` pins only the leading
      tokens; the two are alternatives. `04` §5.2
- [ ] **P-27** `argvDeny` tokens are rejected wherever they appear in argv. `04` §5.2
- [ ] **P-28** `{name}` placeholders are validated against `placeholders.name`. `04` §5.2
- [ ] **P-29** For a shell rule, the **entire** script must match one of `scriptPatterns` —
      not merely contain a match. `04` §5.2
- [ ] **P-30** Every regular expression used in an **allow** decision — `placeholders` and
      `scriptPatterns` — is anchored at both ends with `^` and `$`, and an unanchored one is
      **rejected at load time** as a policy validation failure. `04` §5.3
- [ ] **P-31** Deny patterns are **not** required to be anchored, and the agent does not
      reject them for lacking anchors. `04` §5.3
- [ ] **P-32** A deny rule requires at least one of `executableRegex`, `argvRegex`,
      `scriptRegex`, or `cwdRegex`, and requires `reason`. `04` §5.4
- [ ] **P-33** `argvRegex` is matched against the argument vector joined with single spaces,
      so a rule can span token boundaries. `04` §5.4
- [ ] **P-34** `executableSearchPath` is the only place a bare executable name is resolved.
      `04` §5.5
- [ ] **P-35** Per-rule `maxTimeoutMs` and `maxOutputBytes` may exceed the global defaults and
      are honoured; `cwdRoots` narrows the permitted working directories for that rule.
      `04` §5.2
- [ ] **P-36** Every process the agent started is killed when the connection drops, except
      for allow-rule ids listed in `detachOnDisconnect`, which is empty by default.
      `04` §5.7

### 8.5 Stage 2 — model-assisted review

Skip this subsection entirely if the agent does not advertise the `policy.modelReview`
feature. An agent without stage 2 is not less conformant; it behaves exactly like one whose
reviewer approves everything, because stage 1 is the floor.

- [ ] **P-37** Stage 2 runs **only** on requests stage 1 has already allowed. `04` §6.1
- [ ] **P-38** Stage 2 can only ever **deny**; there is no code path by which a model verdict
      widens what the deterministic rules permitted or overturns a stage-1 denial. `04` §6.1
- [ ] **P-39** The reviewer `endpoint` resolves to a loopback address or a local IPC
      mechanism, and the agent **refuses to start** with a remote endpoint. `04` §6.3
- [ ] **P-40** `failMode = "closed"` denies on reviewer error or timeout; `failMode = "open"`
      allows. `04` §6.4
- [ ] **P-41** Every fallback caused by a reviewer error or timeout is logged at warning level
      **and** recorded in the audit trail, under either fail mode. `04` §6.4
- [ ] **P-42** A stage-2 denial is reported as `POLICY_DENIED` with `rule =
      "policy.modelReview"` and `details.reasonSource = "model"`. `04` §6.6
- [ ] **P-43** The reviewer's output is parsed into a strict verdict shape — an allow/deny
      boolean and a bounded reason string — and everything else it emitted is discarded.
      `04` §6.6
- [ ] **P-44** The reason string is length-capped and stripped of control characters.
      `04` §6.6
- [ ] **P-45** The reviewer's output can never select the rule id, the error code, or any
      other structured field; it fills exactly one slot, `details.reason`. `04` §6.6
- [ ] **P-46** A per-rule `modelReview = false` skips stage 2 for that rule, and a per-rule
      `modelReview = true` forces it. `04` §6.2
- [ ] **P-47** `appliesTo` defaults to `["exec.start"]` only. `04` §6.2

### 8.6 The handshake summary

- [ ] **P-48** The handshake carries a summary and **never** the full policy. `04` §7
- [ ] **P-49** The summary includes at least `policyVersion`, `policyHash`, `state`,
      `readRoots`, `execMode`, `writeEnabled`, and `denialDisclosure`. `04` §7
- [ ] **P-50** `policyHash` is `sha256:` of the file bytes, so the operator can confirm what
      is live. `04` §7
- [ ] **P-51** Only allow-rule **ids** are ever disclosed, never rule bodies. `04` §7

### 8.7 Reporting a denial

- [ ] **P-52** A denial is an `err` with `code: "POLICY_DENIED"`, `class: "policy"`, and
      `retryable: false` — always false, with no exceptions. `04` §8, `03` §7.2
- [ ] **P-53** `rule` identifies the deciding rule as `namespace[id]`, or `namespace[index]`
      when the rule has no id. `04` §8, `03` §7.3
- [ ] **P-54** `message` is safe to show an end user and leaks no paths or rule internals
      beyond what `denialDisclosure` permits. `03` §7.3
- [ ] **P-55** `details.reasonSource` is present whenever `details.reason` is, and is exactly
      one of `rule`, `agent`, `model`. `03` §7.3
- [ ] **P-56** (SHOULD) `details.allowedSummary` is included, so the caller can propose a
      permitted alternative instead of guessing at variants. `03` §7.3, `04` §8
- [ ] **P-57** Under `denialDisclosure = "notfound"`, a path outside every root returns
      `NOT_FOUND` and the true reason is logged **locally only**. `04` §8
- [ ] **P-58** `POLICY_DENIED` and `ACCESS_DENIED` are never conflated: a Windows ACL refusal
      is `ACCESS_DENIED` with `winError` attached, and a policy refusal is `POLICY_DENIED`.
      `04` §8.1

---

## 9. Streaming and backpressure

- [ ] **B-01** Flushes an `exec.output` chunk when **any** of the three conditions becomes
      true: 64 KiB accumulated for that stream; 250 ms elapsed since the previous flush with
      data pending; or a newline boundary crossed with at least 4 KiB pending. `03` §9.2
- [ ] **B-02** Never splits a multi-byte character sequence across chunks: an incomplete
      trailing sequence is retained and prepended to the next chunk. `03` §9.2
- [ ] **B-03** Never has more than `ackWindowChunks` unacknowledged `exec.output` chunks
      outstanding for one correlation. `03` §9.3
- [ ] **B-04** Never has more than `ackWindowBytes` unacknowledged bytes outstanding for one
      correlation. `03` §9.3
- [ ] **B-05** Uses the **minimum** of what each side offered as the effective window, taking
      the value from the `session.hello` response. `03` §9.3
- [ ] **B-06** Treats `exec.ack` as cumulative — the highest contiguous `seq` and the
      cumulative byte count — so a lost ack is superseded by the next one rather than
      stalling the stream. `03` §9.3
- [ ] **B-07** When the window is full, **stops reading the child's pipes** rather than
      buffering without bound or dropping chunks, letting ordinary OS backpressure block the
      child's writes. `03` §9.3
- [ ] **B-08** If the window stays full for `sendStallTimeoutMs` (default 30 000 ms),
      terminates the process tree and emits `exec.exit` with `exitReason: "backpressure"` and
      `truncationReason: "backpressure"`. `03` §9.3
- [ ] **B-09** Keeps each `exec.output` chunk payload at or under 256 KiB. `03` §9.4
- [ ] **B-10** Counts Base64 expansion **inside** the frame cap, so a 1 MiB frame carries at
      most roughly 768 KiB of binary payload. `03` §9.4
- [ ] **B-11** Does not stream `fs.read`: file reads are range-addressed, and chunking is a
      frame-size mechanism, not a streaming mode. `03` §9.1
- [ ] **B-12** (SHOULD, server) Acknowledges eagerly on consuming a chunk rather than
      batching acks, since the window bounds memory rather than pacing the sender. `03` §9.3

---

## 10. Concurrency and ordering

- [ ] **C-01** Services multiple concurrent in-flight requests over a single WebSocket,
      correlating by `id`, and does **not** serialize them — a four-minute build does not
      block a twenty-millisecond directory listing. `03` §8.1
- [ ] **C-02** Does not assume responses arrive in request order; a receiver never relies on
      FIFO. `03` §8.2
- [ ] **C-03** Delivers events sharing a `corr` in `seq` order, gapless, starting at 0.
      `03` §8.2
- [ ] **C-04** On detecting a gap in `seq`, **fails that request** rather than proceeding with
      missing output. `03` §8.2
- [ ] **C-05** Rejects a request that would exceed `maxConcurrentRequests` or
      `maxConcurrentProcesses` with `AGENT_BUSY`, rather than queueing it unboundedly.
      `03` §8.3
- [ ] **C-06** (server) Respects both advertised limits and queues locally rather than
      overshooting. `03` §8.3
- [ ] **C-07** Rejects a `req` whose `id` duplicates one already seen on the same connection
      with `INVALID_ARGUMENT`, and the message identifies the duplicate. `03` §8.5
- [ ] **C-08** Scopes request identifiers to a connection: after a reconnect, all identifiers
      are fresh and reuse is expected. `03` §8.5
- [ ] **C-09** The agent's execution timeout is authoritative: on expiry it terminates the
      process tree and emits `exec.exit` with `exitReason: "timeout"` **and** the output
      captured so far. `03` §8.6
- [ ] **C-10** (server) Sets its own timeout as a safety net at the agent's timeout plus a
      margin, and logs at WARN plus fails with `AGENT_TIMEOUT` if it ever fires. `03` §8.6
- [ ] **C-11** Never re-issues or re-runs an `exec.start` after a failure; the operation is
      not idempotent and retrying it is a decision for the human or the model, made with the
      audit log in hand. `03` §8.7

---

## 11. Versioning and forward compatibility

- [ ] **V-01** Ignores unknown fields in any object at any nesting depth; an unknown field is
      never an error. `03` §11.1
- [ ] **V-02** Ignores an `evt` with an unknown `op`, logging at debug level. `03` §11.1
- [ ] **V-03** Replies `err UNSUPPORTED_OPERATION` to a `req` with an unknown `op`, and does
      **not** close the connection. `03` §11.1
- [ ] **V-04** Replies `err NOT_IMPLEMENTED` to a `req` for an operation defined in WSAP/1
      that this build did not implement. `03` §7.2
- [ ] **V-05** Tolerates a new value in a string enumeration by treating it as the documented
      default and logging it — except for `t` and `w`, which are structural and fatal for that
      message. `03` §11.1
- [ ] **V-06** Never sends an `op` it did not advertise in `capabilities`. `03` §11.1
- [ ] **V-07** Never infers a peer's abilities from its version string; abilities are what
      `capabilities`, `features`, and `enabledOps` say they are. `03` §11.3

---

## 12. Operations

These items are about the agent as a deployed piece of software rather than as a protocol
speaker. They are checked by reading configuration, logs, and installer output rather than by
replaying a transcript. Fuller operational guidance is in
[`07-operations.md`](07-operations.md).

### 12.1 Reconnection

- [ ] **O-01** Reconnects with exponential backoff and **full jitter**:
      `delay = random(0, min(60s, 1s * 2^attempt))`, so a fleet does not synchronise on the
      server's recovery. `examples/transcript-reconnect.jsonl`
- [ ] **O-02** Abandons all in-flight state on disconnect: no request, no buffered response,
      and no chunk survives the socket. `03` §3.1
- [ ] **O-03** Terminates every process it started when the connection drops, except those
      whose allow-rule id is listed in `detachOnDisconnect`. `04` §5.7
- [ ] **O-04** On being evicted by a newer connection (close `4009`, `session.bye` with
      `reason: "superseded"`), applies an elevated initial backoff of at least 5 seconds and
      logs the eviction prominently — outside a half-open socket it means two agents are
      sharing one token. `examples/transcript-reconnect.jsonl`,
      [ADR 0007](adr/0007-newest-agent-wins.md)
- [ ] **O-05** Sends `resumeOf` naming the previous session so the two can be stitched
      together in a log, and grants it no authority whatsoever. `03` §3.1

### 12.2 Audit

- [ ] **O-06** Writes every policy decision to an **append-only** file. `04` §9
- [ ] **O-07** Writes execution records additionally to the Windows Event Log. `04` §9
- [ ] **O-08** Before dispatching an `exec.start`, records: the resolved argv, the resolved
      executable, the working directory, the **names** of overlaid environment variables, the
      stage-1 decision with its rule id, the stage-2 verdict when stage 2 ran, and the
      correlation id. `04` §9
- [ ] **O-09** After completion, records the pid, exit code, exit reason, duration, and byte
      counts. `04` §9
- [ ] **O-10** Records **every** denial, including one disclosed to the caller as
      `NOT_FOUND`, with the true reason. `04` §8, §9
- [ ] **O-11** Applies `logging.redactPatterns` to captured output before writing it. `04` §9
- [ ] **O-12** Audits filesystem reads at the verbosity `fs.auditReads` selects — path, byte
      count, decision. `04` §9

### 12.3 Deployment

- [ ] **O-13** Ships as a Windows service running under a virtual or group-managed service
      account, not `LocalSystem`. `03` §10.8
- [ ] **O-14** The policy file is readable by the service account and writable only by
      administrators and `SYSTEM`. `04` §2.1
- [ ] **O-15** Closes with `4013` and declines to serve when it has no valid policy at
      startup — while still connecting, so the operator sees the problem through their MCP
      client. `03` §1.8, `04` §1.2

---

## 13. Test vector index

The four transcripts in [`examples/`](examples/) are the executable form of this checklist.
They are informative in that they introduce no rules, and normative in that a conforming
implementation must be able to produce and consume every message in them — see
[`examples/README.md`](examples/README.md) for the annotation format.

| Transcript | Behaviours exercised | Checklist items principally covered |
|---|---|---|
| [`transcript-happy-path.jsonl`](examples/transcript-happy-path.jsonl) | Handshake with version negotiation and limit intersection; application-level heartbeat with nonce echo; a paged, sorted directory listing with truncation; a tail read of a 17 GiB log with encoding sniffing; an `exec.start` with argv quoting, interleaved stdout and stderr, credit-window acks, and a clean `exec.exit`; graceful `session.bye` and close `1001` | S-01…S-18, F-01…F-15, F-24, F-27, X-08…X-19, B-01…B-06, E-01…E-18 |
| [`transcript-policy-denial.jsonl`](examples/transcript-policy-denial.jsonl) | Denial by deny glob; denial for a path outside every read root; the **junction escape**, where a lexically-inside path resolves to `C:\Users`; denial by an exec deny rule with no process ever created; a stage-2 model review that emits `policy.reviewing` and then denies with `reasonSource: "model"`; a contrasting `ACCESS_DENIED` from a Windows ACL; a rejected lookahead in `fs.grep` | P-01…P-05, P-17…P-21, P-37…P-45, P-52…P-58, W-07, W-08, W-15, F-41, X-11 |
| [`transcript-cancel-timeout.jsonl`](examples/transcript-cancel-timeout.jsonl) | `session.cancel` acknowledged then followed by exactly one terminal `exec.exit`; `CTRL_BREAK_EVENT` grace period then job-object kill of a four-process tree; a timeout that preserves captured output; an output cap reached with `dropped: true` and `truncationReason` set | S-19…S-23, X-16…X-23, C-09, B-07, B-08, W-31, W-33 |
| [`transcript-reconnect.jsonl`](examples/transcript-reconnect.jsonl) | Heartbeat failure and dead-peer detection on both sides; in-flight requests failed rather than hung; job-object cleanup on disconnect; a fresh session with `resumeOf` granting nothing; eviction of an incumbent by a newer connection with `bySessionId` stitching; a restart with a broken policy that connects and then refuses everything with `POLICY_UNAVAILABLE` | O-01…O-05, S-12, S-25…S-29, P-06…P-09, C-08 |

### 13.1 What the harness does with them

The Phase 2 conformance harness ([`09-roadmap.md` §Phase 2](09-roadmap.md)) opens a
WebSocket to the agent under test and **replays these transcripts against it**: it plays the
server side, sends each `S→A` message in order, and asserts that the agent's replies match
the recorded `A→S` messages modulo the fields that legitimately vary — timestamps, pids,
session identifiers, durations, and byte counts of live output.

This is the mechanism that makes WSAP/1 a specification rather than documentation of one
implementation. A protocol described only in prose is, in practice, defined by whatever the
first implementation happened to do, and the second implementer discovers the real rules by
having their agent rejected. A protocol with replayable test vectors has an answer to "is my
agent correct?" that does not require access to anybody's source code. The same harness runs
against the Python mock agent on Linux and against the real Windows agent, and it must pass
identically against both — that identity is the Phase 3 exit criterion, and it is what
proves neither one has quietly become the definition.

The harness cannot check everything. Handle inheritance, job object membership, service
account configuration, file ACLs, log redaction, and the absence of the token from a crash
dump are all outside what a WebSocket peer can observe. Those items are marked in this
document by their subject matter and are verified by inspection.

---

## 14. The security-critical subset

If you have an hour to review an agent rather than a week, review these. Each one is a case
where a wrong implementation is not a bug that produces a wrong answer — it is a hole that
produces the right answer to a request that should never have been permitted. Every one of
them has been chosen because a plausible, reasonable-looking implementation gets it wrong.

| Item | The requirement | What a mistake costs |
|---|---|---|
| **W-07, W-08, P-05** | Policy is evaluated against the **OS-final path**, after junction, symlink, and 8.3 short-name resolution | `C:\src\link` is a junction to `C:\Users`. `C:\PROGRA~1` is `C:\Program Files`. Neither is visible to string manipulation, so a lexical check reads the whole disk while looking correct in every test the implementer thought to write. This is the single most likely security hole in a naive agent. |
| **W-15, P-18** | Containment is tested **component-wise**, not by string prefix | `startsWith("C:\src")` also matches `C:\src2`, `C:\src-backup`, and `C:\srcret`. An attacker who can create a sibling directory gets a read root the operator never granted. |
| **W-10** | All policy comparison is **ordinal, culture-invariant, case-insensitive** | A culture-aware comparison brings the Turkish dotless-i into an authorization decision, so whether a path matches a root depends on the machine's locale. Security decisions must not be locale-dependent. |
| **W-36…W-41** | MSVCRT quoting rules implemented **exactly** | Get the backslash-before-quote rule wrong and an argument containing `"` breaks out of its quoting, appending attacker-controlled tokens to the command line. This is argument injection, and the allowlist that validated the argv does not see it because the corruption happens after validation. |
| **W-27, W-29, P-34** | `argv[0]` resolved against the **policy search path**, never the ambient `PATH` | `PATH` is influenced by whoever can write the service's environment. Resolving against it turns "run `git.exe`" into "run whatever is called `git.exe` in the first directory somebody managed to prepend", and the audit log will faithfully record that `git.exe` ran. |
| **W-46, W-47, P-01** | `PATH`, `PATHEXT`, `ComSpec`, `SystemRoot`, `windir` gated behind `envAllowSensitive`; the token never in a child environment | Allowlisting `C:\Program Files\dotnet\dotnet.exe` gains nothing if the caller can redirect what that process finds when it shells out. And a token in a child environment is a token in any process the child spawns. |
| **P-06…P-09** | **Fail closed** on an invalid policy: connect, report `state: "invalid"`, deny everything | The tempting alternative — fall back to the last known good, or to a built-in default — means a corrupted file silently changes what is permitted. The second tempting alternative, exiting, looks identical to a dead machine and gets debugged as a network problem. |
| **P-02, P-03** | Nothing implicit; **deny beats allow**, unconditionally | An engine that stops at the first allow match, or that evaluates deny rules first and then lets a later allow override, turns every deny rule into a suggestion. |
| **P-37, P-38** | Stage 2 runs only on already-allowed requests and can **only ever deny** | If a model can grant, then the security of the Windows host rests on a small model's judgement under adversarial input, and prompt injection through a file the reviewer was asked about becomes privilege escalation. Keep it a one-way valve and the worst a compromised reviewer achieves is refusing work. |
| **P-43…P-45** | The reviewer's output fills exactly one slot, `details.reason`, as bounded, control-character-stripped, untrusted text | Letting model output select a rule id or an error code hands structured control of the response to generated content. Even in `details.reason` it must be relayed labelled as untrusted, because whatever reads the error may itself be a model. |
| **T-11, W-47, O-11** | The token reaches **no log at any level** and **no child process** under any configuration | A shared secret in a log file is a shared secret in whatever aggregates that log, and a redaction pattern applied only at INFO is not a control. |
| **W-34, W-57** | Only the three standard pipe handles inherited, passed explicitly by handle list; the parent's pipe ends not inheritable | Blanket inheritance leaks the agent's own handles — potentially including its WebSocket — into an arbitrary child process, which is a direct route from "run an allowed command" to "speak on the agent's connection". |
| **W-26** | `cmd` metacharacters `& \| < > ^ %` and unbalanced quotes rejected unless explicitly permitted | Safe quoting for `cmd.exe` is not achievable in general because `cmd` re-parses metacharacters after argument processing. Rejecting is the only correct answer; operators who need pipes go to PowerShell. |
| **W-30** | `.bat`, `.cmd`, `.ps1` refused under `shell: "none"` | Windows silently routes these through a shell, so accepting one means the argv model — the entire basis on which the policy engine can see what it is authorising — is bypassed while `shell: "none"` is still reported. |
| **W-31, W-33, S-22** | Job Object with kill-on-close; process created suspended, assigned, then resumed; cancellation kills the tree | Assign after resume and a fast-starting child spawns a grandchild outside the job, which then survives cancellation, timeout, and the agent's own death. |
| **P-48, P-51** | The handshake carries a policy summary, never the rule set | The server is untrusted, and the exact rules are exactly what an attacker probing for gaps wants. Ids and roots are actionable; bodies are reconnaissance. |

---

## 15. Self-test suggestions

Work through these against your own agent before you claim conformance. Each one is a
concrete request; each one should be **denied**, and the denial should name a rule the
operator can find. If any of them succeeds, the corresponding checklist item above is not
actually implemented, whatever the code looks like.

Set up a policy with `readRoots = ['C:\src']` and a single narrow exec allow rule, then try
the following.

| # | Set-up | Request | Expected outcome |
|---|---|---|---|
| 1 | `mklink /J C:\src\shortcut C:\Users` | `fs.list` on `C:\src\shortcut` | `POLICY_DENIED`. The lexical path is inside the root; the final path is `C:\Users`. If this succeeds you have skipped W-07. |
| 2 | — | `fs.read` on `C:\PROGRA~1\...` when `C:\Program Files` is outside every root | `POLICY_DENIED`. 8.3 short names are resolved by `GetFinalPathNameByHandle` and by nothing else. |
| 3 | — | `fs.read` on `C:\src\..\Windows\win.ini` | `POLICY_DENIED`, after lexical `..` resolution puts the path outside the root. Verify separately that `..` resolution happens **before** the final-path call, not instead of it. |
| 4 | — | `fs.stat` on `C:\src\CON`, `C:\src\NUL.txt`, `C:\src\COM1` | `INVALID_PATH`. Reserved device names are rejected as a component, with or without an extension. |
| 5 | — | `fs.read` on `C:\src\notes.txt:hidden` | `INVALID_PATH` while `allowAlternateDataStreams` is false. An ADS is a place data hides from every directory listing you will look at. |
| 6 | — | `exec.start` with `env: {"PATH": "C:\\attacker"}` while `envAllowSensitive` is false | `POLICY_DENIED` or `INVALID_ARGUMENT`. Then repeat with `Path` and with `pAtH` — the check is case-insensitive or it is not a check. |
| 7 | — | `exec.start` with `argv: ["git.exe", "status"]` where `git.exe` exists on the ambient `PATH` but not on `executableSearchPath` | `EXEC_NOT_FOUND`. If it runs, you resolved against `PATH`. |
| 8 | — | `exec.start` with `shell: "cmd"` and `commandLine: "tasklist & whoami"` | `POLICY_DENIED` or `INVALID_ARGUMENT` for the `&`. Repeat with `\|`, `>`, `^`, `%`, and with an odd number of `"`. |
| 9 | — | `exec.start` with `shell: "none"` and `argv: ["C:\\src\\build.bat"]` | `EXEC_NOT_FOUND`, with a message pointing at `shell: "cmd"`. |
| 10 | Allow rule pins `argv = ["query", "{service}"]` | `exec.start` with `argv: ["query", "spooler\" & whoami & \""]` | Denied by the placeholder regex. Then inspect `commandLineUsed` on a legitimate call and confirm the quoting matches the `03` §10.4 table exactly. |
| 11 | Read root `C:\src` exists | `fs.list` on `C:\src2` (create it) | `POLICY_DENIED`. This is the `startsWith` bug, and it is the one people are most surprised to still have. |
| 12 | Deny glob `**\*.pem` | `fs.read` on `C:\src\certs\server.pem` | `POLICY_DENIED` naming the deny glob, even though the path is inside an allowed root. Deny is evaluated after allow and wins. |
| 13 | Shell rule with `scriptPatterns = ['^Get-Service$']` | `exec.start` with `shell: "powershell"` and script `Get-Service; Remove-Item -Recurse C:\` | `POLICY_DENIED`. The **entire** script must match, which is why anchoring is enforced at load. |
| 14 | Break `policy.toml` with a syntax error and restart the agent | Any request at all | The agent connects, reports `state: "invalid"`, and returns `POLICY_UNAVAILABLE` with the file and location in the message. It does not exit, and it does not serve a default. |
| 15 | Stage 2 configured with an endpoint that never responds, `failMode = "closed"` | A command that stage 1 allows | `POLICY_DENIED`, logged at warning level and written to the audit trail. Then set `failMode = "open"` and confirm the fallback is *still* logged and audited. |
| 16 | — | A `req` reusing an `id` already used on this connection | `INVALID_ARGUMENT` naming the duplicate. This is what stands between a server retry bug and a command running twice. |
| 17 | — | Kill the agent process mid-`exec.start` | Every child process is reaped by the job object, and the server fails the in-flight request rather than hanging. |
| 18 | — | Send a WebSocket **binary** frame containing a valid WSAP/1 message | Rejected. Binary is reserved for a future wire version; parsing it anyway is how a v1 agent becomes accidentally incompatible with v2. |

A useful habit while working through these: for each denial, read the audit record it
produced and ask whether an operator who had never seen the request could tell from that
record alone what was attempted and why it was refused. A denial that is correct but
illegible is a denial nobody will investigate.

---

## Related documents

| Document | Purpose |
|---|---|
| [`03-agent-protocol.md`](03-agent-protocol.md) | The normative wire protocol this checklist is derived from |
| [`04-agent-policy.md`](04-agent-policy.md) | The normative policy engine specification |
| [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md) | What the MCP client sees, including the server-originated error codes that never appear on the WSAP wire |
| [`06-security.md`](06-security.md) | The threat model these requirements exist to serve |
| [`07-operations.md`](07-operations.md) | Deployment, monitoring, and the operational items in [§12](#12-operations) |
| [`09-roadmap.md`](09-roadmap.md) | Where the conformance harness fits in the phase plan |
| [`schemas/wsap-v1-messages.schema.json`](schemas/wsap-v1-messages.schema.json) | The machine-readable message contract |
| [`schemas/policy-v1.schema.json`](schemas/policy-v1.schema.json) | The machine-readable policy contract |
| [`examples/README.md`](examples/README.md) | The transcript format and the example policies |
