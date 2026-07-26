# WinShow Agent Protocol, Version 1 (WSAP/1)

**Status:** Draft
**Wire version:** `1`
**Revision:** 2026-07-26
**Applies to:** the channel between the WinShow MCP server and a WinShow agent running on a Windows host.

This document is the contract. It is written so that an implementer with no access to the
server source code can build a conforming agent in any language. Everything an agent
implementer needs is here or is referenced from here.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as
described in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals.

> **WSAP is not MCP.** The Model Context Protocol governs the link between an MCP client
> and the WinShow server. WSAP governs the link between the WinShow server and the Windows
> agent. They are separate protocols with separate versions, and an agent implementer does
> not need to know anything about MCP. See [ADR 0001](adr/0001-reverse-websocket-transport.md)
> for why.

**Related documents**

| Document | Purpose |
|---|---|
| [`04-agent-policy.md`](04-agent-policy.md) | The policy file that governs what an agent permits. Normative. |
| [`08-conformance.md`](08-conformance.md) | Tickable conformance checklist derived from this document. |
| [`schemas/`](schemas/) | JSON Schema for every message in this document. Normative. |
| [`examples/`](examples/) | Annotated wire transcripts. Informative, but they are the conformance test vectors. |

---

## Table of contents

1. [Transport](#1-transport)
2. [Message envelope](#2-message-envelope)
3. [Session operations](#3-session-operations)
4. [Filesystem operations](#4-filesystem-operations)
5. [Execution operations](#5-execution-operations)
6. [Deferred operations](#6-deferred-operations)
7. [Error codes](#7-error-codes)
8. [Concurrency and ordering](#8-concurrency-and-ordering)
9. [Streaming and backpressure](#9-streaming-and-backpressure)
10. [Windows semantics](#10-windows-semantics)
11. [Versioning and forward compatibility](#11-versioning-and-forward-compatibility)
12. [Changelog](#12-changelog)

---

## 1. Transport

### 1.1 Direction and endpoint

The **agent dials out**. The server never initiates a connection to the Windows host, and
the Windows host **MUST NOT** require any inbound firewall rule.

The agent connects to a URL of the shape:

```
wss://<host>[:<port>]<path>
```

The default path is `/agent`; it is configurable. `ws://` is permitted **only** when the
host is `localhost`, `127.0.0.1`, or `::1`, **or** when the agent's configuration sets
`insecure = true`. In the latter case the agent **MUST** emit a WARN-level log line
containing the literal string `INSECURE TRANSPORT` on every connection attempt.

### 1.2 Subprotocol

The agent **MUST** send:

```
Sec-WebSocket-Protocol: winshow.v1
```

The server **MUST** echo it in the `101 Switching Protocols` response. If the response
omits the header or echoes a different value, the agent **MUST** close the connection and
treat the outcome as a version failure — it is talking to something that is not a WinShow
server.

### 1.3 Handshake request headers

| Header | Presence | Value |
|---|---|---|
| `Authorization` | REQUIRED | `Bearer <token>` — the shared secret, verbatim |
| `Sec-WebSocket-Protocol` | REQUIRED | `winshow.v1` |
| `X-WinShow-Agent-Id` | REQUIRED | Stable agent identifier, 1–64 characters from `[A-Za-z0-9._-]` |
| `X-WinShow-Agent-Version` | REQUIRED | Agent software version, e.g. `1.2.0` |
| `User-Agent` | RECOMMENDED | e.g. `WinShowAgent/1.2.0 (Windows NT 10.0.19045; x64)` |
| `Sec-WebSocket-Version`, `Sec-WebSocket-Key` | REQUIRED | Per RFC 6455 |

### 1.4 Authentication

**A pre-shared bearer token, presented at the HTTP handshake, over validated TLS.**
See [ADR 0004](adr/0004-bearer-token-over-hmac-challenge.md) for why this was chosen over
an HMAC challenge-response.

Requirements:

- The token **MUST** be at least 32 bytes of CSPRNG output, presented as a printable ASCII
  string (Base64url of 32 random bytes is RECOMMENDED).
- The token **MUST** be transported only in the `Authorization` header. It **MUST NOT**
  appear in a query string, where it would land in proxy and server access logs.
- The server **MUST** compare it in constant time.
- The server **MUST** support two simultaneously valid tokens, so that a token can be
  rotated without downtime.
- The agent **MUST** load the token from a file or an OS secret store, not from its own
  source or from a world-readable location. The token **MUST NOT** appear in any log at
  any level.

Rejection happens **before** the WebSocket upgrade. A request with a missing or invalid
token receives `HTTP 401` with a `WWW-Authenticate: Bearer` header and no upgrade. The
server **SHOULD** rate-limit: after five failures from one source address within 60
seconds, respond `429` with `Retry-After`.

**Optional hardening profile — mutual TLS.** A deployment MAY require a client
certificate, in which case the server asserts that the certificate's subject CN or a SAN
entry equals the `agentId`. Support is OPTIONAL for conformance.

### 1.5 Certificate validation

The agent **MUST** verify the full certificate chain to a trusted root **and MUST** verify
the hostname against the certificate's SAN entries. It **MUST** support three
configurable trust modes:

| Mode | Behaviour |
|---|---|
| `system` | Validate against the Windows certificate store. Default. |
| `ca-bundle` | Validate against an explicitly configured PEM bundle. For private CAs. |
| `pin` | Chain validation still applies, **plus** the server's SPKI SHA-256 must match one of the configured pins. At least two pins SHOULD be configured so that a certificate rotation does not brick the agent. |

TLS 1.2 is the minimum; TLS 1.3 is preferred. The agent **MUST NOT** silently disable
revocation checking. An `insecureSkipVerify`-style option **MAY** exist for development
only, and if present **MUST** log at WARN on every use.

### 1.6 Proxy support

Corporate Windows hosts frequently reach the internet only through a proxy. The agent:

- **MUST** support an explicitly configured HTTP proxy and `CONNECT` tunnelling.
- **SHOULD** support Basic and Negotiate/NTLM proxy authentication.
- **SHOULD** honour the Windows system proxy configuration when no explicit proxy is set.
- **MUST** support a `noProxy` list of hosts and CIDR ranges.
- **MUST** keep the TLS session end-to-end with the server. A proxy that terminates TLS
  (corporate interception) **MUST** only be accepted when that proxy's CA is explicitly
  present in the configured trust bundle. Interception must be a deliberate decision, never
  an accident.

### 1.7 Frames

- **Text frames only** in WSAP/1. Binary frames are reserved for a future wire version and
  **MUST** be rejected by a v1 receiver.
- Exactly **one JSON object per frame**. There is no newline framing inside a frame.
- Fragmented frames **MUST** be supported on receive.
- The maximum frame size is negotiated during the handshake (§3.1). Default 1 MiB, hard
  ceiling 8 MiB.
- A frame exceeding the negotiated maximum **MUST** cause the receiver to reply
  `err FRAME_TOO_LARGE` if the frame was parseable enough to correlate, and then close with
  code `1009`.

### 1.8 WebSocket close codes

| Code | Meaning |
|---|---|
| `1000` | Normal closure |
| `1001` | Going away — service stopping, or server shutting down |
| `1009` | Message too big |
| `1011` | Internal error, or dead peer detected |
| `4001` | Unauthenticated (normally surfaced as HTTP 401 instead; reserved) |
| `4004` | Incompatible protocol version — no common wire version |
| `4008` | Hello timeout — no `session.hello` within 10 seconds of the upgrade |
| `4009` | Superseded — another agent connection replaced this one |
| `4013` | Policy load failure — the agent refuses to serve without a valid policy |

---

## 2. Message envelope

### 2.1 Format decision

**One JSON object per WebSocket text frame, UTF-8 encoded. Binary payloads are Base64
(RFC 4648 §4, with padding) inside JSON string fields.**

WebSocket already provides message framing, so newline-delimited JSON inside a frame would
be framing inside framing — two places to get boundaries wrong. One object per frame means
a conforming agent's entire parsing logic is a single `parse` call. Base64 costs roughly
33 % bandwidth on bulk payloads; that is the deliberate price of not needing a
header-frame-then-payload-frame protocol with interleaving rules. See
[ADR 0002](adr/0002-json-envelope-base64-payloads.md).

### 2.2 Envelope fields

| Field | Type | Presence | Description |
|---|---|---|---|
| `w` | integer | always | Wire version. `1` for WSAP/1. A receiver **MUST** reject an unknown value. |
| `t` | string | always | Message type: `"req"`, `"res"`, `"err"`, `"evt"` |
| `id` | string | `req`, `res`, `err` | Correlation identifier, assigned by the originator of the request. Unique per connection. 1–64 characters from `[A-Za-z0-9._-]`. |
| `corr` | string | `evt` | The `id` of the request this event belongs to. |
| `seq` | integer | `evt` | Zero-based, strictly incrementing per `corr`, gapless. |
| `op` | string | `req`, `evt`; echoed on `res` and `err` | Operation name, dotted namespace, e.g. `"fs.list"`. |
| `ts` | string | RECOMMENDED | RFC 3339 UTC timestamp with milliseconds, e.g. `"2026-07-26T18:14:03.211Z"`. Advisory only. |
| `trace` | string | OPTIONAL | W3C Trace Context `traceparent` value, propagated for cross-system correlation. |
| `p` | object | `req`, `res`, `evt` | Operation payload. MAY be `{}`, but **MUST** be present and **MUST** be an object. |
| `e` | object | `err` | Error object (§7.1). |

### 2.3 Direction rules

- `session.hello` is sent **agent → server**. It is the only request the agent originates,
  apart from `session.ping`.
- `session.ping` MAY be sent in **either direction**; the receiver **MUST** answer.
- `session.bye` is an event sent in **either direction**.
- All other requests are sent **server → agent**.
- All other events (`exec.output`, `exec.exit`, `fs.read.chunk`, `policy.reviewing`) are
  sent **agent → server**.

Because only one side originates each request type, the `id` namespaces cannot collide.
Implementations **MUST** nonetheless tolerate any well-formed `id` string from the peer.

### 2.4 Examples

Request:

```json
{"w":1,"t":"req","id":"r-7f3a91c2","op":"fs.list","ts":"2026-07-26T18:14:03.211Z",
 "p":{"path":"D:\\Logs","offset":0,"limit":200}}
```

Response:

```json
{"w":1,"t":"res","id":"r-7f3a91c2","op":"fs.list","ts":"2026-07-26T18:14:03.240Z",
 "p":{"path":"D:\\Logs","entries":[],"total":0,"truncated":false,"truncationReason":null}}
```

Error:

```json
{"w":1,"t":"err","id":"r-7f3a91c2","op":"fs.list","ts":"2026-07-26T18:14:03.240Z",
 "e":{"code":"POLICY_DENIED","class":"policy","retryable":false,
      "message":"Path 'D:\\Logs' is not within any allowed root.","rule":"fs.readRoots"}}
```

Event:

```json
{"w":1,"t":"evt","corr":"r-91b2","seq":3,"op":"exec.output","ts":"2026-07-26T18:14:04.002Z",
 "p":{"stream":"stdout","data":"Build succeeded.\r\n","encoding":"utf-8","bytes":18,
      "totalBytes":4211,"dropped":false}}
```

---

## 3. Session operations

### 3.1 `session.hello` — agent → server, `req`/`res`

Sent by the agent as its first message after the upgrade. If the server does not receive
it within **10 seconds**, the server **MUST** close with code `4008`.

#### Request payload

| Field | Type | Presence | Description |
|---|---|---|---|
| `wireVersions` | integer[] | REQUIRED | Wire versions the agent supports, in descending preference. e.g. `[1]` |
| `agentId` | string | REQUIRED | **MUST** equal the `X-WinShow-Agent-Id` header |
| `agent` | object | REQUIRED | `{name, version, implementation, buildId?}` |
| `os` | object | REQUIRED | `{platform, version, build, ubr?, edition?, arch, is64Bit, hostname, fqdn?, domain?, uptimeSeconds}`. `platform` is `"windows"`. |
| `identity` | object | REQUIRED | Security context, §10.8: `{user, sid, isService, sessionId, isElevated, integrityLevel, privileges[]}` |
| `capabilities` | string[] | REQUIRED | Operation names the agent implements (§5.9 summary table) |
| `features` | string[] | OPTIONAL | Feature flags, e.g. `["longPaths","unc","stdin","policy.modelReview"]` |
| `limits` | object | REQUIRED | See below |
| `policy` | object | REQUIRED | Policy **summary** — never the full policy. See [`04-agent-policy.md` §7](04-agent-policy.md#7-the-policy-summary-reported-at-handshake). |
| `clock` | object | REQUIRED | `{now, tzOffsetMinutes, tzName}` |
| `resumeOf` | string \| null | OPTIONAL | Previous `sessionId`. Informational only — **no state is ever resumed.** |

`limits` fields, all integers:

| Field | Default | Meaning |
|---|---|---|
| `maxFrameBytes` | 1048576 | Largest frame the agent will send or accept |
| `maxConcurrentRequests` | 16 | In-flight requests the agent will service (§8.3) |
| `maxConcurrentProcesses` | 4 | Simultaneously running child processes |
| `maxOutputBytesPerExec` | 4194304 | Combined stdout+stderr bytes per execution |
| `maxExecMillis` | 300000 | Wall-clock ceiling for one execution |
| `maxReadBytes` | 1048576 | Largest single `fs.read` slice |
| `maxGlobResults` | 5000 | Largest `fs.glob` result set |
| `ackWindowChunks` | 64 | Unacknowledged `exec.output` chunks the agent will send (§9.3) |
| `ackWindowBytes` | 4194304 | Unacknowledged bytes the agent will send (§9.3) |

#### Response payload

| Field | Type | Description |
|---|---|---|
| `wireVersion` | integer | Selected version; **MUST** be one the agent offered |
| `sessionId` | string | Server-generated, unique per connection |
| `server` | object | `{name, version}` |
| `serverTime` | string | RFC 3339 UTC — lets the agent compute clock skew |
| `heartbeatIntervalMs` | integer | Cadence at which the server will ping |
| `maxFrameBytes` | integer | `min(agent limit, server limit)` — the effective cap |
| `ackWindowChunks` | integer | Effective chunk window (§9.3) |
| `ackWindowBytes` | integer | Effective byte window (§9.3) |
| `enabledOps` | string[] | Subset of the agent's `capabilities` the server will actually use |

Version negotiation is intersection-of-lists; the server picks the highest version present
in both. If the intersection is empty, the server replies `err INCOMPATIBLE_VERSION` and
closes with `4004`.

The session is not **ready** — and `/readyz` on the server does not go green — until a
successful `session.hello` exchange has completed.

#### Example

```json
{"w":1,"t":"req","id":"h-1","op":"session.hello","ts":"2026-07-26T18:13:59.004Z","p":{
  "wireVersions":[1],
  "agentId":"WS-PROD-01",
  "agent":{"name":"winshow-agent","version":"1.2.0","implementation":"python-3.11"},
  "os":{"platform":"windows","version":"10.0.19045","build":19045,"ubr":4291,
        "edition":"Windows 10 Pro","arch":"x64","is64Bit":true,
        "hostname":"WS-PROD-01","fqdn":"ws-prod-01.corp.local","domain":"CORP",
        "uptimeSeconds":942133},
  "identity":{"user":"NT SERVICE\\WinShowAgent","sid":"S-1-5-80-3245678901-2233445566-778899001-1122334455-5566778899",
              "isService":true,"sessionId":0,"isElevated":false,
              "integrityLevel":"medium","privileges":["SeChangeNotifyPrivilege"]},
  "capabilities":["session.ping","session.cancel","fs.list","fs.stat","fs.read","fs.glob",
                  "fs.grep","exec.start"],
  "features":["longPaths","unc","policy.modelReview"],
  "limits":{"maxFrameBytes":1048576,"maxConcurrentRequests":16,"maxConcurrentProcesses":4,
            "maxOutputBytesPerExec":4194304,"maxExecMillis":300000,"maxReadBytes":1048576,
            "maxGlobResults":5000,"ackWindowChunks":64,"ackWindowBytes":4194304},
  "policy":{"policyVersion":"2026-07-20T09:00:00Z","policyHash":"sha256:9f2c1d4b8a3e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8",
            "state":"ok","readRoots":["C:\\src","D:\\Logs","C:\\inetpub\\wwwroot"],
            "denyGlobCount":9,"execMode":"allowlist","allowedCommandCount":4,
            "allowedCommandIds":["svc-query","tasklist","dotnet-build","ps-diagnostics"],
            "shellsAllowed":["powershell"],"writeEnabled":false,
            "modelReview":{"enabled":true,"failMode":"closed","timeoutMs":8000},
            "maxOutputBytes":4194304,"maxExecMillis":300000,"denialDisclosure":"explicit"},
  "clock":{"now":"2026-07-26T18:13:59.004Z","tzOffsetMinutes":120,"tzName":"W. Europe Standard Time"}}}
```

```json
{"w":1,"t":"res","id":"h-1","op":"session.hello","ts":"2026-07-26T18:13:59.061Z","p":{
  "wireVersion":1,"sessionId":"s-0f9d2a11",
  "server":{"name":"winshow-server","version":"0.1.0"},
  "serverTime":"2026-07-26T18:13:59.061Z","heartbeatIntervalMs":20000,
  "maxFrameBytes":1048576,"ackWindowChunks":64,"ackWindowBytes":4194304,
  "enabledOps":["session.ping","session.cancel","fs.list","fs.stat","fs.read","fs.glob",
                "fs.grep","exec.start"]}}
```

### 3.2 `session.ping` — either direction, `req`/`res`

**Request:** `{"nonce": "<string>"}`
**Response:** `{"nonce": "<echoed verbatim>", "agentTime": "<rfc3339>", "load": {…}}`

The receiver **MUST** echo `nonce` exactly and **MUST** respond within 5 seconds. `load` is
advisory; every field within it is OPTIONAL: `{inflight, processes, cpuPercent, memoryMB}`.

This is an **application-level** heartbeat, deliberately not a WebSocket control ping.
Control pings are frequently answered transparently by libraries and middleboxes, which
proves the socket is alive but not that the agent's event loop is. An agent **MAY**
additionally use WebSocket control pings to keep middleboxes happy.

The agent **MUST** continue answering `session.ping` while any request is being processed,
including while a stage-2 model review (§[policy](04-agent-policy.md#6-stage-2-model-assisted-review))
is running. A ping timeout during a slow review would tear down a healthy connection.

```json
{"w":1,"t":"req","id":"p-118","op":"session.ping","p":{"nonce":"a3f9c1"}}
{"w":1,"t":"res","id":"p-118","op":"session.ping","p":{"nonce":"a3f9c1","agentTime":"2026-07-26T18:14:19.008Z","load":{"inflight":0,"processes":0,"cpuPercent":0.4,"memoryMB":38}}}
```

### 3.3 `session.cancel` — server → agent, `req`/`res`

**Request:** `{"targetId": "<id>", "reason": "client_cancelled" | "timeout" | "server_shutdown" | "buffer_limit"}`
**Response:** `{"targetId": "<id>", "cancelled": true|false}`

There is exactly one cancellation mechanism, fed by three triggers (§8.4). Cancelling an
unknown or already-terminal `id` returns `{"cancelled": false}` and is **NOT** an error —
cancellation is idempotent and racy by nature.

After acknowledging, the agent **MUST** still emit exactly one terminal message for
`targetId`: either an `err` with code `CANCELLED`, or — for an execution — an
`evt exec.exit` with `exitReason: "cancelled"`.

For a running process the agent **MUST** terminate the entire job object (the whole process
tree). It **SHOULD** first attempt graceful termination by delivering `CTRL_BREAK_EVENT` to
the process group and waiting `gracePeriodMs` (default 2000) before a hard kill.

### 3.4 `session.bye` — either direction, `evt`

`{"reason": "shutdown" | "superseded" | "policy_reload_failed" | "fatal", "message": "<string>", "bySessionId": "<string|null>"}`

Sent immediately before closing. Best effort — a receiver **MUST** cope with its absence,
because a connection can vanish without warning.

`session.bye` is the one event with no originating request. Its `corr` **MUST** be set to
the `sessionId` of the connection being closed, and its `seq` starts at 0 for that value.
`bySessionId` names the successor session when `reason` is `superseded`, so that both
sessions can be stitched together in a log.

---

## 4. Filesystem operations

### 4.0 Shared types

#### `FileEntry`

| Field | Type | Notes |
|---|---|---|
| `name` | string | Leaf name in its on-disk casing |
| `path` | string | Canonical absolute path: backslashes, uppercase drive letter, no `\\?\` prefix |
| `kind` | string | `"file"` \| `"dir"` \| `"symlink"` \| `"junction"` \| `"other"` |
| `size` | integer | Bytes. `0` for directories. |
| `mtime` | string | RFC 3339 UTC, last write time |
| `ctime` | string | RFC 3339 UTC, **creation** time. On Windows this is creation, not the POSIX "status change" — a habitual source of confusion. |
| `atime` | string | RFC 3339 UTC, last access time. May be stale; NTFS updates it lazily. |
| `attrs` | string[] | Subset of `readonly, hidden, system, archive, temporary, compressed, encrypted, reparse, offline, notContentIndexed` |
| `linkTarget` | string \| null | Present for `symlink` and `junction` |

Timestamps **MUST** be emitted as RFC 3339 strings, never as raw 64-bit FILETIME ticks —
a JSON number cannot represent them safely.

#### `Encoding`

One of: `"utf-8"`, `"utf-16le"`, `"utf-16be"`, `"utf-32le"`, `"cp1252"`, `"cp850"`,
`"oem"`, `"ansi"`, `"binary"`, `"auto"`.

- `"binary"` means the accompanying `data` field is Base64.
- `"auto"` is **request-only** and instructs the agent to sniff (§10.2). A response
  **MUST NOT** ever report `"auto"`; it reports what was actually used.
- `"oem"` and `"ansi"` resolve at runtime to the machine's actual code pages via
  `GetOEMCP` and `GetACP`.

### 4.1 `fs.list`

#### Request

| Field | Type | Presence | Default | Notes |
|---|---|---|---|---|
| `path` | string | REQUIRED | — | Absolute Windows path (§10.1) |
| `offset` | integer | OPTIONAL | 0 | Entries to skip |
| `limit` | integer | OPTIONAL | 500 | Maximum entries returned; the agent caps at `maxGlobResults` |
| `pattern` | string | OPTIONAL | `"*"` | Wildcard filter on the leaf name (`*`, `?`), case-insensitive |
| `kinds` | string[] | OPTIONAL | all | Filter by `FileEntry.kind` |
| `includeHidden` | boolean | OPTIONAL | false | Include entries with the `hidden` or `system` attribute |
| `sort` | string | OPTIONAL | `"name"` | `"name"` \| `"size"` \| `"mtime"` |
| `descending` | boolean | OPTIONAL | false | |
| `followLinks` | boolean | OPTIONAL | false | When false, reparse points are reported but not traversed |

#### Response

| Field | Type | Notes |
|---|---|---|
| `path` | string | Canonical form of the requested directory |
| `entries` | FileEntry[] | |
| `total` | integer | Total matching entries before `offset` and `limit` are applied |
| `truncated` | boolean | True when `total > offset + entries.length` |
| `truncationReason` | string \| null | `"limit"` \| `"agent_cap"` \| `"time_budget"` |

Sorting **MUST** be deterministic: the requested key first, then ordinal-ignore-case leaf
name, then ordinal leaf name. Without a total order, paging silently skips or duplicates
entries whenever two entries compare equal.

```json
{"w":1,"t":"req","id":"r-7f3a","op":"fs.list","p":{"path":"D:/Logs","pattern":"*.log","limit":3,"sort":"mtime","descending":true}}
```
```json
{"w":1,"t":"res","id":"r-7f3a","op":"fs.list","p":{
 "path":"D:\\Logs","total":47,"truncated":true,"truncationReason":"limit",
 "entries":[
  {"name":"service.log","path":"D:\\Logs\\service.log","kind":"file","size":18446311,
   "mtime":"2026-07-26T18:12:44.117Z","ctime":"2026-05-02T07:31:02.000Z",
   "atime":"2026-07-26T18:12:44.117Z","attrs":["archive"],"linkTarget":null},
  {"name":"service-2026-07-25.log","path":"D:\\Logs\\service-2026-07-25.log","kind":"file",
   "size":22011904,"mtime":"2026-07-26T00:00:03.550Z","ctime":"2026-07-25T00:00:01.000Z",
   "atime":"2026-07-26T00:00:03.550Z","attrs":["archive"],"linkTarget":null},
  {"name":"archive","path":"D:\\Logs\\archive","kind":"dir","size":0,
   "mtime":"2026-07-20T03:00:00.000Z","ctime":"2025-11-11T12:00:00.000Z",
   "atime":"2026-07-26T18:00:00.000Z","attrs":[],"linkTarget":null}]}}
```

### 4.2 `fs.stat`

#### Request

`{"path": string, "resolveLinks": boolean = false, "sniff": boolean = true, "hash": "none" | "sha256" = "none"}`

#### Response

| Field | Type | Notes |
|---|---|---|
| `path` | string | Canonical |
| `exists` | boolean | |
| `entry` | FileEntry \| null | Null when `exists` is false |
| `realPath` | string \| null | Fully resolved path, when `resolveLinks` was set and a reparse point was traversed |
| `sniff` | object \| null | `{isProbablyText, encoding, hasBom, lineEnding, sampledBytes}`. `lineEnding` is `"crlf"` \| `"lf"` \| `"cr"` \| `"mixed"` \| `"none"`. |
| `sha256` | string \| null | Lowercase hex; only when requested and the file is within the policy's `maxHashBytes` |
| `volume` | object \| null | `{driveType, fileSystem, freeBytes, totalBytes}`; `driveType` is `"fixed"` \| `"network"` \| `"removable"` \| `"ram"` \| `"cdrom"` |

**A non-existent path is a successful response with `exists: false`, not an error.**
`NOT_FOUND` is reserved for operations that require the path to exist, such as `fs.read`.
This distinction lets a caller probe for a file without triggering error handling.

Note that policy is still evaluated: a path outside every allowed root is denied with
`POLICY_DENIED` (or reported as `exists: false` when the policy sets
`denialDisclosure = "notfound"`), never silently statted.

### 4.3 `fs.read`

Exactly one of three addressing modes **MUST** be used. Supplying more than one is
`INVALID_ARGUMENT`.

| Mode | Fields | Use |
|---|---|---|
| A — byte range | `offset`, `length` | Precise slicing, binary content |
| B — line range | `fromLine`, `lineCount` | Reading a known region of a text file |
| C — tail | `tailLines` | Log inspection — the dominant real use |

#### Request

| Field | Type | Presence | Default | Notes |
|---|---|---|---|---|
| `path` | string | REQUIRED | — | |
| `offset` | integer | mode A | 0 | Byte offset from the start of the file |
| `length` | integer | mode A | `maxReadBytes` | Bytes to read |
| `fromLine` | integer | mode B | — | **1-based** line number |
| `lineCount` | integer | mode B | 200 | |
| `tailLines` | integer | mode C | — | Number of lines at the end of the file |
| `encoding` | Encoding | OPTIONAL | `"auto"` | `"binary"` forces Base64 passthrough with no decoding |
| `stripBom` | boolean | OPTIONAL | true | |
| `force` | boolean | OPTIONAL | false | Permit text decoding of content that sniffs as binary |
| `maxBytes` | integer | OPTIONAL | policy | Hard cap regardless of mode |

#### Response

| Field | Type | Notes |
|---|---|---|
| `path` | string | Canonical |
| `data` | string | Decoded text, or Base64 when `encoding` is `"binary"`. Omitted when `chunked` is true. |
| `encoding` | Encoding | The encoding **actually used**. Never `"auto"`. |
| `hadBom` | boolean | |
| `byteOffset` | integer | Offset of the first returned byte |
| `byteLength` | integer | Number of raw file bytes represented |
| `fileSize` | integer | Total file size at read time |
| `eof` | boolean | `byteOffset + byteLength >= fileSize` |
| `firstLine` | integer \| null | 1-based, for line modes |
| `lineCount` | integer \| null | For line modes |
| `totalLines` | integer \| null | Only when cheaply known; MAY be null for large files |
| `truncated` | boolean | The requested range was clipped by a cap |
| `lineEnding` | string | As in `sniff` |
| `decodeErrors` | integer | Count of replacement characters substituted. A value above zero warns the caller that the encoding guess may be wrong. |
| `chunked` | boolean | True when the payload was delivered as `fs.read.chunk` events |

**Line semantics.** Terminators are `\r\n`, `\n`, or `\r`. The terminator **IS** included in
the returned `data`, so byte accounting is exact and the slice round-trips. A final line
without a terminator counts as a line.

`tailLines` on a large file **MUST** be implemented by reading backwards from EOF in blocks.
Reading a 20 GiB log from the beginning to return its last 50 lines is a conformance
failure, not merely a performance problem.

**Chunking.** When the response would exceed the negotiated `maxFrameBytes`, the agent
**MUST** instead emit `evt fs.read.chunk` events, each
`{"seq": <int>, "data": "<string>", "encoding": "<Encoding>"}`, followed by the
`res fs.read` carrying all the metadata with `data` omitted and `chunked: true`. The server
reassembles in `seq` order. The `seq` values of `fs.read.chunk` events share the same
gapless sequence space as any other event for that `corr`.

```json
{"w":1,"t":"req","id":"r-2c81","op":"fs.read","p":{"path":"C:\\Program Files\\App\\logs\\service.log","tailLines":50,"encoding":"auto"}}
```
```json
{"w":1,"t":"res","id":"r-2c81","op":"fs.read","p":{
 "path":"C:\\Program Files\\App\\logs\\service.log",
 "data":"2026-07-26 20:12:41 ERROR Unhandled exception\r\n   at App.Worker.Run()\r\n",
 "encoding":"utf-8","hadBom":false,"byteOffset":18446234,"byteLength":77,
 "fileSize":18446311,"eof":true,"firstLine":204881,"lineCount":2,"totalLines":null,
 "truncated":false,"lineEnding":"crlf","decodeErrors":0,"chunked":false}}
```

### 4.4 `fs.glob`

#### Request

`{"root": string, "patterns": string[], "excludes": string[] = [], "maxDepth": int = 16, "maxResults": int = 1000, "timeBudgetMs": int = 10000, "kinds": string[] = ["file"], "includeHidden": bool = false, "followLinks": bool = false, "stat": bool = false}`

**Pattern syntax — normative, and deliberately minimal:**

| Token | Meaning |
|---|---|
| `*` | Any run of characters, not crossing a path separator |
| `?` | Exactly one character, not a path separator |
| `**` | Zero or more whole path segments |
| `[abc]`, `[a-z]`, `[!abc]` | Character class, with `!` for negation |
| `{a,b}` | Alternation |

Both `\` and `/` are accepted as separators within a pattern. Matching is
**case-insensitive**, because Windows paths are. Patterns are relative to `root`.

#### Response

`{"root": string, "matches": string[] | FileEntry[], "count": int, "truncated": bool, "truncationReason": "maxResults"|"timeBudget"|"maxDepth"|null, "scannedDirs": int, "elapsedMs": int}`

`matches` contains `FileEntry` objects when `stat` was true, plain canonical path strings
otherwise.

When `followLinks` is true the agent **MUST** perform cycle detection on resolved paths. A
junction pointing at its own ancestor must not make the agent loop forever.

### 4.5 `fs.grep`

#### Request

| Field | Type | Presence | Default |
|---|---|---|---|
| `root` | string | REQUIRED | — |
| `query` | string | REQUIRED | — |
| `isRegex` | boolean | OPTIONAL | false |
| `caseSensitive` | boolean | OPTIONAL | false |
| `patterns` | string[] | OPTIONAL | `["**/*"]` |
| `excludes` | string[] | OPTIONAL | `[]` |
| `contextBefore` | integer | OPTIONAL | 0 |
| `contextAfter` | integer | OPTIONAL | 0 |
| `maxMatches` | integer | OPTIONAL | 200 |
| `maxMatchesPerFile` | integer | OPTIONAL | 20 |
| `maxFileBytes` | integer | OPTIONAL | 8388608 |
| `skipBinary` | boolean | OPTIONAL | true |
| `timeBudgetMs` | integer | OPTIONAL | 15000 |
| `encoding` | Encoding | OPTIONAL | `"auto"` |

**Regex flavour — normative.** A conservative subset only: literals, `.`, character classes,
`^`, `$`, `*`, `+`, `?`, `{n,m}`, alternation `|`, grouping `()` and `(?:)`, and the escapes
`\d \w \s \b` with their negations. **No backreferences and no lookaround.** This keeps the
pattern expressible by a linear-time engine, which makes catastrophic backtracking
structurally impossible rather than merely unlikely. The agent **MUST** reject an
unsupported construct with `INVALID_ARGUMENT` rather than quietly accepting a pattern that
can hang it.

#### Response

`{"matches": [{"path", "line", "column", "text", "before": string[], "after": string[]}], "count": int, "filesScanned": int, "filesSkipped": int, "truncated": bool, "truncationReason": string|null, "elapsedMs": int}`

`line` and `column` are 1-based.

---

## 5. Execution operations

### 5.1 `exec.start` — server → agent, `req`/`res`

#### Request

| Field | Type | Presence | Default | Notes |
|---|---|---|---|---|
| `argv` | string[] | one of ¹ | — | `argv[0]` is the executable; the rest are already-split arguments. The agent performs the quoting (§10.4). |
| `commandLine` | string | one of ¹ | — | A raw command line. Valid **only** when `shell` is not `"none"`. |
| `shell` | string | OPTIONAL | `"none"` | `"none"` \| `"cmd"` \| `"powershell"` \| `"pwsh"` |
| `cwd` | string | OPTIONAL | policy default | Absolute path to an existing directory |
| `env` | object | OPTIONAL | `{}` | Name → value overlay. A `null` value removes the variable. |
| `envMode` | string | OPTIONAL | `"overlay"` | `"overlay"` \| `"clean"` (§10.6) |
| `timeoutMs` | integer | OPTIONAL | policy default | The agent caps this at `maxExecMillis` |
| `maxOutputBytes` | integer | OPTIONAL | policy default | Combined across both streams |
| `outputEncoding` | Encoding | OPTIONAL | `"utf-8"` | How to decode the child's output bytes |
| `mergeStderr` | boolean | OPTIONAL | false | When true, stderr is emitted interleaved as `stream: "stdout"` |
| `stdin` | string \| null | OPTIONAL | null | Written to the child, then the pipe is closed |
| `stdinEncoding` | Encoding | OPTIONAL | `"utf-8"` | |
| `priority` | string | OPTIONAL | `"normal"` | `"idle"` \| `"belowNormal"` \| `"normal"`. The agent **MUST NOT** permit raising above normal. |

¹ Exactly one of `argv` and `commandLine` **MUST** be present.

#### Response — sent immediately on a successful spawn

| Field | Type | Notes |
|---|---|---|
| `pid` | integer | |
| `startedAt` | string | RFC 3339 UTC |
| `resolvedExecutable` | string | The absolute path actually launched, after resolution (§10.3) |
| `resolvedCwd` | string | |
| `commandLineUsed` | string | The exact command line handed to the OS, after all quoting |

`commandLineUsed` is echoed back deliberately: it is the ground truth of what ran, and it is
what belongs in the audit log. Reconstructing it later from `argv` guesses at the quoting.

A failure to spawn is returned as an `err` on this request (`EXEC_NOT_FOUND` or
`SPAWN_FAILED`) and produces **no** `exec.exit` event, because no process ever existed.

```json
{"w":1,"t":"req","id":"r-91b2","op":"exec.start","p":{
 "argv":["C:\\Program Files\\dotnet\\dotnet.exe","build","-c","Release"],
 "cwd":"C:\\src\\proj","timeoutMs":300000,"maxOutputBytes":4194304,
 "outputEncoding":"utf-8","envMode":"overlay","env":{"DOTNET_CLI_TELEMETRY_OPTOUT":"1"}}}
```
```json
{"w":1,"t":"res","id":"r-91b2","op":"exec.start","p":{
 "pid":8812,"startedAt":"2026-07-26T18:14:03.688Z",
 "resolvedExecutable":"C:\\Program Files\\dotnet\\dotnet.exe","resolvedCwd":"C:\\src\\proj",
 "commandLineUsed":"\"C:\\Program Files\\dotnet\\dotnet.exe\" build -c Release"}}
```

### 5.2 `exec.output` — agent → server, `evt`

| Field | Type | Notes |
|---|---|---|
| `stream` | string | `"stdout"` \| `"stderr"` |
| `data` | string | Decoded text, or Base64 when `encoding` is `"binary"` |
| `encoding` | Encoding | Matches the request's `outputEncoding`, or `"binary"` if decoding was refused |
| `bytes` | integer | Raw pre-decode bytes represented by this chunk |
| `totalBytes` | integer | Cumulative raw bytes for this stream so far |
| `dropped` | boolean | True when output was discarded before this chunk because a cap was hit |

Flush rules are normative — see §9.2.

### 5.3 `exec.ack` — server → agent, `evt`

`{"corr": "<request id>", "ackSeq": <int>, "ackBytes": <int>}`

Sent by the server to advance the flow-control window. Semantics are in §9.3.

Note that this is the one event travelling **server → agent**. It carries `corr` and `seq`
like any event; its `seq` is drawn from a server-side sequence space for that correlation
and is independent of the agent's.

### 5.4 `exec.exit` — agent → server, `evt`

| Field | Type | Notes |
|---|---|---|
| `exitCode` | integer \| null | Windows exit codes are unsigned 32-bit. Reported as an unsigned JSON number, `0`–`4294967295`. Null when the process never completed. |
| `exitCodeSigned` | integer \| null | The same bits read as signed int32. `0xC0000005` reads as `3221225477` unsigned and `-1073741819` signed; both forms appear in documentation, so both are sent. |
| `exitReason` | string | `"exited"` \| `"timeout"` \| `"cancelled"` \| `"killed"` \| `"backpressure"` \| `"agentShutdown"` |
| `startedAt` | string | RFC 3339 UTC |
| `endedAt` | string | RFC 3339 UTC |
| `durationMs` | integer | |
| `stdoutBytes` | integer | Raw bytes emitted |
| `stderrBytes` | integer | Raw bytes emitted |
| `truncated` | boolean | Output hit `maxOutputBytes` |
| `truncationReason` | string \| null | `"maxOutputBytes"` \| `"backpressure"` |
| `cpuTimeMs` | integer \| null | User + kernel, from the job object |
| `peakWorkingSetBytes` | integer \| null | |
| `killedProcesses` | integer \| null | How many processes the job object terminated |

`exec.exit` **MUST** be the final event for its `corr`, and **MUST** be sent exactly once,
including on every failure path after a successful spawn.

**`exitReason` is authoritative.** Consumers **MUST** prefer it over inferring an outcome
from `exitCode`. When the agent terminates a process on timeout or cancellation the exit
code is whatever `TerminateProcess` was given and carries no meaning.

```json
{"w":1,"t":"evt","corr":"r-91b2","seq":41,"op":"exec.exit","ts":"2026-07-26T18:14:38.220Z","p":{
 "exitCode":1,"exitCodeSigned":1,"exitReason":"exited",
 "startedAt":"2026-07-26T18:14:03.688Z","endedAt":"2026-07-26T18:14:38.201Z","durationMs":34513,
 "stdoutBytes":184220,"stderrBytes":0,"truncated":false,"truncationReason":null,
 "cpuTimeMs":29110,"peakWorkingSetBytes":412315648,"killedProcesses":0}}
```

### 5.5 `policy.reviewing` — agent → server, `evt`

`{"stage": "modelReview", "elapsedMs": <int>}`

OPTIONAL. An agent whose stage-2 model review (see
[`04-agent-policy.md` §6](04-agent-policy.md#6-stage-2-model-assisted-review)) exceeds
roughly 1500 ms **SHOULD** emit this event so the server can tell the caller that the
request is under review rather than merely slow. It carries no authorization meaning and
**MUST NOT** be treated as an approval.

### 5.6 On `exec.cancel`

There is **no** `exec.cancel` operation. The name is reserved and **MUST NOT** be used in
WSAP/1. `session.cancel` covers execution cancellation, and one cancellation path means one
set of bugs rather than two.

---

## 6. Deferred operations

These are catalogued so that capability strings are stable from the beginning, and so that
an agent can advertise them without a protocol revision. They are **not** part of the
WSAP/1 MVP and a conforming agent is not required to implement any of them.

| Operation | Capability string | Notes |
|---|---|---|
| `fs.write`, `fs.append` | `fs.write` | Atomic via temp file plus rename. Requires a separate write policy. |
| `fs.upload.begin` / `.chunk` / `.commit` | `fs.upload` | Chunked transfer for files larger than one frame |
| `fs.delete`, `fs.move`, `fs.mkdir` | `fs.mutate` | |
| `proc.list` | `proc.list` | `includeCommandLine` is separately policy-gated: command lines routinely contain credentials |
| `proc.kill` | `proc.kill` | Must refuse to kill the agent itself, `System`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, or any pid ≤ 4 |
| `sys.services`, `sys.eventlog` | `sys.services`, `sys.eventlog` | Structured alternatives to shelling out |

### 6.1 Operation summary

| Operation | Direction | Types | Phase | Capability string |
|---|---|---|---|---|
| `session.hello` | agent → server | req/res | MVP | implicit |
| `session.ping` | both | req/res | MVP | implicit |
| `session.cancel` | server → agent | req/res | MVP | implicit |
| `session.bye` | both | evt | MVP | implicit |
| `fs.list` | server → agent | req/res | MVP | `fs.list` |
| `fs.stat` | server → agent | req/res | MVP | `fs.stat` |
| `fs.read` | server → agent | req/res, `fs.read.chunk` evt | MVP | `fs.read` |
| `fs.glob` | server → agent | req/res | MVP | `fs.glob` |
| `fs.grep` | server → agent | req/res | MVP | `fs.grep` |
| `exec.start` | server → agent | req/res, `exec.output` + `exec.exit` evt | MVP | `exec.start` |
| `exec.ack` | server → agent | evt | MVP | implicit |
| `policy.reviewing` | agent → server | evt | MVP, optional | `policy.modelReview` feature |

Operations marked *implicit* are part of the base protocol and **MUST NOT** be listed in
`capabilities`; every agent implements them.

---

## 7. Error codes

### 7.1 The error object

| Field | Type | Presence | Notes |
|---|---|---|---|
| `code` | string | REQUIRED | From the table below |
| `class` | string | REQUIRED | `transport` \| `auth` \| `policy` \| `os` \| `limit` \| `timeout` \| `cancelled` \| `internal` \| `argument` |
| `retryable` | boolean | REQUIRED | Whether an identical retry could plausibly succeed |
| `message` | string | REQUIRED | Human-readable, safe to display to an end user |
| `rule` | string | OPTIONAL | For `POLICY_DENIED`: the identifier of the deciding rule |
| `winError` | integer \| null | OPTIONAL | The Win32 error code, when one caused this |
| `winErrorName` | string \| null | OPTIONAL | e.g. `ERROR_ACCESS_DENIED` |
| `details` | object | OPTIONAL | Additional structured context; see §7.3 |

### 7.2 Code table

| Code | class | retryable | Meaning |
|---|---|---|---|
| `UNAUTHENTICATED` | auth | no | Token missing or invalid. Normally surfaced as HTTP 401 before the upgrade. |
| `INCOMPATIBLE_VERSION` | auth | no | No common wire version, or a subprotocol mismatch |
| `SUPERSEDED` | transport | no | Another agent connection replaced this one |
| `MALFORMED_MESSAGE` | transport | no | Not valid JSON, or a structural field (`w`, `t`) is missing or wrong |
| `FRAME_TOO_LARGE` | transport | no | A frame exceeded the negotiated maximum |
| `UNSUPPORTED_OPERATION` | argument | no | The `op` is unknown to this agent |
| `NOT_IMPLEMENTED` | argument | no | The `op` is defined in this specification but not implemented by this build |
| `INVALID_ARGUMENT` | argument | no | Payload validation failed: wrong type, mutually exclusive fields, unsupported regex construct, duplicate request id |
| `POLICY_DENIED` | policy | **no** | WinShow agent policy forbade this. `rule` names the deciding rule. |
| `POLICY_UNAVAILABLE` | policy | no | The policy file is missing or invalid; the agent fails closed |
| `NOT_FOUND` | os | no | The path does not exist, for an operation requiring existence |
| `ACCESS_DENIED` | os | no | A Windows ACL or a missing privilege denied it. **Distinct from `POLICY_DENIED`.** |
| `IS_A_DIRECTORY` | os | no | A file was expected |
| `NOT_A_DIRECTORY` | os | no | A directory was expected |
| `INVALID_PATH` | os | no | Malformed, relative, a reserved device name, or containing illegal characters |
| `PATH_TOO_LONG` | os | no | Exceeds limits even with long-path handling |
| `SHARING_VIOLATION` | os | yes | The file is locked by another process |
| `DISK_FULL` | os | no | |
| `IO_ERROR` | os | yes | Generic I/O failure; `winError` carries the specific code |
| `EXEC_NOT_FOUND` | os | no | `argv[0]` could not be resolved to an executable |
| `SPAWN_FAILED` | os | no | Process creation failed; `winError` is set |
| `ENCODING_ERROR` | argument | no | Content could not be decoded and `force` was false |
| `RESOURCE_EXHAUSTED` | limit | yes | Memory pressure, or a limit other than concurrency |
| `AGENT_BUSY` | limit | yes | `maxConcurrentRequests` or `maxConcurrentProcesses` would be exceeded (§8.3) |
| `TIMEOUT` | timeout | yes | The operation exceeded its deadline |
| `CANCELLED` | cancelled | no | Cancelled by request |
| `INTERNAL_ERROR` | internal | no | An agent bug. `details` MAY carry a redacted diagnostic. |

**Server-originated codes** that the MCP server surfaces to its own clients but that never
appear on the WSAP wire: `AGENT_UNAVAILABLE`, `AGENT_DISCONNECTED`, `AGENT_SUPERSEDED`,
`AGENT_TIMEOUT`, `AGENT_PROTOCOL_ERROR`. They are documented in
[`05-mcp-tool-surface.md`](05-mcp-tool-surface.md).

### 7.3 `details` for `POLICY_DENIED`

A denial should leave the caller able to do something useful, so it carries a summary of
what *is* permitted:

```json
{"w":1,"t":"err","id":"r-55c1","op":"exec.start","e":{
  "code":"POLICY_DENIED","class":"policy","retryable":false,
  "rule":"exec.deny[no-destructive]",
  "message":"Command denied: matches deny rule 'no-destructive'.",
  "details":{
    "reason":"Destructive disk and boot operations are never permitted.",
    "reasonSource":"rule",
    "subject":"argv",
    "allowedSummary":{"execMode":"allowlist",
                      "allowedCommandIds":["svc-query","tasklist","dotnet-build","ps-diagnostics"]}}}}
```

Field rules:

- `rule` **MUST** identify the deciding rule by namespace and identifier, or by index when
  the rule has no identifier.
- `message` **MUST** be safe to show to an end user and **MUST NOT** leak paths or rule
  internals beyond what the policy's `denialDisclosure` setting permits.
- `details.reasonSource` **MUST** be present whenever `details.reason` is, and **MUST** be
  one of:

  | Value | Meaning |
  |---|---|
  | `rule` | The operator wrote this text in the policy file |
  | `agent` | The agent composed it deterministically from an OS result or a validation failure |
  | `model` | The stage-2 model review generated it |

  **Text with `reasonSource: "model"` is untrusted generated content.** The server **MUST**
  label it as such when relaying it to an MCP client, and no component — server, client, or
  model — may interpret it as instructions. It is a string to display, nothing more.
- `details.allowedSummary` **SHOULD** be included, so a caller can propose a permitted
  alternative rather than guessing at variants.

### 7.4 Stability

Error codes are **append-only**. A published code **MUST NOT** change meaning and **MUST
NOT** be removed. Adding a code is a minor change (§11). A receiver encountering an unknown
code **MUST** treat it as `class: "internal"`, `retryable: false`.

---

## 8. Concurrency and ordering

### 8.1 Multiplexing is required

> The agent **MUST** support multiple concurrent in-flight requests over a single WebSocket
> connection, correlating them by `id`, and **MUST NOT** serialize them. The server
> **MUST NOT** serialize requests whose relative ordering matters on the agent side unless
> the caller has explicitly serialized them.

This is stated normatively because the failure mode is silent: an agent that reads a frame,
handles it to completion, and only then reads the next frame is functionally correct and
destroys throughput. A 4-minute build would block a 20-millisecond directory listing.

### 8.2 Ordering guarantees

- Responses **MAY** arrive in any order. Receivers **MUST NOT** assume FIFO.
- Events sharing a `corr` **MUST** be delivered in `seq` order, **gapless**, starting at 0.
- `exec.exit` **MUST** be the last event for its `corr`.
- A receiver detecting a gap in `seq` **MUST** fail that request rather than silently
  proceeding with missing output.

WebSocket already guarantees ordered delivery on one connection, so these hold naturally —
they are stated so that an agent which parallelises chunk encoding internally does not
reorder on the way out.

### 8.3 Limits and `AGENT_BUSY`

The agent advertises `maxConcurrentRequests` (default 16) and `maxConcurrentProcesses`
(default 4) in its handshake. The server **MUST** respect both and queue locally rather
than overshooting.

If the server exceeds a limit anyway — a bug, or a stale limit after a reconnect — the
agent **MUST** reject the excess request with `AGENT_BUSY` rather than queueing it
unboundedly or degrading. Unbounded queueing turns a burst into a memory exhaustion, and it
hides the misbehaviour instead of surfacing it.

`AGENT_BUSY` is `retryable: true`; the server **SHOULD** retry after a short delay, with a
bounded number of attempts.

### 8.4 Cancellation

One mechanism (`session.cancel`, §3.3) fed by three triggers:

1. The MCP client sends `notifications/cancelled` for the originating tool call.
2. The MCP client disconnects, or its SSE stream dies.
3. A server-side deadline is exceeded.

Cancellation is best-effort and idempotent. Cancelling an unknown or finished `id` returns
`{"cancelled": false}` and is not an error.

### 8.5 Duplicate request identifiers

An agent receiving a `req` whose `id` matches one already seen **on the same connection**
**MUST** reject it with `INVALID_ARGUMENT` and a message identifying the duplicate. This
protects against a server bug re-issuing a non-idempotent `exec.start`.

Identifiers are scoped to a connection. After a reconnect, all identifiers are fresh.

### 8.6 Timeouts

Two layers:

- **The agent's timeout is authoritative**, because the agent owns the process and can kill
  it. On expiry it terminates the process tree and emits `exec.exit` with
  `exitReason: "timeout"` **and the output captured so far**.
- **The server's timeout is a safety net**, set to the agent's timeout plus a margin
  (5 seconds is RECOMMENDED). If it ever fires, the agent is misbehaving; the server logs
  this at WARN and fails the request with `AGENT_TIMEOUT`.

### 8.7 Idempotency and retries

`fs.*` read operations are side-effect free; a retry is harmless.

**`exec.start` is not idempotent and MUST NOT be retried by anyone.** Neither the server nor
the agent may re-issue or re-run it after a failure, because the server cannot know whether
the command already ran. Retrying is a decision for the human or the model, made with the
audit log in hand.

---

## 9. Streaming and backpressure

### 9.1 What streams and what does not

Command output streams, because a build's output arrives over minutes and is useful as it
arrives. File reads do not stream: `fs.read` is range-addressed, and a caller wanting more
issues another request. A partial file is not a partial truth, and range plus tail plus grep
are the primitives that actually serve the use cases.

### 9.2 Flush rules for `exec.output`

The agent **MUST** flush a chunk when **any** of the following becomes true:

- 64 KiB has accumulated for that stream, or
- 250 ms has elapsed since the previous flush with data pending, or
- a newline boundary is crossed **and** at least 4 KiB is pending.

Together these keep an interactive command responsive without producing one frame per byte.

**Chunks MUST NOT split a multi-byte character sequence.** The agent **MUST** retain an
incomplete trailing sequence and prepend it to the next chunk. Splitting mid-sequence
produces mojibake that looks like a target-program bug and is exceptionally tedious to
diagnose.

### 9.3 The acknowledgement window

Flow control is a credit window, advanced by `exec.ack` (§5.3).

- The agent **MUST NOT** have more than `ackWindowChunks` unacknowledged `exec.output`
  chunks, nor more than `ackWindowBytes` unacknowledged bytes, outstanding for one
  correlation at a time.
- Defaults are **64 chunks** and **4 MiB**, whichever is reached first. Both are advertised
  in `session.hello` and confirmed in the response; the effective value is the minimum of
  what each side offered.
- `exec.ack` carries the highest contiguous `seq` and the cumulative byte count the server
  has consumed. It is cumulative, not per-chunk, so a lost ack is harmless: the next one
  supersedes it.
- The server **SHOULD** acknowledge eagerly — on consuming a chunk — rather than batching,
  since the window exists to bound memory and not to pace the sender.

When the window is full the agent **MUST** stop reading the child process's pipes. The
child then blocks on its own pipe write. This is ordinary operating-system backpressure and
loses no data, which is why it is preferred over dropping chunks.

If the window stays full for `sendStallTimeoutMs` (default 30 000 ms) the agent **MUST**
terminate the process tree and emit `exec.exit` with `exitReason: "backpressure"` and
`truncationReason: "backpressure"`.

### 9.4 Caps

| Cap | Default | Owner |
|---|---|---|
| Frame size | 1 MiB (ceiling 8 MiB) | Negotiated |
| `exec.output` chunk payload | 256 KiB | Agent |
| Output per execution | 4 MiB | Agent policy |
| `fs.read` slice | 1 MiB | Agent policy |
| Unacknowledged window | 64 chunks / 4 MiB | Negotiated |
| Send-stall timeout | 30 s | Agent |

Base64 expansion is counted **inside** the frame cap, not against the raw byte count. A
1 MiB frame therefore carries at most roughly 768 KiB of binary payload.

---

## 10. Windows semantics

This section exists because these are the details that are usually left implicit and then
diverge between implementations. Every rule here is normative.

### 10.1 Path handling

**Accepted separators.** Both `\` and `/`, including mixed forms such as
`D:/Logs\archive`. The agent **MUST** normalise internally to `\`.

**Absolute only.** Accepted forms:

| Form | Example |
|---|---|
| Drive-absolute | `C:\dir\file.txt` |
| UNC | `\\server\share\dir\file.txt` |
| Long-path prefixed | `\\?\C:\…`, `\\?\UNC\server\share\…` |

**Rejected** with `INVALID_PATH`:

| Form | Example | Why |
|---|---|---|
| Relative | `foo\bar` | Depends on the agent's current directory |
| Drive-relative | `C:foo` | Depends on a hidden per-drive current directory — a genuine footgun |
| Rooted, no drive | `\foo` | Depends on the current drive |

Every accepted path must be unambiguous without reference to hidden process state.

**Canonicalisation**, in this order, before any policy evaluation:

1. Convert `/` to `\`.
2. Collapse repeated separators, except the leading `\\` of a UNC path.
3. Resolve `.` and `..` lexically.
4. Uppercase the drive letter.
5. Strip trailing separators, except on a bare root (`C:\` stays `C:\`).
6. Strip any `\\?\` prefix for the value returned to the server.

**The escape check — the single most important rule in this document.** After lexical
canonicalisation the agent **MUST** obtain the **OS-final path** (via
`GetFinalPathNameByHandle` or an equivalent), which resolves symlinks, junctions, and 8.3
short names. **Policy MUST be evaluated against that final path, not against the lexical
one.**

Checking only the lexical path is the most likely security hole in a naive implementation.
`C:\src\link` may be a junction to `C:\Users`. `C:\PROGRA~1` is `C:\Program Files`. Neither
is visible to string manipulation.

**Long paths.** Paths beyond 260 characters **MUST** be supported, either by prefixing
`\\?\` internally — noting that this prefix disables further normalisation by the OS, so
canonicalisation must already be complete — or by declaring long-path awareness in the
process manifest. `\\?\` **MUST NOT** appear in returned paths.

**Case.** Windows paths are case-insensitive and case-preserving. All policy comparison
**MUST** use **ordinal, culture-invariant, case-insensitive** comparison. A culture-aware
comparison introduces the Turkish dotless-i problem into a security decision. Returned names
preserve their on-disk casing.

**Reserved names.** `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9`, with or
without an extension, **MUST** be rejected as a path component. Components with trailing
dots or trailing spaces **MUST** be rejected.

**Alternate data streams.** A `:` after the drive specifier indicates an ADS. It **MUST** be
rejected unless the policy sets `allowAlternateDataStreams = true`.

**UNC and network paths.** Supported. Note that a service account has different network
credentials than the interactive user, and that **mapped drive letters do not exist in
session 0**. The agent **MUST NOT** attempt to resolve mapped drives; policy roots must be
expressed in UNC form. This is the most common "but it works when I run it by hand"
surprise, and belongs in operator documentation.

**Containment testing.** `isWithin(root, path)` **MUST** compare whole path components, not
string prefixes. `C:\src2` **MUST NOT** match root `C:\src`. Split both on `\`, compare
component-wise with ordinal-ignore-case, and require that the root has no more components
than the path.

### 10.2 Encoding

**On the wire**, everything is UTF-8 — WebSocket text frames are UTF-8 by definition.

**File reads with `encoding: "auto"`** use this sniffing order, normatively:

1. **BOM detection.** UTF-8 `EF BB BF`; UTF-32LE `FF FE 00 00`; UTF-16LE `FF FE` not
   followed by `00 00`; UTF-16BE `FE FF`. Check UTF-32LE before UTF-16LE — the shorter
   prefix is a prefix of the longer one.
2. **No BOM:** examine the first 8 KiB. A regular pattern of `NUL` bytes in alternating
   positions suggests UTF-16.
3. Attempt a strict UTF-8 decode. If it succeeds, the content is UTF-8.
4. If at least 1 % of the sample consists of bytes outside printable and common control
   ranges after the above, classify as **binary**.
5. Otherwise fall back to the policy's `defaultAnsiEncoding` (default `cp1252`).

The agent **MUST** report the encoding it chose and **MUST** report `decodeErrors` above
zero when replacement characters were substituted, so the caller can tell that the guess may
be wrong.

**BOM handling.** With `stripBom: true` (the default) the BOM is removed from `data`, but
`byteOffset` and `byteLength` still describe raw file bytes including it, and `hadBom` is
set.

**Line endings are never translated.** `\r\n` is returned as `\r\n`. A tool that silently
rewrites line endings corrupts diffs and invalidates hashes.

**Command output.** The agent **MUST** read raw bytes from the child's pipes and decode
explicitly. It **MUST NOT** attach a text reader to the pipe and hope. Console applications
write in the console output code page (OEM, e.g. CP 850 or CP 437), modern tooling often
writes UTF-8, and Windows PowerShell 5.1 writes UTF-16LE to a redirected pipe under some
configurations. Concretely:

- Decode according to the request's `outputEncoding`, substituting U+FFFD on failure and
  counting the substitutions.
- For `shell: "powershell"` and `shell: "pwsh"`, the agent **MUST** prepend
  `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8;`
  to the script.
- For `shell: "cmd"`, the agent **SHOULD** arrange for UTF-8 output, for example by
  prefixing `chcp 65001>nul & `.
- `outputEncoding: "binary"` passes the bytes through as Base64 for tools that emit genuinely
  binary output.

**JSON validity.** Control characters and lone surrogates arising from decoding **MUST** be
escaped or replaced so that every frame is valid JSON. Invalid UTF-16 surrogate pairs
**MUST** be replaced with U+FFFD rather than emitted raw.

### 10.3 How a command is executed

**The default and required mode is a direct process creation with an explicit argument
vector: `CreateProcessW`, no shell, no `ShellExecute`.**

The reason is that the authorization decision belongs to the agent, and the agent can only
enforce a meaningful policy on values it can see. A policy that permits `sc.exe query
<service>` is only enforceable if `sc.exe` and `query` are separate, inspectable tokens. A
shell string is opaque to policy, and is exactly the shape that command injection exploits.
See [ADR 0006](adr/0006-createprocess-argv-not-shell.md).

Shells are supported as **separate, individually permitted modes**:

| `shell` | Invocation | Mandatory flags and why |
|---|---|---|
| `"powershell"` | `powershell.exe -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass -Command "<script>"` | `-NoProfile` is mandatory: profile scripts are writable by the user and make execution non-deterministic. `-NonInteractive` prevents a prompt from hanging forever. |
| `"pwsh"` | `pwsh.exe` with the same flags | |
| `"cmd"` | `cmd.exe /d /s /c "<commandLine>"` | `/d` skips `HKCU\Software\Microsoft\Command Processor\AutoRun`, a classic persistence vector. `/s` makes the outer-quote stripping rules predictable. |

**The `cmd` caveat, normative.** Safe quoting for `cmd.exe` is not achievable in general,
because `cmd` re-parses metacharacters after argument processing. Therefore, when
`shell: "cmd"`, the agent **MUST** reject a `commandLine` containing any of
`& | < > ^ %`, or containing an odd number of `"` characters, unless the policy sets
`allowUnsafeCmdMetacharacters = true`. Operators who need pipes should be directed to
`powershell`.

**Executable resolution** for `shell: "none"`: `argv[0]` **MUST** be either an absolute path,
or a bare name resolved against a **policy-defined search list**. The ambient `PATH`
**MUST NOT** be used, because `PATH` is influenced by whoever can write the service's
environment, and resolving against it is executable substitution waiting to happen. An
ambiguous resolution is `EXEC_NOT_FOUND`. The resolved absolute path is what policy is
evaluated against and what is reported as `resolvedExecutable`.

**Batch and script files.** The agent **MUST** refuse to execute `.bat`, `.cmd`, or `.ps1`
files under `shell: "none"`, returning `EXEC_NOT_FOUND` with a hint pointing at the
corresponding shell mode. They are not executables; Windows would silently route them
through a shell, which would defeat the entire argv model.

**Process containment.** Every process **MUST** be created inside a **Job Object** with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so that closing the job kills the whole tree and so
that the OS reaps every child if the agent itself dies. The agent **SHOULD** also apply
`JobMemoryLimit` and `ActiveProcessLimit` from policy.

Creation flags: `CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED`, with
`CREATE_NEW_PROCESS_GROUP` so that `CTRL_BREAK_EVENT` can be delivered for graceful
cancellation. The process **MUST** be created suspended, assigned to the job, and only then
resumed — otherwise a fast-starting child can spawn a grandchild before it is contained.

**Handle inheritance.** Only the three standard pipe handles **MUST** be inherited, passed
explicitly via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Blanket handle inheritance leaks the
agent's own handles — potentially including its socket — into an arbitrary child process.

### 10.4 Quoting and argument passing

When building the command line from `argv`, the agent **MUST** implement the Microsoft C
runtime rules exactly, because those are the rules `CommandLineToArgvW` reverses and
therefore what most programs expect:

1. Arguments are separated by a single space.
2. An argument is quoted if it is empty, or if it contains a space, tab, newline, vertical
   tab, or `"`.
3. Inside a quoted argument:
   - a run of *n* backslashes immediately preceding a `"` becomes *2n+1* backslashes
     followed by `\"`;
   - a run of *n* backslashes at the very end of the argument becomes *2n* backslashes;
   - backslashes not adjacent to a quote are literal.
4. `argv[0]` is always quoted when it contains a space, and **MUST** be an absolute path.

Worked examples:

| `argv` element | Emitted |
|---|---|
| `C:\Program Files\dotnet\dotnet.exe` | `"C:\Program Files\dotnet\dotnet.exe"` |
| `build` | `build` |
| `a b` | `"a b"` |
| *(empty string)* | `""` |
| `she said "hi"` | `"she said \"hi\""` |
| `C:\path\` | `"C:\path\\"` |
| `\\?\C:\x` | `\\?\C:\x` (no quoting needed) |

**Known exceptions the agent MUST document rather than work around:** `cmd.exe` and
`.bat`/`.cmd` files do not follow these rules, and some programs — notably `msiexec`,
`robocopy`, and binaries built with Go — parse their raw command line themselves. This is
why `commandLineUsed` is echoed back: it is the only unambiguous record of what was
actually passed.

### 10.5 Exit codes

- Windows exit codes are `DWORD`, unsigned 32-bit. Report `exitCode` unsigned and
  `exitCodeSigned` as the two's-complement reading of the same bits.
- `exitCode: 0` means success **by convention only**. The agent **MUST NOT** reinterpret,
  normalise, or remap exit codes.
- When the agent terminates a process for timeout or cancellation, the exit code is
  whatever `TerminateProcess` was given and is meaningless. `exitReason` is the authoritative
  signal.
- When no process was ever created, `exitCode` is `null` and the failure is reported as an
  `err` on `exec.start`, not as an `exec.exit`.

### 10.6 Environment variables

**`envMode: "overlay"` (default).** The child's environment is the agent service's own
environment, **minus** every variable matching the policy's `envRedact` patterns (default:
`WINSHOW_*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*_KEY`), **plus** the request's `env`
overlay filtered through the policy's `envAllow` patterns.

**`envMode: "clean"`.** The child's environment is the policy's `envBase` list — typically
`SystemRoot`, `windir`, `PATH`, `PATHEXT`, `TEMP`, `TMP`, `ComSpec`,
`NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE` — plus the filtered overlay, and nothing
else. RECOMMENDED for reproducibility.

Rules:

- Variable names are **case-insensitive** on Windows. The agent **MUST** deduplicate
  case-insensitively; a request setting both `Path` and `PATH` is `INVALID_ARGUMENT`.
- Setting `PATH`, `PATHEXT`, `ComSpec`, `SystemRoot`, or `windir` requires the policy to
  set `envAllowSensitive = true`. Overriding `PATH` is executable substitution by another
  name.
- The environment block passed to the OS **MUST** be Unicode
  (`CREATE_UNICODE_ENVIRONMENT`), sorted case-insensitively by name, and terminated with a
  double NUL, as Win32 requires.
- The agent **MUST NOT** expand `%VAR%` inside `argv`. That is a shell's job, and the agent
  is not a shell.

### 10.7 Working directory

Absolute, must exist, must be a directory, and must satisfy the policy's `cwdRoots`
(defaulting to the filesystem read roots). The default comes from the policy's `defaultCwd`.

Note for session-0 services: `%USERPROFILE%` resolves to
`C:\Windows\ServiceProfiles\<account>` — or `C:\Windows\system32\config\systemprofile` for
`LocalSystem` — and `%TEMP%` follows it. This is documented rather than worked around.

### 10.8 Security context

- **Default deployment is a Windows Service** running under a **virtual service account**
  (`NT SERVICE\WinShowAgent`), or a group-managed service account in a domain. It
  **MUST NOT** run as `LocalSystem` by default. `LocalSystem` is the highest-privilege local
  principal; a bug in the agent would then own the machine. A virtual service account gets a
  per-service SID that can be granted ACLs on exactly the directories the policy allows, so
  the operating system becomes a second enforcement layer beneath the policy.
- The service **SHOULD** be configured with `RequiredPrivileges` reduced to
  `SeChangeNotifyPrivilege`, and with a write-restricted token where the platform permits.
- **Session 0 isolation** applies: no interactive desktop, no GUI, no mapped drives, no
  access to the logged-on user's `HKCU`.
- **No impersonation in WSAP/1.** Every operation runs as the agent's own identity. The
  agent **MUST NOT** use `WTSQueryUserToken` with `CreateProcessAsUser` to launch processes
  in another session; that is a privilege-escalation primitive and is out of scope.
- The `identity` block in `session.hello` reports all of this, so an operator can reason
  about why something returned `ACCESS_DENIED`.
- An **interactive mode** for debugging (`--console`) **MUST** exist, runs as the invoking
  user, and **MUST** log `RUNNING INTERACTIVELY AS <user>` at startup.

### 10.9 Standard stream plumbing

Anonymous pipes, or named pipes with unique names when overlapped I/O is needed. The child's
ends are marked inheritable; the parent's ends **MUST NOT** be.

**Both streams MUST be read concurrently.** Reading stdout to completion before touching
stderr deadlocks any program that fills the 64 KiB stderr pipe buffer — a classic bug that
manifests as a hang only on verbose failures, which is when it hurts most. The pipe buffer
size SHOULD be raised to 1 MiB.

---

## 11. Versioning and forward compatibility

### 11.1 Receiver rules

1. Receivers **MUST** ignore unknown fields in any object, at any nesting depth. An unknown
   field **MUST NOT** produce an error.
2. Receivers **MUST** ignore `evt` messages with an unknown `op`, logging at debug level.
3. On receiving a `req` with an unknown `op`, the agent **MUST** reply
   `err UNSUPPORTED_OPERATION`. It **MUST NOT** close the connection.
4. Receivers **MUST** tolerate new values in string enumerations: treat an unrecognised
   value as the documented default and log it. The sole exceptions are `t` and `w`, which
   are structural — an unknown value there is fatal for that message.
5. An agent **MUST NOT** send an `op` it did not advertise in `capabilities`, and a server
   **MUST NOT** send an `op` the agent did not advertise.

### 11.2 What changes the wire version

| Change | Kind | Bumps `w`? |
|---|---|---|
| Adding an optional field | minor | no |
| Adding an operation | minor | no |
| Adding an error code | minor | no |
| Adding an enum value | minor | no |
| Making an optional field required | **major** | yes |
| Removing or renaming a field | **major** | yes |
| Changing a field's type or units | **major** | yes |
| Repurposing an existing error code | **major** | yes |

Because minor changes never bump `w`, a v1 agent and a newer v1 server interoperate
indefinitely, each ignoring what it does not understand.

### 11.3 Capability negotiation, not version guessing

An implementation **MUST NOT** infer a peer's abilities from its version string. Abilities
are what `capabilities`, `features`, and `enabledOps` say they are. Version strings are for
logs and bug reports.

---

## 12. Changelog

| Revision | Wire version | Changes |
|---|---|---|
| 2026-07-26 | 1 | Initial draft. |
