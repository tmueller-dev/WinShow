# Operations

**Status:** Draft · **Revision:** 2026-07-26

This document is for the person who has to run WinShow: deploying the server, getting TLS
right, installing the agent as a Windows service, rotating the token without downtime,
pointing an MCP client at it, and — mostly — working out what is wrong when something does
not connect. It assumes the design is settled and does not re-argue it; where a procedure
exists because of a security property, that property is stated in
[`06-security.md`](06-security.md) and the rules being enforced are in
[`04-agent-policy.md`](04-agent-policy.md).

RFC 2119 keywords are used as described in [`03-agent-protocol.md`](03-agent-protocol.md),
in capitals and only where the statement is genuinely normative.

---

## Table of contents

1. [Deploying the server](#1-deploying-the-server)
2. [TLS](#2-tls)
3. [Installing the agent on Windows](#3-installing-the-agent-on-windows)
4. [Token rotation without downtime](#4-token-rotation-without-downtime)
5. [Connecting an MCP client](#5-connecting-an-mcp-client)
6. [Troubleshooting](#6-troubleshooting)
7. [What to watch](#7-what-to-watch)

---

## 1. Deploying the server

The server is a single Python 3.12 process — one ASGI application under uvicorn — and it
should stay that way. It holds one WebSocket to one Windows agent and brokers MCP calls onto
it; there is no shared state worth clustering and no work worth distributing. A small Linux
VM or a container with 1 vCPU and 512 MiB is ample, and running exactly one process avoids
the failure mode that multiple workers would introduce, which is that the agent's connection
lands in worker 3 and the MCP request lands in worker 1.

Run it as an unprivileged user, on a port above 1024, with TLS terminated either by uvicorn
itself or by a reverse proxy (§2). Restart on failure — `Restart=always` under systemd, or the
container runtime's restart policy — because a crashed server means the agent is reconnecting
into nothing and the operator's first symptom is a red `/readyz` they cannot reach.

### 1.1 Endpoints

One ASGI application serves everything except metrics:

| Path | Methods | Purpose | Exposure |
|---|---|---|---|
| `/mcp` | `POST`, `GET`, `DELETE` | MCP Streamable HTTP. `POST` carries JSON-RPC requests and may return an SSE stream; `GET` opens the server-to-client SSE stream; `DELETE` terminates a session. | Public, authenticated |
| `/agent` | `GET` with a WebSocket upgrade | The WSAP/1 endpoint the Windows agent dials out to. Subprotocol `winshow.v1`, bearer token in the `Authorization` header. | Public, authenticated |
| `/healthz` | `GET` | Liveness. Green whenever the process is running and its event loop is responsive. It says nothing about the agent. | Public or internal |
| `/readyz` | `GET` | Readiness. Green **only** when an agent is connected and has completed a successful `session.hello` exchange. | Public or internal |
| `/metrics` | `GET` | Prometheus exposition. Bound to a **separate admin address**, never routed through the public listener. | Admin only |

The distinction between `/healthz` and `/readyz` is the one that earns its keep. Liveness
answers "should this process be restarted", and restarting the server because the Windows
host rebooted would be exactly wrong. Readiness answers "can this server currently do its
job", which is false — correctly — from the moment the agent drops until the moment it
completes a new handshake. Wire a load balancer to `/readyz` and a process supervisor to
`/healthz`, never the other way round.

`/readyz` deliberately does **not** consider policy state. An agent whose `policy.toml` is
broken still connects and still completes the handshake, reporting `policy.state = "invalid"`
and refusing every operation with `POLICY_UNAVAILABLE`
([`04-agent-policy.md` §1.2](04-agent-policy.md#12-fail-closed)). That is a working
connection carrying a legible error, and it is far more useful than a red readiness probe
that looks identical to a dead machine.

`/metrics` binds a separate address — `127.0.0.1:9090` by default, or a management interface —
because the metric set names the agent, the host, and the denial counts, and none of that
belongs on the internet. This is also the endpoint for which the MCP specification's advice to
bind loopback applies most directly.

### 1.2 Configuration

Configuration is environment variables and a small file; the values that matter operationally
are the listen address and port, the admin bind address for `/metrics`, the set of valid agent
tokens, the allowed `Origin` values, and — behind a proxy — `--proxy-headers` with
`--forwarded-allow-ips`. The server **MUST** validate the `Origin` header on `/mcp` and return
`403` when it is not one of the configured values; the reasoning is in
[`06-security.md` §6](06-security.md#6-mcp-side-security-requirements).

---

## 2. TLS

There are two topologies, and the right one depends on whether anything else already fronts
traffic on that host.

### 2.1 Topology A — uvicorn terminates TLS

The simplest deployment that is not wrong. Point uvicorn at a certificate and key and give it
the port:

```
uvicorn winshow.app:app \
  --host 0.0.0.0 --port 443 \
  --ssl-certfile /etc/winshow/tls/fullchain.pem \
  --ssl-keyfile  /etc/winshow/tls/privkey.pem \
  --timeout-keep-alive 75 \
  --workers 1
```

Nothing sits between the agent and the server, so there is no proxy to misconfigure, no
buffering to disable, and no header-forwarding to get right. The cost is that certificate
renewal has to restart or signal the process, and that uvicorn is doing a job that a dedicated
proxy does better — no request-level rate limiting, no authenticating layer for `/mcp`, no
static-file or multi-site hosting. Choose this for a single-purpose VM.

### 2.2 Topology B — behind nginx, Caddy, or Traefik

The right choice when the deployment needs an authenticating layer in front of `/mcp`
([`06-security.md` §6](06-security.md#6-mcp-side-security-requirements)), or when the host
already terminates TLS for something else. It is also where WinShow deployments most often
break, because two of the required settings are proxy defaults that are wrong for this
workload.

**Checklist — every item is load-bearing:**

- **Pass `Upgrade` and `Connection` on `/agent`.** Without them the WebSocket handshake never
  becomes a `101` and the agent sees a plain HTTP response. This is the first thing to check
  when an agent will not connect through a proxy.
- **Set `proxy_read_timeout` and `proxy_send_timeout` far above the heartbeat interval.** The
  server pings every **20 seconds** (`heartbeatIntervalMs: 20000`), and nginx's default read
  timeout is 60 seconds. A WSAP connection that is idle between heartbeats is a connection the
  proxy will close on schedule. Use **3600s** — a wide margin, not a tight one, because the
  interval is negotiated and a future deployment may lengthen it.
- **Turn `proxy_buffering off` on `/mcp`.** MCP Streamable HTTP returns SSE, and a buffering
  proxy holds the stream until the response completes or the buffer fills. The visible symptom
  is that everything works but nothing streams: the client sees a long silence and then all the
  output at once. Set `proxy_cache off` alongside it.
- **Forward `X-Forwarded-For` and `X-Forwarded-Proto`.** Without them every request appears to
  originate from the proxy, which destroys the rate limiter's ability to distinguish sources
  and makes the access log useless during an incident.
- **Do not rewrite `Origin`.** The server validates it and returns `403` on a mismatch. A proxy
  that helpfully sets `Origin` to its own hostname either breaks every legitimate client or
  defeats the check entirely, depending on which value it picks. Leave it alone.
- **Run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy ip>`.** Uvicorn ignores
  forwarded headers unless told to trust them, and it **MUST** be told to trust only the
  proxy's address. `--forwarded-allow-ips='*'` on a listener anything else can reach lets a
  caller forge its own source address.
- **Set `client_max_body_size` above the negotiated frame size.** 1 MiB is the WSAP default and
  8 MiB the ceiling; nginx's 1 MiB default will reject the larger `/mcp` bodies at exactly the
  wrong moment.

**Worked nginx configuration:**

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    http2  on;
    server_name winshow.example.com;

    ssl_certificate     /etc/letsencrypt/live/winshow.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/winshow.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 16m;

    # ---- the agent's reverse WebSocket -------------------------------------
    location /agent {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Without these two the upgrade never happens.
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # The heartbeat is every 20 s. 60 s (the nginx default) kills the socket
        # roughly every minute; 3600 s leaves a wide margin.
        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
        proxy_buffering     off;
    }

    # ---- MCP Streamable HTTP ------------------------------------------------
    location /mcp {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # SSE: buffering here breaks streaming without breaking anything else,
        # which is why it is so often diagnosed late.
        proxy_buffering    off;
        proxy_cache        off;
        proxy_set_header   Connection '';
        chunked_transfer_encoding off;

        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Origin is passed through untouched: the server validates it.

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location = /healthz { proxy_pass http://127.0.0.1:8080; }
    location = /readyz  { proxy_pass http://127.0.0.1:8080; }

    # /metrics is NOT proxied here. It binds a separate admin address.
}
```

And the corresponding uvicorn invocation:

```
uvicorn winshow.app:app \
  --host 127.0.0.1 --port 8080 \
  --proxy-headers --forwarded-allow-ips=127.0.0.1 \
  --workers 1
```

Caddy and Traefik handle the upgrade and streaming correctly by default, which removes two of
the six ways to get this wrong; the timeout and the forwarded-headers items still apply.

### 2.3 The agent's side of TLS

The agent verifies the full chain and the hostname, with three trust modes — `system`,
`ca-bundle`, and `pin` — configured in `[connection]`
([`03-agent-protocol.md` §1.5](03-agent-protocol.md#15-certificate-validation)). Use
`ca-bundle` with an explicit PEM for a private CA rather than importing into the Windows store,
because an explicit file is a decision that is visible in the policy; use `pin` where the
certificate lifecycle is under your control, and configure **at least two** SPKI pins so that
a renewal does not brick the agent. A corporate TLS-intercepting proxy is accepted only when
its CA is in the configured bundle — deliberately, never by accident.

---

## 3. Installing the agent on Windows

### 3.1 Create a low-privilege service account

The agent **MUST NOT** run as `LocalSystem`. `LocalSystem` is the highest-privilege local
principal, so a defect in the agent would own the machine, and the ACLs that form the second
enforcement layer beneath the policy would be meaningless because that account can read
everything anyway.

Use a **virtual service account**, `NT SERVICE\WinShowAgent`. Windows creates it implicitly
when the service is registered with that identity: it has no password to manage or leak, it
gets a per-service SID that can be named directly in ACLs, and it is confined to session 0 with
no interactive desktop. In a domain, a group-managed service account is the equivalent choice
when the agent needs network credentials for UNC roots.

Reduce its privileges to the minimum the agent needs:

```
sc.exe privs WinShowAgent SeChangeNotifyPrivilege
```

### 3.2 File layout and ACLs

Everything lives under `%ProgramData%\WinShow\`:

| Path | Contents | ACL |
|---|---|---|
| `C:\ProgramData\WinShow\` | Root directory | Administrators + SYSTEM Full; `NT SERVICE\WinShowAgent` Read/Execute |
| `C:\ProgramData\WinShow\policy.toml` | The policy — the only authorization surface | Administrators + SYSTEM Full; `NT SERVICE\WinShowAgent` **Read** |
| `C:\ProgramData\WinShow\agent.token` | The bearer token, one line, no trailing newline required | Administrators + SYSTEM Full; `NT SERVICE\WinShowAgent` **Read** |
| `C:\ProgramData\WinShow\corp-ca.pem` | CA bundle, when `tlsTrust = "ca-bundle"` | Same as `policy.toml` |
| `C:\ProgramData\WinShow\logs\` | `agent.jsonl`, `audit.jsonl` | Administrators + SYSTEM Full; `NT SERVICE\WinShowAgent` Modify |
| `C:\Program Files\WinShow\` | The agent binary or Python distribution | Administrators + SYSTEM Full; `NT SERVICE\WinShowAgent` Read/Execute |

The service account gets **Read** on the policy and **never Write**. A policy that the agent's
own account can rewrite is not a control, and the agent **SHOULD** warn at load if it finds the
file writable by a non-administrative principal. The same reasoning applies to
`executableSearchPath` directories and to every allowlisted executable: if the service account
can write them, the allowlist can be redirected to something else with the same name.

```powershell
New-Item -ItemType Directory -Path 'C:\ProgramData\WinShow\logs' -Force

# Break inheritance, then grant explicitly.
icacls 'C:\ProgramData\WinShow' /inheritance:r
icacls 'C:\ProgramData\WinShow' /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F'
icacls 'C:\ProgramData\WinShow' /grant 'NT SERVICE\WinShowAgent:(OI)(CI)RX'
icacls 'C:\ProgramData\WinShow\logs' /grant 'NT SERVICE\WinShowAgent:(OI)(CI)M'

# Token and policy: read only, and only for the service account.
icacls 'C:\ProgramData\WinShow\agent.token' /inheritance:r
icacls 'C:\ProgramData\WinShow\agent.token' /grant 'Administrators:F' 'SYSTEM:F' 'NT SERVICE\WinShowAgent:R'
icacls 'C:\ProgramData\WinShow\policy.toml' /inheritance:r
icacls 'C:\ProgramData\WinShow\policy.toml' /grant 'Administrators:F' 'SYSTEM:F' 'NT SERVICE\WinShowAgent:R'
```

Grant the service account read access to each configured read root as well. Windows ACLs are
the layer beneath the policy: a root the policy allows but the account cannot open returns
`ACCESS_DENIED`, and that is a different problem with a different fix from `POLICY_DENIED`
([`04-agent-policy.md` §8.1](04-agent-policy.md#81-policy_denied-is-not-access_denied)).

### 3.3 Write the token file

Generate the token on the server, where it is going into the valid-token set anyway:

```
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Transfer it out of band, write it to `agent.token`, and apply the ACL above. It **MUST NOT**
be inlined in `policy.toml`, pasted into a command line that lands in shell history, or put in
a query string. The policy references it by path:

```toml
[connection]
serverUrl = "wss://winshow.example.com/agent"
agentId   = "WS-PROD-01"
tokenFile = 'C:\ProgramData\WinShow\agent.token'
```

The full worked configuration is [`examples/policy.developer.toml`](examples/policy.developer.toml);
start instead from [`examples/policy.minimal.toml`](examples/policy.minimal.toml) — one read
root, no execution — and widen it deliberately, in the order given in
[`04-agent-policy.md` §10](04-agent-policy.md#10-writing-a-policy-a-suggested-order).

### 3.4 Register the service

Register with the virtual service account as the identity, automatic delayed start, and
automatic restart on failure:

```
sc.exe create WinShowAgent ^
   binPath= "\"C:\Program Files\WinShow\winshow-agent.exe\" --service" ^
   DisplayName= "WinShow Agent" ^
   start= delayed-auto ^
   obj= "NT SERVICE\WinShowAgent"

sc.exe description WinShowAgent "Brokers policy-gated file inspection and command execution for WinShow."
sc.exe failure WinShowAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000
sc.exe failureflag WinShowAgent 1
sc.exe privs WinShowAgent SeChangeNotifyPrivilege
sc.exe start WinShowAgent
```

`failureflag 1` matters: without it, Windows applies the recovery actions only when the service
terminates abnormally, and a clean exit after an unrecoverable error would leave the agent
stopped indefinitely. The escalating delays give a transient network problem time to clear
without hammering the server, and the agent's own reconnect backoff — `reconnectMinMs` to
`reconnectMaxMs`, one second to sixty in the example policy — handles the far more common case
where the process stays up and only the connection drops.

Delayed automatic start avoids a boot-time race in which the agent dials out before the
network stack and the certificate store are ready. It costs a minute or two after a reboot and
saves a first-connection failure that looks like a configuration error.

### 3.5 Packaging the Python agent

The reference agent is Python, and there are two sane ways to install it on a Windows host:

- **PyInstaller one-file executable, hosted by [WinSW](https://github.com/winsw/winsw) or
  [NSSM](https://nssm.cc/).** The service manager owns the process lifecycle, restarts, and
  stdout redirection; the executable is a single artifact to sign, copy, and version. This is
  the recommended path.
- **A `pywin32` service host** (`win32serviceutil.ServiceFramework`), registering the Python
  interpreter directly as the service. Fewer moving parts at build time, but the host then
  needs a managed Python installation and the service's identity is tied to that interpreter.

**The honest tradeoff:** a Python runtime on a locked-down Windows host is heavier than a
self-contained native binary — a larger install footprint, an interpreter and its dependency
tree for the security team to inventory, more surface for supply-chain review, and a slower
start. That cost is accepted deliberately, because the Python agent is what makes the stage-2
local model review practical: the inference client, the tokenisation, and the prompt handling
are a few lines against an existing ecosystem, and rewriting that in a language chosen only for
distribution size would trade a real capability for a smaller file. If a deployment does not
want stage 2, `[modelReview] enabled = false` is a perfectly reasonable configuration and the
argument for Python weakens accordingly.

Whichever packaging is used, build the artifact on a machine you control, pin every dependency
version, and sign the executable — the agent is the enforcement point, and replacing it is the
most direct attack on the whole design.

### 3.6 First-run verification

Run interactively before installing the service. The agent **MUST** provide a `--console` mode
that runs as the invoking user and logs `RUNNING INTERACTIVELY AS <user>` at startup, precisely
so that this check is unambiguous:

```
"C:\Program Files\WinShow\winshow-agent.exe" --console
```

Confirm three things in order: that the handshake completes and the server's `/readyz` goes
green; that the policy summary in the log reports `state: "ok"` with the read roots you
expected; and that `policyHash` matches the file you think is live. Then stop it, start the
service, and confirm the same three things again — because the interactive run and the service
run have different identities, different environments, and different views of the filesystem
(§6, "works by hand but not as a service").

---

## 4. Token rotation without downtime

The server **MUST** support two simultaneously valid tokens
([`03-agent-protocol.md` §1.4](03-agent-protocol.md#14-authentication)), and that single rule
is what turns rotation from a coordinated outage into a four-step procedure with no window in
which nothing works.

1. **Generate** a new token: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.
2. **Add** it to the server's valid set *alongside* the current one, and reload the server. Both
   tokens now authenticate. Nothing has changed from the agent's point of view.
3. **Install** the new token on the Windows host — overwrite `agent.token`, re-apply the ACL if
   the editor recreated the file — and restart the agent service. It reconnects with the new
   token. Confirm the new session in the server log and confirm `/readyz` is green; the
   reconnect will show as a step in `winshow_agent_reconnects_total`.
4. **Remove** the old token from the server's set and reload. Rotation is complete.

Do not skip step 2 and swap both at once: that reintroduces the outage the two-token rule
exists to prevent, and it fails in the direction where the agent is reconnecting into `401`s
while you are still editing the server configuration.

Rotate on a schedule, and immediately on any suspicion of exposure — a token pasted into a
ticket, a host being decommissioned, an operator leaving. Rotation is deliberately cheap so
that there is never a reason to defer it. The MCP client's own credential rotates
independently and on its own schedule; the two are unrelated secrets.

---

## 5. Connecting an MCP client

The server speaks MCP Streamable HTTP at `https://<host>/mcp`. A client is configured with
that URL and whatever credential the authenticating layer in front of it expects — in Phase 2,
a static bearer token presented as `Authorization: Bearer <token>`, verified by the reverse
proxy ([`06-security.md` §6](06-security.md#6-mcp-side-security-requirements)).

For Claude Code, add it as a remote MCP server:

```
claude mcp add --transport http winshow https://winshow.example.com/mcp \
  --header "Authorization: Bearer <client-token>"
```

Other clients take the same two values in whatever form their configuration uses. The tool
surface the client will see is documented in [`05-mcp-tool-surface.md`](05-mcp-tool-surface.md).

Verify in this order, because each step rules out the layer below it:

1. `curl -fsS https://winshow.example.com/healthz` — the process is up and reachable.
2. `curl -fsS https://winshow.example.com/readyz` — the agent is connected and has completed
   `session.hello`. If this is red, the problem is between the server and Windows, and no
   amount of client configuration will help.
3. From the client, list tools. If this fails while `/healthz` succeeds, the problem is
   authentication or `Origin` validation, and the server's access log will say which.
4. Ask for something you expect to be **denied**, and confirm you get `POLICY_DENIED` naming a
   rule. A policy nobody has tested a denial against is a policy nobody knows is loaded.

Because the agent reports a policy summary at handshake — the read roots, the execution mode,
the allowed command ids — a well-behaved client can tell the model what is possible before it
tries. That is the difference between an assistant that proposes something workable and one
that spends three turns guessing.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **The agent never connects.** No session in the server log, `/readyz` red. | Wrong or stale token; the server rejects before the upgrade with `401`. Or TLS: the server's chain is not trusted by the agent's configured trust mode. Or a proxy the agent must use to reach the internet is not configured. | Check the server's access log for `401` on `/agent` — that is a token problem, and the token file's contents are the thing to compare, not the file's presence. For TLS, run the agent with `--console` and read the verification error; a private CA needs `tlsTrust = "ca-bundle"` with `caBundle` pointing at the PEM. For a proxy, set `[connection] proxy` explicitly rather than relying on `"system"`, and check `noProxy`. |
| **The agent connects, then drops every ~60 seconds, forever.** Reconnect counter climbing steadily, sessions of suspiciously uniform length. | A reverse proxy is closing the idle WebSocket. The heartbeat is every 20 s and nginx's default `proxy_read_timeout` is 60 s. | Set `proxy_read_timeout 3600s` and `proxy_send_timeout 3600s` on the `/agent` location (§2.2). If the drop interval matches a round number of seconds, a middlebox timeout is almost always the cause — look at every hop, not only the proxy you configured. |
| **`/readyz` is red but `/healthz` is green.** | No agent is connected: the Windows service is stopped, the host is off, or the agent is stuck in reconnect backoff. | Check the service state on the Windows host and read `agent.jsonl`. Backoff runs up to `reconnectMaxMs` (60 s in the example policy), so allow a minute before concluding it is not trying. If the service is running and the log shows repeated handshake failures, treat it as the row above or the row above that. |
| **Every operation returns `POLICY_UNAVAILABLE`.** The agent is connected and the handshake reports `policy.state = "invalid"`. | `policy.toml` is missing, unparseable, or fails schema validation — very often an unknown key, since unknown keys are a load failure rather than a warning, or an unanchored allow pattern, which is rejected at load. | Read the parse error in `agent.jsonl`; it names the file and the location. Fix and save — the agent hot-reloads. **Note that the agent connects anyway precisely so you can see this**: a broken policy produces a legible error through the MCP client you were already using, rather than a silent absence indistinguishable from a dead machine. |
| **Everything returns `POLICY_DENIED`.** Denials name a rule, and `winshow_policy_denials_total` is climbing. | The path is outside every `readRoots` entry, or a `denyGlobs` pattern matches it, or the command matches no allow rule. A frequent subtlety: the path resolves through a junction or an 8.3 short name to somewhere outside the roots, because policy is evaluated against the **OS-final** path. | Compare the requested path against `readRoots` component-wise — `C:\src2` is not inside `C:\src`. Check `denyGlobs` for something broad like `'C:\Users\**'`. The denial's `details.allowedSummary` lists what *is* permitted, which is usually faster than re-reading the file. |
| **`ACCESS_DENIED`, not `POLICY_DENIED`.** WinShow permitted it; Windows refused. | The service account lacks an ACL on the target, or the file is locked, or a UNC share does not grant the machine account access. This is a different problem with a different fix, which is exactly why the two codes are kept distinct. | Grant `NT SERVICE\WinShowAgent` read access with `icacls` on the specific path. For UNC roots, remember that the service account's network identity is the machine account in a domain, not the operator's — the share must permit it. `winError`/`winErrorName` on the error name the underlying Win32 failure. |
| **"It works when I run it by hand, but not as a service."** | Session 0. The service has no mapped drive letters, a different `%USERPROFILE%` (`C:\Windows\ServiceProfiles\WinShowAgent`), a correspondingly different `%TEMP%`, no access to the interactive user's `HKCU`, and no desktop. | Express network roots in **UNC** form — `\\fileserver\share\reports` — never as `Z:\`; the agent **MUST NOT** try to resolve mapped drives. If a command depends on `%TEMP%` or a per-user profile, set it explicitly through `env` and the policy's `envAllow`, or use `envMode = "clean"` with an explicit `envBase` so the environment is the same in both contexts. |
| **Mojibake in command output** — box characters, `Ã©`, or a stream of `?`. | The output code page does not match `outputEncoding`. Console tools write in the OEM code page (CP 850, CP 437), modern tooling writes UTF-8, and Windows PowerShell 5.1 writes UTF-16LE to a redirected pipe under some configurations. | Set `outputEncoding` to what the tool actually emits — `"oem"` resolves at runtime via `GetOEMCP`. The agent already prepends `[Console]::OutputEncoding` and `$OutputEncoding` assignments for `powershell`/`pwsh` and arranges `chcp 65001` for `cmd`. A non-zero `decodeErrors` in the response is the signal that the guess was wrong. Genuinely binary output should use `outputEncoding: "binary"`. |
| **A command hangs and only ever on verbose failures.** No `exec.output` after a point; the run ends at `maxExecMillis` with `exitReason: "timeout"`. | Classic stderr pipe deadlock: the agent is reading stdout to completion before touching stderr, the child fills the 64 KiB stderr buffer, and both sides block. It only shows up when the child is chatty on stderr, which is when something has gone wrong. | The agent **MUST** read both streams concurrently ([`03-agent-protocol.md` §10.9](03-agent-protocol.md#109-standard-stream-plumbing)) and SHOULD raise the pipe buffer to 1 MiB. If this reproduces against the reference agent it is a conformance bug — file it. As an operational workaround, `mergeStderr: true` puts everything on one stream. |
| **The MCP client sees no streaming.** Long silence, then all output at once. | Reverse proxy buffering on `/mcp` holding the SSE stream. | `proxy_buffering off;` and `proxy_cache off;` on the `/mcp` location (§2.2). If the proxy is Cloudflare or a similar CDN, disable buffering and compression for that path as well. Confirm with `curl -N` against `/mcp` directly and then through the proxy — the difference localises it immediately. |
| **`AGENT_BUSY` under load.** | `maxConcurrentRequests` (16) or `maxConcurrentProcesses` (4) reached. The agent refuses rather than queueing, deliberately. | Raise the limits in `[limits]` if the host can genuinely take it, but treat a persistent `AGENT_BUSY` as a signal that something is issuing far more work than a single Windows host should be asked to do. The code is `retryable: true`, so a well-behaved server backs off and retries a bounded number of times. |
| **`exitReason: "backpressure"`, output truncated.** | A command emitted output faster than the server consumed it; the credit window stayed full for `sendStallTimeoutMs` (30 s) and the agent killed the process tree. | Usually a command that should be writing to a file rather than to the console. Redirect the output and read the file with `fs.read`, or narrow the command. Raising `ackWindowBytes` treats the symptom. |

---

## 7. What to watch

### 7.1 Metrics

Exposed on the admin `/metrics` bind address:

| Metric | Type | What it tells you |
|---|---|---|
| `winshow_agent_connected` | gauge, 0 or 1 | Whether an agent is connected and past `session.hello`. It is the same condition `/readyz` reports, in a form you can graph and alert on. |
| `winshow_policy_denials_total{op,rule}` | counter | Policy denials, labelled by operation and deciding rule. **This is the one to alert on.** |
| `winshow_request_duration_seconds{op}` | histogram | End-to-end duration per operation, from the MCP call to the agent's response. |
| `winshow_agent_reconnects_total` | counter | Agent connection establishments. The derivative is what matters, not the value. |

These four are the ones an operator acts on; the full exposed set, including RTT, saturation,
streamed bytes, and truncations, is listed in
[`02-architecture.md` §9.3](02-architecture.md#93-metrics).

`winshow_policy_denials_total` earns the alert because it is the only metric whose rise has two
readings and both are worth waking up for. A steady trickle is a model learning the shape of
the policy and is normal. A sustained rise is either a policy that no longer matches what
people legitimately need — in which case someone is being blocked from doing their job and
nobody has said so — or something probing systematically for a gap. The two look identical in
the counter and completely different in the audit records behind it, so alert on the rate and
then read `audit.jsonl`.

`winshow_agent_reconnects_total` is the second most useful. A flat line is healthy; a step
every sixty seconds is a proxy timeout (§6); a burst with no corresponding restart on the
Windows host suggests two agents evicting each other, which under newest-agent-wins means
either a duplicate deployment or a stolen token
([`06-security.md` §3.1](06-security.md#31-credentials-and-transport)).

`winshow_agent_connected` at 0 for longer than the reconnect ceiling is a page. Below that it
is noise, because a sixty-second reconnect is the system working as designed.

`winshow_request_duration_seconds` is for capacity and for noticing that the stage-2 reviewer
has become the slowest thing in the path. A review costing eight seconds on every `exec.start`
is the sort of thing that gets stage 2 disabled by someone in a hurry; a per-rule
`modelReview = false` on the high-frequency, obviously-safe commands is the better answer.

### 7.2 Logs and audit files

| Side | File | Contents |
|---|---|---|
| Server | stdout/journal | Structured server log: MCP requests, agent sessions, evictions, timeouts. |
| Server | server-side audit | What each MCP client asked for and what was returned. |
| Windows | `C:\ProgramData\WinShow\logs\agent.jsonl` | The agent's operational log at `logging.level`: connection lifecycle, policy load and reload results, decode warnings. |
| Windows | `C:\ProgramData\WinShow\logs\audit.jsonl` | Append-only audit trail: every policy decision, every execution before and after, every denial with its true reason. |
| Windows | Windows Event Log | Execution audit records mirrored when `logging.eventLog = true`, so they reach the organisation's SIEM. |

Read the agent's copy first when the question is "what actually happened". It is written by
the process that made the decisions, on the machine the requests ran against, and it survives
a compromised server ([`06-security.md` §8](06-security.md#8-the-audit-trail-as-a-security-control)).
The server's log is the right place to answer "what was asked", including everything that was
asked and refused.

Records on both sides carry the WSAP correlation id, and the envelope carries an optional W3C
`traceparent`, so a single tool call can be followed from the client through the server to the
agent's decision and the process it started. When investigating anything, start from the
correlation id rather than from a timestamp — clocks differ, and the handshake exchanges
`serverTime` and the agent's `clock` block precisely so that the skew is measurable rather than
mysterious.

Rotation is bounded by `logging.maxFileBytes` and `logging.maxFiles` (32 MiB × 10 in the
developer example). Size those against how long an investigation might reasonably start after
the event, and remember that a chatty attacker can roll records out of the window — which is
the operational argument for the Event Log mirror, not merely a compliance one.
