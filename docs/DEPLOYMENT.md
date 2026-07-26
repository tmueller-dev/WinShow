# Deployment

**Status:** Draft · **Revision:** 2026-07-26

How to run the WinShow server as a container. This covers the image, its configuration
surface, and what to check when it is up. It does **not** re-explain the reverse-proxy
settings or the Windows-side installation — those are in
[`07-operations.md`](07-operations.md) and are not repeated here, because a second copy
is a second thing to get out of date.

---

## 1. The image

Published to the GitHub Container Registry on every version tag:

```sh
docker pull ghcr.io/tmueller-dev/winshow:latest
```

Tags follow the git tag: `v1.2.3` publishes `1.2.3`, `1.2`, `1`, `latest`, and a
`sha-<commit>` tag. Pin to a full version in production; `latest` is for trying it out.

The image is `python:3.12-slim` carrying a virtual environment and nothing else. It runs
as an unprivileged account (uid 10001) with no shell and no home directory, because the
server needs no filesystem access of its own: its only durable state is the audit log,
which is either stdout or a volume you mount deliberately.

Both listeners are exposed:

| Port | Carries | Exposure |
|---|---|---|
| 8080 | `/mcp`, `/agent`, `/healthz`, `/readyz` | Public, behind TLS |
| 9090 | `/metrics` | **Admin only.** Never route this from the internet. |

---

## 2. Configuration

Everything is an environment variable prefixed `WINSHOW_`. The names below are the
complete set that matters operationally; the rest have defaults that are correct until
measurement says otherwise.

| Variable | Default | What it does |
|---|---|---|
| `WINSHOW_AGENT_TOKENS` | *(empty)* | Comma-separated bearer tokens the agent may present. **Two are valid at once**, which is what makes rotation a four-step procedure with no outage ([§4](07-operations.md#4-token-rotation-without-downtime)). |
| `WINSHOW_ALLOWED_AGENT_IDS` | *(empty)* | When set, `X-WinShow-Agent-Id` must appear here. Empty means any identifier. |
| `WINSHOW_ALLOWED_ORIGINS` | *(empty)* | Origins accepted on `/mcp`. Anything else gets **403**. Empty disables the check. |
| `WINSHOW_ALLOWED_HOSTS` | *(empty)* | When set, enables DNS-rebinding protection on the `Host` header. |
| `WINSHOW_WAIT_FOR_AGENT_MS` | `0` | Grace period for a call that arrives during a reconnection blip. `3000` is a good value on a flaky link; `0` fails fast. |
| `WINSHOW_ADMIN_HOST` / `_PORT` | `127.0.0.1` / `9090` | The metrics listener. |
| `WINSHOW_METRICS_ENABLED` | `true` | Set false to omit the admin listener entirely. |
| `WINSHOW_AUDIT_FILE` | *(unset)* | Path for the append-only audit trail. Unset sends audit records to the structured log, which is right for a container whose stdout is already collected. |
| `WINSHOW_LOG_LEVEL` / `_FORMAT` | `INFO` / `json` | `text` is easier to read at a console; `json` is what a log pipeline wants. |

Two of these have a failure mode worth stating plainly.

**An empty `WINSHOW_AGENT_TOKENS` means no agent can ever connect.** The server starts
and serves MCP regardless — that is NFR-15, and it is deliberate — so the symptom is a
green `/healthz`, a permanently red `/readyz`, and `401` in the access log. Generate one:

```sh
docker run --rm ghcr.io/tmueller-dev/winshow:latest --generate-token
```

The server refuses to start on a token shorter than 32 characters. Entropy is not
observable in a string, but length is, and a short token is the one part of the rule that
can be detected from here.

**An empty `WINSHOW_ALLOWED_ORIGINS` disables the origin check.** That is the correct
configuration when an authenticating reverse proxy validates it instead, and an open door
when nothing does — the check exists to stop a *browser* being used as a confused deputy
against a server the user's machine can reach ([`06-security.md` §6](06-security.md#6-mcp-side-security-requirements)).
The server logs a warning at startup when the list is empty, so an accidental omission is
visible rather than silent.

---

## 3. Running it

```sh
docker run -d --name winshow \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -e WINSHOW_AGENT_TOKENS="$(cat agent.token)" \
  -e WINSHOW_ALLOWED_ORIGINS="https://claude.ai" \
  -e WINSHOW_ADMIN_HOST=0.0.0.0 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/tmueller-dev/winshow:latest
```

`WINSHOW_ADMIN_HOST=0.0.0.0` looks alarming and is not, **provided** the port is
published to loopback as above. The default `127.0.0.1` means "inside this container
only", which makes the metrics unreachable even from a sibling container; binding all
interfaces and then publishing only to the host's loopback is how you scrape it without
putting it on the internet. Getting this backwards — `-p 9090:9090` — exposes the agent
identifier, the hostname and the denial counts to anyone who can reach the host.

[`docker-compose.yml`](../docker-compose.yml) in the repository root is the same thing
with the reasoning inline.

**Exactly one worker, always.** The image enforces it and it is not a tuning knob. The
agent holds a single WebSocket; with two workers that socket lands in one of them while
an MCP request may arrive in the other, where the bridge has no agent to route to. WinShow
is not horizontally scalable as designed, and the fix if that ever matters is an
agent-affinity layer in front, not more workers
([`02-architecture.md` §2.1](02-architecture.md#21-a-constraint-from-the-moving-specification)).

---

## 4. TLS

The container speaks plain HTTP. Terminate TLS in front of it — the two topologies and a
worked nginx configuration are in [`07-operations.md` §2](07-operations.md#2-tls).

Two of those settings are proxy **defaults** that are wrong for this workload, and they
are the reason most WinShow deployments fail on first contact:

- `/agent` needs the `Upgrade` and `Connection` headers passed through, or the WebSocket
  handshake never becomes a `101`.
- `/agent` needs a read timeout far above the 20-second heartbeat. nginx defaults to 60
  seconds, which closes a healthy connection roughly every minute. The symptom is a
  reconnect counter climbing in perfectly uniform steps.

---

## 5. Verifying a deployment

In this order, because each step rules out the layer below it:

```sh
curl -fsS http://localhost:8080/healthz   # the process is up
curl -sS  -o /dev/null -w '%{http_code}\n' http://localhost:8080/readyz
```

`/readyz` returning **503** with no agent connected is correct, not a fault. It is the
distinction the whole health split rests on: liveness answers "should this process be
restarted", readiness answers "can it currently do its job". Wire a process supervisor to
`/healthz` and a load balancer to `/readyz`, never the other way round. The image's own
`HEALTHCHECK` uses `/healthz` for exactly this reason — restarting the container because
a Windows machine rebooted would be precisely the wrong response.

Once the agent connects, `/readyz` turns 200 and names the session:

```json
{"status":"ready","agent_connected":true,"agent_id":"WS-PROD-01","session_id":"s-0f9d2a11"}
```

Then ask for something you expect to be **denied**, and confirm you get `POLICY_DENIED`
naming a rule. A policy nobody has tested a denial against is a policy nobody knows is
loaded.

---

## 6. Metrics

```sh
curl -s http://127.0.0.1:9090/metrics | grep winshow_
```

The four an operator acts on are in [`07-operations.md` §7.1](07-operations.md#71-metrics).
`winshow_policy_denials_total` is the one to alert on; `winshow_agent_connected` at 0 for
longer than the reconnect ceiling is a page.

Requesting `/metrics` on the public listener returns 404 with a pointer here, rather than
the data.

---

## 7. Licence obligations when you redistribute the image

WinShow is AGPL-3.0-or-later. Running the stock image imposes nothing on you. **Modifying
it and letting other people reach it over a network does**: §13 requires you to offer
those users the corresponding source of your modified version.

Every dependency's own licence text stays inside the image, which is what the MIT, BSD and
Apache-2.0 terms require of a redistributor. Confirm it for yourself:

```sh
docker run --rm --entrypoint sh ghcr.io/tmueller-dev/winshow:latest \
  -c 'find /opt/venv -path "*.dist-info*" -iname "LICENSE*" | sort'
```

CI asserts this on every build, so an image-slimming change that deletes those files fails
the pipeline rather than quietly breaking the obligation. The full list, with what each
licence asks of you, is in [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md).
