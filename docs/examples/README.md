# Wire transcripts and example policies

These files are informative in the sense that they define no new rules, and normative in the
sense that a conforming implementation must be able to produce and consume them. They are
the test vectors for the Phase 2 conformance harness.

## Transcript format

Each `transcript-*.jsonl` file contains one WSAP/1 message per line, in the order the
messages appear on the wire.

- A line whose first two non-whitespace characters are `//` is an **annotation**, not a
  message. Tooling strips these lines before parsing.
- An annotation immediately preceding a message states the **direction** of that message,
  using `A→S` for agent to server and `S→A` for server to agent, followed by an explanation
  of what is happening and why.
- Blank lines are ignored.

Direction is also derivable from the rules in
[`../03-agent-protocol.md` §2.3](../03-agent-protocol.md#23-direction-rules) for every
message except `session.ping`, which may travel either way. The annotations remove that
ambiguity and carry the commentary.

## The transcripts

| File | What it demonstrates |
|---|---|
| [`transcript-happy-path.jsonl`](transcript-happy-path.jsonl) | Connect, handshake, heartbeat, list a directory, tail a log, run a command with streamed output to a clean exit |
| [`transcript-policy-denial.jsonl`](transcript-policy-denial.jsonl) | Both denial shapes: a path outside every read root, and a command matching a deny rule — including a stage-2 model review denial |
| [`transcript-cancel-timeout.jsonl`](transcript-cancel-timeout.jsonl) | Cancelling a running command, and a command hitting its timeout with partial output preserved |
| [`transcript-reconnect.jsonl`](transcript-reconnect.jsonl) | Heartbeat failure, reconnection as a fresh session, and eviction of a stale connection by a newer one |

## Example policies

| File | Posture |
|---|---|
| [`policy.minimal.toml`](policy.minimal.toml) | Read-only, one root, no execution. The safe starting point. |
| [`policy.developer.toml`](policy.developer.toml) | A realistic developer workstation: several roots, a small command allowlist, PowerShell diagnostics, stage-2 model review enabled |
| [`policy.locked-down.toml`](policy.locked-down.toml) | A single log directory, zero execution, denials disclosed as "not found" |

All three are validated against [`../schemas/policy-v1.schema.json`](../schemas/policy-v1.schema.json)
by `tools/validate-docs.py`.

## Validating these files yourself

```sh
python3 tools/validate-docs.py
```

The script checks that every transcript message validates against
`schemas/wsap-v1-messages.schema.json`, that event sequence numbers are gapless per
correlation, that `exec.exit` is the last event for its correlation, and that every example
policy validates against the policy schema.
