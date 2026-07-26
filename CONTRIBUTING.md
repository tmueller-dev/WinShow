# Contributing

WinShow is in its design phase, so most contributions are changes to documents rather than to
code. The rules below exist because the documents in `docs/` are a **contract**: someone may
be implementing an agent against them in a language nobody here has looked at.

## Before you open a pull request

Run the validator. It is fast and it catches the mistakes that matter.

```sh
pip install jsonschema
python3 tools/validate-docs.py
```

It checks that every schema is a valid JSON Schema, that every message in every transcript
validates against the message schema, that event sequence numbers are gapless per correlation
and that `exec.exit` is last, that every example policy validates against the policy schema,
that the error codes and operation names in the prose match the schemas exactly, and that
every relative link resolves.

## Changing the wire protocol

[`docs/03-agent-protocol.md`](docs/03-agent-protocol.md) has its own version and its own
changelog, because people read it who read nothing else in this repository.

Any change to it must come as a set:

1. The prose in `03-agent-protocol.md`, including a changelog entry.
2. The corresponding JSON Schema in `docs/schemas/`.
3. At least one example in `docs/examples/`, so the change has a test vector.
4. The matching checklist items in [`docs/08-conformance.md`](docs/08-conformance.md).

A change to the prose alone will pass review only by accident, and will diverge from the
schema within a release.

### Minor versus major

Section 11.2 of the protocol document is normative. In short:

| Change | Bumps the wire version? |
|---|---|
| Adding an optional field, an operation, an error code, or an enum value | no |
| Making an optional field required, removing or renaming a field, changing a type or units, repurposing an error code | **yes** |

Because minor changes never bump the version, an older agent and a newer server must keep
interoperating, each ignoring what it does not understand. If your change would break that,
it is a major change, and it needs a new wire version rather than a footnote.

**Error codes are append-only.** A published code never changes meaning and is never removed.

## Changing the policy schema

The policy file is a security control. Two consequences:

- `additionalProperties: false` stays. A typo in a security control must be a load failure,
  not a silently ignored key — a rule that silently does not exist is worse than no rule.
- Every new key needs a documented default, and the default must be the **restrictive** one.
  An operator who omits a setting should end up with less access, never more.

If you add a key, update `docs/schemas/policy-v1.schema.json`,
[`docs/04-agent-policy.md`](docs/04-agent-policy.md), and at least one of the example
policies, so there is a worked instance of it.

## Adding a decision record

Significant choices get an ADR in `docs/adr/`, numbered sequentially, using the existing
format: Context, Decision, Consequences, and — where there was a real choice — Alternatives
considered.

An ADR is worth writing when someone six months from now would otherwise ask "why on earth
did they do it that way". It is not worth writing for a choice with an obvious default.

Do not rewrite an accepted ADR when the decision changes. Write a new one that supersedes it
and mark the old one superseded. The value of the record is the reasoning at the time,
including the reasoning that turned out to be wrong.

## Writing style

The documents are written to be read by an implementer who is not in the room, so:

- Complete sentences and prose that explains **why**, not just what. Avoid telegraphic
  fragments and arrow chains.
- RFC 2119 keywords in capitals **only** where genuinely normative. `MUST` in a paragraph of
  background reads as noise and dilutes the ones that matter.
- Tables for enumerable facts; the reasoning goes in the prose around them rather than crammed
  into cells.
- State a tradeoff in one line rather than listing options and leaving the reader to choose.
  A specification that will not decide is a specification that gets implemented two ways.
- Mermaid for diagrams, so they render on GitHub and stay in the file they describe.
- English throughout, including identifiers, commit messages, and comments in the example
  policies.

## Commit messages

One logical change per commit, present tense, and a body that says why when the subject cannot
carry it. `Add ackWindowBytes to the handshake` beats `update protocol`.
