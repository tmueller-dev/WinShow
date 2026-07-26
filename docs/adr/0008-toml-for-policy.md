# ADR 0008: TOML for the agent policy file

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

The policy file is the whole of WinShow's authorization model. The agent is the sole
enforcement point ([ADR 0003](0003-authorization-on-agent-only.md)), and what it enforces is
whatever this file says. Nothing else grants access, and there is no override path in the
protocol.

That gives the format an unusual weight. This is not a configuration file where a mistake
produces a wrong setting; it is a file where a mistake produces either an outage or a hole.
Its content is also unusually hostile to some formats. It is dense with **Windows paths**,
which are full of backslashes, and dense with **anchored regular expressions**, which are full
of backslashes for a different reason. It has to be readable and reviewable by an operator who
may edit it once a quarter, under pressure, on a production host.

So the selection criteria were not the usual ones. Expressiveness barely mattered — the
schema is small and deliberately shallow. What mattered was: can a human write a Windows path
in it without thinking; can the file explain itself; and does it ever mean something other
than what it looks like it means.

## Decision

**TOML**, loaded from `%ProgramData%\WinShow\policy.toml` by default, validated against
[`../schemas/policy-v1.schema.json`](../schemas/policy-v1.schema.json).

**Unknown keys are a load failure, not a warning.** The schema sets
`additionalProperties: false` at every level.

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| TOML | Literal strings need no escaping, so a Windows path and a regular expression are written exactly as they are. Comments. Unambiguous scalars. Awkward for deep nesting, which the schema avoids. | **Chosen** |
| JSON | Universal and unambiguous, and every path becomes `"C:\\src"` and every regex doubles its backslashes. No comments at all, in a file that is a security control. | Rejected |
| YAML | Comments and readable nesting, at the price of significant whitespace and type inference. In a security file the inference is the problem: `no` becoming `false`, a version number becoming a float, an unquoted string with a colon splitting into a mapping. | Rejected |
| INI | Simple and Windows-native, with no agreed specification for lists, nesting, or types. Every implementation differs in exactly the places we would depend on. | Rejected |
| JSON with comments (JSONC), or a custom dialect | Fixes the comment problem and none of the escaping problem, and buys a format no standard tool validates. | Rejected |

## The decisive reason

The first reason on that list is the one that decided it, and it is worth being concrete
about.

In TOML, a single-quoted **literal string** performs no escape processing whatsoever. `'C:\src'`
is exactly that path. `'^[A-Za-z0-9_.-]{1,64}$'` is exactly that regular expression. What the
operator types is what the agent matches against.

In JSON, both of those double their backslashes: `"C:\\src"`, and a regex that was already
backslash-heavy becomes nearly unreadable. That is not merely ugly. **A policy full of doubled
backslashes is a policy people get wrong**, and the ways they get it wrong are not benign. A
path root written with one backslash too few silently fails to match and denies everything,
which at least announces itself. A deny pattern written with one backslash too few silently
fails to match and denies *nothing*, which does not. The format should not be adding a
transcription step between what the operator means and what the agent enforces, in a file
where a transcription error is a security defect.

The second reason is **comments**. A file that is a security control needs to explain itself:
why this root, why this deny glob, who asked for this command and when it can be removed. JSON
has no comments, and the workarounds — a sibling `"_comment"` key, or a stripping preprocessor
— are worse than the problem, particularly under `additionalProperties: false`.

The third is **unambiguous scalars**. YAML's type inference is convenient right up until a
value in a security file quietly changes type. TOML's scalars mean what they say.

The tradeoff is real: TOML is awkward for deeply nested structures. The schema is kept shallow
because of it — arrays of tables for `[[exec.allow]]` and `[[exec.deny]]`, a small number of
top-level tables, and no structure that would need three levels of inline nesting. That is no
loss. A deeply nested authorization policy is hard to review regardless of format, and being
pushed toward a flat one is a benefit disguised as a constraint.

## The single-quote gotcha

There is one TOML wrinkle that will bite whoever writes the first PowerShell rule, and it is
recorded here because we hit it: **a single-quoted TOML literal string has no escape for a
single quote.** The whole point of a literal string is that nothing inside it is special,
which includes the character that would end it.

That is fine for paths, which do not contain apostrophes. It is not fine for a PowerShell
`scriptPatterns` entry, because PowerShell quotes its own string arguments with single quotes,
so a pattern that matches a realistic command contains them. The answer is the multi-line
literal form:

```toml
scriptPatterns = [
  '''^Get-ChildItem\s+-Path\s+'[^']+'(\s+-Recurse)?$''',
]
```

This was found by `tools/validate-docs.py` while writing the example policies, not by
reasoning about it in advance — which is exactly the argument for having a validator run over
the documentation. It is documented in
[`../04-agent-policy.md` §2](../04-agent-policy.md#2-file-format-and-location) so that the next
person meets it as a known wrinkle rather than as a confusing parse error.

## Unknown keys are a load failure

A related decision, recorded here because it is a property of how the file is read rather than
of the format.

The schema sets `additionalProperties: false` at every level, and an unrecognised key stops
the policy from loading. This is deliberately stricter than ordinary configuration practice,
where an unknown key is usually ignored so that a file can be shared across versions.

The reason is that **in a security control, a silently ignored typo is a rule that silently
does not exist.** Consider `readRoot = [...]` written instead of `readRoots = [...]`. Under
lenient parsing, the agent loads successfully, reports a healthy policy at handshake, and
grants access to nothing — an outage whose cause is invisible, because the file plainly
contains the roots the operator intended. Now consider the same typo in a future revision
where the key names have shifted, and the misspelling happens to be a key that widens access.
The failure mode is no longer an outage.

Failing the load makes both cases loud. Combined with the fail-closed behaviour in
[`../04-agent-policy.md` §1.2](../04-agent-policy.md#12-fail-closed), the outcome is
well-defined: the agent still connects and completes the handshake reporting
`policy.state = "invalid"`, and refuses every operation with `POLICY_UNAVAILABLE` and the
parse error attached. The operator learns what is wrong through the same MCP client they were
already using, instead of staring at a host that has gone silent.

Hot reload is where this pays off most. A failed edit keeps the previous policy live, logs at
error level, and the agent keeps serving
([`../04-agent-policy.md` §2.2](../04-agent-policy.md#22-hot-reload)). A mistyped key can
therefore never widen access, and can never take a working host offline either.

## Consequences

### What this buys us

Operators write Windows paths and anchored regular expressions exactly as they are, with no
escaping layer between intent and enforcement. The file can carry the reasoning for its own
rules, which is what makes a quarterly review possible. Every value means what it appears to
mean. And a typo is a loud, immediate, well-described failure rather than a rule that quietly
evaporated.

Python's standard library has read TOML since 3.11 via `tomllib`, so the reference agent and
the documentation validator parse the policy with no dependency at all.

### What it costs us

Deep nesting is awkward, and the schema is shaped around that. `tomllib` reads but does not
write TOML, so any future tooling that generates or rewrites a policy needs a third-party
writer — acceptable, since a hand-edited, human-reviewed policy is the intended workflow and
a generated one would undercut the reviewability the format was chosen for. TOML is also less
ubiquitous than JSON in Windows administration circles, so some operators will meet it here
first; the example policies in [`../examples/`](../examples/README.md) exist partly to make
that first encounter a matter of editing rather than learning.

The strict-key decision has a cost of its own: adding a key to the schema is a breaking change
for any policy written against it, in the direction of failing to load. That is the right way
round for a security control, but it means schema evolution needs a deliberate migration
story rather than an assumption of tolerant readers.

### What we would have to change to reverse it

The parser and the example policies. The schema itself is format-independent — it describes a
data model, and JSON Schema validates whatever the loader produced — so switching to JSON or
YAML would not change what the rules mean, only how they are written. What would change is the
error surface: JSON would reintroduce the escaping problem the format was chosen to avoid, and
YAML would reintroduce type inference into a file where every value is load-bearing. Reversal
is cheap mechanically and expensive in exactly the property that motivated the decision.
