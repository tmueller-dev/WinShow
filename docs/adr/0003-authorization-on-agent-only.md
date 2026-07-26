# ADR 0003: Authorization is enforced on the agent, and only on the agent

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

This is the central security decision in WinShow, and every other decision defers to it.

The system has two components with very different exposure. The MCP server is reachable from
the internet, it is driven by an MCP client, and that client is driven by a language model
acting on instructions that may include text it read from a file, a log, or a web page a
moment earlier. It is, by construction, the component most likely to be talked into asking
for something it should not. The Windows agent is the opposite: it accepts no inbound
connections, it runs as a service account on a machine the operator controls, and its
configuration is a file that only administrators can write.

Somewhere between those two components there has to be a line where a request is checked
against what the operator actually permitted. The question is which side of the socket that
line sits on. It is tempting to put it on the server, because that is where the request first
appears and where a fast rejection would produce the nicest error message. It is also the
side we control most directly, which makes it the side that feels natural to defend.

That instinct is wrong here, and the reason is that the server is not the machine at risk.
A compromised server can be rebuilt from a container image. A compromised Windows host is
somebody's production machine.

## Decision

**The agent is the sole enforcement point.**

The MCP server performs no authorization. It does not filter paths, does not inspect argument
vectors, does not consult an allowlist, and does not decide what may run. It forwards what it
was asked to forward and relays the answer.

Correspondingly, **the agent accepts no authorization input from the server**. There is no
protocol field, no header, no capability, and no flag that relaxes a rule in the policy file.
An agent implementer who finds themselves adding a "trusted request" path has misread the
design. This is stated normatively in
[`../04-agent-policy.md` §1.1](../04-agent-policy.md#11-the-agent-is-the-sole-enforcement-point),
and the schema in [`../schemas/policy-v1.schema.json`](../schemas/policy-v1.schema.json) has
no field that could express such a relaxation.

The rules themselves live in one place: a TOML file on the Windows host, described in
[`../04-agent-policy.md`](../04-agent-policy.md) and chosen for that role in
[ADR 0008](0008-toml-for-policy.md). The threat model this decision answers is set out in
[`../06-security.md`](../06-security.md).

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| Enforce on the agent only | The machine bearing the risk holds the control. A compromised server gets exactly what the operator wrote down and nothing else. The cost is that the server cannot pre-validate. | **Chosen** |
| Enforce on the server only | Puts the rule set on the internet-facing, model-driven component. An attacker who reaches the server reaches the rules, and the Windows host will faithfully execute whatever arrives. It also means the operator's security posture depends on a component they do not run. | Rejected |
| Enforce on both, as defence in depth | Superficially the safest answer and actually the most dangerous. Two rule sets drift, and the moment they disagree nobody can say which one is authoritative. Worse, it creates the illusion that the server's copy is load-bearing, so a gap in the agent's copy stops being urgent. Defence in depth means independent layers, not the same check written twice. | Rejected |
| Enforce in the MCP client | The client is the least trustworthy participant: it is the one directly steered by model output, and it is often software the operator did not write. A control the attacker's own tooling implements is not a control. | Rejected |

## The layer that genuinely is defence in depth

Rejecting duplicated rules is not the same as rejecting a second layer. There is a real one,
and it sits **beneath** the policy rather than beside it: the operating system's own access
control on the agent's service account.

The default deployment described in
[`../03-agent-protocol.md` §10.8](../03-agent-protocol.md#108-security-context) runs the
agent as a **virtual service account** (`NT SERVICE\WinShowAgent`), not as `LocalSystem`,
with `RequiredPrivileges` reduced to `SeChangeNotifyPrivilege`. A virtual service account
gets a per-service SID, which means the operator can grant NTFS ACLs on exactly the
directories the policy names and nothing else.

The reason this counts as a genuine second layer, where a duplicated rule set does not, is
that it is enforced by a different mechanism, written in a different place, by a different
process, and it fails independently. If the policy engine has a bug — a containment check
implemented with `startsWith`, a junction that was not resolved to its OS-final path — the
agent will attempt an operation the operator did not intend, and the kernel will refuse it
with `ERROR_ACCESS_DENIED`. The policy did not stop it; the ACL did. That is what a second
layer is for.

It is also why the protocol keeps `POLICY_DENIED` and `ACCESS_DENIED` as distinct error
codes rather than collapsing them into one refusal
([`../04-agent-policy.md` §8.1](../04-agent-policy.md#81-policy_denied-is-not-access_denied)).
They come from different layers and they have different fixes: one is an edit to
`policy.toml`, the other is an `icacls` change. An agent that reports both as the same code
makes both unactionable and hides the fact that the second layer just did its job.

## Consequences

### What this buys us

The operator's guarantee is simple enough to state in one sentence and verify by reading one
file: nothing runs on the Windows host except what `policy.toml` permits. That guarantee
survives a compromised server, a compromised MCP client, and a model that has been
prompt-injected into asking for anything at all. The worst outcome from the entire upstream
chain being hostile is that it exercises the permitted operations, which is exactly the risk
the operator accepted when they wrote the file.

It also keeps the server simple in a way that matters for review. A server with no
authorization logic has no authorization bugs, and the security review of the server reduces
to transport, authentication, and not leaking things — none of which requires understanding
Windows path semantics.

The same reasoning explains why the agent sends only a policy **summary** at handshake and
never the full policy
([`../04-agent-policy.md` §7](../04-agent-policy.md#7-the-policy-summary-reported-at-handshake)):
the server is untrusted, and the exact rule set is useful to an attacker probing for gaps.

### What it costs us

**The server cannot give a caller a useful error before dispatch.** Every request makes a
round trip to the Windows host before anyone knows whether it was allowed. There is no
client-side validation, no "that path is not permitted" without asking, and no way to shorten
the loop.

That cost is what the handshake policy summary exists to mitigate. By reporting the read
roots, the execution mode, and the ids of the permitted commands, the agent lets the server
tell the model what is possible *before* it tries. An assistant that knows the three read
roots and the four permitted command ids proposes something that will work; one that does not
spends three turns guessing and annoys the user. The summary is deliberately a summary — ids
and roots, never rule bodies — so it informs without disclosing.

The second cost is that a denial has to travel back as a well-formed, useful error rather
than being caught locally. That is why `POLICY_DENIED` carries `rule`, a human-readable
`reason` with an explicit `reasonSource`, and an `allowedSummary`
([`../04-agent-policy.md` §8](../04-agent-policy.md#8-reporting-a-denial)), and why
`retryable` is always `false` — a model that treats a policy denial as retryable will churn
through variants of a command that will never be permitted.

### What we would have to change to reverse it

Adding server-side enforcement would require the server to hold a copy of the rule set,
which means a distribution mechanism, a synchronisation story, and an answer to the question
of which copy wins when they disagree. It would also require deciding what happens when the
server's copy is stale — the failure mode that makes duplicated enforcement worse than
either single option.

Reversing it in the other direction, to server-only enforcement, would mean deleting the
policy engine from the agent and adding a trusted-request path to the protocol. Both
documents say plainly that no such path exists, and the schema would have to grow a field to
carry it. The absence of that field is deliberate: reversal should require an edit to the
contract, visible in a diff, not a quiet configuration change.
