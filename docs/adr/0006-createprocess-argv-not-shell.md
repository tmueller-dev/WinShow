# ADR 0006: Direct process creation with an explicit argv, not a shell

**Status:** Accepted · **Date:** 2026-07-26 · **Deciders:** WinShow design phase

## Context

The agent's execution operation has to decide what "run this command" means. There are two
possible shapes, and they look almost identical from the caller's side.

The first takes an **argument vector**: `argv[0]` is the executable and the remaining
elements are already-split arguments, handed to `CreateProcessW` after the agent applies the
quoting rules. The second takes a **command line string** and hands it to a shell, which
splits it, expands wildcards, interprets redirections and pipes, and then launches whatever
it decided the user meant.

The second is far more convenient, and it is what almost every remote-execution tool does. It
is also incompatible with the security model of this system, and the reason is not a matter
of taste.

Authorization in WinShow lives entirely on the agent
([ADR 0003](0003-authorization-on-agent-only.md)), expressed as rules in a policy file. Those
rules do things like: permit `C:\Windows\System32\sc.exe` with `argv` exactly
`["query", "{service}"]` where `{service}` matches an anchored pattern. **Policy can only
enforce what it can see.** That rule is enforceable if and only if `sc.exe` and `query` are
separate, inspectable tokens that the agent can compare against a template before anything is
launched.

Hand the agent the string `sc.exe query MyService` and it has nothing to check. To check
anything it would have to parse the string the way the shell will parse it, which means
reimplementing the shell's grammar — including quoting, escaping, variable expansion, and
`cmd.exe`'s habit of re-parsing metacharacters *after* argument processing. Any disagreement
between the agent's parse and the shell's parse is a policy bypass. A shell string is opaque
to policy, and it is exactly the shape that command injection exploits.

## Decision

**The default and required execution mode is a direct process creation with an explicit
argument vector: `CreateProcessW`, no shell, no `ShellExecute`.** This is `shell: "none"`, the
default for `exec.start`, and it is the mode against which executable allow rules are written.

Shells are supported as **separate, individually permitted modes**, never as the default and
never implicitly. The normative details are in
[`../03-agent-protocol.md` §10.3](../03-agent-protocol.md#103-how-a-command-is-executed) and
the policy shapes are in
[`../04-agent-policy.md` §5.2](../04-agent-policy.md#52-allow-rules).

## Alternatives considered

| Option | Assessment | Verdict |
|---|---|---|
| Explicit `argv`, direct `CreateProcessW` | The policy sees exactly what will run, token by token, before it runs. No parsing gap between what was checked and what executes. Costs pipes, wildcards, and redirection. | **Chosen** |
| A command line string through `cmd.exe` by default | Convenient and familiar, and it makes every allow rule a guess about how the shell will split the string. The gap between the agent's parse and `cmd`'s parse is a bypass, and closing it means writing a `cmd` parser. | Rejected |
| `argv` plus automatic shell fallback when parsing looks shell-like | The worst of both: the caller cannot tell which mode they got, and the policy's guarantees change depending on a heuristic. A security boundary that moves based on string inspection is not a boundary. | Rejected |
| `ShellExecute` | Adds file-association dispatch, so the thing that runs is determined by a registry key rather than by the request. Uninspectable by construction. | Rejected |

## The shell modes, and the flags that are not optional

When a shell is explicitly requested and explicitly permitted by policy, the agent still does
not simply pass the string along. Each mode carries mandatory flags, and each flag closes a
specific hole:

| `shell` | Invocation | Why these flags |
|---|---|---|
| `"powershell"` | `powershell.exe -NoProfile -NonInteractive -NoLogo -ExecutionPolicy Bypass -Command "<script>"` | `-NoProfile` is mandatory because profile scripts are writable by the user and would make execution non-deterministic — the same script would do different things depending on what somebody left in a profile. `-NonInteractive` stops a prompt from hanging the process forever, since there is no console to answer it. |
| `"pwsh"` | `pwsh.exe` with the same flags | As above. |
| `"cmd"` | `cmd.exe /d /s /c "<commandLine>"` | `/d` skips `HKCU\Software\Microsoft\Command Processor\AutoRun`, a classic persistence vector: without it, whatever an attacker wrote into that key runs before every single command. `/s` makes the outer-quote stripping rules predictable. |

Shell modes are also matched by a different kind of policy rule. A shell allow rule carries
`scriptPatterns`, and the **entire** script must match one of them. That is why anchoring
every allow pattern at both ends is enforced at load time
([`../04-agent-policy.md` §5.3](../04-agent-policy.md#53-anchoring-is-enforced-at-load)): an
unanchored `Get-Service` pattern would happily match
`Get-Service; Remove-Item -Recurse C:\`, and the rule would have permitted precisely the
thing it existed to prevent.

## The `cmd` metacharacter restriction

Even with `/d /s /c`, **safe quoting for `cmd.exe` is not achievable in general**, because
`cmd` re-parses metacharacters after argument processing. There is no escaping discipline the
agent can apply that reliably prevents a crafted string from being re-interpreted.

Rather than pretend otherwise, the agent refuses the cases it cannot make safe: when
`shell: "cmd"`, a `commandLine` containing any of `& | < > ^ %`, or containing an odd number
of `"` characters, is rejected unless the policy explicitly sets
`allowUnsafeCmdMetacharacters = true`. Operators who need pipes are directed to PowerShell,
whose argument handling is analysable. The escape hatch exists, requires an administrator to
write it down, and is named so that nobody enables it without noticing what they are
enabling.

## Two supporting rules that come from the same principle

**Batch and script files are refused under `shell: "none"`.** A `.bat`, `.cmd`, or `.ps1` file
passed as `argv[0]` returns `EXEC_NOT_FOUND` with a hint pointing at the corresponding shell
mode. They are not executables, and Windows would silently route them through a shell — which
would mean a request that looked like a direct launch, and was checked as one, actually ran
under an interpreter. That single implicit route would defeat the entire argv model.

**`argv[0]` resolves against a policy search path, never the ambient `PATH`.** The only place
a bare executable name is resolved is `executableSearchPath` in the policy
([`../04-agent-policy.md` §5.5](../04-agent-policy.md#55-executable-resolution)). `PATH` is
influenced by whoever can write the service's environment, so resolving against it turns "run
`git.exe`" into "run whatever is called `git.exe` in the first directory somebody managed to
prepend". An ambiguous or failed resolution is `EXEC_NOT_FOUND`, and the **resolved absolute
path** — not the requested string — is what policy is evaluated against and what is reported
back as `resolvedExecutable`. The same reasoning is why overriding `PATH` through the request
environment requires `envAllowSensitive = true`: it is executable substitution by another
name.

## Process containment

Direct creation also lets the agent own the resulting process tree, which a shell-launched
command does not. Every process is created inside a **Job Object** with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, created suspended, assigned to the job, and only then
resumed — the ordering matters, because a fast-starting child can otherwise spawn a
grandchild before it is contained. Closing the job kills the entire tree, and the operating
system reaps every child even if the agent itself dies. That is what makes cancellation and
timeout meaningful: `session.cancel` on a running build terminates the build *and* everything
it started, rather than orphaning a compiler.

Handle inheritance is restricted to the three standard pipes, passed explicitly via
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so that the agent's own handles — including its socket —
never leak into a child process.

## Consequences

### What this buys us

The policy engine evaluates the same tokens the operating system will receive. There is no
parsing step between the check and the launch, and therefore no gap for an injection to live
in. `commandLineUsed` is echoed back on the `exec.start` response as the ground truth of what
ran, which is what belongs in the audit record — reconstructing it later from `argv` would be
guessing at the quoting. Process trees are contained and killable. And the shell, when it is
used at all, is a deliberate, separately-permitted, separately-audited decision rather than
an ambient property of every command.

### What it costs us

**No pipes, no wildcards, no redirection, and no environment variable expansion without
deliberately choosing a shell.** A caller who wants `dir *.log | findstr ERROR` cannot express
it as an argv, and must either request a PowerShell script that the policy permits or use
`fs.glob` and `fs.grep`, which exist partly for this reason. The agent also does not expand
`%VAR%` inside `argv`, because that is a shell's job and the agent is not a shell.

The quoting burden moves onto the agent, and it is fiddly: the Microsoft C runtime rules must
be implemented exactly, because those are the rules `CommandLineToArgvW` reverses and
therefore what most programs expect. There are known exceptions — `cmd.exe`, `.bat` files,
`msiexec`, `robocopy`, and Go binaries all parse their raw command line themselves — which
the protocol documents rather than works around, and which is a second reason
`commandLineUsed` is reported.

### What we would have to change to reverse it

Making a shell the default would invalidate every executable allow rule, since `argv` and
`argvPrefix` templates have nothing to match against. It would require a new rule shape
capable of expressing "this shell string is acceptable", which in practice means regular
expressions over command lines — the `scriptPatterns` mechanism, applied to everything. That
is a strictly weaker control, and adopting it would be a decision to accept a different
security model, not a configuration change.
