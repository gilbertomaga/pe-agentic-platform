# Policy mapped to the OWASP Top 10 for Agentic Applications

Source: *OWASP Top 10 for Agentic Applications 2026*, OWASP GenAI Security Project, Agentic
Security Initiative, version 2026, December 2025. Licensed CC BY-SA 4.0. The ten titles below are
quoted as OWASP writes them; everything else is mine.

Four are addressed, four are partial, two are not addressed at all. The last two are the useful
rows: a mapping that claimed ten out of ten would be describing a different platform.

| | Risk | Status |
|---|---|---|
| ASI01 | Agent Goal Hijack | partial |
| ASI02 | Tool Misuse and Exploitation | addressed |
| ASI03 | Identity and Privilege Abuse | addressed |
| ASI04 | Agentic Supply Chain Vulnerabilities | **not addressed** |
| ASI05 | Unexpected Code Execution (RCE) | addressed |
| ASI06 | Memory & Context Poisoning | addressed by absence |
| ASI07 | Insecure Inter-Agent Communication | **not applicable yet** |
| ASI08 | Cascading Failures | partial |
| ASI09 | Human-Agent Trust Exploitation | partial |
| ASI10 | Rogue Agents | measured, not prevented |

---

## ASI01 · Agent Goal Hijack — partial

The policy does not stop an agent being talked into a different goal. It bounds what a hijacked
goal can produce: every action is evaluated before it runs, anything unlisted is denied, and the
regulated boundary is gated regardless of what the agent believes it was asked to do.

This is containment rather than prevention, and the distinction matters. A hijacked agent on this
platform still cannot deploy, read customer data or rewrite its own policy. It can still waste a
run and produce a wrong answer.

## ASI02 · Tool Misuse and Exploitation — addressed

The policy is an action allowlist. An agent may use what is classified autonomous and nothing else,
and the classification is versioned Rego with tests rather than configuration. The sandbox has no
network, so a tool cannot be turned into an exfiltration channel even if it is misused.

## ASI03 · Identity and Privilege Abuse — addressed

The container runs as uid 65534 with all capabilities dropped and `no-new-privileges` set. It has
no network, so the instance metadata endpoint is unreachable and there are no credentials to
collect. The golden path narrows but never widens: an agent cannot grant itself a gated or
forbidden action at provisioning time, so there is no privilege route through onboarding either.

## ASI04 · Agentic Supply Chain Vulnerabilities — not addressed

The base image is pinned by tag, which is not the same as pinned by digest, and nothing verifies
what is in it. There is no SBOM, no signature verification, and no policy on which model versions
may be used. This is the largest open risk on the list and it is Module 4 work.

## ASI05 · Unexpected Code Execution (RCE) — addressed

Code execution is the point of the sandbox rather than a failure of it, so the control is the
boundary, not the prevention. No network, read only root filesystem, a `noexec` tmpfs, non-root
user, dropped capabilities, memory, CPU and PID limits, and a wall clock timeout. The container is
destroyed afterwards and nothing survives it.

## ASI06 · Memory & Context Poisoning — addressed by absence

Runs are stateless. A fresh container per run, destroyed on teardown, with nothing carried between
runs, so there is no persistent memory to poison. This is a property of the current design rather
than a control, and it stops being true the moment persistent memory is added. If that happens,
this row moves to not addressed until something replaces it.

## ASI07 · Insecure Inter-Agent Communication — not applicable yet

There is one agent and no channel between agents. Recorded here rather than omitted, because the
mapping should say where the platform has not arrived rather than quietly skip the row.

## ASI08 · Cascading Failures — partial

A single run is bounded in breadth by the action list, in duration by the timeout, and in resources
by the container limits, so one run cannot consume the host. What does not exist is anything that
bounds failure across runs: no circuit breaker, no rate limit, nothing that notices a hundred runs
failing the same way.

## ASI09 · Human-Agent Trust Exploitation — partial

The human gate on merge and on every deploy means a confident wrong answer still needs a person to
accept it. That is the control.

The honest gap is the person. A clean, confident review makes a reviewer look less carefully than
an empty one would, which means the gate exists but its quality degrades exactly when the agent
sounds most sure. Nothing here measures that, and nothing can until there is an evaluation saying
how often the agent is wrong.

## ASI10 · Rogue Agents — measured, not prevented

Provisioning is recorded in the trail, so every agent that came through the golden path is
countable. Nothing prevents somebody running an agent outside the platform, and nothing could from
in here.

What this buys is the number worth watching: not how many agents came through the path, but how
many exist that are not in the trail. Those are the ones running with no sandbox, no policy and no
record, and they are the rogue agents in practice.
