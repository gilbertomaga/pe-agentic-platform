# pe-agentic-platform

Module 3 of the Emergn Platform Engineer pathway: the agentic layer.

## What this is

A small, real agent platform: a runtime that contains agent runs, a policy layer that decides what
an agent may do, an audit trail the platform writes rather than the engineer, and a golden path that
provisions all three by default.

It is built here, outside the client, deliberately. See "The boundary" below.

## Why it exists

The entry assessment scored D3, Agent Runtime, Platform and Guardrails, at 1 (Aware), floored by two
competencies:

- **3.2 Agent runtime and sandboxes** at 1
- **3.3 Guardrails and policy** at 1

The platform half of the same domain scored 3: golden paths and self service developer experience
are already built at the client. What is missing is everything that contains an agent. This repo
closes that gap, and it is the only part of the pathway that can be shown to the instructor directly.

## The boundary

**No client code, credentials, account identifiers or infrastructure in this repository.** The client
platform is evidenced separately by description and, if asked, by a live walkthrough. Standing up an
agent runtime on the client's accounts is cost they did not agree to and a security review that would
have to be justified, so the agentic layer is built here instead, at no cost to them.

## Stack, and why

| Concern | Choice | Reason |
|---|---|---|
| Language | Python | The PE-A foundation lab was Python; the concepts carry straight over |
| Sandbox | Docker | A container per run, created and destroyed. Free, local, genuinely isolated |
| Policy | Open Policy Agent | The category the pathway names. Free, runs locally, policy as versioned code |
| Trail | Append only JSONL | Same shape as the PE-A audit trail, already walked end to end |
| Gates | GitHub Actions | Free on a personal repository, and mirrors how the client platform gates change |

The stack is deliberately close to PE-A so the effort goes into the decisions rather than into
learning new tools.

## The four components

Build order is runtime first, portal last. The pathway is explicit: build the platform before the
portal, never the portal first.

1. **`runtime/`** — the agent runtime and sandboxes. Isolation model, data boundary, resource and
   network limits, and how a run is recorded on teardown.
2. **`policy/`** — the guardrail layer. Every action classified autonomous, human gated or forbidden.
   Deny by default. Mapped to the OWASP Agentic Top 10.
3. **`trail/`** — traceability. One immutable record per consequential action, emitted by the
   platform automatically, plus an audit gate that stops un-recorded change from shipping.
4. **`golden_path/`** — self service by intent. Provisioning that hands a new service the sandbox,
   the policy and the trail without the team choosing them.

## How we work in here

**Claude writes the plumbing. Gilberto decides the rules.**

Docker wiring, OPA invocation, file formats and test scaffolding are implementation and can be
written for him. What an agent may do, where the human gate sits, what gets recorded and what must
never be reachable are competencies 3.2 and 3.3 themselves, they are what the instructor asks about
out loud, and they are his to decide. Record each decision in `docs/decisions.md` as it is made,
with the reasoning, not just the outcome.

## Conventions

- Deny by default, always. An action nobody wrote a rule for stops.
- Every denial carries a reason. An unexplained denial is indistinguishable from a bug, and engineers
  route around things they think are bugs.
- The trail is not a step anyone can skip. If capture is optional it will be skipped under deadline.
- No agent may edit the policy. An agent that can edit its own policy has no policy.
- Prose written for hand-ins avoids dashes as punctuation and stays short.
