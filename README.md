# pe-agentic-platform

A small agent platform, built to be defensible rather than large.

**A contained runtime.** One container per run, created and destroyed. No network at all: whatever
needs the outside world happens outside the boundary and is passed in. Non root, read only root
filesystem, capabilities dropped, memory, CPU and process limits, and a wall clock timeout, because
a step limit bounds breadth and not duration.

**Policy as code.** Every action is evaluated before it runs. Three classes: autonomous, human
gated, forbidden. Anything nobody wrote a rule for is denied, with a reason. Written in Rego and
tested, because a guardrail that is not asserted is a comment.

**An audit trail the platform writes.** One record when an action is decided, another when it
executes. Append only and hash chained, so an edited or removed entry breaks the chain. The newest
record is anchored separately, because a chain alone does not detect truncation.

**A golden path that narrows.** Provisioning an agent takes a name, a purpose and the actions it
needs. An agent can ask for fewer actions than the platform allows and never for more, so there is
no privilege route through onboarding. Provisioning records itself, which is where the adoption
number comes from.

**One path, not four parts.** `runtime/runner.py` is the only way an action happens: scope, then
policy, then a record of the decision, then the approver if the policy gates it, then the sandbox,
then a record of what ran. It fails closed when the policy engine is unreachable and stops at the
first refusal instead of continuing down the list. A test fails the build if any other module
reaches a container directly, because an invariant nobody enforces is a convention.

## Running it

    python -m pytest -q
    opa test policy/ -v
    python -m golden_path.new_agent my-agent
    python -m trail.gate

CI runs the containment proof on every push. The sandbox test opens a socket from inside the
container and fails if it connects. Tests do not skip there: a missing Docker daemon or a missing
OPA fails the build rather than quietly reducing the proof to a skip. The audit gate runs there
too, against a trail the golden path writes during the build, because a gate that only ever runs
against its own fixtures is a library.

## Reading it

`docs/decisions.md` is the decision log, with the reasoning rather than only the outcome, including
the two defects I wrote and then found. `docs/owasp-mapping.md` maps the policy to the OWASP Top 10
for Agentic Applications 2026: four addressed, four partial, two not.
