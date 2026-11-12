"""
The runtime: the only way an action happens.

Until this module existed the three parts of the platform were real but separate. The policy was
asked a question at provisioning time, the sandbox executed commands, and the trail was written by
whoever remembered to write it. Nothing joined them, so "every action is evaluated before it runs"
and "every run leaves a record" were true of the design and false of the code. This is the join.

One action takes exactly one path through here:

    scope  ->  policy  ->  decided record  ->  (approver, if gated)  ->  sandbox  ->  executed record

Three properties that path is built to have:

  The decision is recorded before the thing happens, not after. A record written afterwards is a
  report. Written first, it is the reason the action was allowed to proceed, and the audit gate
  fails any execution that has no decision in front of it.

  It fails closed. If the policy engine cannot be reached, nothing runs. A guardrail that becomes
  permissive when its dependency is down is worse than none, because everybody still believes it
  is there.

  It stops at the first refusal rather than carrying on with the rest of the list. An agent that
  is told no and continues to step four has not been told no.

Scope is checked before the policy, not after. The policy says what the platform permits; the
agent's own action list says what this agent asked for, which can only ever be narrower. Asking
the policy first would let an agent reach an action it never declared, as long as the platform
allowed it generally.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from policy import evaluate
from runtime import alert, sandbox
from trail import trail

#: Bounds breadth. The sandbox wall clock bounds duration. Neither substitutes for the other:
#: twenty short steps and one that never returns are different failures.
DEFAULT_MAX_STEPS = 20

DEFAULT_IMAGE = "python:3.12-slim"


@dataclass(frozen=True)
class Action:
    """One thing an agent wants to do, and the command that does it inside the sandbox.

    `command` is required. An action with no command has no effect here, and recording it as
    executed would put a line in the trail for something that never ran.
    """
    verb: str
    target: str
    command: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError(
                f"{self.name} has no command. This runtime executes in the sandbox; an effect "
                "that reaches outside the boundary is not this runtime's to take (decision D1).")

    @property
    def name(self) -> str:
        return f"{self.verb}:{self.target}"


@dataclass(frozen=True)
class Step:
    step: int
    action: str
    outcome: str                      # allow | human_gated | forbidden | deny | out_of_scope
    reason: str
    executed: bool
    approver: str | None = None
    result: sandbox.Result | None = None


@dataclass(frozen=True)
class Run:
    run_id: str
    steps: tuple[Step, ...]
    stopped_because: str              # completed | refused | needs_approval | step_limit | failed

    @property
    def executed(self) -> tuple[Step, ...]:
        return tuple(s for s in self.steps if s.executed)


def _why_not(result: sandbox.Result) -> str:
    """What goes in the trail when a step did not succeed.

    "sandbox error" on its own sends whoever reads this back to the machine it ran on, which by
    then is gone. The reason the container never started belongs in the record.
    """
    if result.stopped_because == "timeout":
        return "stopped by the wall clock before it finished"
    if result.stopped_because == "error":
        return f"the container never started: {result.stderr.strip() or 'no detail'}"
    tail = result.stderr.strip().splitlines()
    return f"exit code {result.exit_code}" + (f": {tail[-1]}" if tail else "")


def execute(
    prompt: str,
    actions: list[Action],
    scope: list[str],
    workspace: Path,
    run_id: str | None = None,
    approvals: dict[str, str] | None = None,
    image: str = DEFAULT_IMAGE,
    max_steps: int = DEFAULT_MAX_STEPS,
    trail_path: Path = trail.DEFAULT_TRAIL,
    writable: bool = False,
) -> Run:
    """Run a sequence of actions, and stop at the first one that is not permitted.

    `scope` is the agent's own action list from `agent.toml`, which the golden path has already
    checked against the policy. `approvals` names the human behind each gated action, keyed by
    "verb:target"; an action the policy gates and nobody has approved halts the run with its
    decision recorded and nothing executed, which is the platform working rather than a finding.
    """
    run_id = run_id or uuid.uuid4().hex[:12]
    approvals = approvals or {}
    allowed = set(scope)
    steps: list[Step] = []

    def record(step: int, action: Action, outcome: str, reason: str,
               event: str, approver: str | None = None) -> None:
        trail.append(run_id, step, prompt, action.verb, action.target,
                     outcome, reason, event, approver=approver, path=trail_path)

    for index, action in enumerate(actions, start=1):
        if index > max_steps:
            return Run(run_id, tuple(steps), "step_limit")

        # 1. Scope. What this agent declared, which the policy has already narrowed.
        if action.name not in allowed:
            reason = f"{action.name} is not in this agent's declared actions"
            record(index, action, "out_of_scope", reason, "decided")
            alert.raise_alert(run_id, index, action.name, "out_of_scope", reason)
            steps.append(Step(index, action.name, "out_of_scope", reason, executed=False))
            return Run(run_id, tuple(steps), "refused")

        # 2. Policy. Raises if OPA cannot be reached, and nothing after this line runs.
        decision = evaluate.decide(action.verb, action.target)
        outcome, reason = decision["outcome"], decision["reason"]

        # 3. The decision is recorded before anything happens.
        approver = approvals.get(action.name) if outcome == "human_gated" else None
        record(index, action, outcome, reason, "decided", approver=approver)

        if outcome not in ("allow", "human_gated"):
            # Blocked and recorded above. The alert is what reaches someone who was not looking.
            alert.raise_alert(run_id, index, action.name, outcome, reason)
            steps.append(Step(index, action.name, outcome, reason, executed=False))
            return Run(run_id, tuple(steps), "refused")

        if outcome == "human_gated" and not approver:
            steps.append(Step(index, action.name, outcome, reason, executed=False))
            return Run(run_id, tuple(steps), "needs_approval")

        # 4. Only now does it run.
        result = sandbox.run(image, action.command, workspace, writable=writable)
        ran = result.stopped_because == "completed" and result.exit_code == 0
        event = "executed" if ran else "failed"
        detail = reason if ran else _why_not(result)

        record(index, action, outcome, detail, event, approver=approver)
        steps.append(Step(index, action.name, outcome, detail,
                          executed=ran, approver=approver, result=result))

        if not ran:
            return Run(run_id, tuple(steps), "failed")

    return Run(run_id, tuple(steps), "completed")
