"""
`python -m runtime <plan-file>`, the command CLAUDE.md has documented since the first commit and
nothing implemented. A documented command that does not run is the same defect as a health check
path that does not match the image: it is believed until the day somebody follows it.

A plan says what an agent should do. It does not say what the agent is allowed to do: that comes
from the agent's own `agent.toml`, written at provisioning time and already checked against the
policy. A plan cannot widen it, which is why the scope is read from the agent rather than taken
from the plan file.

    agent  = "my-agent"
    prompt = "fix the failing test"

    [[actions]]
    verb    = "run"
    target  = "tests"
    command = ["python", "-m", "pytest", "-q"]

    [approvals]
    "deploy:production" = "r.okonkwo"
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from golden_path import new_agent
from policy import evaluate
from runtime import runner

USAGE = "usage: python -m runtime <plan-file>"


def load_plan(path: Path) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def scope_of(agent: str, root: Path = new_agent.AGENTS) -> list[str]:
    """What this agent declared at provisioning. The plan cannot add to it."""
    config = root / agent / "agent.toml"
    if not config.exists():
        raise FileNotFoundError(
            f"no provisioned agent at {config}. Run the golden path first: "
            f"python -m golden_path.new_agent {agent}")
    return list(new_agent.load(config).get("actions", []))


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(USAGE)
        return 2

    plan_path = Path(argv[0])
    if not plan_path.exists():
        print(f"no plan at {plan_path}")
        return 2

    plan = load_plan(plan_path)
    agent = plan.get("agent")
    if not agent:
        print("the plan does not say which agent it is for")
        return 2

    try:
        scope = scope_of(agent)
    except FileNotFoundError as err:
        print(err)
        return 2

    actions = [
        runner.Action(a["verb"], a["target"], list(a.get("command", [])))
        for a in plan.get("actions", [])
    ]
    if not actions:
        print("the plan has no actions")
        return 2

    workspace = Path(plan.get("workspace", new_agent.AGENTS / agent)).resolve()

    try:
        run = runner.execute(
            plan.get("prompt", ""), actions, scope=scope, workspace=workspace,
            approvals=plan.get("approvals", {}),
        )
    except evaluate.PolicyUnavailable as err:
        # Fail closed, and say so rather than reporting a generic crash.
        print(f"POLICY UNAVAILABLE, nothing ran: {err}")
        return 1

    print(f"run {run.run_id}")
    for step in run.steps:
        mark = "ran" if step.executed else step.outcome
        who = f" (approved by {step.approver})" if step.approver else ""
        print(f"  {step.step}. {step.action:28} {mark}{who}")
        if not step.executed:
            print(f"     {step.reason}")

    print(f"\n{run.stopped_because}, {len(run.executed)} of {len(actions)} actions executed")
    return 0 if run.stopped_because == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
