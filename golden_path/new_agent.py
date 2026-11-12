"""
The golden path: provisioning an agent by intent.

A team says what the agent is for and which actions it needs. Everything that makes the agent safe
to run, the sandbox limits, the policy binding and the trail, arrives already decided. They do not
choose those, and they do not have to know they exist.

Two things make this a path rather than a suggestion:

  A gate that fails stops the path. A golden path that lets you past a red gate is documentation.

  The path can only narrow, never widen. An agent may ask for fewer actions than the platform
  allows. It cannot grant itself one the policy does not already treat as autonomous, so there is
  no route to privilege through provisioning.

Provisioning is itself recorded in the trail, which is where the adoption number comes from.
"""
from __future__ import annotations

import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from policy import evaluate
from trail import trail

TEMPLATE = Path(__file__).with_name("template")
AGENTS = Path(__file__).with_name("agents")

#: Defaults the platform owns. A team does not set these.
SANDBOX_DEFAULTS = {
    "image": "python:3.12-slim",
    "network": "none",
    "timeout_seconds": 120,
    "memory": "512m",
    "cpus": "1.0",
}


@dataclass(frozen=True)
class Gate:
    name: str
    passed: bool
    detail: str = ""


def load(config: Path) -> dict:
    with open(config, "rb") as fh:
        return tomllib.load(fh)


def gates(config: Path) -> list[Gate]:
    """Run in order and stop at the first failure. The path does not continue past a red gate."""
    checks: list[Gate] = []

    if not config.exists():
        return [Gate("config present", False, f"no agent.toml at {config}")]
    checks.append(Gate("config present", True))

    try:
        spec = load(config)
    except Exception as err:
        checks.append(Gate("config parses", False, str(err)))
        return checks
    checks.append(Gate("config parses", True))

    for field in ("name", "purpose", "actions"):
        if not spec.get(field):
            checks.append(Gate("config complete", False, f"missing {field}"))
            return checks
    checks.append(Gate("config complete", True))

    # The control that matters: an agent cannot grant itself more than the policy allows.
    for action in spec["actions"]:
        verb, _, target = action.partition(":")
        decision = evaluate.decide(verb, target)
        if decision["outcome"] != "allow":
            checks.append(Gate(
                "actions are within policy", False,
                f"{action} is {decision['outcome']}, not autonomous: {decision['reason']}"))
            return checks
    checks.append(Gate("actions are within policy", True))

    checks.append(Gate("sandbox has no network", SANDBOX_DEFAULTS["network"] == "none"))
    checks.append(Gate("sandbox is time bounded", SANDBOX_DEFAULTS["timeout_seconds"] > 0))
    return checks


def provision(name: str, root: Path = AGENTS) -> Path:
    """Create the agent workspace from the template, without clobbering what is there.

    Re-running the path on an existing agent validates it. It does not reset it. Copying the
    template over an existing config would mean a team could never fail a gate on their own
    changes, because the changes would be gone before the gate ran.
    """
    workspace = root / name
    workspace.mkdir(parents=True, exist_ok=True)
    for source in TEMPLATE.glob("*"):
        destination = workspace / source.name
        if destination.exists():
            continue
        text = source.read_text(encoding="utf-8").replace("{{NAME}}", name)
        destination.write_text(text, encoding="utf-8")
    return workspace


def record(name: str, cleared: bool) -> None:
    """Provisioning is an action, so it goes in the trail like any other.

    This is also the adoption instrument: every agent that exists came through here, and the ones
    that did not are not in the trail, which is the number worth watching.
    """
    outcome = "allow" if cleared else "deny"
    reason = "provisioned through the golden path" if cleared else "stopped at a gate"
    for event in ("decided", "executed") if cleared else ("decided",):
        trail.append(f"provision-{name}", 1, f"provision agent {name}",
                     "create", "agent", outcome, reason, event)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python -m golden_path.new_agent <name>")
        return 2

    name = argv[0]

    # Checked before anything is created, not when the first gate reaches for it. Without this
    # the path left a traceback and an agent directory with no provisioning record behind it,
    # which the adoption census would then count as somebody who went around the path. A failed
    # run must not manufacture the signal that something was evaded.
    if not evaluate.available():
        print("opa is not on PATH, and the path cannot check what an agent may do without it.\n"
              "Install it from openpolicyagent.org/docs/latest/#running-opa, or point OPA_BIN at\n"
              "the binary, then run this again. Nothing was created.")
        return 2

    workspace = provision(name)
    print(f"created {workspace}\n")

    cleared = True
    for gate in gates(workspace / "agent.toml"):
        print(f"  [{'PASS' if gate.passed else 'FAIL'}] {gate.name}"
              + (f" - {gate.detail}" if gate.detail else ""))
        cleared &= gate.passed

    record(name, cleared)
    print("\n" + ("GOLDEN PATH CLEAR, the agent is ready to run."
                  if cleared else
                  "STOPPED at a failing gate. The path does not continue past a red gate."))
    return 0 if cleared else 1


if __name__ == "__main__":
    raise SystemExit(main())
