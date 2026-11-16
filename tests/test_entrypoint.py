"""
`python -m runtime <plan-file>`, which is the second thing anybody runs and was the only
command in the README with no test behind it at all.

The last test is the one worth having. The plan the golden path writes for you is the first
thing a newcomer executes, and until 16 November its one action ran pytest inside an image that
has no pytest in it and no network to go and get one. The first real run could only ever fail,
and a default that cannot succeed reads as a broken platform rather than as a wrong plan. That
is not something the suite could have noticed, because nothing asserted the template was
runnable at all.
"""
from __future__ import annotations

import os
import subprocess

import pytest

from golden_path import new_agent
from policy import evaluate
from runtime import __main__ as entrypoint
from runtime import sandbox

_has_opa = evaluate.available()
if os.environ.get("REQUIRE_OPA") == "1" and not _has_opa:
    raise RuntimeError("REQUIRE_OPA=1 but opa is not on PATH")
needs_opa = pytest.mark.skipif(not _has_opa, reason="opa not on PATH (local machine)")


def plan(tmp_path, body: str):
    path = tmp_path / "plan.toml"
    path.write_text(body, encoding="utf-8")
    return path


# ------------------------------------------------- it says what is wrong, and stops

def test_no_argument_prints_the_usage(capsys):
    assert entrypoint.main([]) == 2
    assert "python -m runtime" in capsys.readouterr().out


def test_a_plan_that_is_not_there_is_named(tmp_path, capsys):
    missing = tmp_path / "nope.toml"
    assert entrypoint.main([str(missing)]) == 2
    assert str(missing) in capsys.readouterr().out


def test_a_plan_that_does_not_say_which_agent_stops(tmp_path, capsys):
    assert entrypoint.main([str(plan(tmp_path, 'prompt = "do a thing"\n'))]) == 2
    assert "which agent" in capsys.readouterr().out


def test_an_unprovisioned_agent_is_told_to_walk_the_path(tmp_path):
    """The error a newcomer is most likely to see, so it carries the command that fixes it."""
    with pytest.raises(FileNotFoundError) as refused:
        entrypoint.scope_of("never-provisioned", root=tmp_path)
    assert "python -m golden_path.new_agent never-provisioned" in str(refused.value)


def test_the_scope_comes_from_the_agent_and_not_from_the_plan(tmp_path):
    """A plan can narrow what an agent declared. It can never add to it."""
    new_agent.provision("probe", root=tmp_path)
    assert "read:repository" in entrypoint.scope_of("probe", root=tmp_path)


# ------------------------------------------- the first run has to be able to succeed

@needs_opa
def test_the_plan_the_path_writes_can_actually_run(tmp_path):
    """Every action in the shipped plan is declared by the shipped agent and runs unattended.

    An action outside the declared scope is refused before it reaches a container, and a gated
    one halts for an approver nobody has named yet. Either way the first run a newcomer makes
    would not execute, and they have no way to tell that from a platform that does not work.
    """
    workspace = new_agent.provision("probe", root=tmp_path)
    declared = set(new_agent.load(workspace / "agent.toml")["actions"])
    actions = entrypoint.load_plan(workspace / "plan.toml").get("actions", [])

    assert actions, "the shipped plan has no actions, so the first run does nothing"
    for action in actions:
        name = f"{action['verb']}:{action['target']}"
        assert name in declared, f"the shipped plan asks for {name}, which the agent never declared"
        assert evaluate.decide(action["verb"], action["target"])["outcome"] == "allow", (
            f"{name} does not run unattended, so the first run stops rather than executing")


def test_the_shipped_plan_runs_a_command_the_sandbox_image_actually_has(tmp_path):
    """Structural, and it is the defect this file was written for.

    The sandbox is a bare Python image with no network. A default command that needs anything
    installed into it cannot work, and the first thing a newcomer runs is this one.
    """
    workspace = new_agent.provision("probe", root=tmp_path)
    needs_installing = ("pytest", "pip", "poetry", "npm", "node", "curl", "git")

    for action in entrypoint.load_plan(workspace / "plan.toml").get("actions", []):
        command = " ".join(action.get("command", []))
        for tool in needs_installing:
            assert tool not in command.split(), (
                f"the shipped plan runs `{command}`, and {tool} is not in the sandbox image "
                "and cannot be fetched from inside it")


# ------------------------------------------- what a cold run found, on somebody else's machine

def test_an_installed_docker_with_no_daemon_says_which_of_the_two_is_wrong(monkeypatch, capsys):
    """The first person to follow the README read "start Docker", typed `docker`, saw it print
    its usage, and stopped. The command being on PATH says nothing about the daemon answering."""
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/local/bin/docker")
    monkeypatch.setattr(sandbox.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "cannot connect"))

    reachable, why = sandbox.availability()
    assert reachable is False
    assert why == sandbox.NO_DAEMON
    assert "not running" in why, "it has to name the thing to go and start"


def test_no_docker_at_all_is_a_different_message(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    reachable, why = sandbox.availability()
    assert reachable is False
    assert why == sandbox.NO_DOCKER
    assert sandbox.NO_DOCKER != sandbox.NO_DAEMON, "one message for two problems helps neither"


def test_the_plan_is_not_run_when_the_sandbox_cannot_be_reached(monkeypatch, tmp_path, capsys):
    """Nothing decided and nothing recorded, so a stopped machine leaves no trail to explain."""
    monkeypatch.setattr(sandbox, "availability", lambda: (False, sandbox.NO_DAEMON))
    workspace = new_agent.provision("probe", root=tmp_path)
    monkeypatch.setattr(entrypoint, "scope_of", lambda agent, **kw: ["read:repository"])

    assert entrypoint.main([str(workspace / "plan.toml")]) == 2
    out = capsys.readouterr().out
    assert sandbox.NO_DAEMON in out
    assert "Nothing was decided or recorded" in out
