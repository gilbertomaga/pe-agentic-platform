"""
The golden path, asserted.

The test that matters is the one where a team asks for more than the platform allows. A path that
cannot stop that is a template with good intentions.
"""
import os

import pytest

from golden_path import new_agent
from policy import evaluate

# Same rule as the containment tests: locally these may skip, in CI they must run.
_has_opa = evaluate.available()
if os.environ.get("REQUIRE_OPA") == "1" and not _has_opa:
    raise RuntimeError("REQUIRE_OPA=1 but opa is not on PATH")
needs_opa = pytest.mark.skipif(not _has_opa, reason="opa not on PATH (local machine)")


@pytest.fixture
def agent(tmp_path):
    def make(actions):
        workspace = new_agent.provision("probe", root=tmp_path)
        config = workspace / "agent.toml"
        config.write_text(
            'name = "probe"\n'
            'purpose = "a probe"\n'
            "actions = [\n" + "".join(f'  "{a}",\n' for a in actions) + "]\n",
            encoding="utf-8")
        return config
    return make


def passed(gates):
    return all(g.passed for g in gates)


def failure(gates):
    return next(g for g in gates if not g.passed)


@needs_opa
def test_a_well_formed_agent_clears_the_path(agent):
    assert passed(new_agent.gates(agent(["read:repository", "run:tests"])))


@needs_opa
def test_an_agent_cannot_grant_itself_a_gated_action(agent):
    """The path narrows. It never widens."""
    bad = failure(new_agent.gates(agent(["read:repository", "deploy:production"])))
    assert bad.name == "actions are within policy"
    assert "human_gated" in bad.detail


@needs_opa
def test_an_agent_cannot_grant_itself_a_forbidden_action(agent):
    bad = failure(new_agent.gates(agent(["read:customer_data"])))
    assert "forbidden" in bad.detail


@needs_opa
def test_an_agent_cannot_invent_an_action(agent):
    """Unlisted is denied, at provisioning time rather than at run time."""
    bad = failure(new_agent.gates(agent(["delete:ticket_store"])))
    assert "deny" in bad.detail


def test_a_missing_config_stops_the_path(tmp_path):
    bad = failure(new_agent.gates(tmp_path / "nothing.toml"))
    assert bad.name == "config present"


def test_an_incomplete_config_stops_the_path(tmp_path):
    config = tmp_path / "agent.toml"
    config.write_text('name = "probe"\n', encoding="utf-8")
    bad = failure(new_agent.gates(config))
    assert bad.name == "config complete"


def test_reprovisioning_does_not_overwrite_the_config(tmp_path):
    """The defect that makes a gate untestable: the path resetting what it is about to check."""
    workspace = new_agent.provision("probe", root=tmp_path)
    config = workspace / "agent.toml"
    config.write_text('name = "edited"\n', encoding="utf-8")

    new_agent.provision("probe", root=tmp_path)
    assert config.read_text(encoding="utf-8") == 'name = "edited"\n'


def test_no_policy_engine_creates_nothing(monkeypatch, capsys):
    """A first run that fails must not leave a half provisioned agent behind.

    It did: a traceback, and a directory with no provisioning record, which the adoption census
    reads as somebody who went around the path. A broken install is not an evasion.
    """
    def must_not_run(*args, **kwargs):
        raise AssertionError("the path created an agent before checking the policy engine")

    monkeypatch.setattr(evaluate, "available", lambda: False)
    monkeypatch.setattr(new_agent, "provision", must_not_run)

    assert new_agent.main(["probe"]) == 2
    assert "opa is not on PATH" in capsys.readouterr().out


def test_provisioning_leaves_a_runnable_plan(tmp_path):
    """A documented command that cannot run is the defect this repo keeps finding elsewhere.

    The README told a newcomer to run `python -m runtime plan.toml` and no plan shipped, so the
    first thing anyone following it hit was exit code 2. The path hands you one now, named for
    your agent, and this fails if it ever stops doing that or stops being within scope.
    """
    workspace = new_agent.provision("probe", root=tmp_path)
    plan = workspace / "plan.toml"
    assert plan.exists(), "the golden path provisioned an agent with nothing to run"

    spec = new_agent.load(plan)
    declared = set(new_agent.load(workspace / "agent.toml")["actions"])

    assert spec["agent"] == "probe"
    assert spec["actions"], "the example plan has no actions"
    for action in spec["actions"]:
        name = f"{action['verb']}:{action['target']}"
        assert name in declared, f"the example plan asks for {name}, which the agent never declared"
        assert action["command"], f"{name} has no command"
