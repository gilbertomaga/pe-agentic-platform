"""
The golden path, asserted.

The test that matters is the one where a team asks for more than the platform allows. A path that
cannot stop that is a template with good intentions.
"""
import pytest

from golden_path import new_agent
from policy import evaluate

needs_opa = pytest.mark.skipif(not evaluate.available(), reason="opa not on PATH")


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
