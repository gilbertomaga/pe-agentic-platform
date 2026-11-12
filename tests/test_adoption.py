"""
The adoption census, asserted.

The test that matters is the one where an agent exists and never came through the path. A census
that only counts the people who used the front door measures the door, not adoption.
"""
from __future__ import annotations

from golden_path import adoption
from trail import trail


def provisioned(path, name, cleared=True):
    """What new_agent.record writes, without needing OPA to get there."""
    outcome = "allow" if cleared else "deny"
    for event in ("decided", "executed") if cleared else ("decided",):
        trail.append(f"provision-{name}", 1, f"provision agent {name}",
                     "create", "agent", outcome, "through the path", event, path=path)


def agent_dir(root, name):
    workspace = root / name
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "agent.toml").write_text(f'name = "{name}"\n', encoding="utf-8")


def test_an_agent_that_walked_the_path_is_counted(tmp_path):
    path = tmp_path / "t.jsonl"
    agents = tmp_path / "agents"
    provisioned(path, "tidy")
    agent_dir(agents, "tidy")

    result = adoption.census(path, agents)
    assert result.through == ("tidy",)
    assert result.outside == ()
    assert result.share == 1.0


def test_an_agent_that_appeared_without_the_path_is_the_number_that_matters(tmp_path):
    """Somebody copied the template directory. No sandbox binding, no policy, no trail."""
    path = tmp_path / "t.jsonl"
    agents = tmp_path / "agents"
    provisioned(path, "tidy")
    agent_dir(agents, "tidy")
    agent_dir(agents, "smuggled")

    result = adoption.census(path, agents)
    assert result.outside == ("smuggled",)
    assert result.share == 0.5


def test_an_agent_stopped_at_a_gate_is_friction_not_adoption(tmp_path):
    path = tmp_path / "t.jsonl"
    agents = tmp_path / "agents"
    provisioned(path, "greedy", cleared=False)

    result = adoption.census(path, agents)
    assert result.through == ()
    assert result.stopped_at_a_gate == 1


def test_an_inventory_widens_the_denominator_and_says_so(tmp_path):
    path = tmp_path / "t.jsonl"
    agents = tmp_path / "agents"
    provisioned(path, "tidy")
    agent_dir(agents, "tidy")

    inventory = tmp_path / "inventory.txt"
    inventory.write_text("# gathered from the org\ntidy\nelsewhere\n", encoding="utf-8")

    result = adoption.census(path, agents, inventory=inventory)
    assert result.outside == ("elsewhere",)
    assert "inventory.txt" in result.denominator


def test_nothing_known_yet_reports_no_share_rather_than_a_hundred_percent(tmp_path):
    """Zero over zero is not full adoption, and a census must not round it up to one."""
    result = adoption.census(tmp_path / "t.jsonl", tmp_path / "agents")
    assert result.total == 0
    assert result.share is None
