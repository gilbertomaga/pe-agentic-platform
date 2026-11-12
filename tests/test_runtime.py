"""
The runtime, asserted.

The tests that matter here are not the happy path. They are the three ways an action could reach
the sandbox without the platform having agreed to it: an action the agent never declared, one the
policy forbids, and one the policy gates that nobody approved. If any of those executes, the
guardrail layer and the trail are both decorative.

The last test is structural rather than behavioural. It fails if any module outside the runtime
calls the sandbox directly, because an invariant that depends on everyone remembering it is not
an invariant.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from policy import evaluate
from runtime import runner, sandbox
from trail import gate, trail

_has_opa = evaluate.available()
if os.environ.get("REQUIRE_OPA") == "1" and not _has_opa:
    raise RuntimeError("REQUIRE_OPA=1 but opa is not on PATH")
needs_opa = pytest.mark.skipif(not _has_opa, reason="opa not on PATH (local machine)")

_has_docker = sandbox.available()
if os.environ.get("REQUIRE_DOCKER") == "1" and not _has_docker:
    raise RuntimeError("REQUIRE_DOCKER=1 but no Docker daemon is reachable")
needs_docker = pytest.mark.skipif(not _has_docker, reason="no Docker daemon (local machine)")

REPO = Path(__file__).resolve().parent.parent

READ = runner.Action("read", "repository", ["true"])
TESTS = runner.Action("run", "tests", ["true"])
DEPLOY = runner.Action("deploy", "production", ["true"])
SECRET = runner.Action("write", "secret", ["true"])

SCOPE = ["read:repository", "run:tests", "deploy:production", "write:secret"]


@pytest.fixture
def path(tmp_path):
    return tmp_path / "audit_trail.jsonl"


@pytest.fixture
def no_container(monkeypatch):
    """Stand in for the sandbox so the control flow can be asserted without Docker.

    Containment is proven in test_sandbox.py against a real container. What is under test here is
    whether anything reaches the sandbox that should not, so the sandbox itself is a spy.
    """
    calls: list[list[str]] = []

    def fake(image, command, workspace, **kw):
        calls.append(command)
        return sandbox.Result("fake", "completed", 0, "", "", 0.0)

    monkeypatch.setattr(sandbox, "run", fake)
    return calls


# ------------------------------------------------------ nothing runs that was not agreed to
def test_an_action_outside_the_agents_scope_never_reaches_the_sandbox(path, no_container, tmp_path):
    run = runner.execute("do a thing", [READ], scope=["run:tests"],
                         workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "refused"
    assert no_container == [], "an undeclared action reached the sandbox"
    assert [e["event"] for e in trail.read_all(path)] == ["decided"]


@needs_opa
def test_a_forbidden_action_never_reaches_the_sandbox(path, no_container, tmp_path):
    run = runner.execute("read the customers", [SECRET], scope=SCOPE,
                         workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "refused"
    assert no_container == [], "a forbidden action reached the sandbox"
    assert trail.read_all(path)[0]["outcome"] == "forbidden"


@needs_opa
def test_a_gated_action_with_no_approver_never_reaches_the_sandbox(path, no_container, tmp_path):
    run = runner.execute("ship it", [DEPLOY], scope=SCOPE,
                         workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "needs_approval"
    assert no_container == [], "a gated action ran without an approver"
    assert trail.unresolved(path) == [], "halting is the platform working, not a finding"


@needs_opa
def test_a_gated_action_with_an_approver_runs_and_names_them(path, no_container, tmp_path):
    run = runner.execute("ship it", [DEPLOY], scope=SCOPE, workspace=tmp_path,
                         trail_path=path, approvals={"deploy:production": "r.okonkwo"})

    assert run.stopped_because == "completed"
    assert all(e["approver"] == "r.okonkwo" for e in trail.read_all(path))
    assert trail.unresolved(path) == []


@needs_opa
def test_a_refusal_stops_the_rest_of_the_list(path, no_container, tmp_path):
    run = runner.execute("do four things", [READ, SECRET, TESTS, TESTS],
                         scope=SCOPE, workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "refused"
    assert len(no_container) == 1, "the run continued past a refusal"
    assert len(run.steps) == 2


# ------------------------------------------------------ the record is written, and in order
@needs_opa
def test_every_executed_action_has_a_decision_recorded_before_it(path, no_container, tmp_path):
    runner.execute("do two things", [READ, TESTS], scope=SCOPE,
                   workspace=tmp_path, trail_path=path)

    events = [(e["seq"], e["event"]) for e in trail.read_all(path)]
    assert [e for _, e in events] == ["decided", "executed", "decided", "executed"]
    assert gate.check(path) == []


@needs_opa
def test_a_failing_step_is_recorded_as_failed_and_stops_the_run(path, monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox, "run", lambda *a, **k: sandbox.Result(
        "fake", "completed", 1, "", "boom", 0.0))

    run = runner.execute("do two things", [READ, TESTS], scope=SCOPE,
                         workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "failed"
    assert [e["event"] for e in trail.read_all(path)] == ["decided", "failed"]
    assert run.executed == ()


@needs_opa
def test_the_policy_being_unreachable_stops_everything(path, no_container, tmp_path, monkeypatch):
    """Fail closed. A policy engine that is down must not become a permissive one."""
    def unavailable(verb, target):
        raise evaluate.PolicyUnavailable("opa is not on PATH")

    monkeypatch.setattr(evaluate, "decide", unavailable)

    with pytest.raises(evaluate.PolicyUnavailable):
        runner.execute("do a thing", [READ], scope=SCOPE, workspace=tmp_path, trail_path=path)

    assert no_container == []


@needs_opa
def test_the_step_limit_bounds_breadth(path, no_container, tmp_path):
    run = runner.execute("do it forever", [TESTS] * 5, scope=SCOPE,
                         workspace=tmp_path, trail_path=path, max_steps=2)

    assert run.stopped_because == "step_limit"
    assert len(no_container) == 2


# ------------------------------------------------------ end to end, against a real container
@needs_docker
@needs_opa
def test_a_real_run_executes_in_a_container_and_leaves_a_trail(path, tmp_path):
    run = runner.execute(
        "run the tests", [runner.Action("run", "tests", ["python", "-c", "print('ok')"])],
        scope=["run:tests"], workspace=tmp_path, trail_path=path)

    assert run.stopped_because == "completed"
    assert run.executed[0].result.stdout.strip() == "ok"
    assert gate.check(path) == []


# ------------------------------------------------------ the invariant, structurally
def test_nothing_outside_the_runtime_calls_the_sandbox_directly():
    """An action must not be able to reach a container except through execute()."""
    allowed = {REPO / "runtime" / "runner.py", REPO / "runtime" / "sandbox.py"}
    offenders = []

    for source in REPO.rglob("*.py"):
        if source in allowed or "tests" in source.parts or ".venv" in source.parts:
            continue
        if "sandbox.run(" in source.read_text(encoding="utf-8"):
            offenders.append(str(source.relative_to(REPO)))

    assert offenders == [], f"these call the sandbox without going through the runtime: {offenders}"
