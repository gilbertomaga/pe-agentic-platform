"""
The isolation model, asserted.

These tests exist so the containment claim is checkable rather than described. The first group
needs no Docker: the flags are what the isolation is, so they are tested as data.
"""
from pathlib import Path

import pytest

from runtime import sandbox


@pytest.fixture
def argv(tmp_path):
    return sandbox.docker_argv("abc123", "python:3.12-slim", ["python", "-c", "print(1)"], tmp_path)


def pair(argv, flag):
    """The value following a flag, or None."""
    return argv[argv.index(flag) + 1] if flag in argv else None


def test_the_sandbox_has_no_network(argv):
    """D1: zero egress. The orchestrator reaches the outside world, the container never does."""
    assert pair(argv, "--network") == "none"


def test_the_container_is_destroyed(argv):
    """Teardown is not a step anyone can forget."""
    assert "--rm" in argv


def test_the_agent_is_not_root(argv):
    assert pair(argv, "--user") == "65534:65534"


def test_the_root_filesystem_is_immutable(argv):
    assert "--read-only" in argv


def test_capabilities_are_dropped(argv):
    assert pair(argv, "--cap-drop") == "ALL"
    assert pair(argv, "--security-opt") == "no-new-privileges"


def test_resources_are_bounded(argv):
    assert pair(argv, "--memory") == sandbox.DEFAULT_MEMORY
    assert pair(argv, "--cpus") == sandbox.DEFAULT_CPUS
    assert pair(argv, "--pids-limit") == str(sandbox.DEFAULT_PIDS)


def test_the_workspace_is_read_only_unless_asked(tmp_path):
    ro = sandbox.docker_argv("r", "img", ["true"], tmp_path)
    rw = sandbox.docker_argv("r", "img", ["true"], tmp_path, writable=True)
    assert pair(ro, "--volume").endswith(":ro")
    assert not pair(rw, "--volume").endswith(":ro")


# --------------------------------------------------------------- needs Docker
needs_docker = pytest.mark.skipif(not sandbox.available(), reason="no Docker daemon")


@needs_docker
def test_a_run_completes_and_is_torn_down(tmp_path):
    out = sandbox.run("python:3.12-slim", ["python", "-c", "print('hello')"], tmp_path)
    assert out.stopped_because == "completed"
    assert out.exit_code == 0
    assert "hello" in out.stdout


@needs_docker
def test_the_sandbox_cannot_reach_the_network(tmp_path):
    """The containment claim, proven rather than asserted."""
    probe = ["python", "-c",
             "import socket;socket.create_connection(('1.1.1.1',53),timeout=5)"]
    out = sandbox.run("python:3.12-slim", probe, tmp_path, timeout=30)
    assert out.exit_code != 0, "the sandbox reached the network"


@needs_docker
def test_a_hung_step_is_stopped_by_the_clock(tmp_path):
    """The fourth stop condition: a step limit bounds breadth, not duration."""
    out = sandbox.run("python:3.12-slim", ["sleep", "60"], tmp_path, timeout=5)
    assert out.stopped_because == "timeout"
    assert out.seconds < 20
