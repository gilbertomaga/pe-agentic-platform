"""
The sandbox: one container per run, created and destroyed.

Decision D1 (docs/decisions.md): the sandbox has zero egress. Anything that needs the outside
world, the model call included, is done by the orchestrator outside this boundary and passed in.
That makes the isolation claim simple enough to defend: the container cannot reach anything.

The container flags below are the isolation model. They are not configuration to tune, they are
the thing a client security lead reads.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

#: Wall clock limit for a single run. The step limit bounds breadth; this bounds duration.
#: A step that never returns is the failure that takes a platform down at 3am, and it is the
#: stop condition most runtimes forget.
DEFAULT_TIMEOUT_SECONDS = 120

DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS = 128

WORKSPACE = "/workspace"


@dataclass(frozen=True)
class Result:
    run_id: str
    stopped_because: str  # completed | timeout | denied | error
    exit_code: int | None
    stdout: str
    stderr: str
    seconds: float


def docker_argv(
    run_id: str,
    image: str,
    command: list[str],
    workspace: Path,
    writable: bool = False,
    memory: str = DEFAULT_MEMORY,
    cpus: str = DEFAULT_CPUS,
    pids: int = DEFAULT_PIDS,
) -> list[str]:
    """Build the container invocation.

    Pure, so the isolation model can be asserted in tests without Docker running.
    """
    mount = f"{workspace.resolve()}:{WORKSPACE}" + ("" if writable else ":ro")
    return [
        "docker", "run",
        "--rm",                              # teardown is not optional
        "--name", f"run-{run_id}",
        "--network", "none",                 # D1: zero egress
        "--read-only",                       # root filesystem is immutable
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--user", "65534:65534",             # nobody, never root
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", memory,
        "--cpus", cpus,
        "--pids-limit", str(pids),
        "--workdir", WORKSPACE,
        "--volume", mount,
        image,
        *command,
    ]


def available() -> bool:
    """Is a Docker daemon reachable?"""
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "info"], capture_output=True, text=True)
    return probe.returncode == 0


def run(
    image: str,
    command: list[str],
    workspace: Path,
    run_id: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    **limits,
) -> Result:
    """Execute one command inside a fresh container, and destroy it afterwards."""
    run_id = run_id or uuid.uuid4().hex[:12]
    argv = docker_argv(run_id, image, command, workspace, **limits)
    started = time.monotonic()

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        _kill(run_id)
        return Result(
            run_id=run_id,
            stopped_because="timeout",
            exit_code=None,
            stdout=_text(expired.stdout),
            stderr=_text(expired.stderr),
            seconds=time.monotonic() - started,
        )
    except OSError as err:
        return Result(run_id, "error", None, "", str(err), time.monotonic() - started)

    return Result(
        run_id=run_id,
        stopped_because="completed",
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        seconds=time.monotonic() - started,
    )


def _kill(run_id: str) -> None:
    subprocess.run(["docker", "kill", f"run-{run_id}"], capture_output=True)


def _text(raw) -> str:
    if raw is None:
        return ""
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
