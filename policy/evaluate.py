"""
Evaluating the policy from Python.

The policy lives in Rego and is tested by OPA. This is the thin way the runtime and the golden
path ask it a question. It shells out rather than reimplementing the rules, because two copies of
a guardrail drift and the Rego is the one a security lead reads.

If OPA is not on PATH this raises rather than falling back to a permissive answer. A policy engine
that fails open is worse than none, because everybody believes it is there.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

POLICY_DIR = Path(__file__).parent
QUERY = "data.agent.policy.decision"

#: The client's compliance controls, kept in their own file and their own package so that
#: changing them is not a change to the platform's guardrail. See docs/decisions.md D15.
COMPLIANCE_QUERY = "data.compliance.policy.decision"


class PolicyUnavailable(RuntimeError):
    """OPA could not be reached. Deny, do not guess."""


@lru_cache(maxsize=1)
def _opa() -> str:
    found = shutil.which("opa") or os.environ.get("OPA_BIN")
    if not found:
        raise PolicyUnavailable(
            "opa is not on PATH. Install it, or set OPA_BIN to the binary.")
    return found


def _ask(rego: str, query: str, probe: dict) -> dict:
    try:
        result = subprocess.run(
            [_opa(), "eval", "-d", str(POLICY_DIR / rego),
             "-I", query, "--format", "raw"],
            input=json.dumps(probe), capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise PolicyUnavailable(str(err)) from err

    if result.returncode != 0:
        raise PolicyUnavailable(result.stderr.strip() or "opa eval failed")

    return json.loads(result.stdout.strip())


def decide(verb: str, target: str) -> dict:
    """Ask the policy about one action. Returns {'outcome': ..., 'reason': ...}."""
    return _ask("agent.rego", QUERY, {"verb": verb, "target": target})


def comply(outcome: str, verb: str, target: str,
           requested_by: str | None, approver: str | None) -> dict:
    """Ask the client's compliance controls about the people around one action.

    Separate from `decide` because they answer different questions and belong to different
    owners. `decide` is the platform's guardrail. This is the client's control set, and on a
    real engagement it is the file that gets replaced wholesale when their framework changes.
    """
    return _ask("compliance.rego", COMPLIANCE_QUERY, {
        "outcome": outcome,
        "verb": verb,
        "target": target,
        "requested_by": requested_by or "",
        "approver": approver or "",
    })


def available() -> bool:
    try:
        _opa()
        return True
    except PolicyUnavailable:
        return False
