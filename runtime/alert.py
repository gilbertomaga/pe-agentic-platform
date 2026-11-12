"""
Alerting on an attempted escape.

The criterion is "an attempted escape is alerted and blocked", and until now only the second half
was true. Blocking was proven in CI; the attempt went into the trail and stopped there. A trail is
read afterwards, by someone who already suspects something. An alert is what reaches a person who
does not yet know to look, and the gap between the two is the whole point.

What counts as an attempt, and what deliberately does not:

  forbidden, deny and out_of_scope are attempts. The agent asked for something it was never
  entitled to, whether the platform forbids it outright, has no rule for it, or the agent itself
  never declared it. One is a bug in a plan. A handful in a run is an agent probing.

  human_gated with nobody to approve it is not an attempt. It is the gate working exactly as
  designed, and paging someone every time a deploy waits for its approver is how an alert channel
  becomes noise that nobody reads. The same distinction `trail.unresolved` already makes.

Where an alert goes is deliberately not a vendor. It is written to stderr, and to a JSONL file when
PLATFORM_ALERT_FILE names one, because every collector in use anywhere reads one of those two. The
day this needs to reach a specific SIEM, that is a sink added here and nothing else changes.

A sink that fails must never swallow the refusal. The action was already blocked and already
recorded before anything here is called, so a broken alerting path degrades the signal and not the
control.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

#: Outcomes that mean the agent reached for something it was not entitled to.
ESCAPE_OUTCOMES = frozenset({"forbidden", "deny", "out_of_scope"})

ALERT_FILE_ENV = "PLATFORM_ALERT_FILE"


@dataclass(frozen=True)
class Alert:
    at: str
    run_id: str
    step: int
    action: str
    outcome: str
    reason: str

    def line(self) -> str:
        return (f"ESCAPE ATTEMPT BLOCKED  run={self.run_id} step={self.step} "
                f"action={self.action} outcome={self.outcome}: {self.reason}")


def is_escape(outcome: str) -> bool:
    return outcome in ESCAPE_OUTCOMES


def raise_alert(run_id: str, step: int, action: str, outcome: str, reason: str) -> Alert:
    """Signal one blocked attempt. Called after the refusal is already recorded."""
    alert = Alert(
        at=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        run_id=run_id, step=step, action=action, outcome=outcome, reason=reason,
    )

    for sink in (_stderr, _file):
        try:
            sink(alert)
        except Exception as err:  # noqa: BLE001 - a broken sink must not break the refusal
            print(f"alert sink {sink.__name__} failed: {err}", file=sys.stderr)

    return alert


def _stderr(alert: Alert) -> None:
    print(alert.line(), file=sys.stderr)


def _file(alert: Alert) -> None:
    target = os.environ.get(ALERT_FILE_ENV)
    if not target:
        return
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(alert)) + "\n")
