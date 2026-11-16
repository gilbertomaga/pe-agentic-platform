"""
The exception register: findings somebody looked at and decided to carry, for a while.

This exists because the image gate fired on its first run, against a real vulnerability with a
real fix that is not available in any published base image yet. There were three ways out of
that and two of them were wrong.

Turning the control off would have removed the only thing that found it. Loosening the
threshold would have removed it along with everything else at that severity, which is the same
thing with more steps. So the control stays exactly as it was and the two findings are written
down, by identifier, with the reason, a named person and a date they stop counting.

Four properties, and every one of them is there to stop this becoming the thing it replaced:

  Per finding, never per control. An exception names the findings it covers. A new vulnerability
  in the same image blocks the build on the day it appears, because nobody has looked at it yet.
  "DEMO-SE-02 is excepted" would just be the gate switched off with extra ceremony.

  It expires. Carrying a finding is a decision about today, not a permanent property of it. An
  expired exception stops applying and the control blocks again, which is the only mechanism that
  reliably brings somebody back to a decision they took in a hurry.

  It is never a pass. The control reads `excepted`, not `held`, and every bundle filed in the
  evidence store carries that word, the identifiers and the reason. An auditor reading a year of
  bundles can see exactly how long something was carried and who said so. An exception that
  reads as a pass is how exceptions become permanent.

  It names a person. Not a team, not a ticket on its own. Somebody decided.

See docs/decisions.md D14.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

DEFAULT_REGISTER = Path(__file__).with_name("exceptions.toml")


class RegisterError(Exception):
    """The exception register is not usable, which is a stop rather than an empty register."""


@dataclass(frozen=True)
class Carried:
    control: str
    findings: tuple[str, ...]
    reason: str
    raised_by: str
    raised_on: date
    expires: date

    def live(self, today: date) -> bool:
        return today <= self.expires

    def describe(self, today: date) -> str:
        return (f"{', '.join(self.findings)} carried by {self.raised_by} "
                f"since {self.raised_on.isoformat()}, "
                f"{'expires' if self.live(today) else 'EXPIRED'} {self.expires.isoformat()}: "
                f"{self.reason}")


def load(path: Path = DEFAULT_REGISTER) -> tuple[Carried, ...]:
    """An absent register is an empty one. An unreadable register is a stop.

    Those are different: no exceptions is a normal state, and a register that will not parse
    means nobody can tell which findings are being carried, which is not a state to assess
    controls in.
    """
    if not path.exists():
        return ()
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as broken:
        raise RegisterError(f"{path} does not parse: {broken}") from broken

    carried = []
    for entry in raw.get("exception", []):
        for field in ("control", "findings", "reason", "raised_by", "raised_on", "expires"):
            if not entry.get(field):
                raise RegisterError(
                    f"an exception for {entry.get('control', 'an unnamed control')} has no "
                    f"{field}. Every one of those is the difference between a decision and a "
                    "finding that quietly stopped counting.")
        carried.append(Carried(
            control=entry["control"],
            findings=tuple(entry["findings"]),
            reason=entry["reason"],
            raised_by=entry["raised_by"],
            raised_on=date.fromisoformat(str(entry["raised_on"])),
            expires=date.fromisoformat(str(entry["expires"])),
        ))

    for one in carried:
        if one.expires <= one.raised_on:
            raise RegisterError(
                f"the exception for {one.control} expires on or before the day it was raised")
    return tuple(carried)


def apply(control: str, findings: tuple[str, ...], register: tuple[Carried, ...],
          today: date) -> tuple[bool, str]:
    """Is every finding on this control carried by a live exception, and what to say about it.

    Returns (covered, detail). Covered is only true when nothing is left over: one uncovered
    finding and the control blocks, which is the whole point of writing them down one by one.
    """
    if not findings:
        return False, ""

    relevant = [c for c in register if c.control == control]
    live = {f for c in relevant if c.live(today) for f in c.findings}
    stale = {f for c in relevant if not c.live(today) for f in c.findings}

    uncovered = [f for f in findings if f not in live]
    if uncovered:
        expired = [f for f in uncovered if f in stale]
        note = (f"; the exception for {', '.join(expired)} expired" if expired else "")
        return False, f"not carried: {', '.join(uncovered)}{note}"

    return True, "; ".join(c.describe(today) for c in relevant if c.live(today))
