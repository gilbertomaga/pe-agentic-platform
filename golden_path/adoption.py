"""
Adoption: are people using the path, or going around it?

The criterion asks for a measure of whether Builders choose the path or route around it, and the
first half was easy enough that it hid the second. Counting who came through is trivial, because
provisioning writes its own record. That number on its own is a vanity metric: it goes up whether
adoption is total or negligible, and it cannot go down.

The number that means something is the other one, agents that exist and never came through. Those
are the ones running with no sandbox binding, no policy check and no trail, which is the OWASP
ASI10 row in practice rather than in theory.

What this can see, honestly:

  An agent directory that exists with no provisioning record is somebody who copied a template
  instead of walking the path. That is the route-around at the scale this platform is at, and it
  is real: it is measured here, not asserted.

  Nothing in this process can see an agent on somebody else's laptop, in another repository, or
  called straight from a CI job. No code inside the platform ever could. So the denominator is
  only as wide as the inventory handed to it, and with no inventory it is this host alone. The
  report says which it is, every time, because a coverage number that does not state its
  denominator is worse than no number.

  Provisioning attempts that stopped at a gate are counted too. They are not failures of the
  platform, they are its friction, and friction is what makes a Builder look for the way around.
  A rising number here is the leading indicator of a falling number above.

    python -m golden_path.adoption [inventory-file]
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from golden_path.new_agent import AGENTS
from trail import trail

PROVISION_PREFIX = "provision-"


@dataclass(frozen=True)
class Census:
    through: tuple[str, ...]
    outside: tuple[str, ...]
    stopped_at_a_gate: int
    denominator: str

    @property
    def total(self) -> int:
        return len(self.through) + len(self.outside)

    @property
    def share(self) -> float | None:
        """Share of known agents that came through the path. None when nothing is known yet."""
        return (len(self.through) / self.total) if self.total else None


def _name(run_id: str) -> str:
    return run_id[len(PROVISION_PREFIX):]


def through_the_path(path: Path = trail.DEFAULT_TRAIL) -> set[str]:
    """Agents with a provisioning record that actually cleared the gates."""
    return {
        _name(e["run_id"]) for e in trail.read_all(path)
        if e["run_id"].startswith(PROVISION_PREFIX)
        and e["event"] == "executed" and e["outcome"] == "allow"
    }


def stopped_at_a_gate(path: Path = trail.DEFAULT_TRAIL) -> int:
    """Provisioning attempts the path refused. Friction, not failure."""
    return len([
        e for e in trail.read_all(path)
        if e["run_id"].startswith(PROVISION_PREFIX) and e["outcome"] == "deny"
    ])


def on_disk(root: Path = AGENTS) -> set[str]:
    if not Path(root).exists():
        return set()
    return {d.name for d in Path(root).iterdir() if (d / "agent.toml").exists()}


def read_inventory(path: Path) -> set[str]:
    """An externally gathered list of agents, one name per line. Widens the denominator."""
    return {
        line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def census(
    trail_path: Path = trail.DEFAULT_TRAIL,
    agents_root: Path = AGENTS,
    inventory: Path | None = None,
) -> Census:
    known = on_disk(agents_root)
    denominator = "this host only"

    if inventory:
        known |= read_inventory(inventory)
        denominator = f"this host plus {inventory}"

    provisioned = through_the_path(trail_path)
    return Census(
        through=tuple(sorted(provisioned)),
        outside=tuple(sorted(known - provisioned)),
        stopped_at_a_gate=stopped_at_a_gate(trail_path),
        denominator=denominator,
    )


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    result = census(inventory=Path(argv[0]) if argv else None)

    print("adoption census")
    print(f"  through the golden path   {len(result.through)}")
    print(f"  outside it                {len(result.outside)}"
          + (f"   {', '.join(result.outside)}" if result.outside else ""))
    print(f"  stopped at a gate         {result.stopped_at_a_gate}")

    if result.share is None:
        print("\nno agents known yet, so there is nothing to report a share of.")
    else:
        print(f"\n{result.share:.0%} of known agents came through the path.")

    print(f"denominator: {result.denominator}. Agents this process cannot see are not counted,")
    print("and no code inside the platform could see them. Widen it with an inventory file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
