"""
The audit gate: un-recorded change does not ship.

A trail nobody checks is a log. The gate is what turns it into a control, and it runs in CI on
every change rather than when somebody remembers to look.

It fails on three things:

  a broken chain, which means a record was edited or removed
  an action that needed a human, went ahead, and cannot name who approved it
  a run that executed without a decision recorded first
"""
from __future__ import annotations

import sys
from pathlib import Path

from trail import trail


def check(path: Path = trail.DEFAULT_TRAIL) -> list[str]:
    """Every reason the gate would stop a change. Empty means it passes."""
    problems: list[str] = []

    for fault in trail.verify(path):
        problems.append(f"record {fault.seq}: {fault.why}")

    for entry in trail.unresolved(path):
        problems.append(
            f"record {entry['seq']}: {entry['verb']} {entry['target']} went ahead "
            f"without a named approver"
        )

    decided = {(e["run_id"], e["step"]) for e in trail.read_all(path) if e["event"] == "decided"}
    for entry in trail.read_all(path):
        if entry["event"] == "executed" and (entry["run_id"], entry["step"]) not in decided:
            problems.append(
                f"record {entry['seq']}: executed with no decision recorded before it"
            )

    return problems


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = Path(argv[0]) if argv else trail.DEFAULT_TRAIL

    if not path.exists():
        print(f"no trail at {path}; nothing to gate")
        return 0

    problems = check(path)
    if problems:
        print(f"AUDIT GATE FAILED ({len(problems)}):")
        for p in problems:
            print(f"  {p}")
        return 1

    total = len(trail.read_all(path))
    print(f"audit gate clear: {total} records, chain intact, 0 unnamed approvals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
