"""
The audit trail.

The platform writes this, not the engineer. That is the whole design principle: if capturing the
trail is a step a person can skip under deadline, it will be skipped, so it must not be a step.

Two properties a log does not have:

  Append only. Records are never updated. An action that is decided and then executes produces two
  records, not one that changes.

  Hash chained. Each record carries the hash of the one before it, so removing or editing a line
  breaks the chain and `verify()` says where. A regulated client does not just need the trail to
  exist, they need to know nobody edited it.

A chain alone does not detect truncation: delete the last record and every remaining one still
links correctly. So the head, the sequence and hash of the newest record, is written separately
and checked. See docs/decisions.md D4 for what that does and does not buy.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TRAIL = Path(__file__).with_name("audit_trail.jsonl")

GENESIS = "0" * 64

#: Fields that are hashed. Order matters and must not change, or every existing chain breaks.
SIGNED = ("seq", "prev_hash", "at", "run_id", "step", "prompt",
          "verb", "target", "outcome", "reason", "approver", "event")


@dataclass(frozen=True)
class Broken:
    seq: int
    why: str


def _digest(entry: dict) -> str:
    payload = json.dumps({k: entry.get(k) for k in SIGNED}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def head_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".head")


def _last(path: Path) -> dict | None:
    if not path.exists():
        return None
    tail = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                tail = json.loads(line)
    return tail


def append(
    run_id: str,
    step: int,
    prompt: str,
    verb: str,
    target: str,
    outcome: str,
    reason: str,
    event: str,
    approver: str | None = None,
    path: Path = DEFAULT_TRAIL,
) -> dict:
    """Write one record. `event` is 'decided', 'executed' or 'failed'.

    Called by the runtime, never by a caller choosing to record. There is no code path that
    executes an action without passing through here.
    """
    previous = _last(path)
    entry = {
        "seq": (previous["seq"] + 1) if previous else 1,
        "prev_hash": previous["hash"] if previous else GENESIS,
        "at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "run_id": run_id,
        "step": step,
        "prompt": prompt,
        "verb": verb,
        "target": target,
        "outcome": outcome,
        "reason": reason,
        "approver": approver,
        "event": event,
    }
    entry["hash"] = _digest(entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    # The anchor that makes truncation visible.
    head_path(path).write_text(
        json.dumps({"seq": entry["seq"], "hash": entry["hash"]}), encoding="utf-8")
    return entry


def read_all(path: Path = DEFAULT_TRAIL) -> list[dict]:
    if not Path(path).exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def find(run_id: str, path: Path = DEFAULT_TRAIL) -> list[dict]:
    """Every record for one run, in order. This is the walk me through it query."""
    return [e for e in read_all(path) if e["run_id"] == run_id]


def verify(path: Path = DEFAULT_TRAIL) -> list[Broken]:
    """Check the chain. An empty list means nothing was edited or removed."""
    faults: list[Broken] = []
    expected_prev = GENESIS
    expected_seq = 1
    for entry in read_all(path):
        if entry.get("seq") != expected_seq:
            faults.append(Broken(entry.get("seq", -1), f"expected seq {expected_seq}"))
        if entry.get("prev_hash") != expected_prev:
            faults.append(Broken(entry.get("seq", -1), "does not follow the previous record"))
        if entry.get("hash") != _digest(entry):
            faults.append(Broken(entry.get("seq", -1), "contents do not match the recorded hash"))
        expected_prev = entry.get("hash")
        expected_seq = entry.get("seq", expected_seq) + 1

    faults.extend(_check_head(path, expected_prev, expected_seq - 1))
    return faults


def _check_head(path: Path, last_hash: str, last_seq: int) -> list[Broken]:
    """Truncation is the one edit a chain cannot see on its own."""
    anchor = head_path(path)
    if not anchor.exists():
        return [] if last_seq == 0 else [Broken(last_seq, "no head anchor to check against")]
    recorded = json.loads(anchor.read_text(encoding="utf-8"))
    if recorded["seq"] != last_seq or recorded["hash"] != last_hash:
        return [Broken(recorded["seq"],
                       f"trail ends at {last_seq} but the head records {recorded['seq']}; "
                       "records were removed from the end")]
    return []


def unresolved(path: Path = DEFAULT_TRAIL) -> list[dict]:
    """Actions that needed a human, went ahead anyway, and cannot name who approved.

    Note what this does not count: an action that needed a human and was correctly stopped. That
    is the platform working. What must be zero is the action that proceeded without a name against
    it, because that is the one an auditor finds and nobody can explain.
    """
    return [e for e in read_all(path)
            if e.get("outcome") == "human_gated"
            and e.get("event") == "executed"
            and not e.get("approver")]
