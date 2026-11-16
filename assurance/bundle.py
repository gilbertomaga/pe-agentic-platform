"""
The assurance bundle: one change, everything that was proved about it, in the client's shape.

Module 3 made the platform traceable. The trail answers "what did the agent do" perfectly and
answers nothing a risk function actually asks. It is one file, it grows forever, it has no notion
of a change, it carries no quality or security or compliance evidence, and it lives in the
storage of the party being audited. A regulated client does not accept an audit record held by
the people it is auditing, and they are right not to.

So the platform assembles a bundle per run, maps it to the client's controls, and hands it over.
Four properties, each of which is a decision rather than a detail:

  Reproducible. The bundle carries no assembly timestamp, no path, nothing about the machine that
  built it. Assemble it again from the same evidence and the bytes are identical, so its digest
  is something a person who was not there can re-derive and check. When this proved awkward it
  was the right thing and the timestamp went in the receipt, which is about the act of landing a
  bundle rather than about the change.

  Content addressed. The bundle's name is its own digest, so a store cannot hold two different
  bundles under one name, and an altered bundle is a bundle with a different name.

  It always lands, pass or fail. A failing change produces a bundle that says which control
  failed and why, and it goes to the evidence store like any other. Suppressing it would leave an
  evidence store containing only successes, which is a marketing database with an audit trail's
  filename. What blocks the change is the gate reading the bundle, not the bundle going missing.

  Published shape. `STEP_FIELDS` is a contract with the three roles downstream that consume this,
  so the trail's internal record can change without breaking them, and adding a field to the
  trail does not silently leak into what a client's auditor receives. There is a test for that.

See docs/decisions.md D11.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

from assurance import catalog as catalog_module
from assurance import collect
from trail import trail

#: The shape the Product Builder, Outcome Lead and FDE bundles consume. Changing it is a contract
#: break with three other pathways, not a refactor, so it is written down and asserted.
STEP_FIELDS = ("step", "at", "prompt", "action", "decision", "reason",
               "approver", "executed", "ran_on", "records")

#: Changing the bundle shape needs this bumped and the consumers told. The trail taught this
#: lesson at some cost on 2026-11-16; it is cheaper to learn it once. See D10 and D11.
BUNDLE_VERSION = 1


def _steps(records: list[dict]) -> list[dict]:
    """Project trail records into the published shape: prompt, action, decision, approval.

    One action is two records, decided and then executed. An auditor reads one line per action,
    not a pair they have to join themselves, so the join happens here and the bundle says plainly
    whether the thing that was allowed actually ran.
    """
    by_step: dict[int, dict] = {}
    for record in sorted(records, key=lambda r: r["seq"]):
        step = record["step"]
        slot = by_step.setdefault(step, {
            "step": step,
            "at": record["at"],
            "prompt": record["prompt"],
            "action": f"{record['verb']} {record['target']}",
            "decision": record["outcome"],
            "reason": record["reason"],
            "approver": record["approver"],
            "executed": False,
            "ran_on": None,
            "records": [],
        })
        slot["records"].append(record["hash"])
        if record["event"] in ("executed", "failed"):
            slot["executed"] = record["event"] == "executed"
            slot["ran_on"] = (record.get("evidence") or {}).get("image_digest")
        if record.get("approver"):
            slot["approver"] = record["approver"]

    steps = [by_step[k] for k in sorted(by_step)]
    for step in steps:
        assert tuple(step) == STEP_FIELDS, "the projection drifted from the published shape"
    return steps


def _attested(control, root: Path, today: date) -> tuple[bool | None, str]:
    """Read an attestation, and refuse one that has gone stale."""
    path = root / control.attestation
    if not path.exists():
        return None, f"no attestation at {control.attestation}; nobody has signed this control"

    import tomllib
    with open(path, "rb") as fh:
        signed = tomllib.load(fh)

    who, when = signed.get("accepted_by"), signed.get("on")
    if not who or not when:
        return False, f"{control.attestation} does not say who accepted it, or when"
    if signed.get("control") != control.id:
        return False, (f"{control.attestation} attests to {signed.get('control')}, "
                       f"not to {control.id}")

    on = date.fromisoformat(str(when))
    expires = on + timedelta(days=control.valid_days)
    if today > expires:
        return False, (f"accepted by {who} on {on.isoformat()}, expired {expires.isoformat()}. "
                       "An attestation older than the platform it describes is a historical "
                       "document, not evidence.")
    return True, f"accepted by {who} on {on.isoformat()}, valid to {expires.isoformat()}"


def assess(control, facts: dict[str, collect.Fact], root: Path, today: date) -> dict:
    """One control, its evidence, and whether it held. The mapping an auditor reads."""
    if control.gap:
        held, detail, state = None, control.gap, "declared_gap"
    elif control.attestation:
        held, detail = _attested(control, root, today)
        state = {True: "attested", False: "not_held", None: "not_evidenced"}[held]
    else:
        fact = facts[control.fact]
        held, detail, state = fact.held, fact.detail, fact.state

    return {
        "control": control.id,
        "statement": control.statement,
        "satisfied_by": control.kind,
        "evidence": control.fact or control.attestation or None,
        "state": state,
        "detail": detail,
        "blocking": control.blocking,
    }


def assemble(
    run_id: str,
    evidence_dir: Path,
    subject: dict,
    trail_path: Path = trail.DEFAULT_TRAIL,
    catalog_path: Path = catalog_module.DEFAULT_CATALOG,
    today: date | None = None,
) -> dict:
    """Everything proved about one run, mapped to the client's controls.

    `subject` is what the pipeline knows and the platform does not: which commit, which build,
    which repository. It is passed in rather than read from the environment so that assembling
    the same bundle twice gives the same bytes on any machine.
    """
    today = today or datetime.now().date()
    catalog = catalog_module.load(catalog_path)
    facts = collect.facts(run_id, evidence_dir, trail_path)
    records = trail.find(run_id, trail_path)

    assessed = [assess(c, facts, catalog_path.parent, today) for c in catalog.controls]
    anchor_path = trail.head_path(trail_path)
    anchor = (json.loads(anchor_path.read_text(encoding="utf-8"))
              if anchor_path.exists() else None)

    return {
        "bundle_version": BUNDLE_VERSION,
        "subject": dict(sorted(subject.items())) | {"run_id": run_id},
        "traceability": {
            "steps": _steps(records),
            # The bundle quotes the chain rather than copying it. Edit the trail afterwards and
            # these hashes stop matching it, which is the point: the bundle is pinned to a
            # position in a chain, not to a copy of some records.
            "chain": {
                "records": len(records),
                "first_seq": records[0]["seq"] if records else None,
                "last_seq": records[-1]["seq"] if records else None,
                "head_anchor": anchor,
            },
        },
        "evidence": {key: {"state": fact.state, "detail": fact.detail}
                     for key, fact in sorted(facts.items())},
        "controls": {
            "catalog": {"version": catalog.version,
                        "framework": catalog.framework,
                        "source": catalog.source},
            "assessed": assessed,
            "summary": _summary(assessed),
        },
    }


def _summary(assessed: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for entry in assessed:
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    return {"total": len(assessed),
            "by_state": dict(sorted(counts.items())),
            "blocking_failures": len(_failures(assessed))}


def _failures(assessed: list[dict]) -> list[dict]:
    return [e for e in assessed
            if e["blocking"] and e["state"] not in ("held", "attested")]


def blocking_failures(bundle: dict) -> list[str]:
    """Why this change does not ship. Empty means it does."""
    return [f"{e['control']} is {e['state']}: {e['detail']}"
            for e in _failures(bundle["controls"]["assessed"])]


def canonical(bundle: dict) -> bytes:
    """The bytes that get hashed and stored. Same convention as the trail, for the same reason."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(bundle: dict) -> str:
    return hashlib.sha256(canonical(bundle)).hexdigest()


def name(bundle: dict) -> str:
    """Content addressed: the bundle's name is what is in it."""
    return f"{bundle['subject']['run_id']}.{digest(bundle)}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble the assurance bundle for one run.")
    parser.add_argument("run_id")
    parser.add_argument("--evidence", type=Path, required=True,
                        help="directory the pipeline steps wrote their results into")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory to write the bundle into")
    parser.add_argument("--trail", type=Path, default=trail.DEFAULT_TRAIL)
    parser.add_argument("--catalog", type=Path, default=catalog_module.DEFAULT_CATALOG)
    parser.add_argument("--commit", default="")
    parser.add_argument("--repository", default="")
    parser.add_argument("--build", default="")
    args = parser.parse_args(argv)

    bundle = assemble(
        args.run_id, args.evidence,
        subject={"commit": args.commit, "repository": args.repository, "build": args.build},
        trail_path=args.trail, catalog_path=args.catalog)

    args.out.mkdir(parents=True, exist_ok=True)
    written = args.out / name(bundle)
    written.write_bytes(canonical(bundle))

    summary = bundle["controls"]["summary"]
    print(f"bundle {written.name}")
    print(f"  {summary['total']} controls: " +
          ", ".join(f"{n} {state}" for state, n in summary["by_state"].items()))

    failures = blocking_failures(bundle)
    if failures:
        # The bundle is already written. It lands whether or not the change ships, because an
        # evidence store that only ever receives passes is not evidence of anything.
        print(f"\nBLOCKED ({len(failures)}):")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print("  no blocking control failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
