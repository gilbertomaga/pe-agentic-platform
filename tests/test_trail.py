"""
The trail, asserted.

The tests that matter are the tampering ones. A trail that cannot detect an edit is a log with
extra steps.
"""
import json

import pytest

from trail import gate, trail


@pytest.fixture
def path(tmp_path):
    return tmp_path / "audit_trail.jsonl"


def write_run(path, approver=None):
    trail.append("RUN-1", 1, "ship the fix", "read", "repository",
                 "allow", "permitted inside the sandbox", "decided", path=path)
    trail.append("RUN-1", 1, "ship the fix", "read", "repository",
                 "allow", "permitted inside the sandbox", "executed", path=path)
    trail.append("RUN-1", 2, "ship the fix", "deploy", "production",
                 "human_gated", "requires a named human approver", "decided",
                 approver=approver, path=path)
    trail.append("RUN-1", 2, "ship the fix", "deploy", "production",
                 "human_gated", "requires a named human approver", "executed",
                 approver=approver, path=path)


def test_the_chain_starts_from_genesis(path):
    first = trail.append("R", 1, "p", "read", "repository", "allow", "ok", "decided", path=path)
    assert first["prev_hash"] == trail.GENESIS
    assert first["seq"] == 1


def test_each_record_follows_the_one_before(path):
    write_run(path, approver="r.okonkwo")
    records = trail.read_all(path)
    for earlier, later in zip(records, records[1:]):
        assert later["prev_hash"] == earlier["hash"]
    assert trail.verify(path) == []


def test_an_edited_record_breaks_the_chain(path):
    """The property a log does not have."""
    write_run(path, approver="r.okonkwo")
    records = trail.read_all(path)
    records[1]["approver"] = "someone.else"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    faults = trail.verify(path)
    assert faults, "an edited record was not detected"
    assert any("hash" in f.why for f in faults)


def test_a_removed_record_breaks_the_chain(path):
    write_run(path, approver="r.okonkwo")
    records = trail.read_all(path)
    del records[1]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    assert trail.verify(path), "a removed record was not detected"


def test_truncation_is_detected(path):
    """The one tamper a chain cannot see from inside.

    Delete the newest record and every remaining one still links correctly, so verify() has
    nothing to complain about until it checks the anchor. This is the whole reason the head is
    written separately, and it went untested until the claim was audited.
    """
    write_run(path, approver="r.okonkwo")
    rows = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(rows[:-1]) + "\n", encoding="utf-8")

    faults = trail.verify(path)
    assert faults, "the newest record was removed and nothing noticed"
    assert any("removed from the end" in f.why for f in faults)


def test_removing_the_whole_trail_is_detected(path):
    """An anchor with no trail is not an empty platform, it is an erased one."""
    write_run(path, approver="r.okonkwo")
    path.unlink()

    assert trail.head_path(path).exists(), "the anchor is what is left to catch this"
    assert gate.check(path), "the trail was deleted and the gate said nothing"
    assert gate.main([str(path)]) == 1


def test_a_platform_with_no_trail_and_no_anchor_passes(path):
    """Nothing has run yet. That is not a tamper, and the gate must not cry wolf about it."""
    assert not path.exists()
    assert gate.main([str(path)]) == 0


def test_an_approved_action_names_the_approver(path):
    write_run(path, approver="r.okonkwo")
    deploy = [e for e in trail.find("RUN-1", path) if e["verb"] == "deploy"]
    assert all(e["approver"] == "r.okonkwo" for e in deploy)
    assert trail.unresolved(path) == []


def test_an_action_that_went_ahead_unnamed_is_found(path):
    """What must be zero for a regulated client."""
    write_run(path, approver=None)
    assert len(trail.unresolved(path)) == 1


def test_a_halted_action_is_not_a_finding(path):
    """Halting is the platform working. Only proceeding unnamed counts against you."""
    trail.append("RUN-2", 1, "ship it", "deploy", "production",
                 "human_gated", "requires a named human approver", "decided", path=path)
    assert trail.unresolved(path) == []


# ------------------------------------------------------------------ the gate
def test_the_gate_passes_a_clean_trail(path):
    write_run(path, approver="r.okonkwo")
    assert gate.check(path) == []


def test_the_gate_stops_an_unnamed_approval(path):
    write_run(path, approver=None)
    assert any("without a named approver" in p for p in gate.check(path))


def test_the_gate_stops_a_tampered_trail(path):
    write_run(path, approver="r.okonkwo")
    records = trail.read_all(path)
    del records[2]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    assert gate.check(path)


def test_the_gate_stops_execution_with_no_decision(path):
    """An action cannot execute without a decision recorded before it."""
    trail.append("RUN-3", 1, "sneak it", "deploy", "production",
                 "allow", "no decision was recorded", "executed",
                 approver="someone", path=path)
    assert any("no decision recorded" in p for p in gate.check(path))


def test_editing_the_supply_chain_evidence_breaks_the_chain(tmp_path):
    """The evidence is inside the hash, so which image a run claims cannot be adjusted later.

    This is the whole reason the signed field set changed rather than the field being bolted on
    outside it. A digest an auditor can rewrite proves nothing about what ran.
    """
    path = tmp_path / "audit_trail.jsonl"
    trail.append("r1", 1, "p", "read", "repository", "allow", "fine", "executed",
                 evidence={"image": "python@sha256:" + "a" * 64}, path=path)
    assert trail.verify(path) == []

    record = json.loads(path.read_text(encoding="utf-8").strip())
    record["evidence"]["image"] = "python@sha256:" + "b" * 64
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    faults = trail.verify(path)
    assert faults, "the evidence was rewritten and the chain did not notice"
    assert "do not match" in faults[0].why


def test_a_record_from_before_the_field_change_is_named_rather_than_guessed_at(tmp_path):
    """A wall of "contents do not match" sends somebody hunting for an edit that never happened.

    The one case this platform can tell apart is its own field change, so it says so instead.
    """
    path = tmp_path / "audit_trail.jsonl"
    entry = {
        "seq": 1, "prev_hash": trail.GENESIS, "at": "2026-11-12T10:00:00.000+00:00",
        "run_id": "r1", "step": 1, "prompt": "p", "verb": "read", "target": "repository",
        "outcome": "allow", "reason": "fine", "approver": None, "event": "executed",
    }
    entry["hash"] = trail._digest(entry, trail.SIGNED_BEFORE_EVIDENCE)
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    trail.head_path(path).write_text(
        json.dumps({"seq": 1, "hash": entry["hash"]}), encoding="utf-8")

    faults = trail.verify(path)
    assert faults, "a record written under the old shape should not verify under the new one"
    assert "before 2026-11-16" in faults[0].why
