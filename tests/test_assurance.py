"""
The assurance bundle.

What is asserted here is narrow and deliberate. None of it proves the platform is compliant with
anything; a control catalog is the client's and this repository ships a demonstration one. What
these cover is that the bundle says the same thing twice, that it cannot quietly say something
softer than the evidence, and that the shape three other pathways consume does not drift when
somebody adds a field somewhere else.

Two are structural. One holds the published step shape against the trail's record, because the
cheapest way to break a contract is to add a field to the thing behind it. The other refuses a
catalog that claims to be a client's, because a demonstration control set wearing a real
framework's name is the exact failure this module is supposed to prevent.
"""
from __future__ import annotations

import json
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from assurance import bundle as bundle_module
from assurance import catalog as catalog_module
from assurance import collect, sink
from trail import trail

REPO = Path(__file__).resolve().parent.parent
SHIPPED = catalog_module.DEFAULT_CATALOG

TODAY = date(2026, 11, 16)


# ------------------------------------------------------------------ fixtures

@pytest.fixture
def trail_path(tmp_path):
    """A run that was decided and then executed, as the golden path writes it."""
    path = tmp_path / "audit_trail.jsonl"
    for event in ("decided", "executed"):
        trail.append("run-1", 1, "provision agent probe", "create", "agent",
                     "allow", "provisioned through the golden path", event,
                     evidence={"image": "python@sha256:" + "a" * 64,
                               "image_digest": "sha256:" + "a" * 64},
                     path=path)
    return path


@pytest.fixture
def evidence(tmp_path):
    """What the pipeline steps leave behind, all of them passing."""
    directory = tmp_path / "evidence"
    directory.mkdir()
    (directory / "tests.json").write_text(json.dumps(
        {"passed": 70, "failed": 0, "errors": 0, "skipped": 0,
         "containment_exercised": True}), encoding="utf-8")
    (directory / "quality.json").write_text(json.dumps(
        {"held": True, "comparable": True, "uncovered": 250, "statements": 1000,
         "baseline": 256, "baseline_recorded_on": "2026-11-16", "breaches": [],
         "tests_not_run": []}), encoding="utf-8")
    (directory / "security.json").write_text(json.dumps(
        {"secrets": {"scanner": "gitleaks", "scanned": "history", "findings": 0,
                     "rules": [], "paths": []},
         "image_vulnerabilities": {"scanner": "trivy", "target": "python@sha256:aaa",
                                   "severities": "HIGH,CRITICAL", "total": 4,
                                   "fixable": 0, "unfixable": 4, "fixable_ids": []}}),
        encoding="utf-8")
    (directory / "supply.json").write_text(json.dumps(
        {"image": "python@sha256:" + "a" * 64,
         "policy_engine_verified": True,
         "policy_engine_version": "v1.22.4",
         "bill_of_materials": {"format": "cyclonedx-json", "components": 180,
                               "sha256": "b" * 64}}), encoding="utf-8")
    return directory


@pytest.fixture
def catalog(tmp_path):
    """A small catalog with one of each kind, so the states are reachable in a test."""
    path = tmp_path / "controls.toml"
    path.write_text(
        'version = "test-1"\n'
        'framework = "test"\n'
        'source = "written for this test"\n'
        '[[control]]\nid = "T-1"\nstatement = "Recorded."\n'
        'fact = "trail.run_recorded"\nblocking = true\n'
        '[[control]]\nid = "T-2"\nstatement = "Tested."\n'
        'fact = "tests.all_passed"\nblocking = true\n'
        '[[control]]\nid = "T-3"\nstatement = "Signed off."\n'
        'attestation = "att.toml"\nvalid_days = 30\nblocking = true\n'
        '[[control]]\nid = "T-4"\nstatement = "Not met yet."\n'
        'gap = "named and tracked"\nblocking = false\n', encoding="utf-8")
    (tmp_path / "att.toml").write_text(
        'control = "T-3"\naccepted_by = "A Person"\non = "2026-11-01"\n', encoding="utf-8")
    return path


def build(evidence, trail_path, catalog, today=TODAY):
    return bundle_module.assemble(
        "run-1", evidence, subject={"commit": "abc123", "repository": "r", "build": "7"},
        trail_path=trail_path, catalog_path=catalog, today=today)


# -------------------------------------------------- the catalog refuses nonsense

def test_the_shipped_catalog_loads():
    loaded = catalog_module.load(SHIPPED)
    assert loaded.controls
    assert all(c.kind in ("fact", "attestation", "gap") for c in loaded.controls)


def test_the_shipped_catalog_does_not_claim_to_be_a_client_framework():
    """Structural. A demonstration control set wearing a real regime's name is the failure."""
    loaded = catalog_module.load(SHIPPED)
    assert "demonstration" in loaded.source.lower() or "not taken from" in loaded.source.lower()
    for regime in ("SOC 2", "SOC2", "ISO 27001", "PCI-DSS", "NIST", "HIPAA"):
        assert regime.lower() not in loaded.framework.lower(), (
            f"the shipped catalog claims to be {regime}, which it is not")


def test_a_control_mapped_to_evidence_nobody_produces_is_a_load_error(tmp_path):
    """Otherwise it reads as unmet forever while looking like a data problem."""
    path = tmp_path / "c.toml"
    path.write_text('version = "v"\nframework = "f"\nsource = "s"\n'
                    '[[control]]\nid = "X"\nstatement = "s"\nfact = "nothing.produces.this"\n',
                    encoding="utf-8")
    with pytest.raises(catalog_module.CatalogError) as refused:
        catalog_module.load(path)
    assert "does not produce" in str(refused.value)


def test_a_control_satisfied_two_ways_is_a_load_error(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('version = "v"\nframework = "f"\nsource = "s"\n'
                    '[[control]]\nid = "X"\nstatement = "s"\nfact = "tests.all_passed"\n'
                    'gap = "also a gap"\n', encoding="utf-8")
    with pytest.raises(catalog_module.CatalogError):
        catalog_module.load(path)


def test_an_attestation_that_never_expires_is_a_load_error(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('version = "v"\nframework = "f"\nsource = "s"\n'
                    '[[control]]\nid = "X"\nstatement = "s"\nattestation = "a.toml"\n',
                    encoding="utf-8")
    with pytest.raises(catalog_module.CatalogError) as refused:
        catalog_module.load(path)
    assert "expiry" in str(refused.value)


def test_a_missing_catalog_stops_rather_than_defaults(tmp_path):
    with pytest.raises(catalog_module.CatalogError):
        catalog_module.load(tmp_path / "not-here.toml")


# ------------------------------------------------------- the bundle itself

def test_the_bundle_is_reproducible(evidence, trail_path, catalog):
    """Its digest is only worth something if somebody else can re-derive it."""
    first = build(evidence, trail_path, catalog)
    second = build(evidence, trail_path, catalog)
    assert bundle_module.canonical(first) == bundle_module.canonical(second)
    assert bundle_module.digest(first) == bundle_module.digest(second)


def test_the_bundle_is_named_by_its_own_contents(evidence, trail_path, catalog):
    """An altered bundle is a different object, not a replacement for this one."""
    built = build(evidence, trail_path, catalog)
    original = bundle_module.name(built)
    assert bundle_module.digest(built) in original

    built["subject"]["commit"] = "tampered"
    assert bundle_module.name(built) != original


def test_the_bundle_quotes_the_chain_rather_than_copying_it(evidence, trail_path, catalog):
    built = build(evidence, trail_path, catalog)
    chain = built["traceability"]["chain"]
    anchor = json.loads(trail.head_path(trail_path).read_text(encoding="utf-8"))
    assert chain["head_anchor"] == anchor
    assert chain["records"] == 2


def test_the_published_step_shape_does_not_drift(evidence, trail_path, catalog):
    """Structural: three other pathways read these keys, so adding a trail field must not leak."""
    built = build(evidence, trail_path, catalog)
    step = built["traceability"]["steps"][0]
    assert tuple(step) == bundle_module.STEP_FIELDS
    assert step["action"] == "create agent"
    assert step["decision"] == "allow"
    assert step["executed"] is True
    assert step["ran_on"] == "sha256:" + "a" * 64


def test_two_records_for_one_action_read_as_one_line(evidence, trail_path, catalog):
    """An auditor reads one line per action, not a pair they have to join themselves."""
    built = build(evidence, trail_path, catalog)
    assert len(built["traceability"]["steps"]) == 1
    assert len(built["traceability"]["steps"][0]["records"]) == 2


def test_all_controls_held_means_nothing_blocks(evidence, trail_path, catalog):
    built = build(evidence, trail_path, catalog)
    assert bundle_module.blocking_failures(built) == []
    assert built["controls"]["summary"]["blocking_failures"] == 0


def test_a_failing_test_result_blocks_the_change(evidence, trail_path, catalog):
    (evidence / "tests.json").write_text(json.dumps(
        {"passed": 69, "failed": 1, "errors": 0, "skipped": 0,
         "containment_exercised": True}), encoding="utf-8")
    built = build(evidence, trail_path, catalog)
    failures = bundle_module.blocking_failures(built)
    assert any("T-2" in f for f in failures)


def test_missing_evidence_is_not_the_same_finding_as_failed_evidence(
        evidence, trail_path, catalog):
    """"We checked and it failed" and "we never checked" send an auditor different ways."""
    (evidence / "tests.json").unlink()
    built = build(evidence, trail_path, catalog)
    assert built["evidence"]["tests.all_passed"]["state"] == "not_evidenced"
    assert any("not_evidenced" in f for f in bundle_module.blocking_failures(built))


def test_the_bundle_is_still_assembled_when_a_control_fails(evidence, trail_path, catalog):
    """An evidence store that only ever receives passes is not evidence of anything."""
    (evidence / "supply.json").unlink()
    (evidence / "tests.json").unlink()
    built = build(evidence, trail_path, catalog)
    assert bundle_module.blocking_failures(built), "this fixture is supposed to fail"
    assert built["controls"]["assessed"], "the bundle went missing when the change failed"
    assert bundle_module.digest(built)


def test_an_expired_attestation_is_not_held(evidence, trail_path, catalog):
    """A signature from before the platform changed is a historical document."""
    held = build(evidence, trail_path, catalog, today=date(2026, 11, 20))
    expired = build(evidence, trail_path, catalog, today=date(2027, 1, 20))

    def state(built, control):
        return next(e["state"] for e in built["controls"]["assessed"]
                    if e["control"] == control)

    assert state(held, "T-3") == "attested"
    assert state(expired, "T-3") == "not_held"
    assert any("T-3" in f for f in bundle_module.blocking_failures(expired))


def test_a_declared_gap_appears_in_the_bundle_rather_than_scoring_green(
        evidence, trail_path, catalog):
    """A tracked gap is honest. A control nothing evaluates is the audit finding."""
    built = build(evidence, trail_path, catalog)
    gap = next(e for e in built["controls"]["assessed"] if e["control"] == "T-4")
    assert gap["state"] == "declared_gap"
    assert gap["detail"] == "named and tracked"


def test_a_coverage_gate_that_could_not_judge_is_not_recorded_as_a_pass(
        evidence, trail_path, catalog):
    """Not comparable is an unanswered question, and an unanswered question is not a yes."""
    (evidence / "quality.json").write_text(json.dumps(
        {"held": False, "comparable": False, "tests_not_run": ["tests.test_sandbox::x"]}),
        encoding="utf-8")
    built = build(evidence, trail_path, catalog)
    assert built["evidence"]["quality.no_new_untested_code"]["state"] == "not_evidenced"


def test_a_failed_coverage_gate_names_what_breached(evidence, trail_path, catalog):
    (evidence / "quality.json").write_text(json.dumps(
        {"held": False, "comparable": True, "uncovered": 300, "statements": 1000,
         "baseline": 256, "breaches": ["quality/gate.py: 12 uncovered lines, 4 allowed"],
         "tests_not_run": []}), encoding="utf-8")
    built = build(evidence, trail_path, catalog)
    fact = built["evidence"]["quality.no_new_untested_code"]
    assert fact["state"] == "not_held"
    assert "quality/gate.py" in fact["detail"]


def test_a_clean_pair_of_scans_holds_both_security_controls(evidence, trail_path, catalog):
    built = build(evidence, trail_path, catalog)
    assert built["evidence"]["security.no_committed_secrets"]["state"] == "held"
    assert built["evidence"]["security.image_free_of_fixable_vulnerabilities"]["state"] == "held"


def test_an_image_vulnerability_with_a_fix_available_is_not_held(
        evidence, trail_path, catalog):
    """A finding nobody can act on is a different thing from one somebody can."""
    (evidence / "security.json").write_text(json.dumps(
        {"image_vulnerabilities": {"scanner": "trivy", "target": "x", "total": 5,
                                   "fixable": 1, "unfixable": 4,
                                   "fixable_ids": ["CVE-2026-1"]}}), encoding="utf-8")
    built = build(evidence, trail_path, catalog)
    assert built["evidence"]["security.image_free_of_fixable_vulnerabilities"]["state"] \
        == "not_held"


def test_scanners_that_did_not_run_are_not_a_clean_scan(evidence, trail_path, catalog):
    (evidence / "security.json").unlink()
    built = build(evidence, trail_path, catalog)
    for key in ("security.no_committed_secrets",
                "security.image_free_of_fixable_vulnerabilities"):
        assert built["evidence"][key]["state"] == "not_evidenced"


def test_the_bundle_never_carries_the_secrets_the_scanner_found(tmp_path, trail_path, catalog):
    """An evidence store holds this for a year. A leak copied into it is a worse leak."""
    leaked = "AKIAIOSFODNN7EXAMPLE"
    report = tmp_path / "gitleaks.json"
    report.write_text(json.dumps([{"RuleID": "aws-access-token", "File": "deploy/run.sh",
                                   "Secret": leaked, "Match": f"key={leaked}"}]),
                      encoding="utf-8")

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    written = collect.security_evidence(report, None)
    (evidence_dir / "security.json").write_text(json.dumps(written), encoding="utf-8")

    built = build(evidence_dir, trail_path, catalog)
    assert leaked not in bundle_module.canonical(built).decode("utf-8")
    assert leaked not in json.dumps(written)
    assert written["secrets"]["findings"] == 1
    assert written["secrets"]["rules"] == ["aws-access-token"]
    assert written["secrets"]["paths"] == ["deploy/run.sh"]


def test_an_image_report_is_split_into_what_can_be_fixed_and_what_cannot(tmp_path):
    """The gate acts on one of those two numbers and the bundle carries both."""
    report = tmp_path / "trivy.json"
    report.write_text(json.dumps({"ArtifactName": "python@sha256:abc", "Results": [
        {"Target": "python", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-1", "Severity": "HIGH", "FixedVersion": "1.2.3"},
            {"VulnerabilityID": "CVE-2026-2", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2026-3", "Severity": "HIGH", "FixedVersion": ""},
        ]},
        {"Target": "no vulnerabilities key"},
    ]}), encoding="utf-8")

    written = collect.security_evidence(None, report)["image_vulnerabilities"]
    assert written["total"] == 3
    assert written["fixable"] == 1
    assert written["unfixable"] == 2
    assert written["fixable_ids"] == ["CVE-2026-1"]
    assert written["target"] == "python@sha256:abc"


def test_scanners_that_wrote_nothing_produce_no_evidence_rather_than_zeroes(tmp_path):
    """Absent is not clean, and the difference has to survive this far."""
    assert collect.security_evidence(tmp_path / "nope.json", tmp_path / "also-nope.json") == {}


def test_an_empty_secret_report_reads_as_nothing_found(tmp_path):
    report = tmp_path / "gitleaks.json"
    report.write_text("", encoding="utf-8")
    assert collect.security_evidence(report, None)["secrets"]["findings"] == 0


def test_the_collector_writes_what_the_pipeline_asks_it_for(tmp_path):
    """These three run in CI and nothing asserted them, which is its own kind of untested."""
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite tests="3" failures="0" errors="0" skipped="1">'
        '<testcase classname="tests.test_a" name="one"/>'
        '<testcase classname="tests.test_a" name="two"/>'
        '<testcase classname="tests.test_sandbox" name="network"><skipped/></testcase>'
        "</testsuite>", encoding="utf-8")

    out = tmp_path / "tests.json"
    assert collect.main(["tests", "--junit", str(junit), "--out", str(out)]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written == {"passed": 2, "failed": 0, "errors": 0, "skipped": 1,
                       "containment_exercised": False,
                       "containment_tests_skipped": ["network"]}

    report = tmp_path / "gitleaks.json"
    report.write_text("[]", encoding="utf-8")
    scans = tmp_path / "security.json"
    assert collect.main(["security", "--secrets", str(report), "--out", str(scans)]) == 0
    assert json.loads(scans.read_text(encoding="utf-8"))["secrets"]["findings"] == 0

    chain = tmp_path / "supply.json"
    assert collect.main(["supply", "--out", str(chain)]) == 0
    recorded = json.loads(chain.read_text(encoding="utf-8"))
    assert "@sha256:" in recorded["image"]
    assert "policy_engine_detail" in recorded


def test_the_bill_of_materials_is_read_from_the_file_the_build_produced(tmp_path):
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX",
                                "components": [{"name": "a"}, {"name": "b"}]}),
                    encoding="utf-8")
    written = collect.supply_evidence(sbom)["bill_of_materials"]
    assert written["components"] == 2
    assert written["format"] == "CycloneDX-json"
    assert len(written["sha256"]) == 64


def test_the_fact_keys_are_exactly_what_the_catalog_may_name(evidence, trail_path):
    found = collect.facts("run-1", evidence, trail_path)
    assert set(found) == set(collect.PRODUCES)


# ------------------------------------------------------------------ the sink

def test_the_local_sink_refuses_to_rewrite_a_name(tmp_path):
    store = sink.FileSink(tmp_path / "bundles")
    store.put("b.json", b"the bundle")
    store.put("b.json", b"the bundle")  # same bytes, same bundle, allowed
    with pytest.raises(sink.SinkRefused):
        store.put("b.json", b"a different bundle")


def test_the_local_sink_says_it_is_not_the_record_of_account(tmp_path):
    receipt = sink.FileSink(tmp_path).put("b.json", b"x")
    assert receipt.mode == "development"
    assert receipt.digest == __import__("hashlib").sha256(b"x").hexdigest()


def test_the_write_asks_for_compliance_retention_not_governance(tmp_path):
    """The flags are the control, the same way the container flags are the containment."""
    argv = sink.put_argv("bucket", "assurance/b.json", tmp_path / "b", "2027-11-16T00:00:00Z")
    assert argv[argv.index("--object-lock-mode") + 1] == "COMPLIANCE"
    assert "--object-lock-retain-until-date" in argv
    assert "GOVERNANCE" not in argv


def test_an_unlocked_bucket_is_refused_before_anything_is_written(monkeypatch):
    """A bundle in an ordinary bucket looks exactly like evidence and anyone can delete it."""
    monkeypatch.setattr(sink, "_run", lambda argv: subprocess.CompletedProcess(
        argv, 1, "", "An error occurred (ObjectLockConfigurationNotFoundError)"))
    store = sink.ObjectStore("some-bucket")
    with pytest.raises(sink.SinkRefused) as refused:
        store.put("b.json", b"x")
    assert "object lock" in str(refused.value)


def test_the_store_checks_the_lock_before_it_puts(monkeypatch):
    calls = []

    def record(argv):
        calls.append(argv[1:3])
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    monkeypatch.setattr(sink, "_run", record)
    receipt = sink.ObjectStore("b", prefix="assurance").put("x.json", b"x")
    assert calls[0] == ["s3api", "get-object-lock-configuration"]
    assert calls[1] == ["s3api", "put-object"]
    assert receipt.location.startswith("s3://b/assurance/")
    assert receipt.location.endswith("/x.json")
    assert receipt.mode == "write-once"


def test_bundles_are_filed_under_the_day_they_were_filed(monkeypatch):
    """An auditor asks what shipped in a period, and a flat prefix makes that a full scan."""
    store = sink.ObjectStore("b", prefix="assurance")
    key = store.key_for("run-1.abc.json", on=datetime(2026, 11, 16, tzinfo=timezone.utc))
    assert key == "assurance/2026/11/16/run-1.abc.json"
