"""
The facts a bundle can be built from, and nothing else.

This module reads what the pipeline left behind. It does not run anything and it does not decide
anything, which is the point: a component that both produces the evidence and judges it is a
component that can be asked to judge gently. The steps that do the work write their own result,
and this reads those files back.

Three states, not two. A fact is held, not held, or not evidenced, and the third one is not a
polite version of the second. "We checked and it failed" and "we never checked" send an auditor
in different directions, and collapsing them into one red cross loses the difference exactly
where it matters.

`PRODUCES` is the full set of keys this module can ever return. The catalog is checked against it
when it loads, so a control mapped to evidence nobody emits is a startup error rather than a
control that quietly reads as unmet on every bundle until somebody looks.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path

from supply import verify as supply
from trail import trail


@dataclass(frozen=True)
class Fact:
    #: True held, False not held, None not evidenced at all.
    held: bool | None
    detail: str

    @property
    def state(self) -> str:
        return {True: "held", False: "not_held", None: "not_evidenced"}[self.held]


#: Every key this module can return. The catalog may not name anything outside it.
PRODUCES = (
    "trail.chain_intact",
    "trail.no_unnamed_approvals",
    "trail.run_recorded",
    "tests.all_passed",
    "tests.containment_exercised",
    "supply.image_pinned",
    "supply.policy_engine_verified",
    "supply.bill_of_materials",
)


def _read(path: Path) -> dict | None:
    """A missing evidence file is not evidenced. A malformed one is a failure, loudly."""
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _tests(evidence: dict | None) -> dict[str, Fact]:
    if evidence is None:
        missing = Fact(None, "no tests.json in the evidence directory; the suite result was "
                             "never written, so this bundle cannot speak for it")
        return {"tests.all_passed": missing, "tests.containment_exercised": missing}

    failed = evidence.get("failed", 0) + evidence.get("errors", 0)
    passed = evidence.get("passed", 0)
    contained = bool(evidence.get("containment_exercised"))
    return {
        "tests.all_passed": Fact(
            failed == 0 and passed > 0,
            f"{passed} passed, {failed} failed, {evidence.get('skipped', 0)} skipped"),
        # A suite that skipped the containment tests is green and proves nothing about
        # containment. The count alone cannot tell you that, so the step that ran it says so.
        "tests.containment_exercised": Fact(
            contained,
            "the sandbox tests ran against a real daemon" if contained else
            "the sandbox tests were skipped, so this run proves nothing about containment"),
    }


def _supply(evidence: dict | None) -> dict[str, Fact]:
    if evidence is None:
        missing = Fact(None, "no supply.json in the evidence directory")
        return {"supply.image_pinned": missing,
                "supply.policy_engine_verified": missing,
                "supply.bill_of_materials": missing}

    image = evidence.get("image", "")
    sbom = evidence.get("bill_of_materials") or {}
    return {
        "supply.image_pinned": Fact(
            "@sha256:" in image, image or "no image recorded"),
        "supply.policy_engine_verified": Fact(
            bool(evidence.get("policy_engine_verified")),
            evidence.get("policy_engine_detail")
            or ("opa matched its pinned checksum"
                if evidence.get("policy_engine_verified") else
                "the policy engine on this machine is not the binary that was pinned")),
        # Evidence, not a gate. It answers what was in the thing that ran, after the fact,
        # which is the question a disclosure makes urgent and nobody can answer in arrears.
        "supply.bill_of_materials": Fact(
            bool(sbom.get("sha256")),
            f"{sbom.get('format', 'unknown format')}, {sbom.get('components', '?')} components, "
            f"sha256 {sbom.get('sha256', 'none')}" if sbom else "no bill of materials"),
    }


def _trail(run_id: str, trail_path: Path) -> dict[str, Fact]:
    records = trail.find(run_id, trail_path)
    faults = trail.verify(trail_path)
    unnamed = [e for e in trail.unresolved(trail_path) if e["run_id"] == run_id]
    return {
        "trail.chain_intact": Fact(
            not faults,
            "chain and head anchor verify" if not faults else
            "; ".join(f"record {f.seq}: {f.why}" for f in faults)),
        "trail.no_unnamed_approvals": Fact(
            not unnamed,
            "no gated action proceeded without a named approver" if not unnamed else
            f"{len(unnamed)} gated actions went ahead with nobody named against them"),
        "trail.run_recorded": Fact(
            bool(records),
            f"{len(records)} records for this run" if records else
            f"nothing in the trail for run {run_id}, so there is nothing to assure"),
    }


def facts(run_id: str, evidence_dir: Path, trail_path: Path) -> dict[str, Fact]:
    """Every fact the platform can state about one run, keyed exactly as `PRODUCES`."""
    found = {}
    found.update(_trail(run_id, trail_path))
    found.update(_tests(_read(evidence_dir / "tests.json")))
    found.update(_supply(_read(evidence_dir / "supply.json")))

    # The contract this module publishes is the key set, so it is checked rather than trusted.
    assert set(found) == set(PRODUCES), (
        f"collect.facts and collect.PRODUCES disagree: {set(found) ^ set(PRODUCES)}")
    return found


# ------------------------------------------------------------------------------------------
# Turning what a pipeline step produced into the evidence file this module reads back.
#
# These run in the pipeline, beside the step whose result they are recording. They read output
# rather than take the step's word for it, which is the difference between evidence and a
# pipeline asserting its own success: a workflow that was edited to install the policy engine
# from somewhere else would still print a green tick, and would not survive the hash below.
# ------------------------------------------------------------------------------------------

def from_junit(path: Path) -> dict:
    """Test evidence, read out of the suite's own report.

    A suite that skipped the sandbox tests is green and proves nothing about containment, and the
    pass count cannot tell you that, so the skips are read by name rather than counted.
    """
    root = ElementTree.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")

    total = int(suite.get("tests", 0))
    failed = int(suite.get("failures", 0))
    errors = int(suite.get("errors", 0))
    skipped = int(suite.get("skipped", 0))

    not_exercised = sorted(
        case.get("name", "?") for case in suite.iter("testcase")
        if "test_sandbox" in (case.get("classname") or "")
        and case.find("skipped") is not None)

    return {
        "passed": total - failed - errors - skipped,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "containment_exercised": not not_exercised,
        "containment_tests_skipped": not_exercised,
    }


def supply_evidence(sbom: Path | None = None) -> dict:
    """Supply chain evidence, checked here rather than reported by the step that installed it."""
    evidence: dict = {"image": supply.sandbox_image()}

    pin = supply.opa()
    installed = shutil.which("opa")
    if not installed:
        evidence["policy_engine_verified"] = False
        evidence["policy_engine_version"] = "not installed"
        evidence["policy_engine_detail"] = (
            "no opa on PATH, so nothing here can say which binary made the policy decisions")
    else:
        actual = supply.sha256_of(Path(installed))
        matched = actual == pin["sha256"]
        evidence["policy_engine_verified"] = matched
        evidence["policy_engine_version"] = pin["version"]
        evidence["policy_engine_sha256"] = actual
        evidence["policy_engine_detail"] = (
            f"the opa on PATH is {pin['asset']} {pin['version']}, matching its pinned checksum"
            if matched else
            f"the opa on PATH is not the pinned binary: found {actual}, "
            f"pinned {pin['sha256']} for {pin['asset']}")

    if sbom and sbom.exists():
        parsed = json.loads(sbom.read_text(encoding="utf-8"))
        evidence["bill_of_materials"] = {
            "format": parsed.get("bomFormat", "unknown") + "-json",
            "components": len(parsed.get("components", [])),
            "sha256": supply.sha256_of(sbom),
        }
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write one evidence file for the bundle.")
    sub = parser.add_subparsers(dest="what", required=True)

    tests = sub.add_parser("tests", help="read the suite's junit report")
    tests.add_argument("--junit", type=Path, required=True)
    tests.add_argument("--out", type=Path, required=True)

    chain = sub.add_parser("supply", help="check the pins against what is installed")
    chain.add_argument("--sbom", type=Path, default=None)
    chain.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    written = from_junit(args.junit) if args.what == "tests" else supply_evidence(args.sbom)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(written, indent=2, sort_keys=True), encoding="utf-8")
    print(f"{args.out}: " + ", ".join(f"{k}={v}" for k, v in sorted(written.items())
                                      if not isinstance(v, (dict, list))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
