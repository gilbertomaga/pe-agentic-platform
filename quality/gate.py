"""
The quality gate: a change does not ship if it leaves more code untested than it found.

A gate that warns is a note nobody reads, so this exits non zero and the build stops. What took
the thinking was not making it block, it was deciding what it blocks on.

**Not a coverage percentage.** A target of eighty percent is either below where a legacy codebase
already sits, in which case it never fires, or above it, in which case every team is red on day
one and the gate is switched off within a fortnight. Worse, a percentage can be held level while
untested code is added, by adding tested code beside it. So the number here is uncovered lines,
an integer, and the rule is that it may not go up.

**A recorded baseline rather than a computed one.** The allowance lives in `baseline.toml`, in
the repository, and lowering it is a commit somebody reviews. A gate that recalculates its own
bar from the previous build is a gate that can be walked downwards one change at a time, with
every individual step looking reasonable.

**A new file starts at zero.** Code arriving with no tests has to be either tested or written
into the baseline in the same change, where a reviewer sees it. That is the difference between
debt that was taken on and debt that accumulated.

**It refuses to judge an incomplete run.** If any test was skipped, the coverage numbers describe
a run where some code could not execute, and comparing those to a baseline recorded from a full
run fails people for their laptop rather than for their change. That is precisely how a gate
earns the reputation that gets it bypassed. So a skipped test produces "not comparable", which
names what was skipped and what to do, and is still a non zero exit in CI where nothing should
skip.

The same gate runs on every change. There is no author, actor or branch anywhere in it, so an
agent's change meets exactly the gate a person's change meets. There is a test for that.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from quality import coverage

DEFAULT_BASELINE = Path(__file__).with_name("baseline.toml")


@dataclass(frozen=True)
class Breach:
    where: str
    allowed: int
    found: int

    def __str__(self) -> str:
        return (f"{self.where}: {self.found} uncovered lines, "
                f"{self.allowed} allowed ({self.found - self.allowed} more than the baseline)")


@dataclass(frozen=True)
class Baseline:
    total: int
    files: dict[str, int]
    recorded_on: str = ""
    recorded_from: str = ""


def load(path: Path = DEFAULT_BASELINE) -> Baseline:
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError as missing:
        raise SystemExit(
            f"no baseline at {path}. Record one from a complete run with --update, and commit "
            "it, so that what the gate holds you to is a reviewed number rather than whatever "
            "the last build happened to produce.") from missing
    return Baseline(int(raw.get("total", 0)), dict(raw.get("files", {})),
                    str(raw.get("recorded_on", "")), str(raw.get("recorded_from", "")))


def skipped_tests(junit: Path) -> list[str]:
    """Which tests did not run. An empty list is the only state coverage can be judged from."""
    root = ElementTree.parse(junit).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    return sorted(f"{case.get('classname', '?')}::{case.get('name', '?')}"
                  for case in suite.iter("testcase")
                  if case.find("skipped") is not None)


def check(report: coverage.Report, baseline: Baseline) -> list[Breach]:
    """Every reason this change does not ship. Empty means it does."""
    breaches = []
    if report.uncovered > baseline.total:
        breaches.append(Breach("the repository", baseline.total, report.uncovered))

    for measured in report.files:
        allowed = baseline.files.get(measured.path)
        if allowed is None and measured.uncovered:
            breaches.append(Breach(f"{measured.path} (not in the baseline)", 0,
                                   measured.uncovered))
        elif allowed is not None and measured.uncovered > allowed:
            breaches.append(Breach(measured.path, allowed, measured.uncovered))
    return breaches


def slack(report: coverage.Report, baseline: Baseline) -> list[str]:
    """Where the baseline is now looser than the code. Reported, never enforced.

    Tightening is a decision, and a gate that tightens itself is a gate whose bar nobody agreed
    to. Printing the line to change is the most it should do.
    """
    loose = []
    if report.uncovered < baseline.total:
        loose.append(f"total = {report.uncovered}  (baseline says {baseline.total})")
    for measured in report.files:
        allowed = baseline.files.get(measured.path)
        if allowed is not None and measured.uncovered < allowed:
            loose.append(f'"{measured.path}" = {measured.uncovered}  (baseline says {allowed})')
    return loose


def record(report: coverage.Report, note: str, path: Path = DEFAULT_BASELINE) -> None:
    """Write the baseline from this run. Deliberate, and the diff is the review."""
    lines = [
        "# Uncovered lines allowed, per file and in total. This is the quality gate's bar.",
        "#",
        "# It only ever goes down. A number here going up is a change that left more code",
        "# untested than it found, and it belongs in the same commit as the reason.",
        "#",
        "# Record it from a complete run. Numbers from a run with skips describe code that",
        "# could not execute, and a bar set from those is loose in some places and arbitrary",
        "# in others. `recorded_from` below says which kind of run this one came from.",
        "# See quality/gate.py.",
        "",
        f'recorded_on = "{date.today().isoformat()}"',
        f'recorded_from = "{note}"',
        f"total = {report.uncovered}",
        "",
        "[files]",
    ]
    lines += [f'"{m.path}" = {m.uncovered}' for m in report.files]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarise(report: coverage.Report, baseline: Baseline,
              breaches: list[Breach], not_run: list[str]) -> str:
    """What a blocked Builder reads. The numbers, and the file to change, not a link to a log."""
    out = ["## Quality gate", ""]
    if not_run:
        out += [f"**Not comparable.** {len(not_run)} tests did not run, so these coverage "
                "numbers describe a partial execution.", ""]
        out += [f"- `{name}`" for name in not_run[:10]]
        out += ["", "Run the full suite, or record the baseline from one."]
        return "\n".join(out)

    out += [f"{report.uncovered} uncovered lines of {report.statements}, "
            f"baseline {baseline.total}, recorded {baseline.recorded_on or 'unknown'}.", ""]
    if breaches:
        out += ["**Blocked.** This change leaves more code untested than it found.", "",
                "| where | allowed | found |", "|---|---|---|"]
        out += [f"| `{b.where}` | {b.allowed} | {b.found} |" for b in breaches]
        out += ["", "Either cover the lines, or raise the allowance in `quality/baseline.toml` "
                "in this change, where a reviewer can see what is being taken on."]
    else:
        out += ["Passed. Nothing in this change left more code untested than it found."]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hold a change to the coverage baseline.")
    parser.add_argument("--report", type=Path, required=True,
                        help="coverage.py/Cobertura XML, or JaCoCo XML")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--tests", type=Path, default=None,
                        help="the suite's junit report, so a partial run is not judged")
    parser.add_argument("--summary", type=Path, default=None,
                        help="write the Builder facing summary here, e.g. GITHUB_STEP_SUMMARY")
    parser.add_argument("--evidence", type=Path, default=None,
                        help="write the machine readable result for the assurance bundle")
    parser.add_argument("--update", metavar="NOTE", default=None,
                        help="record the baseline from this run instead of checking it")
    args = parser.parse_args(argv)

    report = coverage.read(args.report)
    not_run = skipped_tests(args.tests) if args.tests else []

    if args.update:
        if not_run:
            print(f"refusing to record a baseline from a run with {len(not_run)} skipped tests.")
            return 1
        record(report, args.update, args.baseline)
        print(f"baseline recorded: {report.uncovered} uncovered lines "
              f"across {len(report.files)} files")
        return 0

    baseline = load(args.baseline)
    breaches = [] if not_run else check(report, baseline)
    held = not breaches and not not_run

    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summarise(report, baseline, breaches, not_run) + "\n")

    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps({
            "held": held,
            "comparable": not not_run,
            "uncovered": report.uncovered,
            "statements": report.statements,
            "baseline": baseline.total,
            "baseline_recorded_on": baseline.recorded_on,
            "produced_by": report.produced_by,
            "breaches": [str(b) for b in breaches],
            "tests_not_run": not_run,
        }, indent=2, sort_keys=True), encoding="utf-8")

    if not_run:
        print(f"NOT COMPARABLE: {len(not_run)} tests did not run, so this coverage report "
              "describes a partial execution.")
        for name in not_run:
            print(f"  {name}")
        print("\nHolding a change to a baseline recorded from a full run, using numbers from a\n"
              "partial one, fails people for their machine rather than for their change.")
        return 1

    print(f"{report.uncovered} uncovered lines of {report.statements} "
          f"({report.produced_by}), baseline {baseline.total}")

    if breaches:
        print(f"\nQUALITY GATE FAILED ({len(breaches)}):")
        for breach in breaches:
            print(f"  {breach}")
        print("\nCover the lines, or raise the allowance in the baseline in this change so the\n"
              "debt is something somebody agreed to rather than something that accumulated.")
        return 1

    loose = slack(report, baseline)
    if loose:
        print(f"\nThe baseline is looser than the code in {len(loose)} places. Tightening is a\n"
              "decision, so it is not done here. The lines to change:")
        for line in loose[:12]:
            print(f"  {line}")
    print("\nquality gate clear: nothing in this change left more code untested than it found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
