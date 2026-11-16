"""
The quality gate.

The gate's job is narrow: a change may not leave more code untested than it found. These cover
that rule and the three judgments around it that decide whether anybody keeps using it, which
are that a new file starts at zero, that the bar is never tightened automatically, and that a
partial run is not judged at all.

The last one is structural. Nothing in this platform's build may be conditioned on who made the
change, because the whole claim about agent change is that it meets the gate a person meets, and
a single `if: github.actor` somewhere would make that claim false while the tests stayed green.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from quality import coverage, gate

REPO = Path(__file__).resolve().parent.parent

COVERAGE_PY = """<?xml version="1.0" ?>
<coverage lines-valid="6" lines-covered="4">
  <packages><package name="."><classes>
    <class filename="pkg/a.py"><lines>
      <line number="1" hits="1"/><line number="2" hits="0"/><line number="3" hits="1"/>
    </lines></class>
    <class filename="pkg\\b.py"><lines>
      <line number="1" hits="1"/><line number="2" hits="1"/><line number="3" hits="0"/>
    </lines></class>
  </classes></package></packages>
</coverage>
"""

JACOCO = """<?xml version="1.0" ?>
<report name="svc">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <counter type="LINE" missed="4" covered="16"/>
    </sourcefile>
    <sourcefile name="Bar.java">
      <counter type="LINE" missed="0" covered="9"/>
    </sourcefile>
  </package>
  <counter type="LINE" missed="4" covered="25"/>
</report>
"""

JUNIT_WITH_SKIPS = """<?xml version="1.0" ?>
<testsuite tests="3" failures="0" errors="0" skipped="1">
  <testcase classname="tests.test_a" name="one"/>
  <testcase classname="tests.test_a" name="two"/>
  <testcase classname="tests.test_sandbox" name="no_network"><skipped/></testcase>
</testsuite>
"""

JUNIT_CLEAN = """<?xml version="1.0" ?>
<testsuite tests="2" failures="0" errors="0" skipped="0">
  <testcase classname="tests.test_a" name="one"/>
  <testcase classname="tests.test_a" name="two"/>
</testsuite>
"""


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "coverage.xml"
    path.write_text(COVERAGE_PY, encoding="utf-8")
    return path


@pytest.fixture
def baseline(tmp_path):
    path = tmp_path / "baseline.toml"
    path.write_text('total = 2\n[files]\n"pkg/a.py" = 1\n"pkg/b.py" = 1\n', encoding="utf-8")
    return path


# ------------------------------------------------------------------ reading

def test_coverage_py_xml_is_read_as_uncovered_lines(report):
    parsed = coverage.read(report)
    assert parsed.produced_by == "coverage.py"
    assert parsed.uncovered == 2
    assert parsed.statements == 6
    assert parsed.by_path()["pkg/a.py"].uncovered == 1


def test_a_windows_path_reads_the_same_as_a_posix_one(report):
    """A baseline recorded on one machine has to read on another."""
    assert "pkg/b.py" in coverage.read(report).by_path()


def test_jacoco_xml_is_read_too(tmp_path):
    """The delivery platform underneath this one is mostly Java."""
    path = tmp_path / "jacoco.xml"
    path.write_text(JACOCO, encoding="utf-8")
    parsed = coverage.read(path)
    assert parsed.produced_by == "jacoco"
    assert parsed.uncovered == 4
    assert parsed.by_path()["com/example/Foo.java"].uncovered == 4
    assert parsed.by_path()["com/example/Bar.java"].uncovered == 0


def test_a_report_this_does_not_understand_is_refused(tmp_path):
    """Guessing at a third format is how a gate passes a report it did not read."""
    path = tmp_path / "other.xml"
    path.write_text("<something/>", encoding="utf-8")
    with pytest.raises(coverage.Unreadable) as refused:
        coverage.read(path)
    assert "something" in str(refused.value)


# ------------------------------------------------------------------- the rule

def test_a_change_that_leaves_more_untested_is_blocked(report, baseline):
    baseline.write_text('total = 1\n[files]\n"pkg/a.py" = 0\n"pkg/b.py" = 1\n', encoding="utf-8")
    breaches = gate.check(coverage.read(report), gate.load(baseline))
    assert [b.where for b in breaches] == ["the repository", "pkg/a.py"]


def test_a_change_that_holds_the_line_passes(report, baseline):
    assert gate.check(coverage.read(report), gate.load(baseline)) == []


def test_a_new_file_starts_at_zero(report, baseline):
    """Untested code arriving has to be tested or written into the baseline, where it is seen."""
    baseline.write_text('total = 9\n[files]\n"pkg/a.py" = 1\n', encoding="utf-8")
    breaches = gate.check(coverage.read(report), gate.load(baseline))
    assert len(breaches) == 1
    assert "pkg/b.py" in breaches[0].where and "not in the baseline" in breaches[0].where


def test_a_new_file_that_is_fully_covered_does_not_need_an_entry(tmp_path, baseline):
    path = tmp_path / "coverage.xml"
    path.write_text(COVERAGE_PY.replace('filename="pkg/a.py"', 'filename="pkg/new.py"')
                    .replace('<line number="2" hits="0"/>', '<line number="2" hits="3"/>'),
                    encoding="utf-8")
    breaches = gate.check(coverage.read(path), gate.load(baseline))
    assert [b.where for b in breaches] == []


def test_the_gate_never_tightens_itself(report, baseline):
    """A bar that moves on its own is a bar nobody agreed to."""
    baseline.write_text('total = 5\n[files]\n"pkg/a.py" = 3\n"pkg/b.py" = 1\n', encoding="utf-8")
    loaded = gate.load(baseline)
    assert gate.check(coverage.read(report), loaded) == []

    loose = gate.slack(coverage.read(report), loaded)
    assert any("total = 2" in line for line in loose)
    assert any("pkg/a.py" in line for line in loose)
    assert baseline.read_text(encoding="utf-8").count("= 3") == 1, "the gate rewrote the bar"


# --------------------------------------------------- a partial run is not judged

def test_a_run_with_skips_is_not_comparable(report, baseline, tmp_path, capsys):
    """Failing somebody for their laptop is how a gate earns the reputation that kills it."""
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT_WITH_SKIPS, encoding="utf-8")

    code = gate.main(["--report", str(report), "--baseline", str(baseline),
                      "--tests", str(junit)])
    out = capsys.readouterr().out
    assert code == 1
    assert "NOT COMPARABLE" in out
    assert "tests.test_sandbox::no_network" in out


def test_a_complete_run_is_judged(report, baseline, tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT_CLEAN, encoding="utf-8")
    assert gate.main(["--report", str(report), "--baseline", str(baseline),
                      "--tests", str(junit)]) == 0


def test_a_baseline_is_not_recorded_from_a_partial_run(report, baseline, tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT_WITH_SKIPS, encoding="utf-8")
    before = baseline.read_text(encoding="utf-8")

    assert gate.main(["--report", str(report), "--baseline", str(baseline),
                      "--tests", str(junit), "--update", "a note"]) == 1
    assert baseline.read_text(encoding="utf-8") == before


def test_recording_a_baseline_round_trips(report, tmp_path):
    written = tmp_path / "new.toml"
    gate.main(["--report", str(report), "--baseline", str(written), "--update", "a full run"])
    recorded = gate.load(written)
    assert recorded.total == 2
    assert recorded.files == {"pkg/a.py": 1, "pkg/b.py": 1}
    assert recorded.recorded_from == "a full run"


# ------------------------------------------------------------ what a Builder sees

def test_a_blocked_builder_is_told_the_numbers_and_the_file_to_change(report, baseline):
    baseline.write_text('total = 0\n[files]\n', encoding="utf-8")
    text = gate.summarise(coverage.read(report), gate.load(baseline),
                          gate.check(coverage.read(report), gate.load(baseline)), [])
    assert "Blocked" in text
    assert "pkg/a.py" in text
    assert "quality/baseline.toml" in text, "it has to say where the bar lives"


def test_the_summary_says_what_did_not_run_rather_than_a_number(report, baseline):
    text = gate.summarise(coverage.read(report), gate.load(baseline), [], ["tests.x::y"])
    assert "Not comparable" in text
    assert "tests.x::y" in text


# ---------------------------------------------- the same gate for everybody

def test_nothing_in_the_build_is_conditioned_on_who_made_the_change():
    """Structural, and it is the whole claim about agent change.

    An agent's change meets the gate a person's change meets. One `if: github.actor ==` would
    make that false while every other test stayed green, so the build is read rather than
    trusted.
    """
    actors = ("github.actor", "github.triggering_actor", "pull_request.user", "github.event.sender")
    offenders = []
    for workflow in (REPO / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        offenders += [f"{workflow.name}: {a}" for a in actors if a in text]
    assert offenders == [], f"the build treats some authors differently: {offenders}"


def test_the_repository_baseline_is_recorded_and_says_where_from():
    """A bar with no provenance is a number somebody typed."""
    recorded = gate.load()
    assert recorded.total > 0
    assert recorded.recorded_on, "the baseline does not say when it was recorded"
    assert recorded.recorded_from, "the baseline does not say what run it came from"
