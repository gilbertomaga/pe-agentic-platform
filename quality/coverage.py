"""
Read a coverage report. Two formats, because the platform this belongs to is not one language.

The agent platform is Python and the delivery platform underneath it is mostly Java, so a
coverage gate that only understands one of them is a gate for half the estate and an argument
for the other half. Both formats are XML and both carry the same two numbers per file, so
supporting the second one costs about thirty lines and removes the reason somebody would build
a second gate.

What is read is the number of uncovered lines, not a percentage. A percentage lets a change add
untested code and stay level by adding tested code beside it, which is how a coverage target
gets met by a module nobody has tested. An uncovered line count only goes the right way.
"""
from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path


class Unreadable(Exception):
    """The report is not a coverage report this understands."""


@dataclass(frozen=True)
class Measured:
    path: str
    uncovered: int
    statements: int

    @property
    def covered(self) -> int:
        return self.statements - self.uncovered


@dataclass(frozen=True)
class Report:
    produced_by: str
    files: tuple[Measured, ...]

    @property
    def uncovered(self) -> int:
        return sum(f.uncovered for f in self.files)

    @property
    def statements(self) -> int:
        return sum(f.statements for f in self.files)

    def by_path(self) -> dict[str, Measured]:
        return {f.path: f for f in self.files}


def _coverage_py(root: ElementTree.Element) -> Report:
    """coverage.py / Cobertura: one <class> per file, one <line> per statement."""
    files = []
    for element in root.iter("class"):
        lines = list(element.iter("line"))
        uncovered = sum(1 for line in lines if line.get("hits") == "0")
        files.append(Measured(_normal(element.get("filename", "?")), uncovered, len(lines)))
    return Report("coverage.py", tuple(sorted(files, key=lambda f: f.path)))


def _jacoco(root: ElementTree.Element) -> Report:
    """JaCoCo: one <sourcefile> per file, with a LINE counter carrying missed and covered."""
    files = []
    for package in root.iter("package"):
        prefix = package.get("name", "")
        for element in package.iter("sourcefile"):
            counter = next((c for c in element.findall("counter")
                            if c.get("type") == "LINE"), None)
            if counter is None:
                continue
            missed = int(counter.get("missed", 0))
            covered = int(counter.get("covered", 0))
            name = element.get("name", "?")
            files.append(Measured(_normal(f"{prefix}/{name}" if prefix else name),
                                  missed, missed + covered))
    return Report("jacoco", tuple(sorted(files, key=lambda f: f.path)))


def _normal(path: str) -> str:
    """One spelling for a path, so a baseline recorded on one platform reads on another."""
    return path.replace("\\", "/").lstrip("./")


def read(path: Path) -> Report:
    """Whichever of the two formats this is, or a refusal that names what it found."""
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError as broken:
        raise Unreadable(f"{path} is not XML: {broken}") from broken

    if root.tag == "coverage":
        return _coverage_py(root)
    if root.tag == "report":
        return _jacoco(root)
    raise Unreadable(
        f"{path} has a <{root.tag}> root. This reads coverage.py or Cobertura XML "
        "(<coverage>) and JaCoCo XML (<report>), and guessing at a third is how a gate ends up "
        "passing a report it did not understand.")
