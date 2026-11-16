"""
The control catalog: the client's controls, loaded as data.

The catalog is never this platform's. A regulated client is held to a specific set of controls
from a specific regime, and a platform that ships its own checklist and calls it compliance has
answered a question nobody asked. So the catalog is a file, the mapping from control to evidence
is written down where an auditor can read it, and the code here does nothing but load it and
check it is honest.

Three ways a control is satisfied, and they are deliberately different things:

  `fact`        the platform produces machine evidence, on every change, automatically.
  `attestation` a person accepted something a scanner cannot see. It carries a name and a date,
                and it expires, because a signature from two years ago is a historical document
                rather than evidence about today.
  `gap`         the control cannot be met yet, written down with the reason. A tracked gap is
                honest. A control quietly scoring green because nothing evaluates it is the
                failure that waits for the audit to surface it.

Two checks run at load, and both are failures rather than warnings. A control naming evidence
the platform does not produce is a drift between the catalog and the platform, and it would
otherwise read as "not evidenced" forever while looking like a data problem. A control naming
none of the three is a control nobody decided about.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from assurance import collect

DEFAULT_CATALOG = Path(__file__).with_name("controls.toml")


class CatalogError(Exception):
    """The catalog and the platform disagree about what can be evidenced."""


@dataclass(frozen=True)
class Control:
    id: str
    statement: str
    blocking: bool
    fact: str | None = None
    attestation: str | None = None
    valid_days: int = 0
    gap: str | None = None

    @property
    def kind(self) -> str:
        return "fact" if self.fact else "attestation" if self.attestation else "gap"


@dataclass(frozen=True)
class Catalog:
    version: str
    framework: str
    source: str
    controls: tuple[Control, ...]


def load(path: Path = DEFAULT_CATALOG) -> Catalog:
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError as missing:
        raise CatalogError(
            f"no control catalog at {path}. The catalog is the client's, so this is a stop "
            "rather than a default: a bundle assembled against a catalog nobody supplied is "
            "mapped to nothing.") from missing
    except tomllib.TOMLDecodeError as broken:
        raise CatalogError(f"{path} does not parse: {broken}") from broken

    for field in ("version", "framework", "source"):
        if not raw.get(field):
            raise CatalogError(f"{path} does not say its {field}")

    controls = []
    for entry in raw.get("control", []):
        if not entry.get("id") or not entry.get("statement"):
            raise CatalogError(f"{path} has a control with no id or no statement")

        control = Control(
            id=entry["id"],
            statement=entry["statement"],
            blocking=bool(entry.get("blocking", True)),
            fact=entry.get("fact"),
            attestation=entry.get("attestation"),
            valid_days=int(entry.get("valid_days", 0)),
            gap=entry.get("gap"),
        )

        named = [x for x in (control.fact, control.attestation, control.gap) if x]
        if len(named) != 1:
            raise CatalogError(
                f"{control.id} names {len(named)} of fact, attestation and gap. It has to name "
                "exactly one: how a control is satisfied is a decision, not a default.")

        if control.fact and control.fact not in collect.PRODUCES:
            raise CatalogError(
                f"{control.id} is mapped to evidence `{control.fact}`, which this platform does "
                "not produce. Either the mapping is wrong or the control is a gap this platform "
                f"has not declared. Evidence it can produce: {', '.join(collect.PRODUCES)}")

        if control.attestation and control.valid_days <= 0:
            raise CatalogError(
                f"{control.id} is attested but never expires. An attestation with no expiry is a "
                "signature somebody gave once about a platform that has changed since.")

        controls.append(control)

    if not controls:
        raise CatalogError(f"{path} defines no controls")

    ids = [c.id for c in controls]
    if len(set(ids)) != len(ids):
        raise CatalogError(f"{path} has duplicate control ids")

    return Catalog(raw["version"], raw["framework"], raw["source"], tuple(controls))
