"""
The supply chain: what the platform runs, fixed by content rather than by name.

Everything else in this repository is about what an agent may do once it is running. This module
is about what gets to run in the first place, which is the question the rest of it quietly
assumed somebody else had answered.

Three things arrived here from outside and were trusted on sight:

  The sandbox image, by the tag `python:3.12-slim`. A tag is a label the publisher can move. It
  names who built the image, not what is in it, so the containment model was asserted against
  bytes nobody had fixed.

  The policy engine, downloaded in CI from a `latest` URL over the network with no verification.
  That was the worst of the three by some distance. Every guardrail decision in this platform is
  whatever that binary says, so substituting it turns the whole thing permissive while the build
  stays green and the trail records each decision as normal.

  The build's own actions, by tag. Same property as the image, on the thing that has the token.

This module does not make any of that safe. It makes it fixed, and fixed is what a reviewer can
check. See docs/decisions.md D10 for what a digest buys and what it does not.

It fails closed, like the policy: a reference that content does not pin raises rather than
falling back to the tag, because a supply chain control that degrades to trusting the label is
the same control the platform already did not have.
"""
from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

PINNED = Path(__file__).with_name("pinned.toml")

#: What a reference has to carry before anything will run it.
DIGEST_MARKER = "@sha256:"

_READ_SIZE = 1024 * 1024


class Unpinned(Exception):
    """Something would run from a reference that content does not fix."""


def _load(path: Path = PINNED) -> dict:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError as missing:
        raise Unpinned(
            f"no pin file at {path}. Nothing runs unpinned, so this is a stop rather than a "
            "warning: restore the file or re-derive it with the commands in its comments."
        ) from missing
    except tomllib.TOMLDecodeError as broken:
        raise Unpinned(f"{path} does not parse: {broken}") from broken


def sandbox_image(path: Path = PINNED) -> str:
    """The image reference every sandbox runs, as `repository@sha256:...`."""
    pin = _load(path).get("sandbox_image", {})
    repository, digest = pin.get("repository"), pin.get("digest")
    if not repository or not digest:
        raise Unpinned(
            f"{path} has no pinned sandbox image. Without one the platform would fall back to a "
            "tag, which is the thing the pin exists to stop.")
    return require_digest(f"{repository}@{digest}")


def evidence_store_emulator(path: Path = PINNED) -> str:
    """The S3 compatible server the build starts to exercise the evidence store path.

    Pinned like anything else that runs here. It is a test fixture rather than a runtime
    component, and an unpinned test fixture is still a container pulled by a label somebody can
    move, on a runner holding a token.
    """
    pin = _load(path).get("evidence_store_emulator", {})
    repository, digest = pin.get("repository"), pin.get("digest")
    if not repository or not digest:
        raise Unpinned(f"{path} has no pinned evidence store emulator")
    return require_digest(f"{repository}@{digest}")


def require_digest(reference: str) -> str:
    """Return the reference, or refuse it for naming an image by a label somebody can move."""
    if DIGEST_MARKER not in reference:
        raise Unpinned(
            f"{reference} names an image by tag. A tag says who published the image, not what is "
            f"in it, and the publisher can move it after you read it. Pin the digest in {PINNED} "
            "and run this again.")
    return reference


def digest_of(reference: str) -> str:
    """The digest half of a pinned reference, for the record the runtime writes."""
    return require_digest(reference).split("@", 1)[1]


def opa(path: Path = PINNED) -> dict:
    """The policy engine the build is allowed to install: version, asset, checksum and URL."""
    pin = _load(path).get("opa", {})
    for field in ("version", "asset", "sha256"):
        if not pin.get(field):
            raise Unpinned(f"{path} has no pinned OPA {field}")
    pin = dict(pin)
    pin["url"] = (
        "https://github.com/open-policy-agent/opa/releases/download/"
        f"{pin['version']}/{pin['asset']}")
    return pin


def sha256_of(path: Path) -> str:
    """The checksum of a file on disk, read in chunks because a release binary is not small."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_READ_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected: str) -> str:
    """Raise unless the file on disk is the bytes that were pinned."""
    actual = sha256_of(path)
    if actual != expected:
        raise Unpinned(
            f"{path} is not what was pinned.\n"
            f"  expected {expected}\n"
            f"  found    {actual}\n"
            "Either the pin is stale or the download is not the file it claims to be. Both are "
            "reasons to stop rather than to carry on and find out.")
    return actual
