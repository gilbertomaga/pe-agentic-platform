"""
The supply chain pin.

What these assert is narrow on purpose. A digest does not make an image safe, and a checksum
published by the same project as the binary does not make that project trustworthy. What both do
is fix the bytes, so that what a reviewer reads today is what runs tomorrow. These tests cover
that property and nothing wider, because a test suite that implies more than the control delivers
is the same failure as a gate that warns instead of blocking.

The last two are structural. They fail if anything in the repository goes back to naming the
image by tag, or if the build installs the policy engine without checking what it downloaded,
because both are one careless line away from returning at any time.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from supply import verify as supply

REPO = Path(__file__).resolve().parent.parent

HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: The canonical OCI form: the algorithm is part of the digest, not decoration on it.
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def test_the_pin_file_is_there_and_parses():
    assert supply.PINNED.exists(), "the pin file is the only source of truth for what runs"
    assert supply._load() != {}


def test_the_sandbox_image_is_a_digest_reference():
    reference = supply.sandbox_image()
    assert supply.DIGEST_MARKER in reference
    assert DIGEST.match(supply.digest_of(reference)), "a digest is content, not a label"


def test_a_tag_is_refused_rather_than_accepted_quietly():
    with pytest.raises(supply.Unpinned) as refused:
        supply.require_digest("python:3.12-slim")
    assert "tag" in str(refused.value)


def test_a_missing_pin_file_stops_rather_than_falls_back(tmp_path):
    """Fail closed. A supply chain control that degrades to the tag is the absence of one."""
    with pytest.raises(supply.Unpinned):
        supply.sandbox_image(tmp_path / "not-here.toml")


def test_a_pin_file_without_an_image_stops_too(tmp_path):
    empty = tmp_path / "pinned.toml"
    empty.write_text("[opa]\nversion = \"v1.0.0\"\n", encoding="utf-8")
    with pytest.raises(supply.Unpinned):
        supply.sandbox_image(empty)


def test_the_policy_engine_is_pinned_to_a_version_and_a_checksum():
    opa = supply.opa()
    assert opa["version"].startswith("v")
    assert HEX64.match(opa["sha256"])
    assert opa["version"] in opa["url"] and opa["asset"] in opa["url"]


def test_a_file_that_matches_its_checksum_passes(tmp_path):
    artifact = tmp_path / "downloaded"
    artifact.write_bytes(b"the bytes that were pinned")
    assert supply.verify_file(artifact, supply.sha256_of(artifact))


def test_a_file_that_does_not_match_is_refused(tmp_path):
    artifact = tmp_path / "downloaded"
    artifact.write_bytes(b"something else entirely")
    with pytest.raises(supply.Unpinned) as refused:
        supply.verify_file(artifact, "0" * 64)
    assert str(artifact) in str(refused.value)


def test_nothing_in_the_repository_names_the_sandbox_image_by_tag():
    """Structural. One line is all it takes to go back to trusting a label."""
    tag = "python:3.12-slim"
    # The one module allowed to say it is the module that exists to explain why it is wrong.
    explains_it = REPO / "supply" / "verify.py"
    offenders = []

    for source in list(REPO.rglob("*.py")) + list(REPO.rglob("*.yml")):
        parts = source.parts
        if "tests" in parts or ".venv" in parts or ".git" in parts or source == explains_it:
            continue
        if tag in source.read_text(encoding="utf-8"):
            offenders.append(str(source.relative_to(REPO)))

    assert offenders == [], f"these name the image by tag rather than by digest: {offenders}"


def test_the_evidence_store_emulator_is_pinned_too():
    """A test fixture is still a container pulled onto a runner that is holding a token."""
    reference = supply.evidence_store_emulator()
    assert supply.DIGEST_MARKER in reference
    assert DIGEST.match(supply.digest_of(reference))


def test_every_container_the_build_starts_comes_from_the_pin():
    """Structural. A `docker run` with a tag in it is the pin quietly stepped around."""
    offenders = []
    for workflow in (REPO / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        for verb in ("docker pull", "docker run"):
            start = 0
            while (found := text.find(verb, start)) != -1:
                if "steps.pin.outputs" not in text[found:found + 200]:
                    offenders.append(f"{workflow.name}: {verb} not from the pin")
                start = found + 1
    assert offenders == [], offenders


def test_the_build_verifies_the_policy_engine_it_downloads():
    """Structural, and the reason this module exists.

    The build used to fetch OPA from a `latest` URL with nothing checked. Every guardrail
    decision in this platform is whatever that binary says, so an unverified download is the
    whole policy layer taken on trust from the network.
    """
    workflows = list((REPO / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflows found; this test is asserting against nothing"

    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        if "opa" not in text.lower():
            continue
        assert "downloads/latest" not in text, (
            f"{workflow.name} installs OPA from a moving URL")
        assert "sha256sum -c" in text or "sha256sum --check" in text, (
            f"{workflow.name} downloads OPA without checking what it got")
