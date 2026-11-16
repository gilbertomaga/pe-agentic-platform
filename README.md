# pe-agentic-platform

A small agent platform, built to be defensible rather than large.

**A contained runtime.** One container per run, created and destroyed. No network at all: whatever
needs the outside world happens outside the boundary and is passed in. Non root, read only root
filesystem, capabilities dropped, memory, CPU and process limits, and a wall clock timeout, because
a step limit bounds breadth and not duration.

**Policy as code.** Every action is evaluated before it runs. Three classes: autonomous, human
gated, forbidden. Anything nobody wrote a rule for is denied, with a reason. Written in Rego and
tested, because a guardrail that is not asserted is a comment.

**An audit trail the platform writes.** One record when an action is decided, another when it
executes. Append only and hash chained, so an edited or removed entry breaks the chain. The newest
record is anchored separately, because a chain alone does not detect truncation. Each executed
record carries the digest of the image the step ran on, inside the hash.

**A supply chain fixed by content.** The sandbox image by digest, the policy engine by checksum,
the build's actions by commit, all in `supply/pinned.toml` with the command that produced each
value. The runtime refuses to start on an image that is named by tag. None of it is a signature,
and `docs/decisions.md` D10 says where that line sits rather than leaving it to be assumed.

**A quality gate that blocks.** A change may not leave more code untested than it found. The bar
is uncovered lines rather than a percentage, because a percentage can be held level while
untested code is added beside tested code, and it lives in `quality/baseline.toml`, so lowering
it is a commit somebody reviews rather than a number the last build computed. A new file starts
at zero. If any test skipped, the gate says the run is not comparable instead of failing you for
your machine. Nothing in it reads who made the change, so an agent's change meets the gate a
person's change meets, and a structural test fails the build if that ever stops being true.

**Security scanning that blocks, decided in one place.** The history is scanned for secrets and
the image that runs is scanned for known vulnerabilities. Neither scanner decides: both report,
and the control catalog reads the evidence, so the severity that stops a build is a reviewed line
in a control rather than a flag in a YAML argument. The image gate blocks on findings with a fix
available and counts the ones without, because a build cannot act on a vulnerability with no
patch. Both scanners are pinned by checksum for the same reason the policy engine is: a scanner
that did not run reports nothing, and nothing is what a clean result looks like. The raw reports
never leave the runner, because a secret scanner's findings are the secrets.

**An assurance bundle the build hands over.** Every run assembles one: the traceability projected
into a shape other consumers can read, the test and supply chain evidence the pipeline produced,
and every control in the client's catalog with its state and the evidence behind it. It is
reproducible byte for byte, named by its own digest, and it lands whether the change passed or
failed, because an evidence store that only receives successes is not evidence of anything. The
control catalog is the client's and lives in a file; the one shipped here says plainly that it is
a demonstration set. The bundle goes to a bucket in the client's account under write once
retention, with credentials that can write and nothing else, so the platform cannot reach back
into what it filed. `assurance/system-of-record.md` is what the client configures.

**A golden path that narrows.** Provisioning an agent takes a name, a purpose and the actions it
needs. An agent cannot give itself an action the policy forbids or has no rule for, so there is no
privilege route through onboarding. It may declare a gated one, and the path says so, but gated is
what it stays: the human is named in the plan at run time, and nobody approves their own.
Provisioning records itself, so the census can count who
came through and, more usefully, who did not: an agent that exists with no provisioning record is
somebody who copied a template instead of walking the path, and that is the number worth watching.

**One path, not four parts.** `runtime/runner.py` is the only way an action happens: scope, then
policy, then a record of the decision, then the approver if the policy gates it, then the sandbox,
then a record of what ran. It fails closed when the policy engine is unreachable and stops at the
first refusal instead of continuing down the list. A test fails the build if any other module
reaches a container directly, because an invariant nobody enforces is a convention.

An action the agent never declared, or one the policy forbids, is blocked, recorded and then
alerted on stderr and to `PLATFORM_ALERT_FILE`. A gated action waiting for its approver is not
alerted: that is the gate working, and paging someone for it is how a channel becomes noise.

## Running it

    python -m pytest -q
    opa test policy/ -v
    python -m golden_path.new_agent my-agent
    python -m runtime golden_path/agents/my-agent/plan.toml
    python -m golden_path.adoption
    python -m trail.gate
    python -m pytest -q --cov --cov-report=xml:coverage.xml --junitxml=junit.xml
    python -m quality.gate --report coverage.xml --tests junit.xml
    python -m assurance.collect supply --out evidence/supply.json
    python -m assurance.bundle <run-id> --evidence evidence --out bundles
    python -m assurance.land bundles/<bundle>.json --directory ./filed

CI runs the containment proof on every push. The sandbox test opens a socket from inside the
container and fails if it connects. Tests do not skip there: a missing Docker daemon or a missing
OPA fails the build rather than quietly reducing the proof to a skip. The audit gate runs there
too, against a trail the golden path writes during the build, because a gate that only ever runs
against its own fixtures is a library. The build then assembles the assurance bundle for the
change it just checked and hands it to an S3 compatible store, which exercises the refusal on an
unlocked bucket as well as the write, so the path to a client's evidence store is run rather than
described.

Run the bundler locally and it will tell you the truth about the machine you are on: with Docker
unavailable the containment control reads not held, because the sandbox tests skipped and a suite
that skipped them proves nothing about containment.

## Reading it

`docs/decisions.md` is the decision log, with the reasoning rather than only the outcome, including
the two defects I wrote and then found. `docs/owasp-mapping.md` maps the policy to the OWASP Top 10
for Agentic Applications 2026: four addressed, five partial, one that does not apply yet.
`assurance/system-of-record.md` is the bucket configuration a client applies so that this platform
can hand over an audit record it is then unable to touch, and the last section of it is what
retention does not solve.
