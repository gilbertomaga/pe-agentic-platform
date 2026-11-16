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

**The client's compliance controls, in their own file.** `policy/compliance.rego` is a separate
package from the platform's own guardrail, because it belongs to whoever the platform is deployed
for: when their control set arrives it replaces a file rather than reaching into the runtime. It
holds the controls that are about the people around an action rather than the action itself, and
the first of them is separation of duties. The person approving is not the person who asked, both
are named, and an action that cannot show the separation is refused rather than assumed. Every
control in the catalog names either references into the client's framework or the reason it has
none, and the catalog refuses to load on silence.

**Security scanning that blocks, decided in one place.** The history is scanned for secrets and
the image that runs is scanned for known vulnerabilities. Neither scanner decides: both report,
and the control catalog reads the evidence, so the severity that stops a build is a reviewed line
in a control rather than a flag in a YAML argument. The image gate blocks on findings with a fix
available and counts the ones without, because a build cannot act on a vulnerability with no
patch. Both scanners are pinned by checksum for the same reason the policy engine is: a scanner
that did not run reports nothing, and nothing is what a clean result looks like. The secret
scanner's report never leaves the runner, because its findings are the secrets.

**An exception register, because the gate fired.** The image scan blocked on its first run
against a real vulnerability with no fixed base image to move to. Rather than switch the control
off or lower the bar, the two findings are written down by identifier in
`assurance/exceptions.toml` with the reason, a named person and a date they stop counting. The
control then reads `excepted`, never `held`, in every bundle that is filed, so how long something
was carried and who said so is in the record. A new finding on the same control still blocks,
because an exception names findings rather than controls.

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

## What you need

**Python 3.11 or newer.** The platform reads its own configuration with `tomllib`, which arrived
in 3.11. On anything older it says so and stops, rather than failing somewhere confusing later.

**OPA on your PATH.** Every decision about what an agent may do is made by it, so the platform
refuses to start without it rather than falling back to a permissive answer. Install it from
[openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa), or point
`OPA_BIN` at the binary. Check with `opa version`.

**Docker, only to actually run an agent.** Provisioning, the policy, the gates and the audit trail
all work without it. Without a daemon the four containment tests skip, and the platform tells you
which ones rather than quietly counting them as passed.

**pytest, only to run the suite.** `python -m pip install pytest`.

## Standing up an agent

Three commands. The first two are the product; the third is how you check it told you the truth.

    python -m golden_path.new_agent my-agent

Creates the agent's folder and walks it through the gates: the config parses, the actions it asked
for are within policy, the sandbox image is pinned by digest. It prints the digest, so you can see
the bytes your agent will run on rather than being told they are fine. A failing gate stops here.

    python -m runtime golden_path/agents/my-agent/plan.toml

Runs the plan the path just wrote for you. One action, in a container with no network at all, on a
read only copy of the agent's own folder, destroyed when it finishes.

    python -m trail.gate

Checks the record of what just happened: the chain is intact, nothing executed without a decision
recorded first, and no gated action went ahead without a named approver.

To watch it refuse something, open `golden_path/agents/my-agent/plan.toml` and uncomment the
`deploy:production` block at the bottom, then run the second command again. The agent never
declared that action, so it is refused before it reaches a container, and the refusal is recorded
and alerted. Declare it in `agent.toml` instead and it is still refused, now for a different
reason: it is gated, and a gated action needs a named approver who is not the person who asked.

## The platform's own gates

These are what CI runs against every change. They are platform operations rather than part of
standing up an agent.

    python -m pytest -q                                   the suite
    opa test policy/ -v                                   the guardrail and compliance policies
    python -m golden_path.adoption                        who came through the path, and who did not

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

Run the bundler on your own machine and it will tell you the truth about that machine rather than
about the platform: with Docker unavailable the containment control reads not held, because the
sandbox tests skipped and a suite that skipped them proves nothing about containment.

## Reading it

`docs/decisions.md` is the decision log, with the reasoning rather than only the outcome, including
the two defects I wrote and then found. `docs/owasp-mapping.md` maps the policy to the OWASP Top 10
for Agentic Applications 2026: four addressed, five partial, one that does not apply yet.
`assurance/system-of-record.md` is the bucket configuration a client applies so that this platform
can hand over an audit record it is then unable to touch, and the last section of it is what
retention does not solve.
