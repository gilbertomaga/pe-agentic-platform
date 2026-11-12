# Decisions

One entry per decision, with the reasoning and not just the outcome. These are what the instructor
asks about out loud.

---

## D1 · Network is bounded, not absent
**2026-11-06 · runtime**

An agent run gets network, but closed by default with named destinations opened.

**Why.** Network is required because the model is a remote service the agent has to reach, not
because the model fetches knowledge: what it knows is in its weights, on the provider's side. A
sandbox with no network at all only works where the model runs locally, which is not the case here.

Once network exists it has to be bounded. Three destinations are opened and nothing else:

- the model API endpoint
- the package registry, because running tests means resolving dependencies
- the container registry, to pull the base image

**What stays closed matters more than what opens.** The internal network, other services' endpoints,
and specifically the instance metadata endpoint at `169.254.169.254`. A container that can reach
metadata collects IAM credentials nobody granted it, and that is the difference between a sandbox and
something that looks like one.

**Fit with the client's risk.** The client is audit conscious, has its own security function, and
separates production from non production by account rather than by naming convention. An open egress
sandbox would not survive their review, and should not.

---

## D2 · The containment proof runs in CI, not locally
**2026-11-06 · runtime**

The three tests that prove containment, that the sandbox cannot reach the network, that a hung step
is stopped by the clock, and that a run is torn down, execute on a GitHub Actions runner rather than
on my machine.

**Why.** Virtualization is disabled in BIOS on the work machine, so Docker cannot run there. Rather
than describe the containment and leave it unproven, the proof moved to a runner that does have a
daemon.

**Why this is better than running it locally.** A local run proves it once, on one machine, on one
day. In CI it is proven on every push, and the evidence is a build anyone can open. It is also the
same pattern the client platform already uses: the proof lives in the pipeline, not in somebody
having checked.

**The trap avoided.** A skipped test is not a passing test. `REQUIRE_DOCKER=1` is set in the
workflow, which turns a missing daemon into a collection error, so the containment proof cannot
quietly degrade into a skip while the build stays green.

---

## D3 · The action classification
**2026-11-06 · policy**

Three buckets, with precedence forbidden, then human gated, then autonomous. Anything in no bucket
is denied, with a reason.

**Autonomous:** read repository, read knowledge base, run tests, build image, write to a branch,
open a pull request. All reversible, all contained, none leaves a consequence that survives the run.

**Human gated:** merge to main, and deploy to every environment including dev.

Opening a pull request is autonomous but merging is not, because the merge is where a change enters
the trunk and a named human owns that. On the client estate CODEOWNERS already enforces it from both
groups, so the gate is not new, it is the one that already exists.

Dev is gated like the rest because dev environments there are shared with other teams. An unattended
deploy to dev breaks somebody else's work, not just the agent's own, which makes it a production
problem wearing a dev label.

**Forbidden:** read customer data, write secrets, write policy.

Forbidden is not a strict gate, it is a different thing. A gate implies somebody could say yes.
Nobody here can: the approval to put customer data through a model belongs to the client's data
governance owner, not to me and not to the model provider. And an agent that can edit its own policy
has no policy, because every other control derives from it and the trail would record the edit as
normal.

**Deny by default.** The three sets are what somebody remembered to write. The default is what
happens to everything else, which is most of the world, and it is the single most consequential line
in the file.

---

## D4 · The record, and what a hash chain does not catch
**2026-11-06 · trail**

Each record carries sequence, previous hash, timestamp, run, step, prompt, verb, target, policy
outcome, reason, approver and event. `event` is decided, executed or failed: an action that is
decided and then runs produces two records rather than one that gets updated. The trail is append
only, so nothing is ever rewritten.

**Written by the platform, not by the caller.** There is no code path that executes an action
without passing through the writer. If capture were a step somebody could choose, it would be
skipped under deadline, which is when it matters most.

**The hole I found while testing.** A hash chain detects an edited record and a record removed from
the middle, because the links stop matching. It does not detect **truncation**: delete the last
record and every remaining one still chains correctly. That is the easiest way to hide an action,
and the gate passed it cleanly until I tried it.

**What closes it, and what it does not close.** The head, the sequence and hash of the newest
record, is written to a separate file and checked by the gate, so a trail that ends short of its
head is reported. This raises the bar rather than removing it: somebody who deletes the record and
the head together passes again. Closing it properly needs an anchor outside the system, a periodic
notarisation to append only storage or a transparency log. That is the honest limit of a local
build, and it is where this would go on real infrastructure.

**The audit gate.** Runs in CI on every change and fails on three things: a broken chain, an action
that needed a human and went ahead without naming who approved, and an execution with no decision
recorded before it. A trail nobody checks is a log.

---

## D5 · The golden path narrows, it never widens
**2026-11-06 · golden_path**

A team provisioning an agent supplies three things: a name, a purpose, and the actions it needs.
The sandbox limits, the policy binding and the trail are not theirs to choose and do not appear in
the config at all.

**The control.** Every action requested is evaluated against the policy at provisioning time. An
agent may ask for fewer actions than the platform allows. It cannot ask for one the policy gates or
forbids, and it cannot invent one: unlisted is denied here rather than at run time, so the failure
arrives while somebody is still reading the output.

**The defect I wrote by accident.** The first version copied the template over the workspace before
running the gates, so a team's edits were erased before the thing that checks them ran. Every gate
passed on an agent that had asked for `deploy:production`. This is exactly the defect I reported in
the PE-A lab a few hours earlier, and I reproduced it without noticing. Re-running the path now
validates an existing agent rather than resetting it, and there is a test for that specific
behaviour because it is the kind of bug that makes every other gate meaningless while looking fine.

**Adoption, instrumented from the first provisioning.** The path records itself in the trail, so
every agent that exists came through here and is countable. The number worth watching is not how
many came through. It is how many agents exist that are not in the trail, because those are the
ones running without a sandbox, a policy or a record.

---

## D6 · The OWASP mapping says where the platform has not arrived
**2026-11-06 · policy**

Mapped against *OWASP Top 10 for Agentic Applications 2026* (OWASP GenAI Security Project, Agentic
Security Initiative, December 2025, CC BY-SA 4.0). Full mapping in `docs/owasp-mapping.md`.

Four addressed, four partial, two not addressed. The rows that are not addressed are the ones worth
reading:

**ASI04, Agentic Supply Chain Vulnerabilities.** The base image is pinned by tag rather than digest,
nothing verifies its contents, there is no SBOM and no signature checking, and no policy governs
which model versions may be used. It is the largest open risk on the list, and it is Module 4 work.

**ASI07, Insecure Inter-Agent Communication.** One agent, no channel between agents. Recorded as not
applicable rather than omitted, because a mapping that silently drops rows reads as coverage.

**ASI06 is addressed by absence rather than by a control.** Runs are stateless, so there is no
persistent memory to poison. That is a property of the current design, not something I built, and it
stops being true the moment memory is added.

**ASI09 is where the control depends on a human staying sceptical.** The gate on merge means a
confident wrong answer still needs a person to accept it. The gap is that a clean, confident review
makes a reviewer look less carefully than an empty one would, so the gate degrades exactly when the
agent sounds most sure. Nothing measures that until there is an evaluation.

## D7 · The runtime is the join, and the gate was not guarding anything
**2026-11-12 · runtime, trail**

Auditing my own criteria before submitting found the defect this platform was built to make
impossible, which is the third one I have written and then caught.

The three parts were real and separate. `policy/evaluate.py` was called once, by the provisioning
gate. `trail/trail.py` was written once, by the same place. `runtime/sandbox.py` imported neither
and executed commands. So "every action is evaluated before it runs" and "every run leaves a
record" were properties of the design and not of the code, and a sandbox run left nothing behind
at all. A reviewer opening `sandbox.py` would have seen that in about ten seconds.

`runtime/runner.py` is the join. One action takes one path: scope, then policy, then a decided
record, then the approver if the policy gates it, then the sandbox, then an executed record. It
fails closed, it stops at the first refusal rather than continuing down the list, and the decision
is written before the action rather than after, because a record written afterwards is a report.

The invariant is asserted structurally as well as behaviourally. `test_nothing_outside_the_runtime
_calls_the_sandbox_directly` fails if any module reaches a container without going through
`execute()`, because an invariant that depends on everybody remembering it is a convention.

The second half is worse and smaller. `trail/*.jsonl` was ignored by git while
`audit_trail.jsonl.head` was committed, so a fresh clone had an anchor claiming ten records and no
trail. The gate opened with `if not path.exists(): return 0` and said "nothing to gate". Deleting
the entire trail passed. The anchor exists precisely to catch that, `verify()` catches it
correctly, and `main()` returned before ever asking. Two lines, and they made the control
agree that nothing had happened.

The gate was also not in CI at all, which the workbook claimed it was. It runs now: the golden
path writes a trail on every build and the gate has to clear it. The anchor is no longer committed,
because shipping an anchor without its trail is what made the hole look like an empty platform.

Both are now tested: truncation of the newest record, and removal of the whole trail.

## D8 · The two criteria that were ticked without an instrument
**2026-11-12 · runtime, golden path**

Auditing the done-when criteria against the code found two that were honest in intent and empty in
practice. Both are now built, and the building changed what I think each one means.

**An attempted escape is alerted and blocked.** Blocking was proven in CI. Alerting did not exist:
the attempt went into the trail and stopped there. A trail is read afterwards by somebody who
already suspects something, and an alert is what reaches a person who does not yet know to look.

`runtime/alert.py` fires on `forbidden`, `deny` and `out_of_scope`, which are the three ways an
agent reaches for something it was never entitled to. It deliberately does not fire on a gated
action waiting for its approver. That is the gate working as designed, and paging someone every
time a deploy waits is how an alert channel becomes noise nobody reads. It is the same distinction
`trail.unresolved` already draws, and getting it wrong in either direction is the common failure:
alert on everything and the signal is lost, alert on nothing and the control is invisible.

Sinks are stderr and an optional JSONL file rather than a vendor, because every collector reads one
of those two and the day this needs a specific SIEM, that is a sink added and nothing else changed.
A sink that throws is caught: the action was blocked and recorded before alerting is reached, so a
broken collector degrades the signal and never the control.

**Measuring whether they choose the path or route around it.** Counting who came through was
already possible and it is a vanity metric. It rises whether adoption is total or negligible and it
cannot fall. `golden_path/adoption.py` counts the other side: agents that exist with no
provisioning record, which is somebody who copied a template rather than walking the path, running
with no sandbox binding, no policy check and no trail. That is ASI10 measured rather than described.

The limit is stated by the tool itself every time it runs. It sees this host unless it is given an
inventory, and no code inside the platform could ever see an agent on somebody else's laptop or
called straight from a CI job. A coverage number that does not state its denominator is worse than
no number, so the report prints the denominator next to the percentage, and reports no share at all
rather than rounding zero over zero up to full adoption.

Provisioning attempts that stopped at a gate are counted too. They are not failures, they are the
platform's friction, and friction is what sends a Builder looking for the way around. A rising
number there is the leading indicator of a falling number above.
