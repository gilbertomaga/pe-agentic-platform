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

## D9 · A gated action has to be declarable, or the human gate is unreachable
**2026-11-12 · golden path, runtime**

Somebody who had never seen this repository ran the golden path on a Mac and sent back five
things. This is the one that was a gap rather than a rough edge, and I had not seen it in a week
of working on the code.

The path refused any action the policy did not treat as autonomous, gated ones included, on the
grounds that it narrows and never widens. The runtime then refuses anything the agent did not
declare in `agent.toml`. Put those together and a gated action could never be declared, so it
could never reach the runtime, so it could never be approved. The `approvals` block, the
`approver` field in every record, `trail.unresolved` and the audit gate's unnamed-approval check
were all unreachable through the product. My own tests exercised them only by calling `execute()`
with a hand built scope, which is the shape of a test that proves a mechanism works and not that
anything can get to it.

D5 was right about what it was protecting and wrong about how. The thing that must not happen is
an agent granting itself an action, and declaring a gated one is not that, because it stays gated.
Forbidden and unlisted still stop the path. A gated action is accepted, the path says it will need
a named approver and where to put one, and the human is named at run time, which is the only place
a human can be named at all.

The other four were friction rather than gaps, and three of them were about the first two minutes:
a stock macOS has no `python` and its `python3` is 3.9, where this fails on `import tomllib` with
a traceback and no hint; the refusal said a named approver was required without saying where to
name one; and provisioning wrote three files while naming only the folder. All three are now
handled, and the version guard sits in the package `__init__` so it runs before anything can
import tomllib and fail less kindly. `new_agent.py` also imported `subprocess` and never used it,
which is the kind of thing only a stranger reads closely enough to notice.


## D10 · Pin what runs by content, and be clear that a digest is not a signature
**2026-11-16 · supply chain, runtime, trail, CI**

Everything in this repository up to here is about what an agent may do once it is running.
Nothing was about what got to run in the first place, and three things arrived from outside and
were trusted on sight.

The sandbox image, by the tag `python:3.12-slim`. A tag is a label the publisher can move, so it
names who built the image and not what is in it. The containment model, which is the claim this
platform leans on hardest, was asserted against bytes nobody had fixed.

The policy engine, downloaded in CI from a `latest` URL with nothing checked. That one is worse
than the other two together. Every guardrail decision here is whatever that binary says, so
substituting it makes the platform permissive while the build stays green and the trail records
each decision as normal. The audit trail would be intact, hash chained, and wrong.

The build's own actions, by tag, on the job that holds the token.

All three are now pinned by content in `supply/pinned.toml`, with the command that produced each
value written beside it, because a pin nobody can re-derive is a number somebody eventually bumps
without checking. The runtime resolves the image from that file and raises before the first
decision if what it gets is not a digest, which is the same reflex as failing closed on an
unreachable policy engine: a run nobody can describe should not start. The golden path prints the
digest as a gate, so a Builder sees the bytes their agent will run on rather than being told they
are fine. CI reads the same file rather than repeating it, verifies the OPA download against the
pinned checksum, and emits a CycloneDX SBOM of the image that actually ran.

**What this does not do, which matters more than what it does.** A digest says the bytes did not
change since I looked. It does not say who made them or that they are safe, and pinning a
compromised image pins the compromise. The OPA checksum is published by the same project as the
binary, so it catches a corrupted or substituted download and not a compromised release. There is
still no signature verification, because the Docker official images are not signed by a publisher
identity this platform can name, and verifying nothing against nobody is theatre with a green
tick on it. The honest position is that an image we build ourselves is the point at which signing
and provenance become real, and that is named rather than claimed. The pins also only bind what
CI installs; a developer's locally installed OPA is their own, and the platform cannot see it.

**One consequence, recorded rather than smoothed over.** The signed field set in the trail gained
`evidence`, which carries the digest the step ran on. It had to be inside the hash: a digest an
auditor can rewrite afterwards proves nothing about what ran. Changing the signed set invalidates
every record written before it, and the local chain broke exactly as designed the moment the field
landed. No chain outside a build existed at that point, so the cost was a developer trail, closed
and kept rather than deleted. The verifier now recognises the old shape and says so by name
instead of reporting twenty-four identical hash mismatches and sending somebody hunting for an
edit that never happened. It still fails: a chain carrying two shapes is a real break, and rolling
it forward is a decision somebody takes. After this the field set is frozen, and the next change
needs a versioned record and a migration rather than an edit.


## D11 · The evidence leaves the building

**2026-11-16 · assurance, trail, CI**

The note that started this was one sentence: the trail lives in a file in my repository. That is
the whole problem. An audit record held by the party being audited is worth exactly what that
party's word is worth, and not having to take anyone's word was the point of writing it.

Three things are wrong with the trail as an audit record, and only the first one is obvious. It
sits in the platform's own storage. It has no notion of a change, so it answers "what did the
agent do" and cannot answer "what shipped on Tuesday", which is the question an auditor actually
asks. And it carries traceability and nothing else: no test result, no scan, no control. All
three are fixed by the same move, which is to stop treating the trail as the deliverable and
start treating it as one input to something that is.

**What a bundle is.** One per run. It carries the traceability projected into a published shape,
the quality and security evidence the pipeline produced, and every control in the client's
catalog with its state and the evidence behind it. Four properties, each a decision rather than
a detail.

It is reproducible. No assembly timestamp, no path, nothing about the machine that built it.
Assemble it twice from the same evidence and the bytes are identical, so the digest is something
a person who was not there can re-derive and check. When that turned out to be awkward the
timestamp moved into the receipt, where it belongs: when a bundle was filed is a fact about the
filing, not about the change.

It is content addressed. The bundle's name is its own digest, so an altered bundle is a
different object rather than a replacement for this one, and a store cannot hold two different
bundles under one name.

It always lands, pass or fail. A failing change produces a bundle that says which control failed
and why, and that bundle goes to the evidence store like any other. This was the one decision I
went back and forth on, and the argument that settled it is that an evidence store containing
only successes is a marketing database with an audit trail's filename. What stops the change is
the exit code of the step that reads the bundle, not the bundle going missing.

Its shape is published. `STEP_FIELDS` is a contract with the three pathways downstream that
consume this bundle, so the trail's internal record can change without breaking them and a field
added to the trail does not silently leak into what a client's auditor receives. There is a test
holding one against the other, which is the only form of contract that survives contact with a
deadline.

**The catalog is the client's, so it is data.** The temptation here was to ship a SOC 2 mapping
and call the component done. I do not have the client's control framework; I have an open thread
with their security team and no answer yet, and inventing one would have produced a document that
maps real evidence to controls nobody is held to. So the catalog is a file, the shipped one says
in its first line that it is a demonstration set, and a test fails if it ever claims to be a
named regime. Replacing it with the client's own is the only change a real engagement needs.

A control is satisfied in exactly one of three ways, and they are deliberately different. Machine
evidence, produced automatically on every change. An attestation, where a person accepted
something no scanner can see. Or a declared gap, which is the control written down with the
reason it cannot be met yet. The gap is the one worth defending: a control that simply is not in
the catalog scores nothing and looks like nothing, and a control nothing evaluates scores green.
Both are the same audit finding eighteen months later. Two gaps are declared here, signing and
secret scanning, and they are in the bundle every time it is assembled.

Two checks run when the catalog loads and both are failures rather than warnings. A control
mapped to evidence the platform does not produce means the catalog and the platform have drifted,
and it would otherwise read as unmet forever while looking like a data problem. A control naming
none of the three means nobody decided about it.

**The attestation expires, and it will go red in February.** A signature given once about a
platform that has changed since is a historical document, not evidence about today, so an
attestation carries a date and a validity period and the bundle reads an expired one as not held.
The one in this repository is ninety days from 2026-11-16. It is also signed by the person who
built the platform, which on a client engagement is the wrong name and the right mechanism, and
the file says so rather than leaving it to be noticed.

**Where it lands, and what that costs the platform.** The sink writes into a bucket in the
client's own account with object lock in compliance mode, and the credentials it writes with hold
`s3:PutObject` and nothing else. Not delete, not the retention setting, not the lifecycle rules.
Once a bundle is filed this platform cannot change it or remove it, and that inability is the
thing that makes the producer of the record an acceptable producer of the record.

Compliance mode rather than governance, because governance retention can be removed by anyone
holding one extra permission, which makes a governance bucket write once for people who do not
have it. The sink checks the bucket is locked before it writes anything, because object lock is
bucket configuration rather than a flag on the write: pointed at an ordinary bucket it would
write successfully, return a clean receipt, and produce something indistinguishable from an audit
record that anybody could delete.

**What this does not prove, which is the part worth reading.** The build starts a real S3
compatible store and exercises the whole path against it: the refusal on an unlocked bucket, the
write with compliance retention, the retention read back off the object. That is evidence about
this platform's behaviour. It is not evidence that retention is enforced, because an emulator
refusing a delete proves only that the emulator refuses deletes. Enforcement belongs to the
client's store and their account configuration, and the delete probe in CI therefore reports what
happened instead of asserting an outcome it is not in a position to know. What would close this
properly is the store countersigning its own receipt at the time of the write, which is the
client's store's job and is named in assurance/system-of-record.md rather than claimed anywhere.


## D12 · A quality gate that blocks, and a bar somebody agreed to

**2026-11-16 · quality, CI, assurance**

The suite ran on every change and nothing was held to it beyond passing. Coverage was not
measured, so the platform could not tell a change that added tested code from one that added
untested code, and both were green. That is the gap this closes, and making it block was the
easy part. What took the thinking was what it blocks on.

**Not a coverage percentage.** A target of eighty percent is either below where the code already
sits, in which case it never fires and is decoration, or above it, in which case everybody is red
on the first day and the gate is switched off inside a fortnight. Worse than either, a percentage
can be held level while untested code is added, by adding tested code beside it in the same file.
So the number is uncovered lines, an integer, and the rule is that it may not go up. A change
that adds code with no tests fails whatever it adds elsewhere.

**A recorded baseline, not a computed one.** The allowance is a file in the repository and
lowering it is a commit. A gate that recalculates its bar from the previous build can be walked
downwards one change at a time, with every individual step looking reasonable and nobody ever
seeing the slope. Here the slope is a diff.

**A new file starts at zero.** Code arriving untested has to be either tested or written into the
baseline in the same change, where a reviewer sees the number being taken on. That is the
difference between debt somebody accepted and debt that accumulated while everyone was looking at
a percentage that had not moved much.

**It refuses to judge a run that did not finish.** This is the decision I would defend hardest.
If any test was skipped, the coverage numbers describe a run where some code could not execute,
and comparing those against a baseline recorded from a full run fails a person for their machine
rather than for their change. Do that twice and the gate has the reputation that gets it bypassed,
and a bypassed gate is worse than no gate because it still appears on the board. So a skipped test
produces "not comparable", which names what did not run, and that is a non zero exit in CI, where
nothing should skip. The assurance bundle records it as unevidenced rather than as a pass,
because an unanswered question is not a yes.

That distinction cost nothing to build and is the same one the bundle already makes about
evidence. It keeps turning out to be the useful one.

**The same gate for everybody.** There is no author, actor or branch anywhere in the gate or in
the build around it, so an agent's change meets exactly the gate a person's change meets. That is
a claim worth more than a sentence, so a structural test reads the workflows and fails if any of
them mentions who made the change. One `if: github.actor ==` would have made the claim false
while every other test stayed green.

**What a blocked Builder gets.** The numbers, the files, and the name of the file where the bar
lives, written to the job summary rather than left in a log. Somebody who has to read a build log
to find out why they were stopped is somebody learning to work around the thing that stopped them.

**What this does not do, which is most of quality.** Coverage says a line executed. It does not
say anything was asserted about it, and a suite of tests that call everything and assert nothing
scores perfectly here. The honest instrument for that is mutation testing, which is not in this
platform, and the reason is cost rather than principle: it is minutes per run where this is
seconds. Naming it is better than implying the gate measures something it does not. The gate also
reads JaCoCo as well as coverage.py, because the delivery platform underneath this one is mostly
Java, and a quality gate that understands half an estate is an argument for a second gate.


## D13 · Scanners report, the catalog decides

**2026-11-16 · security, supply chain, assurance, CI**

Two scans were missing and both are the kind whose absence is invisible. Nothing looked for
secrets in the history, and nothing looked at what was in the image the sandbox runs, which the
SBOM described without ever asking whether any of it was known to be vulnerable. A repository
with no secret scanner and a repository with no secrets look identical from outside.

**The scanners do not decide.** Both run with their exit code forced to zero and write a report.
What blocks the change is the control catalog reading the evidence derived from that report. So
the severity that stops a build is a line in a control somebody reviewed, not a flag buried in a
YAML argument where changing it reads as a formatting commit, and one place enforces every
control rather than each scanner enforcing its own.

It costs something, and the cost is honest to name: feedback arrives at the assurance step
rather than the moment the scanner finishes. On a build this size that is seconds. On a long
pipeline it would be worth failing fast as well, and the catalog would still be where the
threshold lives.

**Fixable and unfixable are different findings.** The image gate blocks on vulnerabilities that
have a fix available and not on the ones that do not, because a build cannot act on a
vulnerability with no patch, and a gate that stops everybody for something nobody can fix is a
gate that gets an exception written for it in a fortnight. The unfixable ones are counted in
every bundle so the number is visible rather than quietly dropped by an `--ignore-unfixed` flag.

That leaves a real gap and it is declared as one rather than rounded off. Nothing routes an
unfixable finding to a person, so today it is visible and unhandled. Visible and unhandled is
worth writing down; it is the state that turns into a surprise when somebody finally reads the
count.

**The scanners are pinned and checksummed, like the policy engine.** This is the same lesson as
D10 and it generalises past the thing that taught it: every tool the build downloads and then
trusts is a tool whose silence looks like good news. A substituted policy engine allows
everything, a scanner that did not run reports nothing, and a secret scanner that failed finds no
secrets. All three produce a green build. The structural test now counts downloads against
checksum checks across every workflow rather than naming the one tool that once got this wrong.

The vulnerability scanner publishes a sigstore bundle beside its checksums, which is a real
publisher identity and more than the base image offers. Verifying it needs cosign and is the step
up from here. The checksum is what is claimed today.

**The raw reports stay on the runner.** A secret scanner's findings are the secrets. Copying them
into an assurance bundle, which is then filed in a store where nobody can delete it for a year,
is making a second and more durable copy of the leak in the one place designed to keep things
forever. What travels is the count, the rule names and the paths. There is a test that puts a
credential-shaped string through the whole chain and fails if it appears anywhere in the bundle.

**The history, not the tip.** The secret scan reads every commit, which is why the build now
checks out the full history. A secret removed in a later commit is still in the repository, and
the history is where somebody looking for one would look.

**What is still not covered, named rather than implied.** There is no dynamic testing, because
there is no running environment to point it at; this platform is a runtime and a set of
libraries, not a service. There is no dependency scan, because there are no third party runtime
dependencies to scan: that is a property of this codebase rather than a control this platform
provides, and claiming the control would be claiming credit for the absence of the risk. Signing
and provenance remain where D10 left them.


## D14 · The gate fired, so there is a register

**2026-11-16 · security, assurance**

The image scan from D13 blocked the build on its first run. Two HIGH findings, both against the
same package, zlib1g, in the Debian base of the pinned sandbox image, with a fixed Debian version
published and no rebuilt official Python image carrying it. Forty seven more findings at the same
severity had no fix available at all.

So the control was correct, the finding was real, and there was no version to move to. Three ways
out of that and two of them are the same mistake.

Turning the control off removes the only thing that found it. Lowering the threshold removes it
along with every other finding at that severity, which is the same act with more steps and a
better name. Both end with a platform that has an image scanner and does not know what is in its
image, which is where it started, except now there is a green tick.

**So the finding is written down.** `assurance/exceptions.toml` names the two identifiers, the
package, the reason, the person who decided and the date it stops counting. The control is
untouched. Four properties keep this from becoming the thing it replaced.

It is per finding, never per control. An exception lists the identifiers it covers, so a new
vulnerability in the same image blocks the build on the day it appears, because nobody has looked
at it yet. A control level exception would be the gate switched off with ceremony.

It expires. Carrying a finding is a decision about today and not a permanent property of it. An
expired exception stops applying and the control blocks again, which is the only mechanism I know
of that reliably brings somebody back to a decision they made in a hurry. This one runs to
2026-12-14.

It is never a pass. The control reads `excepted`, not `held`, in every bundle filed in the
evidence store, and the bundle carries the identifiers, the reason and the name. An auditor
reading a year of bundles can see how long something was carried and who said so without asking
anybody. An exception that reads as a pass is precisely how an exception becomes permanent.

It names a person. Not a team and not a ticket on its own.

**The reason is the part worth reviewing**, and what makes this one defensible is not the
severity, it is the containment. Reaching a zlib flaw needs the container to be handed attacker
chosen compressed input, and the only thing that enters this sandbox is a plan the platform
wrote, with no network, non root, a read only root filesystem and a clock. That argument is in
the register rather than in somebody's head, which means a reviewer can disagree with it.

**The expiry is pointed at a specific piece of work.** There is no published base image where
this is clean, so the fix is to build the image instead of consuming one. That is also the point
at which signing and provenance stop being a declared gap, which D10 said and this date now
forces.

**A correction to D11, which claimed the bundle carries no clock.** It carries a date now,
`assessed_on`, because attestations and exceptions expire and the day they were weighed against
is an input to the result rather than a fact about the filing. Leaving it out made the bundle
quietly non reproducible across a boundary; putting it in makes the judgment re-derivable by
somebody reading the bundle alone. It is the same distinction that put the storage time in the
receipt and not in the bundle, applied in the other direction.

**One thing deliberately cannot be excepted.** A committed secret produces no finding
identifiers, so there is nothing for an exception to match on and the control blocks until the
scan is clean. A leaked credential is rotated, not carried for a month.


## D15 · The client's controls, when nobody can tell you what they are

**2026-11-16 · policy, compliance, assurance**

This was blocked on a question I had been treating as somebody else's to answer: which control
framework is this platform actually held to. Grepping the codebase for the usual names had found
nothing, which proves only that control frameworks do not live in code.

So I looked where they do live. The client has a compliance and integrated risk function and a
Confluence space for it. The space contains three things: the default welcome page, the default
banner image that came with it, and the space itself. Created in March, never written in.

What exists instead is on the engineering wiki. A numbered data protection requirement set, R01
to R11 with a retention sub-set beneath one of them, written by somebody who has since left the
company, last edited in 2025, twenty views. A per rollout checklist with its own lettered
sections and Pass or Gap against each. A list in a QA space of the artifacts that team keeps for
software lifecycle compliance. All three are real and in use. None of them is a control framework
anybody is held to, and treating one as if it were is how a platform ends up mapped to a
document nobody agreed to.

**So the platform must not depend on knowing.** Two changes, and the first is the one that
matters.

**The mapping is now required and the absence of one is a stated absence.** Every control names
either `maps_to`, with references into the client's framework, or `unmapped_because`, with the
reason there are none, and the catalog refuses to load if a control says neither. The mapping is
the thing an auditor reads, and silence in that field reads as mapped to whatever the reader
assumes.

Four of fifteen controls carry a reference, to the clauses of that data protection set where the
fit is honest: records of processing, immutable logs, approval workflows, assigned
responsibility. The other eleven say why they have none, and the reason is almost always the same
one: the only numbered requirement set available is about personal data and most of this
platform's controls are about engineering assurance. The supply chain controls are the sharpest
case, because nothing in that requirement set reaches a supply chain at all.

That split is the useful output. A catalog where everything maps is a catalog that is guessing,
and the eleven reasons are a better thing to put in front of their risk function than a
mapping I invented. The references that are there are marked as proposals in the catalog's own
header, because nobody has confirmed them.

**The client's controls live in their own file.** `policy/compliance.rego`, its own package,
evaluated through its own entry point. `agent.rego` is the platform's guardrail and changes when
the platform changes. This one belongs to the client, so when their control set arrives it is a
file that gets replaced rather than a change that reaches into the runtime.

**The control I implemented, and why that one.** Separation of duties: the person who approves an
action is not the person who requested it. It is in every control framework there has ever been,
and this platform claimed it. The plan template said "nobody here approves their own" in a
comment, and nothing checked it. Worse than unenforced, it was uncheckable: the trail recorded
who approved and never recorded who asked, so there was no second name to compare against.

Finding that the platform asserted a control it could not evaluate is worth more than the fix.

**Where the requester went.** Into `evidence`, not into a field of its own, because the signed
field set was frozen in D10 after changing it broke every record written before. Evidence is
already inside the hash, which is the property that matters here: a separation of duties control
is worth nothing if the name of whoever asked can be edited afterwards. The freeze paid for
itself the first time it was tested.

**Two kinds of stop, kept apart.** A gated action still waiting for an approver halts quietly
with no alert, because that is the gate working. Somebody approving their own request is an
attempt to get around a control, so it is refused, recorded as non compliant, and alerted. Those
are different events and collapsing them would make one of them invisible.

**The evidence is read back off the record.** The runtime refuses a non compliant action, so in
the normal case the check against the trail can only ever confirm. That is deliberate: a control
is evidenced by the record it left, not by the assurance that a gate ran, and a record written by
an older runtime or by any route that stopped going through the gate fails here rather than being
assumed clean.

**What this does not do.** Comparing names without case or spacing catches the careless case. It
is not identity resolution, and anybody determined to approve their own work can do it with a
second account. That is a joiners and leavers problem and no policy file reaches it. The platform
also has no environments, so "evaluated against every environment" is a property of this control
set it cannot demonstrate here; on the client's estate it is the same policy evaluated in the
same pipeline, which is where that sentence becomes testable.
