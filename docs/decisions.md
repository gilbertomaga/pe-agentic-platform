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
