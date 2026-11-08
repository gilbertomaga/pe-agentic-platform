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
