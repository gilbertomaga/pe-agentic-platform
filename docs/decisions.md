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
