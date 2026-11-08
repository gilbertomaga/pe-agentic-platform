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

**Fit with the client's risk.** The client is a data centre with its own security function and
production separated from non production by account rather than by naming convention. An open egress
sandbox would not survive their review, and should not.

---
