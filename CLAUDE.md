# pe-agentic-platform

Agent runtime, policy layer, audit trail and golden path. Python, Docker, OPA.

## Layout

- `runtime/` sandbox lifecycle, the runner that joins the three, and alerting
- `policy/` OPA policies and the evaluation entry point
- `trail/` append only JSONL writer and the audit gate
- `golden_path/` provisioning, and the adoption census
- `supply/` what the platform runs, pinned by content: `pinned.toml` is the only source of truth
- `quality/` the coverage gate and `baseline.toml`, the bar a change is held to
- scanners live in CI only: they report, and `assurance/controls.toml` decides what blocks
- `assurance/` the control catalog, the bundle assembled per run, and the sink that files it
- `docs/decisions.md` decision log, read this before changing behaviour

## Running

    python -m pytest -q
    python -m runtime <plan-file>
    python -m golden_path.new_agent <name>
    python -m golden_path.adoption [inventory-file]
    python -m trail.gate
    python -m quality.gate --report coverage.xml --tests junit.xml [--update NOTE]
    python -m assurance.collect {tests,supply} --out <file>
    python -m assurance.bundle <run-id> --evidence <dir> --out <dir>
    python -m assurance.land <bundle> --bucket <bucket> | --directory <dir>

## Rules

- No client code, credentials or account identifiers in this repo.
- Policy denies by default. Every denial carries a reason.
- The trail is written by the platform, never by the caller.
- An action reaches a container only through `runtime.runner.execute`. There is a test for this.
- Nothing names the sandbox image by tag. It comes from `supply/pinned.toml`, by digest, and the
  runtime raises on anything else. There is a test for this too.
- The trail's signed field set is frozen. Changing it breaks every record written before the
  change, so it needs a versioned record and a migration, not an edit. See D10.
- The assurance bundle's shape is a contract with three other pathways. `STEP_FIELDS` and
  `BUNDLE_VERSION` in `assurance/bundle.py` change together, deliberately, or not at all. The
  bundle also carries no assembly timestamp: it has to be reproducible byte for byte. See D11.
- The control catalog is the client's. Nothing shipped here may claim to be a named framework,
  and there is a test for that.
- Nothing in the build may be conditioned on who made the change. Agent change meets the gate
  human change meets, and a structural test reads the workflows for `github.actor` and friends.
- `quality/baseline.toml` only goes down. Raising a number belongs in the same commit as the
  reason, and the gate never rewrites it on its own. See D12.
- Every binary the build downloads is checked against a pinned checksum. There is a test that
  counts downloads against checks across all workflows. See D10 and D13.
- A scanner's raw output stays on the runner. Only derived counts, rule names and paths reach
  the evidence directory, because a secret scanner's findings are the secrets. See D13.
- A finding is carried by naming it in `assurance/exceptions.toml`, with a reason, a person and
  an expiry. Never by relaxing a control or a threshold. The state is `excepted`, never `held`,
  and a committed secret can never be excepted. See D14.
- Nothing in here may modify `policy/`.
