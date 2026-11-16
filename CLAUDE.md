# pe-agentic-platform

Agent runtime, policy layer, audit trail and golden path. Python, Docker, OPA.

## Layout

- `runtime/` sandbox lifecycle, the runner that joins the three, and alerting
- `policy/` OPA policies and the evaluation entry point
- `trail/` append only JSONL writer and the audit gate
- `golden_path/` provisioning, and the adoption census
- `supply/` what the platform runs, pinned by content: `pinned.toml` is the only source of truth
- `assurance/` the control catalog, the bundle assembled per run, and the sink that files it
- `docs/decisions.md` decision log, read this before changing behaviour

## Running

    python -m pytest -q
    python -m runtime <plan-file>
    python -m golden_path.new_agent <name>
    python -m golden_path.adoption [inventory-file]
    python -m trail.gate
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
- Nothing in here may modify `policy/`.
