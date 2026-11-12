# pe-agentic-platform

Agent runtime, policy layer, audit trail and golden path. Python, Docker, OPA.

## Layout

- `runtime/` sandbox lifecycle, the runner that joins the three, and alerting
- `policy/` OPA policies and the evaluation entry point
- `trail/` append only JSONL writer and the audit gate
- `golden_path/` provisioning, and the adoption census
- `docs/decisions.md` decision log, read this before changing behaviour

## Running

    python -m pytest -q
    python -m runtime <plan-file>
    python -m golden_path.new_agent <name>
    python -m golden_path.adoption [inventory-file]
    python -m trail.gate

## Rules

- No client code, credentials or account identifiers in this repo.
- Policy denies by default. Every denial carries a reason.
- The trail is written by the platform, never by the caller.
- An action reaches a container only through `runtime.runner.execute`. There is a test for this.
- Nothing in here may modify `policy/`.
